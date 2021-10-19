/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Properties file handling functions
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_panic.h"

#include "properties.h"

struct properties {
	struct util_list list;
};

struct property {
	struct util_list_node node;
	char *name;
	char *value;
};

#define SHA256_DIGEST_LEN	32
#define INTEGRITY_KEY_NAME      "__hash__"

#define RESTRICTED_PROPERTY_NAME_CHARS   "=\n"
#define RESTRICTED_PROPERTY_VALUE_CHARS  "\n"

#define RESTRICTED_STR_LIST_CHARS        ",\n"

static int openssl_initialized;

/**
 * Allocate and initialize a SHA-256 context
 *
 * @returns a SHA context
 */
static EVP_MD_CTX *sha256_init(void)
{
	EVP_MD_CTX *ctx;
	int rc;

	if (!openssl_initialized) {
		OpenSSL_add_all_algorithms();
		openssl_initialized = 1;
	}

	ctx = EVP_MD_CTX_create();
	util_assert(ctx != NULL,
		    "Internal error: OpenSSL MD context allocation failed");

	rc = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	util_assert(rc == 1, "Internal error: SHA-256 digest init failed");

	return ctx;
}

/**
 * Add data to the SHA-256 context
 *
 * @parm[in]    ctx        the SHA context
 * @parm[in]    data       the data to be hashed
 * @parm[in]    data_len   the length of the data
 */
static void sha256_update(EVP_MD_CTX *ctx,
			  const char *data, unsigned int data_len)
{
	int rc;

	util_assert(ctx != NULL, "Internal error: OpenSSL MD context is NULL");
	util_assert(data != NULL || data_len == 0,
		    "Internal error: data is NULL");

	rc = EVP_DigestUpdate(ctx, data, data_len);

	util_assert(rc == 1, "Internal error: SHA-256 digest udpdate failed");
}

/**
 * Produce the digest for the SHA-256 context and free the context
 *
 * @parm[in]     ctx          the SHA context
 * @parm[out]    digest       a buffer where the digest is stored
 * @parm[in/out] digest_len   on entry, *digest_len contains the size of the
 *                            digest buffer, which must be large enough to hold
 *                            a SHA-256 digest (32 bytes),
 *                            on exit it contains the size of the digest
 *                            returned in the buffer.
 */
static void sha256_final(EVP_MD_CTX *ctx,
			 unsigned char *digest, unsigned int *digest_len)
{
	int rc;

	util_assert(ctx != NULL, "Internal error: OpenSSL MD context is NULL");

	if (digest != NULL && digest_len != NULL) {
		util_assert(*digest_len >= (unsigned int)EVP_MD_CTX_size(ctx),
			    "Internal error: digest_len is too small");

		rc = EVP_DigestFinal_ex(ctx, digest, digest_len);
		util_assert(rc == 1,
			    "Internal error: SHA-256 digest final failed");
	}

	EVP_MD_CTX_destroy(ctx);
}

/**
 * Allocates a new properties object
 *
 * @returns the properties object
 */
struct properties *properties_new(void)
{
	struct properties *properties;

	properties = util_zalloc(sizeof(struct properties));

	util_list_init_offset(&properties->list,
			      offsetof(struct property, node));
	return properties;
}

/**
 * Frees a properties object with all its properties
 *
 * @param[in]  properties    the properties object
 */
void properties_free(struct properties *properties)
{
	struct property *property;

	util_assert(properties != NULL, "Internal error: properties is NULL");

	while ((property = util_list_start(&properties->list)) != NULL) {
		free(property->name);
		free(property->value);
		util_list_remove(&properties->list, property);
		free(property);
	}

	free(properties);
}

/**
 * Find a property by its name in the list iof properties
 *
 * @param[in]  properties    the properties object
 * @param[in]  name          the name of the property to find
 *
 * @returns a pointer to the proerty when it has been found, or NULL if not
 */
static struct property *properties_find(struct properties *properties,
					const char *name)
{
	struct property *property;

	property = util_list_start(&properties->list);
	while (property != NULL) {
		if (strcmp(property->name, name) == 0)
			return property;
		property = util_list_next(&properties->list, property);
	}
	return NULL;
}

/**
 * Adds or updates a property
 *
 * @param[in]  properties    the properties object
 * @param[in]  name          the name of the property
 * @param[in]  value         the value of the property
 * @param[in]  uppercase     if true the value is set all uppercase
 *
 * @returns 0 on success,
 *          -EINVAL if the name or value contains invalid characters
 */
int properties_set2(struct properties *properties,
		    const char *name, const char *value, bool uppercase)
{
	struct property *property;
	int i;

	util_assert(properties != NULL, "Internal error: properties is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");
	util_assert(value != NULL, "Internal error: value is NULL");

	if (strpbrk(name, RESTRICTED_PROPERTY_NAME_CHARS) != NULL)
		return -EINVAL;
	if (strpbrk(value, RESTRICTED_PROPERTY_VALUE_CHARS) != NULL)
		return -EINVAL;

	property = properties_find(properties, name);
	if (property != NULL) {
		free(property->value);
		property->value = util_strdup(value);
	} else {
		property = util_zalloc(sizeof(struct property));
		property->name = util_strdup(name);
		property->value = util_strdup(value);
		util_list_add_tail(&properties->list, property);
	}
	if (uppercase) {
		for (i = 0; property->value[i] != '\0'; i++)
			property->value[i] = toupper(property->value[i]);
	}

	return 0;
}

/**
 * Adds or updates a property
 *
 * @param[in]  properties    the properties object
 * @param[in]  name          the name of the property
 * @param[in]  value         the value of the property
 *
 * @returns 0 on success,
 *          -EINVAL if the name or value contains invalid characters
 */
int properties_set(struct properties *properties,
		   const char *name, const char *value)
{
	return properties_set2(properties, name, value, false);
}

/**
 * Gets a property
 *
 * @param[in]  properties    the properties object
 * @param[in]  name          the name of the property
 *
 * @returns a string containing the property value, or NULL if the property
 *          was not found.
 *          Note: The returned string must be freed via free() by the caller.
 */
char *properties_get(struct properties *properties, const char *name)
{
	struct property *property;

	util_assert(properties != NULL, "Internal error: properties is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");

	property = properties_find(properties, name);
	if (property == NULL)
		return NULL;

	return util_strdup(property->value);
}

/**
 * Removes a property
 *
 * @param[in]  properties    the properties object
 * @param[in]  name          the name of the property
 *
 * @returns 0 on success, -ENOENT if the property was not found.
 */
int properties_remove(struct properties *properties, const char *name)
{
	struct property *property;

	util_assert(properties != NULL, "Internal error: properties is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");

	property = properties_find(properties, name);
	if (property == NULL)
		return -ENOENT;

	free(property->name);
	free(property->value);
	util_list_remove(&properties->list, property);
	free(property);
	return 0;
}

/**
 * Saves the properties to a file
 *
 * @param[in]  properties    the properties object
 * @param[in]  filename      the file name
 * @param[in]  check_integrity if TRUE, an hash of the key and values is
 *                           stored as part of the file.
 *
 * @returns 0 on success, -EIO the file could not be created
 */
int properties_save(struct properties *properties, const char *filename,
		    bool check_integrity)
{
	char digest_hex[SHA256_DIGEST_LEN * 2 + 1];
	unsigned char digest[SHA256_DIGEST_LEN];
	unsigned int digest_len = sizeof(digest);
	struct property *property;
	EVP_MD_CTX *ctx = NULL;
	unsigned int i;
	FILE *fp;

	util_assert(properties != NULL, "Internal error: properties is NULL");
	util_assert(filename != NULL, "Internal error: filename is NULL");

	fp = fopen(filename, "w");
	if (fp == NULL)
		return -EIO;

	if (check_integrity)
		ctx = sha256_init();

	property = util_list_start(&properties->list);
	while (property != NULL) {
		fprintf(fp, "%s=%s\n", property->name, property->value);

		if (check_integrity) {
			sha256_update(ctx, property->name,
				      strlen(property->name));
			sha256_update(ctx, property->value,
				      strlen(property->value));
		}

		property = util_list_next(&properties->list, property);
	}

	if (check_integrity) {
		sha256_final(ctx, digest, &digest_len);
		util_assert(digest_len <= SHA256_DIGEST_LEN,
			    "Internal error: digest length too long");

		for (i = 0; i < digest_len; i++)
			sprintf(&digest_hex[i * 2], "%02x", digest[i]);
		digest_hex[digest_len * 2] = '\0';

		fprintf(fp, "%s=%s\n", INTEGRITY_KEY_NAME, digest_hex);
	}

	fclose(fp);
	return 0;
}

/**
 * Loads the properties from a file
 *
 * @param[in]  properties    the properties object
 * @param[in]  filename      the file name
 * @param[in]  check_integrity if TRUE, an hash of the key and values is
 *                           compared with the hash stored as part of the file.
 *
 * @returns 0 on success, -EIO the file could not be created,
 *          -EPERM in case of a syntax error or an integrity error
 */
int properties_load(struct properties *properties, const char *filename,
		    bool check_integrity)
{
	char digest_hex[SHA256_DIGEST_LEN * 2 + 1];
	unsigned char digest[SHA256_DIGEST_LEN];
	unsigned int digest_len = sizeof(digest);
	char *digest_read = NULL;
	EVP_MD_CTX *ctx = NULL;
	char line[4096];
	unsigned int len, i;
	int rc = 0;
	char *ch;
	FILE *fp;

	util_assert(properties != NULL, "Internal error: properties is NULL");
	util_assert(filename != NULL, "Internal error: filename is NULL");

	fp = fopen(filename, "r");
	if (fp == NULL)
		return -EIO;

	if (check_integrity)
		ctx = sha256_init();

	while (fgets(line, sizeof(line), fp) != NULL) {
		len = strlen(line);
		if (line[len - 1] == '\n')
			line[len - 1] = '\0';
		if (line[0] == '#')
			continue;
		if (strlen(line) == 0)
			continue;
		ch = strchr(line, '=');
		if (ch == NULL) {
			rc = -EPERM;
			goto out;
		}

		*ch = '\0';
		ch++;

		if (check_integrity) {
			if (strcmp(line, INTEGRITY_KEY_NAME) == 0) {
				digest_read = util_strdup(ch);
				continue;
			}

			sha256_update(ctx, line, strlen(line));
			sha256_update(ctx, ch, strlen(ch));
		}

		properties_set(properties, line, ch);
	}

	if (check_integrity) {
		sha256_final(ctx, digest, &digest_len);
		ctx = NULL;
		util_assert(digest_len <= SHA256_DIGEST_LEN,
			    "Internal error: digest length too long");

		for (i = 0; i < digest_len; i++)
			sprintf(&digest_hex[i * 2], "%02x", digest[i]);
		digest_hex[digest_len * 2] = '\0';

		if (digest_read == NULL ||
		    strcmp(digest_hex, digest_read) != 0) {
			rc = -EPERM;
			goto out;
		}
	}

out:
	if (ctx != NULL)
		sha256_final(ctx, NULL, NULL);
	if (digest_read != NULL)
		free(digest_read);
	fclose(fp);
	return rc;
}

/**
 * Combines a list of strings into one comma separated string
 *
 * @param[in] strings    zero terminated array of pointers to C-strings
 *
 * @returns a new string. This must be freed by the caller when no longer used.
 *          returns NULL if a string contains an invalid character.
 */
char *str_list_combine(const char **strings)
{
	unsigned int i, size;
	char *str;

	util_assert(strings != NULL, "Internal error: strings is NULL");

	for (i = 0, size = 0; strings[i] != NULL; i++) {
		if (strpbrk(strings[i], RESTRICTED_STR_LIST_CHARS) != NULL)
			return NULL;

		if (i > 0)
			size += 1;
		size += strlen(strings[i]);
	}

	str = util_zalloc(size + 1);
	for (i = 0, size = 0; strings[i] != NULL; i++) {
		if (i > 0)
			strcat(str, ",");
		strcat(str, strings[i]);
	}

	return str;
}

/**
 * Splits a comma separated string into its parts
 *
 * @param[in] str_list   the comma separated string
 *
 * @returns a zero terminated array of pointers to C-strings. This array
 *          and all individual C-Strings need to be freed bay the caller when
 *          no longer used. This can be done using str_list_free_string_array().
 */
char **str_list_split(const char *str_list)
{
	unsigned int i, count;
	char **list;
	char *copy;
	char *tok;

	util_assert(str_list != NULL, "Internal error: str_list is NULL");

	count = str_list_count(str_list);
	list = util_zalloc((count + 1) * sizeof(char *));

	copy = util_strdup(str_list);
	tok = strtok(copy, ",");
	i = 0;
	while (tok != NULL) {
		list[i] = util_strdup(tok);
		i++;
		tok = strtok(NULL, ",");
	}

	free(copy);
	return list;
}

/**
 * Count the number of parts a comma separated string contains
 *
 * param[in] str_list   the comma separated string
 *
 * @returns the number of parts
 */
unsigned int str_list_count(const char *str_list)
{
	unsigned int i, count;

	util_assert(str_list != NULL, "Internal error: str_list is NULL");

	if (strlen(str_list) == 0)
		return 0;

	for (i = 0, count = 1; str_list[i] != '\0'; i++)
		if (str_list[i] == ',')
			count++;
	return count;
}

/**
 * Find a string in a comma separated string
 *
 * @param str_list     the comma separated string.
 * @param str          the string to find
 *
 * @returns a pointer to the string within the comma separated string,
 *          or NULL if the string was not found
 *
 */
static char *str_list_find(const char *str_list, const char *str)
{
	char *before;
	char *after;
	char *ch;

	ch = strstr(str_list, str);
	if (ch == NULL)
		return NULL;

	if (ch != str_list) {
		before = ch - 1;
		if (*before != ',')
			return NULL;
	}

	after = ch + strlen(str);
	if (*after != ',' && *after != '\0')
		return NULL;

	return ch;
}

/**
 * Appends a string to a comma separated string
 *
 * @param str_list     the comma separated string.
 * @param str          the string to add
 *
 * @returns a new comma separated string. This must be freed by the caller when
 *          no longer used. If the string to add is already contained in the
 *          comma separated list, it is not added and NULL is returned.
 *          If the string to be added contains a comma, NULL is returned.
 */
char *str_list_add(const char *str_list, const char *str)
{
	char *ret;

	util_assert(str_list != NULL, "Internal error: str_list is NULL");
	util_assert(str != NULL, "Internal error: str is NULL");

	if (strpbrk(str, RESTRICTED_STR_LIST_CHARS) != NULL)
		return NULL;

	if (str_list_find(str_list, str))
		return NULL;

	ret = util_zalloc(strlen(str_list) + 1 + strlen(str) + 1);
	strcpy(ret, str_list);
	if (strlen(str_list) > 0)
		strcat(ret, ",");
	strcat(ret, str);

	return ret;
}

/**
 * Removes a string from a comma separated string
 *
 * @param str_list     the comma separated string.
 * @param str          the string to remove
 *
 * @returns a new comma separated string. This must be freed by the caller when
 *          no longer used. If the string to remove is not found in the
 *          comma separated string, NULL is returned
 */
char *str_list_remove(const char *str_list, const char *str)
{
	char *after;
	char *ret;
	char *ch;

	util_assert(str_list != NULL, "Internal error: str_list is NULL");
	util_assert(str != NULL, "Internal error: str is NULL");

	ch = str_list_find(str_list, str);
	if (ch == NULL)
		return NULL;

	after = ch + strlen(str);
	if (*after == ',') {
		/* there are more parts after the one to remove */
		ret = util_zalloc(strlen(str_list) - strlen(str) - 1 + 1);
		strncpy(ret, str_list, ch - str_list);
		strcat(ret, after + 1);
	} else if (ch == str_list) {
		/* removing the one and only part -> empty string */
		ret = util_zalloc(1);
	} else {
		/* there are no more parts after the one to remove */
		ret = util_zalloc(strlen(str_list) - strlen(str) - 1 + 1);
		strncpy(ret, str_list, ch - 1 - str_list);
	}

	return ret;
}

/**
 * Frees a string array (as produced by str_list_split())
 *
 * @param strings a NULL terminated array of pointers to C-Strings.
 */
void str_list_free_string_array(char **strings)
{
	char **list = strings;

	util_assert(strings != NULL, "Internal error: strings is NULL");

	while (*strings != NULL) {
		free((void *)*strings);
		strings++;
	}
	free(list);
}
