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
 *
 * @returns 0 on success,
 *          -EINVAL if the name or value contains invalid characters
 */
int properties_set(struct properties *properties,
		   const char *name, const char *value)
{
	struct property *property;

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
	return 0;
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
		if (line[len-1] == '\n')
			line[len-1] = '\0';
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
