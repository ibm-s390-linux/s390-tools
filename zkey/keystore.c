/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Keystore handling functions
 *
 * Copyright IBM Corp. 2018, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <argz.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fnmatch.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_rec.h"

#include "keystore.h"
#include "pkey.h"
#include "cca.h"
#include "properties.h"
#include "utils.h"

struct key_filenames {
	char *skey_filename;
	char *info_filename;
	char *renc_filename;
	char *pass_filename;
};

#define FILE_EXTENSION_LEN	5
#define SKEY_FILE_EXTENSION	".skey"
#define INFO_FILE_EXTENSION	".info"
#define RENC_FILE_EXTENSION	".renc"
#define PASS_FILE_EXTENSION	".pass"

#define DUMMY_PASSPHRASE_LEN	16

#define LOCK_FILE_NAME		".lock"

#define VOLUME_TYPE_PLAIN	"plain"
#define VOLUME_TYPE_LUKS2	"luks2"
#ifdef HAVE_LUKS2_SUPPORT
	#define DEFAULT_VOLUME_TYPE	VOLUME_TYPE_LUKS2
#else
	#define DEFAULT_VOLUME_TYPE	VOLUME_TYPE_PLAIN
#endif

#define REC_KEY			"Key"
#define REC_DESCRIPTION		"Description"
#define REC_SEC_KEY_SIZE	"Secure key size"
#define REC_CLR_KEY_SIZE	"Clear key size"
#define REC_XTS			"XTS type key"
#define REC_KEY_TYPE		"Key type"
#define REC_VOLUMES		"Volumes"
#define REC_APQNS		"APQNs"
#define REC_KEY_FILE		"Key file name"
#define REC_SECTOR_SIZE		"Sector size"
#define REC_STATUS		"Status"
#define REC_MASTERKEY		"Enciphered with"
#define REC_CREATION_TIME	"Created"
#define REC_CHANGE_TIME		"Changed"
#define REC_REENC_TIME		"Re-enciphered"
#define REC_KEY_VP		"Verification pattern"
#define REC_VOLUME_TYPE		"Volume type"
#define REC_KMS			"KMS"
#define REC_KMS_KEY_LABEL	"KMS key label"
#define REC_PASSPHRASE_FILE	"Dummy passphrase"

#define pr_verbose(keystore, fmt...)	do {				\
						if (keystore->verbose)	\
							warnx(fmt);	\
					} while (0)

static int _keystore_kms_key_unbind(struct keystore *keystore,
				    struct properties *properties);

/**
 * Gets the file names of the .skey and .info and .renc files for a named
 * key in the key strore's directory
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[out] names      is filled with the names of the files
 *
 * @returns 0 for success or a negative errno in case of an error*
 */
static int _keystore_get_key_filenames(struct keystore *keystore,
				      const char *name,
				      struct key_filenames *names)
{
	if (strpbrk(name, "/\\ *?'\"")) {
		warnx("Key name '%s' contains invalid characters", name);
		return -EINVAL;
	}

	util_asprintf(&names->skey_filename, "%s/%s%s", keystore->directory,
		      name, SKEY_FILE_EXTENSION);
	util_asprintf(&names->info_filename, "%s/%s%s", keystore->directory,
		      name, INFO_FILE_EXTENSION);
	util_asprintf(&names->renc_filename, "%s/%s%s", keystore->directory,
			      name, RENC_FILE_EXTENSION);
	util_asprintf(&names->pass_filename, "%s/%s%s", keystore->directory,
			      name, PASS_FILE_EXTENSION);

	pr_verbose(keystore, "File names for key '%s': '%s' and '%s'", name,
		   names->skey_filename, names->info_filename);
	return 0;
}

/**
 * Checks if the .renc file exists.
 *
 * @param[in] file_names  names of the files
 *
 * @returns 1 if the file exist, 0 if the file do not exist
 */
static int _keystore_reencipher_key_exists(struct key_filenames *file_names)
{
	return util_path_is_reg_file("%s", file_names->renc_filename);
}

/**
 * Checks if the .pass file exists.
 *
 * @param[in] file_names  names of the files
 *
 * @returns 1 if the file exist, 0 if the file do not exist
 */
static int _keystore_passphrase_file_exists(struct key_filenames *file_names)
{
	return util_path_is_reg_file("%s", file_names->pass_filename);
}

/**
 * Checks if both, the .skey and the .info (and .renc) files exist.
 *
 * @param[in] file_names  names of the files
 *
 * @returns 1 if all files exist, 0 if all files do not exist, -1 if one
 *          file exists but other one does not exist (inconsistent state)
 */
static int _keystore_exists_keyfiles(struct key_filenames *file_names)
{
	bool rc_skey, rc_info;

	rc_skey = util_path_is_reg_file("%s", file_names->skey_filename);
	rc_info = util_path_is_reg_file("%s", file_names->info_filename);

	if (rc_skey && rc_info)
		return 1;
	if (!rc_skey && !rc_info &&
	    _keystore_reencipher_key_exists(file_names) == 0 &&
	    _keystore_passphrase_file_exists(file_names) == 0)
		return 0;
	return -1;
}

/**
 * Checks if the files belonging to a key exist. If not an appropriate error
 * message is issued.
 *
 * @param[in] file_names names of the files
 * @param[in] name       name of the key
 *
 * @returns 0 if the files exist, -ENOENT if the files do not exist, -EPERM if
 *          one file exists but the other does not exist (inconsistent state)
 */
static int _keystore_ensure_keyfiles_exist(struct key_filenames *file_names,
					   const char *name)
{
	int rc;

	rc = _keystore_exists_keyfiles(file_names);
	if (rc == 0) {
		warnx("Key '%s' does not exist", name);
		return -ENOENT;
	}
	if (rc == -1) {
		warnx("Key '%s' is in an inconsistent state", name);
		return -EPERM;
	}

	return 0;
}

/**
 * Checks if the files belonging to a key do not exist. If they files exist,
 * an appropriate error message is issued.
 *
 * @param[in] file_names names of the files
 * @param[in] name       name of the key
 *
 * @returns 0 if the files exist, -EEXIST if the files exist already, -EPERM if
 *          one file exists but the other does not exist (inconsistent state)
 */
static int _keystore_ensure_keyfiles_not_exist(struct key_filenames *file_names,
					       const char *name)
{
	int rc;

	rc = _keystore_exists_keyfiles(file_names);
	if (rc == 1) {
		warnx("Key '%s' exists already", name);
		return -EEXIST;
	}
	if (rc == -1) {
		warnx("Key '%s' is in an inconsistent state", name);
		return -EPERM;
	}

	return 0;
}

/**
 * Frees the file names stored inside the struct key_filenames
 *
 * @param[in] names      names of the files
 */
static void _keystore_free_key_filenames(struct key_filenames *names)
{
	if (names->skey_filename)
		free(names->skey_filename);
	if (names->info_filename)
		free(names->info_filename);
	if (names->renc_filename)
		free(names->renc_filename);
	if (names->pass_filename)
		free(names->pass_filename);
}

/**
 * Sets the file permissions of the file to the permissions and the group
 * of the repository directory
 *
 * @param[in] keystroe     the keystore
 * @param[in] filename     the name of the file to set permissions for
 *
 * @returns 0 on success, or a negative errno value on failure
 */
static int _keystore_set_file_permission(struct keystore *keystore,
					 const char *filename)
{
	int rc;

	if (chmod(filename, keystore->mode) != 0) {
		rc = -errno;
		warnx("chmod failed on file '%s': %s", filename, strerror(-rc));
		return rc;
	}

	if (chown(filename, geteuid(), keystore->owner) != 0) {
		rc = -errno;
		warnx("chown failed on file '%s': %s", filename, strerror(-rc));
		return rc;
	}

	return 0;
}

/**
 *  Checks if the sector size is power of two and in range 512 - 4096 bytes.
 *
 * @param[in] sector_size   the sector size
 *
 * @returns 1 if the sector size is valid, 0 otherwise
 */
static int _keystore_valid_sector_size(size_t sector_size)
{
	if (sector_size == 0)
		return 1;
	if (sector_size < 512 || sector_size > 4096)
		return 0;
	if (sector_size & (sector_size - 1))
		return 0;
	return 1;
}

/**
 *  Checks if the volume type is supported.
 *
 * @param[in] volume_type   the volume type
 *
 * @returns 1 if the volume type is valid, 0 otherwise
 */
static int _keystore_valid_volume_type(const char *volume_type)
{
	if (strcasecmp(volume_type, VOLUME_TYPE_PLAIN) == 0)
		return 1;
#ifdef HAVE_LUKS2_SUPPORT
	if (strcasecmp(volume_type, VOLUME_TYPE_LUKS2) == 0)
		return 1;
#endif
	return 0;
}

/**
 * Returns the volume type contained in the properties. If no volume type
 * property is contained, then 'plain' is assumed (for backward comatibility).
 *
 * @returns a string containing the volume type. Must be freed by the caller.
 */
static char *_keystore_get_volume_type(struct properties *properties)
{
	char *type;

	type = properties_get(properties, PROP_NAME_VOLUME_TYPE);
	if (type == NULL)
		type = util_strdup(VOLUME_TYPE_PLAIN);

	return type;
}

/**
 * Returns the key type contained in the properties. If no key type
 * property is contained, then 'CCA-AESDATA' is assumed (for backward
 * compatibility).
 *
 * @returns a string containing the key type. Must be freed by the caller.
 */
static char *_keystore_get_key_type(struct properties *properties)
{
	char *type;

	type = properties_get(properties, PROP_NAME_KEY_TYPE);
	if (type == NULL)
		type = util_strdup(KEY_TYPE_CCA_AESDATA);

	return type;
}

/**
 *  Checks if the key type is supported.
 *
 * @param[in] key_type   the key type
 *
 * @returns 1 if the key type is valid, 0 otherwise
 */
static int _keystore_valid_key_type(const char *key_type)
{
	if (strcasecmp(key_type, KEY_TYPE_CCA_AESDATA) == 0)
		return 1;
	if (strcasecmp(key_type, KEY_TYPE_CCA_AESCIPHER) == 0)
		return 1;
	if (strcasecmp(key_type, KEY_TYPE_EP11_AES) == 0)
		return 1;

	return 0;
}

/**
 * Checks if the keys is KMS-bound
 *
 * @param[in] key_props     the key properties
 * @param[out] kms_name     the name of the KMS plugin, if KMS-bound
 *
 * @return true if the key is KMS bound, false otherwise
 */
static bool _keystore_is_kms_bound_key(struct properties *key_props,
				       char **kms_name)
{
	bool ret = false;
	char *kms;

	if (kms_name != NULL)
		*kms_name = NULL;

	kms = properties_get(key_props, PROP_NAME_KMS);
	if (kms != NULL && strcasecmp(kms, "LOCAL") != 0)
		ret = true;

	if (kms_name != NULL && ret == true)
		*kms_name = kms;
	else if (kms != NULL)
		free(kms);

	return ret;
}

/**
 * Prints a message followed by a list of associated volumes, if volumes are
 * associated and the volume-type matches (if specified)
 *
 * @param[in] msg          the message to display
 * @param[in] properties   the properties
 * @param[in] volume_type  the volume type to display the message for (or NULL)
 *
 * @returns always zero
 */
static int _keystore_msg_for_volumes(const char *msg,
				     struct properties *properties,
				     const char *volume_type)
{
	char *volumes = NULL;
	char **volume_list;
	char *type = NULL;
	int i;

	if (volume_type != NULL) {
		type = _keystore_get_volume_type(properties);
		if (strcasecmp(type, volume_type) != 0)
			goto out;
	}

	volumes = properties_get(properties, PROP_NAME_VOLUMES);
	if (volumes != NULL && strlen(volumes) > 0) {
		volume_list = str_list_split(volumes);

		util_print_indented(msg, 0);
		for (i = 0; volume_list[i] != NULL; i++)
			printf("  %s\n", volume_list[i]);
		str_list_free_string_array(volume_list);
	}

out:
	if (volumes != NULL)
		free(volumes);
	if (type != NULL)
		free(type);

	return 0;
}

typedef int (*check_association_t)(const char *value, bool remove, bool set,
				   char **normalized, void *private);

/**
 * Set an association property. For each object set function check_func is
 * called (if not NULL).
 *
 * @param[in/out] key_props  the properties object to modify
 * @param[in] property       the name of the property to modify
 * @param[in] newvalue       the new value(s) to add, remove or set
 * @param[in] msg_obj        the name of the object for error messages
 * @param[in] check_func     a function to call on each object before it is
 *                           added, removed or set to the property
 * @param[in] check_private  a private pointer passed to check_func
 *
 * @returns 0 for success, or a negative errno value in case of an error, or
 *          whatever check_func returns if check_func returns a non-zero value.
 */
static int _keystore_set_association(struct properties *key_props,
				     const char *property,
				     const char *newvalue,
				     const char *msg_obj,
				     check_association_t check_func,
				     void *check_private)
{
	char *normalized = NULL;
	char **newvals = NULL;
	char *value = NULL;
	char *changedval;
	char *newval;
	int i, rc = 0;

	newvals = str_list_split(newvalue);
	if (newvals == NULL)
		return -EINVAL;

	for (i = 0; newvals[i] != NULL; i++) {
		if (check_func != NULL) {
			rc = check_func(newvals[i], 0, 1, &normalized,
					check_private);
			if (rc != 0)
				goto out;
		}

		newval = normalized != NULL ? normalized : newvals[i];
		if (value == NULL)
			changedval = str_list_add("", newval);
		else
			changedval = str_list_add(value, newval);
		if (changedval == NULL) {
			warnx("The %s '%s' is already specified or contains "
			      "invalid characters", msg_obj, newval);
			rc = -EEXIST;
			goto out;
		}
		if (normalized != NULL)
			free(normalized);
		normalized = NULL;
		free(value);
		value = changedval;
	}

	rc = properties_set(key_props, property, value != NULL ? value : "");
	if (rc != 0)
		warnx("Invalid characters in %ss", msg_obj);

out:
	if (newvals != NULL)
		str_list_free_string_array(newvals);
	if (value != NULL)
		free(value);
	if (normalized != NULL)
		free(normalized);
	return rc;
}

/**
 * Add a value to an association property. For each object added function
 * check_func is called (if not NULL).
 *
 * @param[in/out] key_props  the properties object to modify
 * @param[in] property       the name of the property to modify
 * @param[in] newvalue       the new value(s) to add, remove or set
 * @param[in] msg_obj        the name of the object for error messages
 * @param[in] check_func     a function to call on each object before it is
 *                           added, removed or set to the property
 * @param[in] check_private  a private pointer passed to check_func
 *
 * @returns 0 for success, or a negative errno value in case of an error, or
 *          whatever check_func returns if check_func returns a non-zero value.
 */
static int _keystore_add_association(struct properties *key_props,
				     const char *property,
				     const char *newvalue,
				     const char *msg_obj,
				     check_association_t check_func,
				     void *check_private)
{
	char *normalized = NULL;
	char **newvals = NULL;
	char *changedval;
	char *newval;
	int i, rc = 0;
	char *value;

	value = properties_get(key_props, property);
	if (value == NULL)
		return _keystore_set_association(key_props, property,
						 newvalue, msg_obj,
						 check_func, check_private);

	newvals = str_list_split(newvalue);
	if (newvals == NULL) {
		rc = -EINVAL;
		goto out;
	}

	for (i = 0; newvals[i] != NULL; i++) {
		if (check_func != NULL) {
			rc = check_func(newvals[i], 0, 0, &normalized,
					check_private);
			if (rc != 0)
				goto out;
		}

		newval = normalized != NULL ? normalized : newvals[i];
		changedval = str_list_add(value, newval);
		if (changedval == NULL) {
			warnx("The %s '%s' is already associated with this key "
			      "or contains invalid characters", msg_obj,
			      newval);
			rc = -EEXIST;
			goto out;
		}
		if (normalized != NULL)
			free(normalized);
		normalized = NULL;
		free(value);
		value = changedval;
	}

	rc = properties_set(key_props, property, value);
	if (rc != 0)
		warnx("Invalid characters in %ss", msg_obj);

out:
	if (newvals != NULL)
		str_list_free_string_array(newvals);
	if (value != NULL)
		free(value);
	if (normalized != NULL)
		free(normalized);
	return rc;
}

/**
 * Removes a value from an association property. For each object removed
 * function check_func is called (if not NULL).
 *
 * @param[in/out] key_props  the properties object to modify
 * @param[in] property       the name of the property to modify
 * @param[in] delvalue       the value(s) to remove
 * @param[in] msg_obj        the name of the object for error messages
 * @param[in] check_func     a function to call on each object before it is
 *                           added, removed or set to the property
 * @param[in] check_private  a private pointer passed to check_func
 *
 * @returns 0 for success, or a negative errno value in case of an error, or
 *          whatever check_func returns if check_func returns a non-zero value.
 */
static int _keystore_remove_association(struct properties *key_props,
					const char *property,
					const char *delvalue,
					const char *msg_obj,
					check_association_t check_func,
					void *check_private)
{
	char *normalized = NULL;
	char **delvals = NULL;
	char *changedval;
	char *delval;
	int i, rc = 0;
	char *value;

	value = properties_get(key_props, property);
	if (value == NULL) {
		warnx("No %ss are currently associated with this key", msg_obj);
		return -ENOENT;
	}

	delvals = str_list_split(delvalue);
	if (delvals == NULL) {
		rc = -EINVAL;
		goto out;
	}

	for (i = 0; delvals[i] != NULL; i++) {
		if (check_func != NULL) {
			rc = check_func(delvals[i], 1, 0, &normalized,
					check_private);
			if (rc != 0)
				goto out;
		}

		delval = normalized != NULL ? normalized : delvals[i];
		changedval = str_list_remove(value, delval);
		if (changedval == NULL) {
			warnx("%s '%s' is not associated with this key",
			      msg_obj, delval);
			rc = -ENOENT;
			goto out;
		}
		if (normalized != NULL)
			free(normalized);
		normalized = NULL;
		free(value);
		value = changedval;
	}

	rc = properties_set(key_props, property, value);
	if (rc != 0)
		warnx("Invalid characters in %ss", msg_obj);

out:
	if (delvals != NULL)
		str_list_free_string_array(delvals);
	if (value != NULL)
		free(value);
	if (normalized != NULL)
		free(normalized);
	return rc;
}

/**
 * Change an association property. This function adds the objects in the
 * comma separated string when newvalue begins with a '+'. It removes the
 * objects when newvalue begins with a '-', or it sets the property to
 * newvalue when newvalue does not begin with '+' or '-'. For each object
 * added, Removed or set function check_func is called (if not NULL).
 *
 * @param[in/out] key_props  the properties object to modify
 * @param[in] property       the name of the property to modify
 * @param[in] newvalue       the new value(s) to add, remove or set
 * @param[in] msg_obj        the name of the object for error messages
 * @param[in] check_func     a function to call on each object before it is
 *                           added, removed or set to the property
 * @param[in] check_private  a private pointer passed to check_func
 *
 * @returns 0 for success, or a negative errno value in case of an error, or
 *          whatever check_func returns if check_func returns a non-zero value.
 */
static int _keystore_change_association(struct properties *key_props,
					const char *property,
					const char *newvalue,
					const char *msg_obj,
					check_association_t check_func,
					void *check_private)
{
	switch (*newvalue) {
	case '+':
		return _keystore_add_association(key_props, property,
						 &newvalue[1], msg_obj,
						 check_func, check_private);
	case '-':
		return _keystore_remove_association(key_props, property,
						    &newvalue[1], msg_obj,
						    check_func, check_private);
	default:
		return _keystore_set_association(key_props, property,
						 newvalue, msg_obj,
						 check_func, check_private);

	}
}

/**
 * Filter match function for APQNs
 *
 * @param[in] pattern    the pattern to match
 * @param[in] apqn       the apqn to match
 * @param[in] flags      Not used here
 *
 * @returns Zero if string matches pattern, FNM_NOMATCH if there is no match
 *          or another nonzero value if there is an error.
 */
static int _keystore_apqn_match(const char *pattern, const char *apqn,
				int UNUSED(flags))
{
	unsigned int card, domain;
	char *pattern_domain;
	char *pattern_card;
	char *modified;
	char *copy;
	size_t i;
	char *ch;
	int rc;

	if (sscanf(pattern, "%x.%x", &card, &domain) == 2) {
		util_asprintf(&modified, "%02x.%04x", card, domain);
		goto match;
	}

	copy = util_strdup(pattern);

	ch = strchr(copy, '.');
	if (ch != NULL) {
		*ch = '\0';
		pattern_card = copy;
		pattern_domain = ch + 1;

		modified = NULL;
		if (strchr(pattern_card, '*') == NULL &&
		    strlen(pattern_card) < 2) {
			for (i = 0; i < 2 - strlen(pattern_card); i++)
				modified = util_strcat_realloc(modified, "0");
		}
		modified = util_strcat_realloc(modified, pattern_card);

		modified = util_strcat_realloc(modified, ".");

		if (strchr(pattern_domain, '*') == NULL &&
		    strlen(pattern_domain) < 4) {
			for (i = 0; i < 4 - strlen(pattern_domain); i++)
				modified = util_strcat_realloc(modified, "0");
		}
		modified = util_strcat_realloc(modified, pattern_domain);
	} else {
		modified = util_strdup(copy);
	}
	free(copy);

match:
	rc = fnmatch(modified, apqn, FNM_CASEFOLD);

	free(modified);
	return rc;
}

typedef int (*filter_match_t)(const char *pattern, const char *string,
			      int flags);

/*
 * Checks if the value matches the filter list. The value can be a comma
 * separated string.
 *
 * If the filter values contain a second part separated by a colon (':'), then
 * the filter matches only if both parts match. If the filter values do not
 * contain a second part,then only the first part is checked, and the second
 * parts of the values are ignored.
 *
 * @param[in] value     the value to check
 * @param[in] filter_list a list of filter strings to match the value with
 * @param[in] match_func the filter match function. If NULL fnmatch() is used.
 *
 * @returns 1 for a match, 0 for not matched
 */
static int _keystore_match_filter(const char *value,
				  char **filter_list,
				  filter_match_t match_func)
{
	char **value_list;
	int i, k, rc = 0;
	char *ch;

	if (filter_list == NULL)
		return 1;

	if (match_func == NULL)
		match_func = fnmatch;

	value_list = str_list_split(value);
	for (i = 0; filter_list[i] != NULL && rc == 0; i++) {
		for (k = 0; value_list[k] != NULL; k++) {
			/*
			 * Ignore part after ':' of value if filter does
			 * not also contain a ':' part.
			 */
			if (strchr(filter_list[i], ':') == NULL) {
				ch = strchr(value_list[k], ':');
				if (ch != NULL)
					*ch = '\0';
			}

			if (match_func(filter_list[i], value_list[k], 0) == 0) {
				rc = 1;
				break;
			}
		}
	}

	str_list_free_string_array(value_list);
	return rc;
}

/*
 * Checks if the property value matches the filter list. The property value
 * can be a comma separated string.
 *
 * If the filter values contain a second part separated by a colon (':'), then
 * the filter matches only if both parts match. If the filter values do not
 * contain a second part,then only the first part is checked, and the second
 * parts of the values are ignored.
 *
 * @param[in] properties   a properties object
 * @param[in] property     the name of the property to check
 * @param[in] filter_list  a list of filter strings to match the value with
 * @param[in] match_func the filter match function. If NULL fnmatch() is used.
 *
 * @returns 1 for a match, 0 for not matched
 */
static int _keystore_match_filter_property(struct properties *properties,
					   const char *property,
					   char **filter_list,
					   filter_match_t match_func)
{
	char *value;
	int rc;

	if (filter_list == NULL)
		return 1;

	value = properties_get(properties, property);
	if (value == NULL)
		return 0;

	rc = _keystore_match_filter(value, filter_list, match_func);

	free(value);
	return rc;
}

/**
 * Checks if the volume type property matches the specified volume type.
 * If the properties do not contain a volume type property, then the default
 * volume type is assumed.
 *
 * @param[in] properties   a properties object
 * @param[in] volume_type  the volume type to match. Can be NULL. In this case
 *                         it always matches.
 *
 * @returns 1 for a match, 0 for not matched
 */
static int _keystore_match_volume_type_property(struct properties *properties,
						const char *volume_type)
{
	char *type;
	int rc = 0;

	if (volume_type == NULL)
		return 1;

	type = _keystore_get_volume_type(properties);
	if (strcasecmp(type, volume_type) == 0)
		rc = 1;

	free(type);
	return rc;
}

/**
 * Checks if the key type property matches the specified key type.
 * If the properties do not contain a key type property, then the default
 * key type is assumed.
 *
 * @param[in] properties   a properties object
 * @param[in] key_type     the key type to match. Can be NULL. In this case
 *                         it always matches.
 *
 * @returns 1 for a match, 0 for not matched
 */
static int _keystore_match_key_type_property(struct properties *properties,
					     const char *key_type)
{
	char *type;
	int rc = 0;

	if (key_type == NULL)
		return 1;

	type = _keystore_get_key_type(properties);
	if (strcasecmp(type, key_type) == 0)
		rc = 1;

	free(type);
	return rc;
}

/**
 * Checks if a key name matches a name filter
 *
 * @param[in] name         the name to check
 * @param[in] name_filter  the name filter to match against
 *
 * @returns 1 if the filter matches, 0 otherwise
 */
static int _keystore_match_name_filter(const char *name,
				       const char *name_filter)
{
	if (name_filter == NULL)
		return 1;

	if (fnmatch(name_filter, name, 0) != 0)
		return 0;

	return 1;
}

/**
 * Filters directory entries for scanfile(). Only entries that are regular
 * files and who's name ends with '.info' are matched.
 */
static int _keystore_info_file_filter(const struct dirent *dirent)
{
	size_t len;

	if (dirent->d_type != DT_REG && dirent->d_type != DT_UNKNOWN)
		return 0;

	len = strlen(dirent->d_name);
	if (len > FILE_EXTENSION_LEN &&
	    strcmp(&dirent->d_name[len - FILE_EXTENSION_LEN],
		   INFO_FILE_EXTENSION) == 0)
		return 1;

	return 0;
}

typedef int (*process_key_t)(struct keystore *keystore,
			     const char *name, struct properties *properties,
			     struct key_filenames *file_names, void *private);

/**
 * Iterates over all keys stored in the keystore. For every key that matches
 * the specified filter process_func is called.
 *
 * @param[in] keystore    the key store
 * @param[in] name_filter    the name filter. Can contain wild cards.
 *                           NULL means no name filter.
 * @param[in] volume_filter  the volume filter. Can contain wild cards, and
 *                           mutliple volume filters separated by commas.
 *                           If the filter does not contain the ':dm-name' part,
 *                           then the volumes are matched without the dm-name
 *                           part. If the filter contains the ':dm-name' part,
 *                           then the filter is matched including the dm-name
 *                           part.
 *                           NULL means no volume filter.
 *                           specification is ignored for filter matching.
 * @param[in] apqn_filter    the APQN filter. Can contain wild cards, and
 *                           mutliple APQN filters separated by commas.
 *                           NULL means no APQN filter.
 * @param[in] volume_type    If not NULL, specifies the volume type.
 * @param[in] key_type       The key type. NULL means no key type filter.
 * @param[in] local          if true, only local keys are processed
 * @param[in] kms_bound      if true, only KMS-bound keys are processed
 * @param[in] process_func   the callback function called for a matching key
 * @param[in/out] process_private private data passed to the process_func
 *
 * @returns 0 for success, or a negative errno value in case of an error, or
 *          whatever process_func returns if process_func returns a non-zero
 *          value.
 */
static int _keystore_process_filtered(struct keystore *keystore,
				      const char *name_filter,
				      const char *volume_filter,
				      const char *apqn_filter,
				      const char *volume_type,
				      const char *key_type,
				      bool local, bool kms_bound,
				      process_key_t process_func,
				      void *process_private)
{
	struct key_filenames file_names = { 0 };
	char **apqn_filter_list = NULL;
	char **vol_filter_list = NULL;
	struct properties *key_props;
	struct dirent **namelist;
	int n, i, rc = 0;
	bool skip = 0;
	char *name;
	int len;

	pr_verbose(keystore, "Process_filtered: name_filter = '%s', "
		   "volume_filter = '%s', apqn_filter = '%s'",
		   name_filter ? name_filter : "(null)",
		   volume_filter ? volume_filter : "(null)",
		   apqn_filter ? apqn_filter : "(null)");

	if (volume_filter != NULL)
		vol_filter_list = str_list_split(volume_filter);
	if (apqn_filter != NULL)
		apqn_filter_list = str_list_split(apqn_filter);

	n = scandir(keystore->directory, &namelist, _keystore_info_file_filter,
		    alphasort);
	if (n == -1) {
		rc = -errno;
		pr_verbose(keystore, "scandir failed with: %s", strerror(-rc));
		return rc;
	}

	for (i = 0; i < n ; i++) {
		if (skip)
			goto free;

		name = namelist[i]->d_name;
		len = strlen(name);
		if (len > FILE_EXTENSION_LEN)
			name[len - FILE_EXTENSION_LEN] = '\0';

		if (_keystore_match_name_filter(name, name_filter) == 0) {
			pr_verbose(keystore,
				   "Key '%s' filtered out due to name filter",
				   name);
			goto free;
		}

		rc = _keystore_get_key_filenames(keystore, name, &file_names);
		if (rc != 0)
			goto free;

		rc = _keystore_ensure_keyfiles_exist(&file_names, name);
		if (rc != 0)
			goto free_names;

		key_props = properties_new();
		rc = properties_load(key_props, file_names.info_filename, 1);
		if (rc != 0) {
			warnx("Key '%s' does not exist or is invalid", name);
			goto free_prop;
		}

		rc = _keystore_match_filter_property(key_props,
						     PROP_NAME_VOLUMES,
						     vol_filter_list, NULL);
		if (rc == 0) {
			pr_verbose(keystore,
				   "Key '%s' filtered out due to volumes filter",
				   name);
			goto free_prop;
		}

		rc = _keystore_match_filter_property(key_props,
						     PROP_NAME_APQNS,
						     apqn_filter_list,
						     _keystore_apqn_match);
		if (rc == 0) {
			pr_verbose(keystore,
				   "Key '%s' filtered out due to APQN filter",
				   name);
			goto free_prop;
		}

		rc = _keystore_match_volume_type_property(key_props,
							  volume_type);
		if (rc == 0) {
			pr_verbose(keystore,
				   "Key '%s' filtered out due to volume type",
				   name);
			goto free_prop;
		}

		rc = _keystore_match_key_type_property(key_props,
						       key_type);
		if (rc == 0) {
			pr_verbose(keystore,
				   "Key '%s' filtered out due to key type",
				   name);
			goto free_prop;
		}

		if (local && _keystore_is_kms_bound_key(key_props, NULL)) {
			pr_verbose(keystore,
				   "Key '%s' filtered out because it is KMS "
				   "bound", name);
			rc = 0;
			goto free_prop;
		}
		if (kms_bound && !_keystore_is_kms_bound_key(key_props, NULL)) {
			pr_verbose(keystore,
				   "Key '%s' filtered out because it is not "
				   "KMS bound", name);
			rc = 0;
			goto free_prop;
		}

		rc = process_func(keystore, name, key_props, &file_names,
				  process_private);
		if (rc != 0) {
			pr_verbose(keystore, "Process function returned %d",
				   rc);
			skip = 1;
		}

free_prop:
		properties_free(key_props);
free_names:
		_keystore_free_key_filenames(&file_names);
free:
		free(namelist[i]);
	}
	free(namelist);

	if (vol_filter_list)
		str_list_free_string_array(vol_filter_list);
	if (apqn_filter_list)
		str_list_free_string_array(apqn_filter_list);

	pr_verbose(keystore, "Process_filtered rc = %d", rc);
	return rc;
}

struct apqn_check {
	bool noonlinecheck;
	bool nomsg;
	enum card_type cardtype;
};

/**
 * Checks an APQN value for its syntax. This is a callback function for
 * function _keystore_change_association().
 *
 * @param[in] apqn     the APQN value to check
 * @param[in] remove   if true the apqn is removed
 * @param[in] set      if true the apqn is set (not used here)
 * @param[out] normalized normalized value on return or NULL if no change
 * @param[in] private  private data (struct apqn_check)
 *
 * @returns 0 if successful, a negative errno value otherwise
 */
static int _keystore_apqn_check(const char *apqn, bool remove, bool UNUSED(set),
				char **normalized, void *private)
{
	struct apqn_check *info = (struct apqn_check *)private;
	unsigned int card, domain;
	regmatch_t pmatch[1];
	unsigned int num;
	regex_t reg_buf;
	int rc;

	*normalized = NULL;

	rc = regcomp(&reg_buf, "[[:xdigit:]]+\\.[[:xdigit:]]", REG_EXTENDED);
	if (rc != 0)
		return -EIO;

	rc = regexec(&reg_buf, apqn, (size_t) 1, pmatch, 0);
	if (rc != 0) {
		warnx("the APQN '%s' is not valid", apqn);
		rc = -EINVAL;
		goto out;
	}

	if (sscanf(apqn, "%x.%x%n", &card, &domain, (int *)&num) != 2 ||
	    num != strlen(apqn) || card > 0xff || domain > 0xFFFF) {
		warnx("the APQN '%s' is not valid", apqn);
		rc = -EINVAL;
		goto out;
	}

	util_asprintf(normalized, "%02x.%04x", card, domain);

	if (remove || info->noonlinecheck) {
		rc = 0;
		goto out;
	}

	rc = sysfs_is_apqn_online(card, domain, info->cardtype);
	if (rc != 1) {
		if (info->nomsg == 0)
			warnx("The APQN %02x.%04x is %s", card, domain,
			      rc == -1 ? "not the correct type" : "not online");
		rc = -EIO;
		goto out;
	} else {
		rc = 0;
	}

out:
	regfree(&reg_buf);
	return rc;
}


struct volume_check {
	struct keystore *keystore;
	const char *name;
	const char *volume;
	bool set;
	bool nocheck;
};

/**
 * Processing callback function for the volume association check function.
 *
 * @param[in] keystore   the keystore (not used here)
 * @param[in] name       the name of the key
 * @param[in] properties the properties object of the key (not used here)
 * @param[in] file_names the file names used by this key (not used here)
 * @param[in] private    private data: struct volume_check
 *
 * @returns 0 if the key name is equal to the key we are checking the volume
 *          associations for, -EINVAL otherwise (i.e. to indicate duplicate
 *          volume association)
 */
static int _keystore_volume_check_process(struct keystore *UNUSED(keystore),
					  const char *name,
					  struct properties *UNUSED(properties),
					  struct key_filenames
							  *UNUSED(file_names),
					  void *private)
{
	struct volume_check *info = (struct volume_check *)private;

	if (info->set) {
		if (strcmp(name, info->name) == 0)
			return 0;
	}

	warnx("Key '%s' is already associated with volume '%s'", name,
	      info->volume);
	return -EINVAL;
}

/**
 * Checks if the volume is a block device
 *
 * @param[in] volume the volume to check
 *
 * @return 1 if the volume is a block device, 0 otherwise
 */
static int _keystore_is_block_device(const char *volume)
{
	struct stat sb;

	if (stat(volume, &sb))
		return 0;
	if (!S_ISBLK(sb.st_mode))
		return 0;

	return 1;
}

/**
 * Checks an Volume value for its syntax and if it is already associated with
 * another key. This is a callback function for function
 * _keystore_change_association().
 *
 * @param[in] volume     the Volume value to check
 * @param[in] remove     if true the volume is removed
 * @param[in] set        if true the volume is set
 * @param[out] normalized normalized value on return or NULL if no change
 * @param[in] private    private data: struct volume_check
 *
 * @returns 0 if successful, a negative errno value otherwise
 */
static int _keystore_volume_check(const char *volume, bool remove, bool set,
				  char **normalized, void *private)
{
	struct volume_check *info = (struct volume_check *)private;
	char *ch;
	int rc;

	*normalized = NULL;

	if (strpbrk(volume, "*?") != NULL) {
		warnx("Volume name can not contain '*' or '?'");
		return -EINVAL;
	}

	info->volume = util_strdup(volume);
	ch = strchr(info->volume, ':');
	if (ch == NULL || strlen(ch + 1) == 0) {
		warnx("Volume specification must contain a dm-crypt mapping "
		      "name separated by a colon");
		rc = -EINVAL;
		goto out;
	}

	if (remove || info->nocheck) {
		rc = 0;
		goto out;
	}

	/*
	 * Strip off the ':dm-name' part, so that the volume filter only
	 * matches the volume part.
	 */
	*ch = '\0';

	if (!_keystore_is_block_device(info->volume)) {
		warnx("Volume '%s' is not a block device or is not available",
		      info->volume);
		rc = -EINVAL;
		goto out;
	}

	info->set = set;
	rc = _keystore_process_filtered(info->keystore, NULL, info->volume,
					NULL, NULL, NULL, false, false,
					_keystore_volume_check_process, info);
out:
	free((void *)info->volume);
	info->volume = NULL;
	return rc;
}

/**
 * Locks the repository against other processes.
 *
 * @param[in] keystore   the keystore
 *
 * @returns 0 if successful, a negative errno value otherwise
 */
static int _keystore_lock_repository(struct keystore *keystore)
{
	char *lock_file_name;
	struct stat sb;
	int rc;

	util_asprintf(&lock_file_name, "%s/%s", keystore->directory,
		      LOCK_FILE_NAME);

	if (stat(lock_file_name, &sb) == 0) {
		keystore->lock_fd = open(lock_file_name, O_RDONLY);
		if (keystore->lock_fd == -1) {
			rc = -errno;
			warnx("Failed to open lock file '%s': %s",
			      lock_file_name,
			      strerror(-rc));
			goto out;
		}
	} else {
		keystore->lock_fd = open(lock_file_name, O_CREAT | O_RDONLY,
					 keystore->mode);
		if (keystore->lock_fd == -1) {
			rc = -errno;
			warnx("Failed to create lock file '%s': %s",
			      lock_file_name,
			      strerror(-rc));
			goto out;
		}

		if (fchown(keystore->lock_fd, geteuid(),
			   keystore->owner) != 0) {
			rc = -errno;
			warnx("chown faild on file '%s': %s", lock_file_name,
			      strerror(-rc));
			return rc;
		}
	}

	rc = flock(keystore->lock_fd, LOCK_EX);
	if (rc == -1) {
		rc = -errno;
		warnx("Failed to obtain the file lock on '%s': %s",
		      lock_file_name, strerror((-rc)));
	}

out:
	free(lock_file_name);
	return rc;
}

/**
 * Unlocks the repository
 *
 * @param[in] keystore   the keystore
 *
 * @returns 0 if successful, a negative errno value otherwise
 */
static int _keystore_unlock_repository(struct keystore *keystore)
{
	int rc;

	if (keystore->lock_fd == -1)
		return 0;

	rc = flock(keystore->lock_fd, LOCK_UN);
	if (rc == -1) {
		rc = -errno;
		warnx("Failed to release the file lock: %s", strerror((-rc)));
	}

	close(keystore->lock_fd);
	keystore->lock_fd = -1;

	return rc;
}

/**
 * Allocates new keystore object
 *
 * @param[in]    directory     the directory where the keystore resides
 * @param[in]    kms_info      KMS plugin info
 * @param[in]    verbose       if true, verbose messages are printed
 *
 * @returns a new keystore object
 */
struct keystore *keystore_new(const char *directory,
			      struct kms_info *kms_info, bool verbose)
{
	struct keystore *keystore;
	struct stat sb;
	int rc;

	util_assert(directory != NULL, "Internal error: directory is NULL");

	if (stat(directory, &sb) != 0) {
		warnx("Can not access '%s': %s", directory, strerror(errno));
		return NULL;
	}
	if (!S_ISDIR(sb.st_mode)) {
		warnx("'%s' is not a directory", directory);
		return NULL;
	}
	if (!util_path_is_readable(directory) ||
	    !util_path_is_writable(directory)) {
		warnx("Permission denied for '%s'", directory);
		return NULL;
	}
	if (sb.st_mode & S_IWOTH) {
		warnx("Directory '%s' is writable for others, this is not "
		      "accepted", directory);
		return NULL;
	}

	keystore = util_zalloc(sizeof(struct keystore));

	keystore->owner = sb.st_gid;
	keystore->mode = sb.st_mode & (S_IRUSR | S_IWUSR |
				       S_IRGRP  | S_IWGRP |
				       S_IROTH);
	keystore->lock_fd = -1;
	keystore->verbose = verbose;
	keystore->directory = util_strdup(directory);
	if (keystore->directory[strlen(keystore->directory)-1] == '/')
		keystore->directory[strlen(keystore->directory)-1] = '\0';

	keystore->kms_info = kms_info;

	rc = _keystore_lock_repository(keystore);
	if (rc != 0) {
		keystore_free(keystore);
		return NULL;
	}

	pr_verbose(keystore, "Keystore in directory '%s' opened successfully",
		   keystore->directory);
	return keystore;
}

/**
 * Generate the key verification pattern from the specified secure key file
 *
 * @param[in] keystore    the key store
 * @param[in} keyfile     the key file
 * @param[in] vp          buffer filled with the verification pattern
 * @param[in] vp_len      length of the buffer. Must be at
 *                        least VERIFICATION_PATTERN_LEN bytes in size.
 *
 * @returns 0 for success or a negative errno in case of an error
 */
static int _keystore_generate_verification_pattern(struct keystore *keystore,
						  const char *keyfile,
						  char *vp, size_t vp_len)
{
	size_t key_size;
	u8 *key;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(vp != NULL, "Internal error: vp is NULL");

	key = read_secure_key(keyfile, &key_size, keystore->verbose);
	if (key == NULL)
		return -EIO;

	rc = generate_key_verification_pattern(key, key_size,
					       vp, vp_len, keystore->verbose);

	free(key);
	return rc;
}

/**
 * Checks if the key verification pattern property exists. If not, then it is
 * created from the secure key.
 *
 * @param[in] keystore    the key store
 * @param[in] file_names  the file names of the key
 * @param[in] key_props   the properties of the key
 *
 *  @returns 0 for success or a negative errno in case of an error
 */
static int _keystore_ensure_vp_exists(struct keystore *keystore,
				      const struct key_filenames *file_names,
				      struct properties *key_props)
{
	char vp[VERIFICATION_PATTERN_LEN];
	char *temp;
	int rc;

	temp = properties_get(key_props, PROP_NAME_KEY_VP);
	if (temp != NULL) {
		free(temp);
		return 0;
	}

	rc = _keystore_generate_verification_pattern(keystore,
						     file_names->skey_filename,
						     vp, sizeof(vp));
	if (rc != 0)
		return rc;

	rc = properties_set(key_props, PROP_NAME_KEY_VP, vp);
	if (rc != 0)
		return rc;

	return 0;
}

/**
 * Sets a timestamp to be used as creation/update/reencipher time into
 * the specified property
 *
 * @param[in] properties   the properties object
 * @param[in] property     the name of the property to set
 *
 * @returns 0 on success, or a negative errno value on error
 */
static int _keystore_set_timestamp_property(struct properties *properties,
					      const char *property)
{
	char *time_str;
	struct tm *tm;
	time_t t;
	int rc;

	t = time(NULL);
	tm = localtime(&t);
	util_assert(tm != NULL, "Internal error: tm is NULL");

	time_str = util_zalloc(200);
	rc = strftime(time_str, 200, "%F %T", tm);
	util_assert(rc > 0, "Internal error: strftime failed");

	rc = properties_set(properties, property, time_str);

	free(time_str);
	return rc;
}

/**
 * Sets the default properties of a key, such as key-type, cipher-name, and
 * IV-mode
 *
 * @param[in] key_props   the properties object
 */
static int _keystore_set_default_properties(struct properties *key_props)
{
	int rc;

	rc = properties_set(key_props, PROP_NAME_CIPHER, "paes");
	if (rc != 0)
		return rc;

	rc = properties_set(key_props, PROP_NAME_IV_MODE, "plain64");
	if (rc != 0)
		return rc;

	rc = _keystore_set_timestamp_property(key_props,
					      PROP_NAME_CREATION_TIME);
	if (rc != 0)
		return rc;

	return 0;
}

/**
 * Generate, Set or remove a dummy LUKS2 passphrase of a key.
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] file_names  the file names of the key
 * @param[in] properties  the properties of the key
 * @param[in] prompt      if true, prompt for removal (if passphrase exists)
 *
 * @returns 0 on success, or a negative errno value on error
 */
static int _keystore_remove_passphrase(struct keystore *keystore,
				       const char *name,
				       const struct key_filenames *filenames,
				       struct properties *properties,
				       bool prompt)
{
	int rc;

	if (_keystore_passphrase_file_exists((struct key_filenames *)filenames)
	    && prompt) {
		util_print_indented("ATTENTION: When you remove the LUKS2 "
				    "dummy passphrase of a key, you might no "
				    "longer be able to open the LUKS2 volumes "
				    "associated with the key, unless you still "
				    "know a passphrase of one of the key slots "
				    "of these volumes!", 0);
		_keystore_msg_for_volumes("The following volumes are encrypted "
					  "with this key:", properties, NULL);
		printf("%s: Remove passphrase for key '%s' [y/N]? ",
		       program_invocation_short_name, name);
		if (!prompt_for_yes(keystore->verbose)) {
			warnx("Operation aborted");
			return -ECANCELED;
		}
	}

	rc = remove(filenames->pass_filename);
	if (rc != 0 && errno != ENOENT) {
		rc = -errno;
		warnx("Failed to remove file '%s': %s",
		      filenames->pass_filename, strerror(-rc));
		return rc;
	}

	return 0;
}

/**
 * Generate, Set or remove a dummy LUKS2 passphrase of a key.
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] passphrase_file the file name of a file containing a passphrase
 *                        for LUKS2. If NULKL, the passphrase is generated by
 *                        random.
 * @param[in] file_names  the file names of the key
 * @param[in] properties  the properties of the key
 * @param[in] prompt      if true, prompt for change, if passphrase exists
 *                        already
 *
 * @returns 0 on success, or a negative errno value on error
 */
static int _keystore_set_passphrase(struct keystore *keystore,
				    const char *name,
				    const char *passphrase_file,
				    const struct key_filenames *filenames,
				    struct properties *properties,
				    bool prompt)
{
	char *volume_type;
	int rc;

	if (_keystore_passphrase_file_exists((struct key_filenames *)filenames)
	    && prompt) {
		warnx("There is already a LUKS2 dummy passphrase associated "
		     "with key '%s'.", name);
		util_print_indented("To change a dummy passphrase of a key, "
				    "first remove the currently associated "
				    "passphrase with command 'zkey change "
				    "--name <key> --remove-dummy-passphrase' "
				    "and then set the new dummy passphrase for "
				    "the key.", 0);
		return -EEXIST;
	}

	volume_type = _keystore_get_volume_type(properties);
	if (volume_type == NULL) {
		pr_verbose(keystore, "No volume type available");
		return -EINVAL;
	}
	if (strcasecmp(volume_type, VOLUME_TYPE_LUKS2) != 0) {
		warnx("The LUKS2 dummy passphrase can only be set for keys "
		      "with a volume type of LUKS2.");
		free(volume_type);
		return -EINVAL;
	}
	free(volume_type);

	if (passphrase_file != NULL) {
		rc = copy_file(passphrase_file, filenames->pass_filename, 0);
		if (rc != 0) {
			warnx("Failed to copy the passphrase phase '%s': %s",
			      passphrase_file, strerror(-rc));
			return rc;
		}
	} else {
		rc = copy_file("/dev/urandom", filenames->pass_filename,
			       DUMMY_PASSPHRASE_LEN);
		if (rc != 0) {
			warnx("Failed to generate the dummy passphrase: %s",
			      strerror(-rc));
			return rc;
		}
	}

	rc = _keystore_set_file_permission(keystore, filenames->pass_filename);
	if (rc != 0)
		return rc;

	return 0;
}

/**
 * Creates the key properties for a key
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] description textual description of the key (optional, can be NULL)
 * @param[in] volumes     a comma separated list of volumes associated with this
 *                        key (optional, can be NULL)
 * @param[in] apqns       a comma separated list of APQNs associated with this
 *                        key (optional, can be NULL)
 * @param[in] noapqncheck if true, the specified APQN(s) are not checked for
 *                        existence and type.
 * @param[i] novolscheck  if true, the specified Volume(s) are not checked for
 *                        existence or duplicate use
 * @param[in] sector_size the sector size to use with dm-crypt. It must be power
 *                        of two and in range 512 - 4096 bytes. 0 means that
 *                        the sector size is not specified and the system
 *                        default is used.
 * @param[in] volume_type the type of volume
 * @param[in] key_type    the type of the key
 * @param[in] kms         the name of the KMS plugin, or NULL if no KMS is bound
 * @param[out] props      the properties object is allocated and returned
 *
 * @returns 0 on success, or a negative errno value on error
 */
static int _keystore_create_info_props(struct keystore *keystore,
				       const char *name,
				       const char *description,
				       const char *volumes, const char *apqns,
				       bool noapqncheck, bool novolcheck,
				       size_t sector_size,
				       const char *volume_type,
				       const char *key_type,
				       const char *kms,
				       struct properties **props)
{
	struct volume_check vol_check = { .keystore = keystore, .name = name,
					  .set = 0, .nocheck = novolcheck };
	struct apqn_check apqn_check = { .noonlinecheck = noapqncheck,
					 .nomsg = 0,
					 .cardtype = get_card_type_for_keytype(
								key_type), };
	struct properties *key_props;
	char temp[10];
	int rc;

	*props = NULL;

	key_props = properties_new();
	rc = _keystore_set_default_properties(key_props);
	if (rc != 0)
		goto out;

	rc = properties_set(key_props, PROP_NAME_DESCRIPTION,
			    description != NULL ? description : "");
	if (rc != 0) {
		warnx("Invalid characters in description");
		goto out;
	}

	rc = properties_set2(key_props, PROP_NAME_KEY_TYPE, key_type, true);
	if (rc != 0) {
		warnx("Invalid characters in key-type");
		goto out;
	}

	rc = _keystore_change_association(key_props, PROP_NAME_VOLUMES,
					  volumes != NULL ? volumes : "",
					  "volume", _keystore_volume_check,
					  &vol_check);
	if (rc != 0)
		goto out;

	rc = _keystore_change_association(key_props, PROP_NAME_APQNS,
					  apqns != NULL ? apqns : "",
					  "APQN", _keystore_apqn_check,
					  &apqn_check);
	if (rc != 0)
		goto out;

	if (!_keystore_valid_sector_size(sector_size)) {
		warnx("Invalid sector-size specified");
		rc = -EINVAL;
		goto out;
	}
	sprintf(temp, "%lu", sector_size);
	rc = properties_set(key_props, PROP_NAME_SECTOR_SIZE,
			    temp);
	if (rc != 0) {
		warnx("Invalid characters in sector-size");
		goto out;
	}

	if (volume_type == NULL)
		volume_type = DEFAULT_VOLUME_TYPE;
	if (!_keystore_valid_volume_type(volume_type)) {
		warnx("Invalid volume-type specified");
		rc = -EINVAL;
		goto out;
	}
	rc = properties_set2(key_props, PROP_NAME_VOLUME_TYPE, volume_type,
			     true);
	if (rc != 0) {
		warnx("Invalid characters in volume-type");
		goto out;
	}

	if (kms != NULL) {
		rc = properties_set(key_props, PROP_NAME_KMS, kms);
		if (rc != 0) {
			warnx("Invalid characters in KMS");
			goto out;
		}
	}

out:
	if (rc == 0)
		*props = key_props;
	else
		properties_free(key_props);

	return rc;
}


/**
 * Creates an initial .info file for a key
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] filenames   the file names of the key files
 * @param[in] description textual description of the key (optional, can be NULL)
 * @param[in] volumes     a comma separated list of volumes associated with this
 *                        key (optional, can be NULL)
 * @param[in] apqns       a comma separated list of APQNs associated with this
 *                        key (optional, can be NULL)
 * @param[in] noapqncheck if true, the specified APQN(s) are not checked for
 *                        existence and type.
 * @param[in] sector_size the sector size to use with dm-crypt. It must be power
 *                        of two and in range 512 - 4096 bytes. 0 means that
 *                        the sector size is not specified and the system
 *                        default is used.
 * @param[in] volume_type the type of volume
 * @param[in] key_type    the type of the key
 * @param[in] gen_passphrase if true, generate a (dummy) passphrase for LUKS2
 * @param[in] passphrase_file the file name of a file containing a passphrase
 *                        for LUKS2 (optional, can be NULL)
 * @param[in] kms         the name of the KMS plugin, or NULL if no KMS is bound
 *
 * @returns 0 on success, or a negative errno value on error
 */
static int _keystore_create_info_file(struct keystore *keystore,
				      const char *name,
				      const struct key_filenames *filenames,
				      const char *description,
				      const char *volumes, const char *apqns,
				      bool noapqncheck,
				      size_t sector_size,
				      const char *volume_type,
				      const char *key_type,
				      bool gen_passphrase,
				      const char *passphrase_file,
				      const char *kms)
{
	struct properties *key_props = NULL;
	int rc;

	rc = _keystore_create_info_props(keystore, name, description, volumes,
					 apqns, noapqncheck, false, sector_size,
					 volume_type, key_type, kms,
					 &key_props);
	if (rc != 0)
		return rc;

	if (gen_passphrase || passphrase_file != NULL) {
		rc = _keystore_set_passphrase(keystore, name, gen_passphrase ?
							NULL : passphrase_file,
					      filenames, key_props, true);
		if (rc != 0) {
			pr_verbose(keystore, "Failed to set the passphrase: %s",
				   strerror(-rc));
			goto out;
		}
	}

	rc = _keystore_ensure_vp_exists(keystore, filenames, key_props);
	if (rc != 0) {
		warnx("Failed to generate the key verification pattern: %s",
		      strerror(-rc));
		warnx("Make sure that kernel module 'paes_s390' is loaded and "
		      "that the 'paes' cipher is available");
		remove(filenames->pass_filename);
		goto out;
	}

	rc = properties_save(key_props, filenames->info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   filenames->info_filename, strerror(-rc));
		remove(filenames->pass_filename);
		goto out;
	}

	rc = _keystore_set_file_permission(keystore, filenames->info_filename);
	if (rc != 0) {
		remove(filenames->info_filename);
		remove(filenames->pass_filename);
		goto out;
	}

out:
	properties_free(key_props);
	return rc;
}

/**
 * Generates a secure key by random and adds it to the key store
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] description textual description of the key (optional, can be NULL)
 * @param[in] volumes     a comma separated list of volumes associated with this
 *                        key (optional, can be NULL)
 * @param[in] apqns       a comma separated list of APQNs associated with this
 *                        key (optional, can be NULL)
 * @param[in] noapqncheck if true, the specified APQN(s) are not checked for
 *                        existence and type.
 * @param[in] sector_size the sector size to use with dm-crypt. It must be power
 *                        of two and in range 512 - 4096 bytes. 0 means that
 *                        the sector size is not specified and the system
 *                        default is used.
 * @param[in] keybits     cryptographical size of the key in bits
 * @param[in] xts         if true, an XTS key is generated
 * @param[in] clear_key_file if not NULL the secure key is generated from the
 *                        clear key contained in the file denoted here.
 *                        if NULL, the secure key is generated by random.
 * @param[in] volume_type the type of volume
 * @param[in] key_type    the type of the key
 * @param[in] gen_passphrase if true, generate a (dummy) passphrase for LUKS2
 * @param[in] passphrase_file the file name of a file containing a passphrase
 *                        for LUKS2 (optional, can be NULL)
 * @param[in] pkey_fd     the file descriptor of /dev/pkey
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_generate_key(struct keystore *keystore, const char *name,
			  const char *description, const char *volumes,
			  const char *apqns, bool noapqncheck,
			  size_t sector_size, size_t keybits, bool xts,
			  const char *clear_key_file, const char *volume_type,
			  const char *key_type, bool gen_passphrase,
			  const char *passphrase_file, int pkey_fd)
{
	struct key_filenames file_names = { 0 };
	struct properties *key_props = NULL;
	char **apqn_list = NULL;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");
	util_assert(key_type != NULL, "Internal error: key_type is NULL");

	if (!_keystore_valid_key_type(key_type)) {
		warnx("Invalid key-type specified");
		return -EINVAL;
	}

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out_free_key_filenames;

	rc = _keystore_ensure_keyfiles_not_exist(&file_names, name);
	if (rc != 0)
		goto out_free_key_filenames;

	rc = cross_check_apqns(apqns, NULL,
			       get_min_card_level_for_keytype(key_type),
			       get_min_fw_version_for_keytype(key_type),
			       get_card_type_for_keytype(key_type),
			       true, keystore->verbose);
	if (rc == -EINVAL)
		goto out_free_key_filenames;
	if (rc != 0 && rc != -ENOTSUP && noapqncheck == 0) {
		warnx("Your master key setup is improper");
		goto out_free_key_filenames;
	}

	if (apqns != NULL)
		apqn_list = str_list_split(apqns);

	if (clear_key_file == NULL)
		rc = generate_secure_key_random(pkey_fd,
						file_names.skey_filename,
						keybits, xts, key_type,
						(const char **)apqn_list,
						keystore->verbose);
	else
		rc = generate_secure_key_clear(pkey_fd,
					       file_names.skey_filename,
					       keybits, xts, clear_key_file,
					       key_type,
					       (const char **)apqn_list,
					       keystore->verbose);
	if (rc != 0)
		goto out_free_props;

	rc = _keystore_set_file_permission(keystore, file_names.skey_filename);
	if (rc != 0)
		goto out_free_props;

	rc = _keystore_create_info_file(keystore, name, &file_names,
					description, volumes, apqns,
					noapqncheck, sector_size, volume_type,
					key_type, gen_passphrase,
					passphrase_file, NULL);
	if (rc != 0)
		goto out_free_props;

	pr_verbose(keystore,
		   "Successfully generated a secure key in '%s' and key info "
		   "in '%s'", file_names.skey_filename,
		   file_names.info_filename);

out_free_props:
	if (apqn_list != NULL)
		str_list_free_string_array(apqn_list);
	if (key_props != NULL)
		properties_free(key_props);
	if (rc != 0)
		remove(file_names.skey_filename);
out_free_key_filenames:
	_keystore_free_key_filenames(&file_names);

	if (rc != 0)
		pr_verbose(keystore, "Failed to generate key '%s': %s",
			   name, strerror(-rc));
	return rc;
}

/**
 * Generates a secure key by using a KMS plugin and adds it to the key store
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] description textual description of the key (optional, can be NULL)
 * @param[in] volumes     a comma separated list of volumes associated with this
 *                        key (optional, can be NULL)
 * @param[in] sector_size the sector size to use with dm-crypt. It must be power
 *                        of two and in range 512 - 4096 bytes. 0 means that
 *                        the sector size is not specified and the system
 *                        default is used.
 * @param[in] keybits     cryptographical size of the key in bits
 * @param[in] xts         if true, an XTS key is generated
 * @param[in] volume_type the type of volume
 * @param[in] key_type    the type of the key (can be NULL)
 * @param[in] gen_passphrase if true, generate a (dummy) passphrase for LUKS2
 * @param[in] passphrase_file the file name of a file containing a passphrase
 *                        for LUKS2 (optional, can be NULL)
 * @param[in] kms_options an array of KMS options specified, or NULL if no
 *                         KMS options have been specified
 * @param[in] num_kms_options the number of options in above array
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_generate_key_kms(struct keystore *keystore, const char *name,
			      const char *description, const char *volumes,
			      size_t sector_size, size_t keybits, bool xts,
			      const char *volume_type, const char *key_type,
			      bool gen_passphrase, const char *passphrase_file,
			      struct kms_option *kms_options,
			      size_t num_kms_options)
{
	struct key_filenames file_names = { 0 };
	struct properties *key_props = NULL;
	struct kms_info *kms_info;
	char *apqns = NULL;
	int rc, i;

	static const char * const key_types[] = {
			KEY_TYPE_CCA_AESDATA,
			KEY_TYPE_CCA_AESCIPHER,
			KEY_TYPE_EP11_AES,
			NULL
	};

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");

	kms_info = keystore->kms_info;
	if (kms_info->plugin_lib == NULL) {
		warnx("The repository is not bound to a KMS plugin");
		return -ENOENT;
	}

	if (key_type == NULL) {
		for (i = 0; kms_info->funcs->kms_supports_key_type != NULL &&
			    key_types[i] != NULL; i++) {
			if (kms_info->funcs->kms_supports_key_type(
					kms_info->handle, key_types[i])) {
				key_type = key_types[i];
				break;
			}
		}
		if (key_type == NULL)
			key_type = KEY_TYPE_CCA_AESDATA;
	}

	if (!_keystore_valid_key_type(key_type)) {
		warnx("Invalid key-type specified");
		return -EINVAL;
	}

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out_free_key_filenames;

	rc = _keystore_ensure_keyfiles_not_exist(&file_names, name);
	if (rc != 0)
		goto out_free_key_filenames;

	rc = get_kms_apqns_for_key_type(kms_info, key_type, true, &apqns,
					keystore->verbose);
	if (rc != 0) {
		if (rc == -ENOTSUP)
			warnx("Key-type not supported by the KMS plugin '%s'",
			      kms_info->plugin_name);
		goto out_free_key_filenames;
	}

	pr_verbose(keystore, "APQNs for keytype %s: '%s'", key_type, apqns);

	rc = _keystore_create_info_props(keystore, name, description, volumes,
					 apqns, false, false, sector_size,
					 volume_type, key_type,
					 kms_info->plugin_name, &key_props);
	if (rc != 0)
		goto out_free_key_filenames;

	if (gen_passphrase || passphrase_file != NULL) {
		rc = _keystore_set_passphrase(keystore, name, gen_passphrase ?
							NULL : passphrase_file,
					      &file_names, key_props, true);
		if (rc != 0) {
			pr_verbose(keystore, "Failed to set the passphrase: %s",
				   strerror(-rc));
			goto out_free_key_filenames;
		}
	}

	rc = generate_kms_key(kms_info, name, key_type, key_props, xts,
			      keybits, file_names.skey_filename,
			      _keystore_passphrase_file_exists(&file_names) ?
						file_names.pass_filename : NULL,
			      kms_options, num_kms_options, keystore->verbose);
	if (rc != 0) {
		warnx("KMS plugin '%s' failed to generate key '%s': %s",
		      kms_info->plugin_name, name, strerror(-rc));
		print_last_kms_error(kms_info);
		goto out_free_props;
	}

	rc = _keystore_set_file_permission(keystore, file_names.skey_filename);
	if (rc != 0)
		goto out_free_props;

	rc = _keystore_ensure_vp_exists(keystore, &file_names, key_props);
	if (rc != 0) {
		warnx("Failed to generate the key verification pattern: %s",
		      strerror(-rc));
		warnx("Make sure that kernel module 'paes_s390' is loaded and "
		      "that the 'paes' cipher is available");
		goto out_free_props;
	}

	rc = properties_save(key_props, file_names.info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   file_names.info_filename, strerror(-rc));
		goto out_del_info_file;
	}

	rc = _keystore_set_file_permission(keystore, file_names.info_filename);
	if (rc != 0) {
		remove(file_names.info_filename);
		goto out_del_info_file;
	}

	pr_verbose(keystore,
		   "Successfully generated a secure key with KMS plugin '%s' "
		   "in '%s' and key info in '%s'", kms_info->plugin_name,
		   file_names.skey_filename, file_names.info_filename);

out_del_info_file:
	if (rc != 0)
		remove(file_names.info_filename);
out_free_props:
	if (key_props != NULL)
		properties_free(key_props);
	if (rc != 0) {
		remove(file_names.skey_filename);
		remove(file_names.pass_filename);
	}
out_free_key_filenames:
	_keystore_free_key_filenames(&file_names);
	if (apqns != NULL)
		free(apqns);

	if (rc != 0)
		pr_verbose(keystore, "Failed to generate key '%s' with KMS "
			   "plugin '%s': %s", name, kms_info->plugin_name,
			   strerror(-rc));
	return rc;

}

/**
 * Imports a secure key from a file and adds it to the key store
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] description textual description of the key (optional, can be NULL)
 * @param[in] volumes     a comma separated list of volumes associated with this
 *                        key (optional, can be NULL)
 * @param[in] apqns       a comma separated list of APQNs associated with this
 *                        key (optional, can be NULL)
 * @param[in] noapqncheck if true, the specified APQN(s) are not checked for
 *                        existence and type.
 * @param[in] sector_size the sector size to use with dm-crypt. It must be power
 *                        of two and in range 512 - 4096 bytes. 0 means that
 *                        the sector size is not specified and the system
 *                        default is used.
 * @param[in] import_file The name of a secure key containing the key to import
 * @param[in] volume_type the type of volume
 * @param[in] gen_passphrase if true, generate a (dummy) passphrase for LUKS2
 * @param[in] passphrase_file the file name of a file containing a passphrase
 *                        for LUKS2 (optional, can be NULL)
 * @param[in] lib         the external library struct
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_import_key(struct keystore *keystore, const char *name,
			const char *description, const char *volumes,
			const char *apqns, bool noapqncheck, size_t sector_size,
			const char *import_file, const char *volume_type,
			bool gen_passphrase, const char *passphrase_file,
			struct ext_lib *lib)
{
	struct key_filenames file_names = { 0 };
	struct properties *key_props = NULL;
	size_t secure_key_size;
	const char *key_type;
	u8 mkvp[MKVP_LENGTH];
	int selected = 1;
	u8 *secure_key;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");
	util_assert(import_file != NULL, "Internal error: import_file is NULL");

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out_free_key_filenames;

	rc = _keystore_ensure_keyfiles_not_exist(&file_names, name);
	if (rc != 0)
		goto out_free_key_filenames;

	secure_key = read_secure_key(import_file, &secure_key_size,
				     keystore->verbose);
	if (secure_key == NULL) {
		rc = -ENOENT;
		goto out_free_key_filenames;
	}

	key_type = get_key_type(secure_key, secure_key_size);
	if (key_type == NULL) {
		warnx("Key '%s' is not a valid secure key", name);
		free(secure_key);
		rc = -EINVAL;
		goto out_free_key_filenames;
	}

	rc = get_master_key_verification_pattern(secure_key, secure_key_size,
						 mkvp, keystore->verbose);
	if (rc != 0) {
		warnx("Failed to get the master key verification pattern: %s",
		      strerror(-rc));
		goto out_free_key;
	}

	rc = cross_check_apqns(apqns, mkvp,
			       get_min_card_level_for_keytype(key_type),
			       get_min_fw_version_for_keytype(key_type),
			       get_card_type_for_keytype(key_type),
			       true, keystore->verbose);
	if (rc == -EINVAL)
		goto out_free_key;
	if (rc != 0 && rc != -ENOTSUP && noapqncheck == 0) {
		warnx("Your master key setup is improper");
		goto out_free_key;
	}

	if (is_cca_aes_cipher_key(secure_key, secure_key_size)) {
		if (lib->cca->lib_csulcca == NULL) {
			rc = load_cca_library(lib->cca, keystore->verbose);
			if (rc != 0)
				goto out_free_key;
		}

		rc = select_cca_adapter_by_mkvp(lib->cca, mkvp, apqns,
						FLAG_SEL_CCA_MATCH_CUR_MKVP |
						FLAG_SEL_CCA_MATCH_OLD_MKVP,
						keystore->verbose);
		if (rc == -ENOTSUP) {
			rc = 0;
			selected = 0;
		}
		if (rc != 0) {
			warnx("No APQN found that is suitable for "
			      "working with the secure AES key '%s'", name);
			rc = 0;
			goto out_free_key;
		}

		rc = restrict_key_export(lib->cca, secure_key, secure_key_size,
					 keystore->verbose);
		if (rc != 0) {
			warnx("Failed to export-restrict the imported secure "
			      "key: %s", strerror(-rc));
			if (!selected)
				print_msg_for_cca_envvars("secure AES key");
			goto out_free_key;
		}

		rc = check_aes_cipher_key(secure_key, secure_key_size);
		if (rc != 0) {
			warnx("The secure key to import might not be secure");
			printf("%s: Do you want to import it anyway [y/N]? ",
			       program_invocation_short_name);
			if (!prompt_for_yes(keystore->verbose)) {
				warnx("Operation aborted");
				rc = -ECANCELED;
				goto out_free_key;
			}
		}
	}

	rc = write_secure_key(file_names.skey_filename, secure_key,
			      secure_key_size, keystore->verbose);
	free(secure_key);
	secure_key = NULL;
	if (rc != 0)
		goto out_free_props;

	rc = _keystore_set_file_permission(keystore, file_names.skey_filename);
	if (rc != 0)
		goto out_free_props;

	rc = _keystore_create_info_file(keystore, name, &file_names,
					description, volumes, apqns,
					noapqncheck, sector_size, volume_type,
					key_type, gen_passphrase,
					passphrase_file, NULL);
	if (rc != 0)
		goto out_free_props;

	pr_verbose(keystore,
		   "Successfully imported a secure key in '%s' and key info in '%s'",
		   file_names.skey_filename, file_names.info_filename);

out_free_key:
	if (secure_key != NULL)
		free(secure_key);
out_free_props:
	if (key_props != NULL)
		properties_free(key_props);
	if (rc != 0)
		remove(file_names.skey_filename);
out_free_key_filenames:
	_keystore_free_key_filenames(&file_names);

	if (rc != 0)
		pr_verbose(keystore, "Failed to import key '%s': %s",
			   name, strerror(-rc));
	return rc;
}


/**
 * Changes properties of a key in the keystore.
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] description textual description of the key. If NULL then the
 *                        description is not changed.
 * @param[in] volumes     a comma separated list of volumes associated with this
 *                        key, or a volume prefixed with '+' or '-' to add or
 *                        remove that volume respectively. If NULL then the
 *                        volumes are not changed.
 * @param[in] apqns       a comma separated list of APQNs associated with this
 *                        key, or an APQN prefixed with '+' or '-' to add or
 *                        remove that APQN respectively. If NULL then the APQNs
 *                        are not changed.
 * @param[in] noapqncheck if true, the specified APQN(s) are not checked for
 *                        existence and type.
 * @param[in] sector_size the sector size to use with dm-crypt. It must be power
 *                        of two and in range 512 - 4096 bytes. 0 means that
 *                        the sector size is not specified and the system
 *                        default is used. Specify -1 if this property should
 *                        not be changed.
 * @param[in] volume_type the type of volume. If NULL then the volume type is
 *                        not changed.
 * @param[in] gen_passphrase if true, generate a (dummy) passphrase for LUKS2
 * @param[in] passphrase_file the file name of a file containing a passphrase
 *                        for LUKS2 (optional, can be NULL)
 * @param[in] remove_passphrase if true, remove the (dummy) passphrase
 * @param[in] quiet       if true no confirmation prompt is shown when removing
 *                        a (dummy) passphrase
 *
 * @returns 0 for success or a negative errno in case of an error
 *
 */
int keystore_change_key(struct keystore *keystore, const char *name,
			const char *description, const char *volumes,
			const char *apqns, bool noapqncheck,
			long int sector_size, const char *volume_type,
			bool gen_passphrase, const char *passphrase_file,
			bool remove_passphrase, bool quiet)
{
	struct volume_check vol_check = { .keystore = keystore, .name = name,
					  .set = 0, .nocheck = 0 };
	struct apqn_check apqn_check = { .noonlinecheck = noapqncheck,
					 .nomsg = 0 };
	struct key_filenames file_names = { 0 };
	struct properties *key_props = NULL;
	const char **passphrase_upd = NULL;
	char *upd_volume_type = NULL;
	char *apqns_prop, *key_type;
	const char *null_ptr = NULL;
	char *upd_volumes = NULL;
	size_t secure_key_size;
	u8 mkvp[MKVP_LENGTH];
	char sect_size[30];
	u8 *secure_key;
	bool kms_bound;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out;

	rc = _keystore_ensure_keyfiles_exist(&file_names, name);
	if (rc != 0)
		goto out;

	key_props = properties_new();
	rc = properties_load(key_props, file_names.info_filename, 1);
	if (rc != 0) {
		warnx("Key '%s' does not exist or is invalid", name);
		goto out;
	}

	kms_bound = _keystore_is_kms_bound_key(key_props, NULL);

	if (description != NULL) {
		rc = properties_set(key_props, PROP_NAME_DESCRIPTION,
				    description);
		if (rc != 0) {
			warnx("Invalid characters in description");
			goto out;
		}
	}

	if (volumes != NULL) {
		rc = _keystore_change_association(key_props, PROP_NAME_VOLUMES,
						  volumes, "volume",
						  _keystore_volume_check,
						  &vol_check);
		if (rc != 0)
			goto out;

		upd_volumes = properties_get(key_props, PROP_NAME_VOLUMES);
	}

	if (apqns != NULL) {
		if (kms_bound) {
			rc = -EINVAL;
			warnx("The APQN association of a KMS-bound key can not "
			      "be changed");
			goto out;
		}

		rc = _keystore_change_association(key_props, PROP_NAME_APQNS,
						  apqns, "APQN",
						  _keystore_apqn_check,
						  &apqn_check);
		if (rc != 0)
			goto out;

		secure_key = read_secure_key(file_names.skey_filename,
					     &secure_key_size,
					     keystore->verbose);
		if (secure_key == NULL) {
			rc = -ENOENT;
			goto out;
		}

		rc = get_master_key_verification_pattern(secure_key,
							 secure_key_size,
							 mkvp,
							 keystore->verbose);
		free(secure_key);
		if (rc)
			goto out;

		apqns_prop = properties_get(key_props, PROP_NAME_APQNS);
		key_type = properties_get(key_props, PROP_NAME_KEY_TYPE);
		rc = cross_check_apqns(apqns_prop, mkvp,
				       get_min_card_level_for_keytype(key_type),
				       get_min_fw_version_for_keytype(key_type),
				       get_card_type_for_keytype(key_type),
				       true, keystore->verbose);
		free(apqns_prop);
		free(key_type);
		if (rc == -ENOTSUP)
			rc = 0;
		if (rc != 0 && noapqncheck == 0) {
			warnx("Your master key setup is improper");
			goto out;
		}
	}

	if (sector_size >= 0) {
		if (!_keystore_valid_sector_size(sector_size)) {
			warnx("Invalid sector-size specified");
			rc = -EINVAL;
			goto out;
		}

		sprintf(sect_size, "%lu", sector_size);
		rc = properties_set(key_props, PROP_NAME_SECTOR_SIZE,
				    sect_size);
		if (rc != 0) {
			warnx("Invalid characters in sector-size");
			goto out;
		}
	}

	if (volume_type != NULL) {
		if (!_keystore_valid_volume_type(volume_type)) {
			warnx("Invalid volume-type specified");
			rc = -EINVAL;
			goto out;
		}

		rc = properties_set2(key_props, PROP_NAME_VOLUME_TYPE,
				     volume_type, true);
		if (rc != 0) {
			warnx("Invalid characters in volume-type");
			goto out;
		}

		upd_volume_type = properties_get(key_props,
						 PROP_NAME_VOLUME_TYPE);

		/* Remove dummy passphrase if change to PLAIN volume type */
		if (strcasecmp(volume_type, VOLUME_TYPE_LUKS2) != 0 &&
		    _keystore_passphrase_file_exists(&file_names)) {
			rc = _keystore_remove_passphrase(keystore, name,
							 &file_names, key_props,
							 false);
			if (rc != 0)
				goto out;

			passphrase_upd = &null_ptr;
		}
	}

	if (gen_passphrase || passphrase_file != NULL) {
		rc = _keystore_set_passphrase(keystore, name, gen_passphrase ?
							NULL : passphrase_file,
					      &file_names, key_props, true);
		if (rc != 0)
			goto out;

		passphrase_upd = (const char **)&file_names.pass_filename;
	}

	if (remove_passphrase) {
		if (_keystore_passphrase_file_exists(&file_names))
			passphrase_upd = &null_ptr;

		rc = _keystore_remove_passphrase(keystore, name, &file_names,
						 key_props, !quiet);
		if (rc != 0)
			goto out;
	}

	if (kms_bound) {
		rc = perform_kms_login(keystore->kms_info, keystore->verbose);
		if (rc != 0)
			goto out;

		rc = set_kms_key_properties(keystore->kms_info, key_props, NULL,
					    description, upd_volumes,
					    upd_volume_type, sector_size >= 0 ?
							sect_size : NULL,
					    passphrase_upd, keystore->verbose);
		if (rc != 0) {
			warnx("KMS plugin '%s' failed to set key properties "
			      "for key '%s': %s",
			      keystore->kms_info->plugin_name, name,
			      strerror(-rc));
			print_last_kms_error(keystore->kms_info);
			goto out;
		}
	}

	rc = _keystore_ensure_vp_exists(keystore, &file_names, key_props);
	/* ignore return code, vp generation might fail if key is not valid */

	rc = _keystore_set_timestamp_property(key_props, PROP_NAME_CHANGE_TIME);
	if (rc != 0)
		goto out;

	rc = properties_save(key_props, file_names.info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   file_names.info_filename, strerror(-rc));
		goto out;
	}

	pr_verbose(keystore, "Successfully changed key '%s'", name);

out:
	if (rc != 0 && passphrase_upd != NULL && *passphrase_upd != NULL)
		remove(*passphrase_upd);
	_keystore_free_key_filenames(&file_names);
	if (key_props != NULL)
		properties_free(key_props);
	if (upd_volumes != NULL)
		free(upd_volumes);
	if (upd_volume_type != NULL)
		free(upd_volume_type);

	if (rc != 0)
		pr_verbose(keystore, "Failed to change key '%s': %s",
			   name, strerror(-rc));
	return rc;
}

/**
 * Renames a key in the keystore
 *
 * @param[in] keystore the key store
 * @param[in] name     the name of the key
 * @param[in] newname  the new name of the key
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_rename_key(struct keystore *keystore, const char *name,
			const char *newname)
{
	struct key_filenames file_names = { 0 };
	struct key_filenames new_names = { 0 };
	struct properties *key_props = NULL;
	bool reenc_exists = false;
	bool pass_exists = false;
	char *msg;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");
	util_assert(newname != NULL, "Internal error: newname is NULL");

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out;

	rc = _keystore_ensure_keyfiles_exist(&file_names, name);
	if (rc != 0)
		goto out;

	rc = _keystore_get_key_filenames(keystore, newname, &new_names);
	if (rc != 0)
		goto out;

	rc = _keystore_ensure_keyfiles_not_exist(&new_names, newname);
	if (rc != 0)
		goto out;

	if (rename(file_names.skey_filename, new_names.skey_filename) != 0) {
		rc = -errno;
		pr_verbose(keystore, "Failed to rename '%s': %s",
			   file_names.skey_filename, strerror(-rc));
		goto out;
	}
	if (rename(file_names.info_filename, new_names.info_filename) != 0) {
		rc = -errno;
		pr_verbose(keystore, "Failed to rename '%s': %s",
			   file_names.info_filename, strerror(-rc));
		goto out_rename_skey;
	}
	if (_keystore_reencipher_key_exists(&file_names)) {
		reenc_exists = true;
		if (rename(file_names.renc_filename,
			   new_names.renc_filename) != 0) {
			rc = -errno;
			pr_verbose(keystore, "Failed to rename '%s': %s",
				   file_names.renc_filename, strerror(-rc));
			goto out_rename_info;
		}
	}
	if (_keystore_passphrase_file_exists(&file_names)) {
		pass_exists = true;
		if (rename(file_names.pass_filename,
			   new_names.pass_filename) != 0) {
			rc = -errno;
			pr_verbose(keystore, "Failed to rename '%s': %s",
				   file_names.pass_filename, strerror(-rc));
			goto out_rename_info;
		}
	}

	key_props = properties_new();
	rc = properties_load(key_props, new_names.info_filename, 1);
	if (rc != 0) {
		warnx("Key '%s' does not exist or is invalid", newname);
		goto out_rename_info;
	}

	if (_keystore_is_kms_bound_key(key_props, NULL)) {
		rc = perform_kms_login(keystore->kms_info, keystore->verbose);
		if (rc != 0)
			goto out_rename_info;

		rc = set_kms_key_properties(keystore->kms_info, key_props,
					    newname, NULL, NULL, NULL, NULL,
					    NULL, keystore->verbose);
		if (rc != 0) {
			warnx("KMS plugin '%s' failed to set key properties "
			      "for key '%s': %s",
			      keystore->kms_info->plugin_name, name,
			      strerror(-rc));
			print_last_kms_error(keystore->kms_info);
			goto out_rename_info;
		}
	}

	util_asprintf(&msg, "The following volumes are associated with the "
		      "renamed key '%s'. You should adjust the corresponding "
		      "crypttab entries and 'cryptsetup plainOpen' commands to "
		      "use the new name.", newname);
	_keystore_msg_for_volumes(msg, key_props, VOLUME_TYPE_PLAIN);
	free(msg);

	if (_keystore_passphrase_file_exists(&new_names)) {
		util_asprintf(&msg, "The following volumes are associated with "
			      "the renamed key '%s'. You should adjust the "
			      "corresponding crypttab entries to use the new "
			      "dummy passphrase file name '%s'.", newname,
			      new_names.pass_filename);
		_keystore_msg_for_volumes(msg, key_props, VOLUME_TYPE_LUKS2);
		free(msg);
	}

	pr_verbose(keystore, "Successfully renamed key '%s' to '%s'", name,
		   newname);

	goto out;

out_rename_info:
	if (reenc_exists)
		rename(file_names.renc_filename, new_names.renc_filename);
	if (pass_exists)
		rename(file_names.pass_filename, new_names.pass_filename);
	rename(new_names.info_filename, file_names.info_filename);

out_rename_skey:
	rename(new_names.skey_filename, file_names.skey_filename);

out:
	_keystore_free_key_filenames(&file_names);
	_keystore_free_key_filenames(&new_names);
	if (key_props != NULL)
		properties_free(key_props);

	if (rc != 0)
		pr_verbose(keystore, "Failed to rename key '%s'to '%s': %s",
			   name, newname, strerror(-rc));
	return rc;
}

/**
 * Sets up a util_rec used for displaying key information
 *
 * @param[in] validation if true the record is used for validate, else it is
 *                       used for display
 *
 * @returns a pointer to a set up  struct util_rec.
 */
static struct util_rec *_keystore_setup_record(bool validation)
{
	struct util_rec *rec;

	rec = util_rec_new_long("-", ":", REC_KEY, 28, 54);
	util_rec_def(rec, REC_KEY, UTIL_REC_ALIGN_LEFT, 54, REC_KEY);
	if (validation)
		util_rec_def(rec, REC_STATUS, UTIL_REC_ALIGN_LEFT, 54,
			     REC_STATUS);
	util_rec_def(rec, REC_DESCRIPTION, UTIL_REC_ALIGN_LEFT, 54,
		     REC_DESCRIPTION);
	util_rec_def(rec, REC_SEC_KEY_SIZE, UTIL_REC_ALIGN_LEFT, 20,
		     REC_SEC_KEY_SIZE);
	util_rec_def(rec, REC_CLR_KEY_SIZE, UTIL_REC_ALIGN_LEFT, 20,
		     REC_CLR_KEY_SIZE);
	util_rec_def(rec, REC_XTS, UTIL_REC_ALIGN_LEFT, 3, REC_XTS);
	util_rec_def(rec, REC_KEY_TYPE, UTIL_REC_ALIGN_LEFT, 54, REC_KEY_TYPE);
	if (validation)
		util_rec_def(rec, REC_MASTERKEY, UTIL_REC_ALIGN_LEFT, 54,
			     REC_MASTERKEY);
	util_rec_def(rec, REC_VOLUMES, UTIL_REC_ALIGN_LEFT, 54, REC_VOLUMES);
	util_rec_def(rec, REC_APQNS, UTIL_REC_ALIGN_LEFT, 54, REC_APQNS);
	util_rec_def(rec, REC_KEY_FILE, UTIL_REC_ALIGN_LEFT, 54, REC_KEY_FILE);
	util_rec_def(rec, REC_SECTOR_SIZE, UTIL_REC_ALIGN_LEFT, 54,
		     REC_SECTOR_SIZE);
	util_rec_def(rec, REC_VOLUME_TYPE, UTIL_REC_ALIGN_LEFT, 54,
		     REC_VOLUME_TYPE);
	util_rec_def(rec, REC_KEY_VP, UTIL_REC_ALIGN_LEFT, 54, REC_KEY_VP);
	util_rec_def(rec, REC_KMS, UTIL_REC_ALIGN_LEFT, 54, REC_KMS);
	util_rec_def(rec, REC_KMS_KEY_LABEL, UTIL_REC_ALIGN_LEFT, 54,
		     REC_KMS_KEY_LABEL);
	util_rec_def(rec, REC_PASSPHRASE_FILE, UTIL_REC_ALIGN_LEFT, 54,
		     REC_PASSPHRASE_FILE);
	util_rec_def(rec, REC_CREATION_TIME, UTIL_REC_ALIGN_LEFT, 54,
		     REC_CREATION_TIME);
	util_rec_def(rec, REC_CHANGE_TIME, UTIL_REC_ALIGN_LEFT, 54,
			REC_CHANGE_TIME);
	util_rec_def(rec, REC_REENC_TIME, UTIL_REC_ALIGN_LEFT, 54,
			REC_REENC_TIME);

	return rec;
}

static void _keystore_print_record(struct util_rec *rec,
				   const char *name,
				   struct properties *properties,
				   bool validation, const char *skey_filename,
				   size_t secure_key_size, bool is_xts,
				   size_t clear_key_bitsize, bool valid,
				   bool is_old_mk, bool reenc_pending, u8 *mkvp,
				   const char *pass_filename)
{
	char temp_vp[VERIFICATION_PATTERN_LEN + 2];
	char *kms_xts_key1_label = NULL;
	char *kms_xts_key2_label = NULL;
	char *kms_key_label = NULL;
	char *volumes_argz = NULL;
	size_t label_argz_len = 0;
	size_t volumes_argz_len;
	char *apqns_argz = NULL;
	char *label_argz = NULL;
	size_t sector_size = 0;
	size_t apqns_argz_len;
	char *description;
	char *volume_type;
	char *reencipher;
	char *key_type;
	char *creation;
	char *volumes;
	char *change;
	char *apqns;
	char *temp;
	char *kms;
	char *vp;
	int len;

	description = properties_get(properties, PROP_NAME_DESCRIPTION);
	volumes = properties_get(properties, PROP_NAME_VOLUMES);
	if (volumes != NULL)
		util_assert(argz_create_sep(volumes, ',',
					    &volumes_argz,
					    &volumes_argz_len) == 0,
			    "Internal error: argz_create_sep failed");
	apqns = properties_get(properties, PROP_NAME_APQNS);
	if (apqns != NULL)
		util_assert(argz_create_sep(apqns, ',',
					    &apqns_argz,
					    &apqns_argz_len) == 0,
			    "Internal error: argz_create_sep failed");

	temp = properties_get(properties, PROP_NAME_SECTOR_SIZE);
	if (temp != NULL) {
		util_assert(sscanf(temp, "%lu", &sector_size) == 1,
			   "Internal error: sscanf failed");
		free(temp);
	}

	creation = properties_get(properties, PROP_NAME_CREATION_TIME);
	change = properties_get(properties, PROP_NAME_CHANGE_TIME);
	reencipher = properties_get(properties, PROP_NAME_REENC_TIME);
	vp = properties_get(properties, PROP_NAME_KEY_VP);
	volume_type = _keystore_get_volume_type(properties);
	key_type = properties_get(properties, PROP_NAME_KEY_TYPE);
	if (_keystore_is_kms_bound_key(properties, &kms)) {
		if (is_xts) {
			kms_xts_key1_label = properties_get(properties,
					PROP_NAME_KMS_XTS_KEY1_LABEL);
			kms_xts_key2_label = properties_get(properties,
					PROP_NAME_KMS_XTS_KEY2_LABEL);

			if (kms_xts_key1_label != NULL &&
			    kms_xts_key2_label != NULL) {
				label_argz_len = util_asprintf(&label_argz,
					 "%s%c%s", kms_xts_key1_label, '\0',
					 kms_xts_key2_label) + 1;
			}
		} else {
			kms_key_label = properties_get(properties,
					PROP_NAME_KMS_KEY_LABEL);

			if (kms_key_label != NULL) {
				label_argz = kms_key_label;
				label_argz_len = strlen(label_argz) + 1;
				kms_key_label = NULL;
			}
		}
	}

	util_rec_set(rec, REC_KEY, name);
	if (validation)
		util_rec_set(rec, REC_STATUS, valid ? "Valid" : "Invalid");
	util_rec_set(rec, REC_DESCRIPTION,
		     description != NULL ? description : "");
	util_rec_set(rec, REC_SEC_KEY_SIZE, "%lu bytes", secure_key_size);
	if ((!validation || valid) && clear_key_bitsize != 0)
		util_rec_set(rec, REC_CLR_KEY_SIZE, "%lu bits",
			     clear_key_bitsize);
	else
		util_rec_set(rec, REC_CLR_KEY_SIZE, "(unknown)");
	util_rec_set(rec, REC_XTS, is_xts ? "Yes" : "No");
	util_rec_set(rec, REC_KEY_TYPE, key_type);
	if (validation) {
		if (valid)
			util_rec_set(rec, REC_MASTERKEY,
				     "%s master key (MKVP: %s)",
				     is_old_mk ? "OLD" : "CURRENT",
				     printable_mkvp(
					 get_card_type_for_keytype(key_type),
					 mkvp));
		else
			util_rec_set(rec, REC_MASTERKEY,
				     "(unknown, MKVP: %s)",
				     printable_mkvp(
					 get_card_type_for_keytype(key_type),
					 mkvp));
	}
	if (volumes_argz != NULL)
		util_rec_set_argz(rec, REC_VOLUMES, volumes_argz,
				  volumes_argz_len);
	else
		util_rec_set(rec, REC_VOLUMES, "(none)");
	if (apqns_argz != NULL)
		util_rec_set_argz(rec, REC_APQNS,
				  apqns_argz, apqns_argz_len);
	else
		util_rec_set(rec, REC_APQNS, "(none)");
	util_rec_set(rec, REC_KEY_FILE, skey_filename);
	if (sector_size == 0)
		util_rec_set(rec, REC_SECTOR_SIZE, "(system default)");
	else
		util_rec_set(rec, REC_SECTOR_SIZE, "%lu bytes",
			     sector_size);
	util_rec_set(rec, REC_VOLUME_TYPE, volume_type);
	if (vp != NULL) {
		len = sprintf(temp_vp, "%.*s%c%.*s",
			      VERIFICATION_PATTERN_LEN / 2, vp,
			      '\0', VERIFICATION_PATTERN_LEN / 2,
			      &vp[VERIFICATION_PATTERN_LEN / 2]);
		util_rec_set_argz(rec, REC_KEY_VP, temp_vp, len + 1);
	} else {
		util_rec_set(rec, REC_KEY_VP, "(not available)");
	}
	util_rec_set(rec, REC_KMS, kms != NULL ? kms : "(local)");
	if (kms != NULL && label_argz != NULL)
		util_rec_set_argz(rec, REC_KMS_KEY_LABEL, label_argz,
				  label_argz_len);
	else
		util_rec_set(rec, REC_KMS_KEY_LABEL, "(local)");
	if (pass_filename != NULL)
		util_rec_set(rec, REC_PASSPHRASE_FILE, pass_filename);
	else
		util_rec_set(rec, REC_PASSPHRASE_FILE, "(none)");
	util_rec_set(rec, REC_CREATION_TIME, creation);
	util_rec_set(rec, REC_CHANGE_TIME,
		     change != NULL ? change : "(never)");
	util_rec_set(rec, REC_REENC_TIME, "%s %s",
		     reencipher != NULL ? reencipher : "(never)",
		     reenc_pending ? "(re-enciphering pending)" : "");

	util_rec_print(rec);

	if (description != NULL)
		free(description);
	if (volumes != NULL)
		free(volumes);
	if (volumes_argz != NULL)
		free(volumes_argz);
	if (apqns != NULL)
		free(apqns);
	if (apqns_argz != NULL)
		free(apqns_argz);
	if (creation != NULL)
		free(creation);
	if (change != NULL)
		free(change);
	if (reencipher != NULL)
		free(reencipher);
	if (vp != NULL)
		free(vp);
	if (volume_type != NULL)
		free(volume_type);
	if (key_type != NULL)
		free(key_type);
	if (kms != NULL)
		free(kms);
	if (kms_key_label != NULL)
		free(kms_key_label);
	if (kms_xts_key1_label != NULL)
		free(kms_xts_key1_label);
	if (kms_xts_key2_label != NULL)
		free(kms_xts_key2_label);
	if (label_argz != NULL)
		free(label_argz);
}

struct validate_info {
	struct util_rec *rec;
	int pkey_fd;
	bool noapqncheck;
	unsigned long int num_valid;
	unsigned long int num_invalid;
	unsigned long int num_warnings;
};

/**
 * Displays the status of the associated APQNs.
 *
 * @param[in] keystore the key store
 * @param[in] properties  the properties of the key
 * @param[in] mkvp        the master key verification pattern of the key
 *
 * @returns 0 in case of success, 1 if at least one of the APQNs is not
 *          available or has a master key mismatch
 */
static int _keystore_display_apqn_status(struct keystore *keystore,
					 struct properties *properties,
					 u8 *mkvp)
{
	int rc, warning = 0;
	char *apqns;
	char *key_type;

	apqns = properties_get(properties, PROP_NAME_APQNS);
	if (apqns == NULL)
		return 0;

	key_type = properties_get(properties, PROP_NAME_KEY_TYPE);
	rc = cross_check_apqns(apqns, mkvp,
			       get_min_card_level_for_keytype(key_type),
			       get_min_fw_version_for_keytype(key_type),
			       get_card_type_for_keytype(key_type), true,
			       keystore->verbose);
	if (rc != 0 && rc != -ENOTSUP)
		warning = 1;

	if (warning)
		printf("\n");

	free(apqns);
	free(key_type);
	return warning;
}
/**
 * Displays the status of the associated volumes.
 *
 * @param[in] properties  the properties of the key
 * @param[in] name        the name of the key
 *
 * @returns 0 in case of success, 1 if at least one of the volumes is not
 *          available
 */
static int _keystore_display_volume_status(struct properties *properties,
					   const char *name)
{
	int i, warning = 0;
	char **volume_list;
	char *volumes;
	char *ch;

	volumes = properties_get(properties, PROP_NAME_VOLUMES);
	if (volumes == NULL)
		return 0;
	volume_list = str_list_split(volumes);

	for (i = 0; volume_list[i] != NULL; i++) {

		ch = strchr(volume_list[i], ':');
		if (ch != NULL)
			*ch = '\0';

		if (!_keystore_is_block_device(volume_list[i])) {
			printf("WARNING: The volume '%s' associated with "
			       "key '%s' is not available\n", volume_list[i],
			       name);
			warning = 1;
		}
	}

	if (warning)
		printf("\n");

	free(volumes);
	str_list_free_string_array(volume_list);
	return warning;
}

/**
 * Processing function for the key validate function. Prints validation
 * information for the key to be validated.
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] properties the properties object of the key
 * @param[in] file_names the file names used by this key
 * @param[in] private    private data: struct validate_info
 *
 * @returns 0 if the validation is successful, a negative errno value otherwise
 */
static int _keystore_process_validate(struct keystore *keystore,
				      const char *name,
				      struct properties *properties,
				      struct key_filenames *file_names,
				      void *private)
{
	struct validate_info *info = (struct validate_info *)private;
	char **apqn_list = NULL;
	size_t clear_key_bitsize;
	size_t secure_key_size;
	u8 mkvp[MKVP_LENGTH];
	char *apqns = NULL;
	u8 *secure_key = NULL;
	int is_old_mk;
	int rc, valid;

	rc = _keystore_ensure_keyfiles_exist(file_names, name);
	if (rc != 0)
		goto out;

	secure_key = read_secure_key(file_names->skey_filename,
				     &secure_key_size, keystore->verbose);
	if (secure_key == NULL) {
		rc = -ENOENT;
		goto out;
	}

	apqns = properties_get(properties, PROP_NAME_APQNS);
	if (apqns != NULL)
		apqn_list = str_list_split(apqns);

	rc = validate_secure_key(info->pkey_fd, secure_key, secure_key_size,
				 &clear_key_bitsize, &is_old_mk,
				 (const char **)apqn_list, keystore->verbose);
	if (rc != 0) {
		valid = 0;
		info->num_invalid++;
		rc = 0;
	} else {
		info->num_valid++;
		valid = 1;
	}

	rc = get_master_key_verification_pattern(secure_key, secure_key_size,
						 mkvp, keystore->verbose);
	if (rc != 0)
		goto out;

	_keystore_print_record(info->rec, name, properties, 1,
			       file_names->skey_filename, secure_key_size,
			       is_xts_key(secure_key, secure_key_size),
			       clear_key_bitsize, valid, is_old_mk,
			       _keystore_reencipher_key_exists(file_names),
			       mkvp,
			       _keystore_passphrase_file_exists(file_names) ?
					file_names->pass_filename : NULL);

	if (valid && is_old_mk) {
		util_print_indented("WARNING: The secure key is currently "
				    "enciphered with the OLD master key. "
				    "To mitigate the danger of data loss "
				    "re-encipher it with the CURRENT "
				    "master key\n", 0);
		info->num_warnings++;
	}
	if (info->noapqncheck == 0)
		if (_keystore_display_apqn_status(keystore, properties,
						  mkvp) != 0)
			info->num_warnings++;
	if (_keystore_display_volume_status(properties, name) != 0)
		info->num_warnings++;

out:
	if (secure_key != NULL)
		free(secure_key);
	if (apqns != NULL)
		free(apqns);
	if (apqn_list != NULL)
		str_list_free_string_array(apqn_list);
	if (rc != 0)
		pr_verbose(keystore, "Failed to validate key '%s': %s",
			   name, strerror(-rc));
	return rc;
}

/**
 * Validates one or multiple keys in the keystore
 *
 * @param[in] keystore the key store
 * @param[in] name_filter  the name filter to select the key (can be NULL)
 * @param[in] apqn_filter  the APQN filter to select the key (can be NULL)
 * @param[in] noapqncheck if true, the specified APQN(s) are not checked for
 *                        existence and type.
 * @param[in] pkey_fd     the file descriptor of /dev/pkey
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_validate_key(struct keystore *keystore, const char *name_filter,
			  const char *apqn_filter, bool noapqncheck,
			  int pkey_fd)
{
	struct validate_info info;
	struct util_rec *rec;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	rec = _keystore_setup_record(1);

	info.pkey_fd = pkey_fd;
	info.noapqncheck = noapqncheck;
	info.rec = rec;
	info.num_valid = 0;
	info.num_invalid = 0;
	info.num_warnings = 0;

	rc = _keystore_process_filtered(keystore, name_filter, NULL,
					apqn_filter, NULL, NULL, false, false,
					_keystore_process_validate, &info);

	util_rec_free(rec);

	if (rc != 0) {
		pr_verbose(keystore, "Failed to validate keys: %s",
			   strerror(-rc));
	} else {
		pr_verbose(keystore, "Successfully validated keys");
		printf("%lu keys are valid, %lu keys are invalid, %lu "
		       "warnings\n", info.num_valid, info.num_invalid,
		       info.num_warnings);
	}
	return rc;
}

struct reencipher_params {
	bool from_old;
	bool to_new;
	bool complete;
	int inplace; /* -1 = autodetect, 0 = not in-place, 1 = in-place */
};

struct reencipher_info {
	struct reencipher_params params;
	int pkey_fd;
	struct ext_lib *lib;
	unsigned long num_reenciphered;
	unsigned long num_failed;
	unsigned long num_skipped;
};

/**
 * Perform the reencipherment of a key
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] lib        the external library struct
 * @param[in] params     reenciphering parameters
 * @param[in] secure_key a buffer containing the secure key
 * @param[in] secure_key_size the size of the secure key
 * @param[in] is_old_mk  if true the key is currently re-enciphered with the
 *            OLD master key
 * @param[in] apqns      the associated APQNs (or NULL if none)
 * @returns 0 if the re-enciphering is successful, a negative errno value
 *          otherwise, 1 if it was skipped
 */
static int _keystore_perform_reencipher(struct keystore *keystore,
					const char *name,
					struct ext_lib *lib,
					struct reencipher_params *params,
					u8 *secure_key, size_t secure_key_size,
					bool is_old_mk, const char *apqns)
{
	bool selected;
	int rc;

	if (!params->from_old && !params->to_new) {
		/* Autodetect reencipher mode */
		if (is_old_mk) {
			params->from_old = 1;
			util_print_indented("The secure key is currently "
					    "enciphered with the OLD "
					    "master key and is being "
					    "re-enciphered with the CURRENT "
					    "master key\n", 0);
		} else {
			params->to_new = 1;
			util_print_indented("The secure key is currently "
					    "enciphered with the CURRENT "
					    "master key and is being "
					    "re-enciphered with the NEW "
					    "master key\n", 0);
		}
	}

	if (params->from_old) {
		if (params->inplace == -1)
			params->inplace = 1;

		pr_verbose(keystore,
			   "Secure key '%s' will be re-enciphered from OLD "
			   "to the CURRENT master key", name);

		rc = reencipher_secure_key(lib, secure_key, secure_key_size,
					   apqns, REENCIPHER_OLD_TO_CURRENT,
					   &selected, keystore->verbose);
		if (rc != 0) {
			if (rc == -ENODEV) {
				warnx("No APQN found that is suitable for "
				      "re-enciphering this secure AES key");
			} else {
				warnx("Failed to re-encipher '%s' from OLD to "
				      "CURRENT master key", name);
				if (!selected &&
				    !is_ep11_aes_key(secure_key,
						     secure_key_size))
					print_msg_for_cca_envvars(
							"secure AES key");
			}
			return rc;
		}
	}
	if (params->to_new) {
		pr_verbose(keystore,
			   "Secure key '%s' will be re-enciphered from "
			   "CURRENT to the NEW master key", name);

		if (params->inplace == -1)
			params->inplace = 0;

		rc = reencipher_secure_key(lib, secure_key, secure_key_size,
					   apqns, REENCIPHER_CURRENT_TO_NEW,
					   &selected, keystore->verbose);
		if (rc != 0) {
			if (rc == -ENODEV) {
				warnx("No APQN found that is suitable for "
				      "re-enciphering this secure AES key and "
				      "has the NEW master key loaded");
			} else {
				warnx("Failed to re-encipher '%s' from CURRENT "
				      "to NEW master key", name);
				if (!selected &&
				    !is_ep11_aes_key(secure_key,
						     secure_key_size))
					print_msg_for_cca_envvars(
							"secure AES key");
			}
			return rc;
		}
	}

	return 0;
}

/**
 * Processing function for the key re-enciphering function.
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] properties the properties object of the key (not used here)
 * @param[in] file_names the file names used by this key
 * @param[in] private    private data: struct reencipher_info
 *
 * @returns 0 if the re-enciphering is successful, a negative errno value
 *          otherwise
 */
static int _keystore_process_reencipher(struct keystore *keystore,
					const char *name,
					struct properties *properties,
					struct key_filenames *file_names,
					void *private)
{
	struct reencipher_info *info = (struct reencipher_info *)private;
	struct reencipher_params params = info->params;
	size_t clear_key_bitsize;
	size_t secure_key_size;
	char **apqn_list = NULL;
	u8 *secure_key = NULL;
	char *apqns = NULL;
	char *out_file;
	int is_old_mk;
	char *temp;
	int rc;

	rc = _keystore_ensure_keyfiles_exist(file_names, name);
	if (rc != 0)
		goto out;

	pr_verbose(keystore, "Complete reencipher: %d", params.complete);
	pr_verbose(keystore, "In-place reencipher: %d", params.inplace);

	if (params.complete) {
		if (!_keystore_reencipher_key_exists(file_names)) {
			warnx("Staged re-enciphering is not pending for key "
			      "'%s', skipping",
			      name);
			info->num_skipped++;
			rc = 0;
			goto out;
		}

		printf("Completing re-enciphering for key '%s'\n", name);

		params.inplace = 1;
	}

	secure_key = read_secure_key(params.complete ?
						file_names->renc_filename :
						file_names->skey_filename,
				     &secure_key_size, keystore->verbose);
	if (secure_key == NULL) {
		rc = -ENOENT;
		goto out;
	}

	apqns = properties_get(properties, PROP_NAME_APQNS);
	if (apqns != NULL)
		apqn_list = str_list_split(apqns);

	rc = validate_secure_key(info->pkey_fd, secure_key, secure_key_size,
				 &clear_key_bitsize, &is_old_mk,
				 (const char **)apqn_list, keystore->verbose);
	if (rc != 0) {
		if (params.complete) {
			warnx("Key '%s' is not valid, re-enciphering is not "
			      "completed", name);
			warnx("The new master key might yet have to be set "
			      "as the CURRENT master key.");
		} else {
			warnx("Key '%s' is not valid, it is not re-enciphered",
			      name);
			info->num_skipped++;
			rc = 0;
		}
		goto out;
	}

	if (!params.complete) {
		printf("Re-enciphering key '%s'\n", name);

		rc = _keystore_perform_reencipher(keystore, name, info->lib,
						  &params, secure_key,
						  secure_key_size, is_old_mk,
						  apqns);
		if (rc < 0)
			goto out;
		if (rc > 0) {
			info->num_skipped++;
			rc = 0;
			goto out;
		}
	}

	pr_verbose(keystore, "In-place reencipher: %d", params.inplace);

	out_file = params.inplace == 1 ? file_names->skey_filename :
					 file_names->renc_filename;
	rc = write_secure_key(out_file, secure_key,
			      secure_key_size, keystore->verbose);
	if (rc != 0)
		goto out;

	if (params.complete || params.inplace == 1) {
		rc = _keystore_set_timestamp_property(properties,
						      PROP_NAME_REENC_TIME);
		if (rc != 0)
			goto out;

		rc = _keystore_ensure_vp_exists(keystore, file_names,
						properties);
		if (rc != 0) {
			warnx("Failed to generate the key verification pattern "
			      "for key '%s': %s", file_names->skey_filename,
			      strerror(-rc));
			warnx("Make sure that kernel module 'paes_s390' is loaded and "
			      "that the 'paes' cipher is available");
			goto out;
		}

		rc = properties_save(properties, file_names->info_filename, 1);
		if (rc != 0) {
			pr_verbose(keystore,
				   "Failed to write key info file '%s': %s",
				   file_names->info_filename, strerror(-rc));
			goto out;
		}

		util_asprintf(&temp, "The following LUKS2 volumes are "
			      "encrypted with key '%s'. You should also "
			      "re-encipher the volume key of those volumes "
			      "using command 'zkey-cryptsetup reencipher "
			      "<device>':", name);
		_keystore_msg_for_volumes(temp, properties, VOLUME_TYPE_LUKS2);
		free(temp);
	}

	if (params.complete ||
	    (params.inplace && _keystore_reencipher_key_exists(file_names))) {
		if (remove(file_names->renc_filename) != 0) {
			rc = -errno;
			pr_verbose(keystore, "Failed to remove '%s': %s",
				   file_names->renc_filename, strerror(-rc));
			goto out;
		}
	}

	if (params.inplace != 1) {
		util_asprintf(&temp, "Staged re-enciphering is initiated for "
			      "key '%s'. After the NEW master key has been "
			      "set to become the CURRENT master key run "
			      "'zkey reencipher' with option '--complete' to "
			      "complete the re-enciphering process", name);
		util_print_indented(temp, 0);
		free(temp);
	}

	info->num_reenciphered++;

out:
	if (apqns != NULL)
		free(apqns);
	if (apqn_list != NULL)
		str_list_free_string_array(apqn_list);
	if (secure_key != NULL)
		free(secure_key);

	printf("\n");

	if (rc != 0) {
		info->num_failed++;
		pr_verbose(keystore, "Failed to re-encipher key '%s': %s",
			   name, strerror(-rc));
		rc = 0;
	}
	return rc;
}

/**
 * Reenciphers a key in the keystore
 *
 * @param[in] keystore the key store
 * @param[in] name_filter  the name filter to select the key (can be NULL)
 * @param[in] apqn_filter  the APQN filter to seletc the key (can be NULL)
 * @param[in] from_old     If true the key is reenciphered from the OLD to the
 *                         CURRENT master key.
 * @param[in] to_new       If true the key is reenciphered from the CURRENT to
 *                         the OLD master key.
 * @param[in] inplace      if true, the key will be re-enciphere in-place
 * @param[in] staged       if true, the key will be re-enciphere not in-place
 * @param[in] complete     if true, a pending re-encipherment is completed
 * @param[in] pkey_fd      the file descriptor of /dev/pkey
 * @param[in] lib          the external library struct
 * Note: if both fromOld and toNew are FALSE, then the reencipherement mode is
 *       detected automatically. If both are TRUE then the key is reenciphered
 *       from the OLD to the NEW master key.
 * Note: if both inplace and staged are FLASE, then the key is re-enciphered
 *       inplace when for OLD-to-CURRENT, and is reenciphered staged for
 *       CURRENT-to-NEW.
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_reencipher_key(struct keystore *keystore, const char *name_filter,
			    const char *apqn_filter,
			    bool from_old, bool to_new, bool inplace,
			    bool staged, bool complete, int pkey_fd,
			    struct ext_lib *lib)
{
	struct reencipher_info info;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	info.params.from_old = from_old;
	info.params.to_new = to_new;
	info.params.inplace = -1;
	if (inplace)
		info.params.inplace = 1;
	if  (staged)
		info.params.inplace = 0;
	info.params.complete = complete;
	info.pkey_fd = pkey_fd;
	info.lib = lib;
	info.num_failed = 0;
	info.num_reenciphered = 0;
	info.num_skipped = 0;

	rc = _keystore_process_filtered(keystore, name_filter, NULL,
					apqn_filter, NULL, NULL, false, false,
					_keystore_process_reencipher, &info);

	if (rc != 0) {
		pr_verbose(keystore, "Failed to re-encipher keys: %s",
			   strerror(-rc));
	} else {
		pr_verbose(keystore, "Successfully re-enciphered keys");
		printf("%lu keys re-enciphered, %lu keys skipped, %lu keys "
		       "failed to re-encipher\n",
		       info.num_reenciphered, info.num_skipped,
		       info.num_failed);
		if (info.num_failed > 0)
			rc = -EIO;
	}
	return rc;
}

/**
 * Copies (duplicates) a key in the keystore. Any existing volume associations
 * are removed from the copy, because a volume can only be associated to one
 * key. However, you can set new volume associations using the volumes
 * parameter.
 *
 * @param[in] keystore the key store
 * @param[in] name     the name of the key
 * @param[in] newname  the new name of the key
 * @param[in] volumes  a comma separated list of volumes associated with this
 *                     key (optional, can be NULL)
 * @param[in] local    if true copy a KMS-bound key to a local one
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_copy_key(struct keystore *keystore, const char *name,
		      const char *newname, const char *volumes, bool local)
{
	struct volume_check vol_check = { .keystore = keystore, .name = newname,
					  .set = 0, .nocheck = 0 };
	struct key_filenames file_names = { 0 };
	struct key_filenames new_names = { 0 };
	struct properties *key_prop = NULL;
	size_t secure_key_size;
	bool kms_bound = false;
	u8 *secure_key;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");
	util_assert(newname != NULL, "Internal error: newname is NULL");

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out;

	rc = _keystore_ensure_keyfiles_exist(&file_names, name);
	if (rc != 0)
		goto out;

	rc = _keystore_get_key_filenames(keystore, newname, &new_names);
	if (rc != 0)
		goto out;

	rc = _keystore_ensure_keyfiles_not_exist(&new_names, newname);
	if (rc != 0)
		goto out;

	key_prop = properties_new();
	rc = properties_load(key_prop, file_names.info_filename, 1);
	if (rc != 0) {
		warnx("Key '%s' does not exist or is invalid", name);
		goto out;
	}

	kms_bound = _keystore_is_kms_bound_key(key_prop, NULL);
	if (kms_bound && !local) {
		rc = -EINVAL;
		warnx("Copying a KMS-bound key requires the "
		      "'--local|-L' option");
		goto out;
	}

	secure_key = read_secure_key(file_names.skey_filename,
				     &secure_key_size, keystore->verbose);
	if (secure_key == NULL) {
		rc = -ENOENT;
		goto out;
	}

	rc = write_secure_key(new_names.skey_filename, secure_key,
			      secure_key_size, keystore->verbose);
	free(secure_key);
	if (rc != 0)
		goto out;

	rc = _keystore_set_file_permission(keystore, new_names.skey_filename);
	if (rc != 0)
		goto out;

	/*
	 * Remove any volume association, since a volume can only be associated
	 * with one key
	 */
	rc = properties_set(key_prop, PROP_NAME_VOLUMES, "");
	if (rc != 0)
		goto out;

	if (volumes != NULL) {
		rc = _keystore_change_association(key_prop, PROP_NAME_VOLUMES,
						  volumes,
						  "volume",
						  _keystore_volume_check,
						  &vol_check);
		if (rc != 0)
			goto out;
	}

	rc = properties_remove(key_prop, PROP_NAME_CHANGE_TIME);
	if (rc != 0 && rc != -ENOENT)
		goto out;

	rc = properties_remove(key_prop, PROP_NAME_REENC_TIME);
	if (rc != 0 && rc != -ENOENT)
		goto out;

	rc = _keystore_set_timestamp_property(key_prop,
					      PROP_NAME_CREATION_TIME);
	if (rc != 0)
		goto out;

	if (kms_bound) {
		rc = _keystore_kms_key_unbind(keystore, key_prop);
		if (rc != 0)
			goto out;
	}

	rc = properties_save(key_prop, new_names.info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   new_names.info_filename, strerror(-rc));
		goto out;
	}

	rc = _keystore_set_file_permission(keystore, new_names.info_filename);
	if (rc != 0)
		goto out;

	if (_keystore_passphrase_file_exists(&file_names)) {
		rc = copy_file(file_names.skey_filename,
			       new_names.pass_filename, 0);
		if (rc != 0) {
			pr_verbose(keystore,
				   "Passphrase file '%s' could not be copied: "
				   "%s", new_names.pass_filename,
				   strerror(-rc));
			goto out;
		}

		rc = _keystore_set_file_permission(keystore,
						   file_names.pass_filename);
		if (rc != 0)
			goto out;
	}

	pr_verbose(keystore, "Successfully copied key '%s' to '%s'", name,
		   newname);

out:
	if (rc != 0) {
		remove(new_names.skey_filename);
		remove(new_names.info_filename);
		remove(new_names.pass_filename);
	}

	_keystore_free_key_filenames(&file_names);
	_keystore_free_key_filenames(&new_names);
	if (key_prop != NULL)
		properties_free(key_prop);

	if (rc != 0)
		pr_verbose(keystore, "Failed to copy key '%s'to '%s': %s",
			   name, newname, strerror(-rc));
	return rc;
}

/**
 * Exports a key from the keystore to a file
 *
 * @param[in] keystore the key store
 * @param[in] name     the name of the key
 * @param[in] export_file the name of the file to export the key to
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_export_key(struct keystore *keystore, const char *name,
			const char *export_file)
{
	struct key_filenames file_names = { 0 };
	size_t secure_key_size;
	u8 *secure_key;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");
	util_assert(export_file != NULL, "Internal error: export_file is NULL");

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out;

	rc = _keystore_ensure_keyfiles_exist(&file_names, name);
	if (rc != 0)
		goto out;

	secure_key = read_secure_key(file_names.skey_filename,
				     &secure_key_size, keystore->verbose);
	if (secure_key == NULL) {
		rc = -ENOENT;
		goto out;
	}

	rc = write_secure_key(export_file, secure_key,
			      secure_key_size, keystore->verbose);
	free(secure_key);

	pr_verbose(keystore, "Successfully exported key '%s' to '%s'", name,
		   export_file);

out:
	_keystore_free_key_filenames(&file_names);

	if (rc != 0)
		pr_verbose(keystore, "Failed to export key '%s': %s",
			   name, strerror(-rc));
	return rc;
}

/**
 * Prompts the user to confirm deletion of a key
 *
 * @param[in] keystore the key store
 * @param[in] name     the name of the key
 * @param[in] file_names the file names of the key
 *
 * @returnd 0 if the user confirmed the deletion, a negative errno value
 *          otherwise
 */
static int _keystore_prompt_for_remove(struct keystore *keystore,
				       const char *name,
				       struct key_filenames *file_names)
{
	struct properties *key_prop;
	char *msg;
	int rc;

	key_prop = properties_new();
	rc = properties_load(key_prop, file_names->info_filename, 1);
	if (rc != 0) {
		warnx("Key '%s' does not exist or is invalid", name);
		goto out;
	}

	util_asprintf(&msg, "When you remove key '%s' the following volumes "
		      "will no longer be usable:", name);
	_keystore_msg_for_volumes(msg, key_prop, VOLUME_TYPE_PLAIN);
	free(msg);

	printf("%s: Remove key '%s' [y/N]? ", program_invocation_short_name,
	       name);
	if (!prompt_for_yes(keystore->verbose)) {
		warnx("Operation aborted");
		rc = -ECANCELED;
		goto out;
	}

out:
	properties_free(key_prop);
	return rc;
}

/**
 * Removes a key from the keystore
 *
 * @param[in] keystore the key store
 * @param[in] name     the name of the key
 * @param[in] quiet    if true no confirmation prompt is shown
 * @param[in] kms_options an array of KMS options specified, or NULL if no
 *                     KMS options have been specified
 * @param[in] num_kms_options the number of options in above array
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_remove_key(struct keystore *keystore, const char *name,
			bool quiet, struct kms_option *kms_options,
			size_t num_kms_options)
{
	struct key_filenames file_names = { 0 };
	struct properties *key_props = NULL;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out;

	rc = _keystore_ensure_keyfiles_exist(&file_names, name);
	if (rc != 0)
		goto out;

	if (!quiet) {
		if (_keystore_prompt_for_remove(keystore, name,
						&file_names) != 0)
			goto out;
	}

	key_props = properties_new();
	rc = properties_load(key_props, file_names.info_filename, 1);
	if (rc != 0) {
		warnx("Key '%s' does not exist or is invalid", name);
		goto out;
	}

	if (_keystore_is_kms_bound_key(key_props, NULL)) {
		rc = perform_kms_login(keystore->kms_info, keystore->verbose);
		if (rc != 0)
			goto out;

		rc = remove_kms_key(keystore->kms_info, key_props,
				    kms_options, num_kms_options,
				    keystore->verbose);

		if (rc != 0) {
			warnx("KMS plugin '%s' failed to remove key '%s': %s",
			      keystore->kms_info->plugin_name, name,
			      strerror(-rc));
			print_last_kms_error(keystore->kms_info);
			goto out;
		}
	}

	if (remove(file_names.skey_filename) != 0) {
		rc = -errno;
		pr_verbose(keystore, "Failed to remove '%s': %s",
			   file_names.skey_filename, strerror(-rc));
		goto out;
	}
	if (remove(file_names.info_filename) != 0) {
		rc = -errno;
		pr_verbose(keystore, "Failed to remove '%s': %s",
			   file_names.info_filename, strerror(-rc));
	}
	if (_keystore_reencipher_key_exists(&file_names)) {
		if (remove(file_names.renc_filename) != 0) {
			rc = -errno;
			pr_verbose(keystore, "Failed to remove '%s': %s",
				   file_names.renc_filename, strerror(-rc));
		}
	}
	if (_keystore_passphrase_file_exists(&file_names)) {
		if (remove(file_names.pass_filename) != 0) {
			rc = -errno;
			pr_verbose(keystore, "Failed to remove '%s': %s",
				   file_names.pass_filename, strerror(-rc));
		}
	}
	pr_verbose(keystore, "Successfully removed key '%s'", name);

out:
	_keystore_free_key_filenames(&file_names);
	if (key_props != NULL)
		properties_free(key_props);

	if (rc != 0)
		pr_verbose(keystore, "Failed to remove key '%s': %s",
			   name, strerror(-rc));
	return rc;
}

/**
 * Processing function for the key display function.
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] properties the properties object of the key
 * @param[in] file_names the file names used by this key
 * @param[in] private    private data: struct reencipher_info
 *
 * @returns 0 if the display is successful, a negative errno value otherwise
 */
static int _keystore_display_key(struct keystore *keystore,
				 const char *name,
				 struct properties *properties,
				 struct key_filenames *file_names,
				 void *private)
{
	struct util_rec *rec = (struct util_rec *)private;
	u8 *secure_key;
	size_t secure_key_size, clear_key_bitsize = 0;
	int rc = 0;

	secure_key = read_secure_key(file_names->skey_filename,
				     &secure_key_size, keystore->verbose);
	if (secure_key == NULL)
		return -EIO;

	if (secure_key_size < MIN_SECURE_KEY_SIZE) {
		pr_verbose(keystore,
			   "Size of secure key is too small: %lu expected %lu",
			   secure_key_size, MIN_SECURE_KEY_SIZE);
		rc = -EIO;
		goto out;
	}

	get_key_bit_size(secure_key, secure_key_size, &clear_key_bitsize);

	_keystore_print_record(rec, name, properties, 0,
			       file_names->skey_filename, secure_key_size,
			       is_xts_key(secure_key, secure_key_size),
			       clear_key_bitsize, 0, 0,
			       _keystore_reencipher_key_exists(file_names),
			       NULL,
			       _keystore_passphrase_file_exists(file_names) ?
					file_names->pass_filename : NULL);

out:
	free(secure_key);
	return rc;
}

/**
 * Lists keys in the keystore that matches the filters
 *
 * @param[in] keystore the key store
 * @param[in] name_filter    the name filter. Can contain wild cards.
 *                           NULL means no name filter.
 * @param[in] volume_filter  the volume filter. Can contain wild cards, and
 *                           mutliple volume filters separated by commas.
 *                           The ':dm-name' part of the volume is optional
 *                           for the volume filter. If not specified, the filter
 *                           checks the volume part only.
 *                           NULL means no volume filter.
 * @param[in] apqn_filter    the APQN filter. Can contain wild cards, and
 *                           mutliple APQN filters separated by commas.
 *                           NULL means no APQN filter.
 * @param[in] volume_type    The volume type. NULL means no volume type filter.
 * @param[in] key_type       The key type. NULL means no key type filter.
 * @param[in] local          if true, only local keys are listed
 * @param[in] kms_bound      if true, only KMS-bound keys are listed
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_list_keys(struct keystore *keystore, const char *name_filter,
		       const char *volume_filter, const char *apqn_filter,
		       const char *volume_type, const char *key_type,
		       bool local, bool kms_bound)
{
	struct util_rec *rec;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	if (volume_type != NULL &&
	    !_keystore_valid_volume_type(volume_type)) {
		warnx("Invalid volume-type specified");
		return -EINVAL;
	}

	if (key_type != NULL &&
	    !_keystore_valid_key_type(key_type)) {
		warnx("Invalid key-type specified");
		return -EINVAL;
	}

	rec = _keystore_setup_record(0);

	rc = _keystore_process_filtered(keystore, name_filter, volume_filter,
					apqn_filter, volume_type, key_type,
					local, kms_bound,
					_keystore_display_key, rec);
	util_rec_free(rec);

	if (rc != 0)
		pr_verbose(keystore, "Failed to list keys: %s",
			   strerror(-rc));
	else
		pr_verbose(keystore, "Successfully listed keys");
	return rc;
}

/**
 * Executes a command via system().
 *
 * @param[in] cmd        the command to execute
 * @param[in] msg_cmd    the short command name (for messages)
 *
 * @returns the exit code of the command execution, or -1 in case of an error
 */
static int _keystore_execute_cmd(const char *cmd,
				 const char *msg_cmd)
{
	int rc;

	rc = setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
	if (rc < 0)
		return rc;

	rc = system(cmd);
	if (WIFEXITED(rc)) {
		rc = WEXITSTATUS(rc);
		if (rc != 0)
			printf("%s exit code: %d\n", msg_cmd, rc);
	} else {
		rc = -EIO;
		warnx("%s terminated abnormally", msg_cmd);
	}

	return rc;
}


struct crypt_info {
	bool execute;
	bool batch_mode;
	const char *keyfile;
	size_t keyfile_offset;
	size_t keyfile_size;
	size_t tries;
	bool open;
	bool format;
	char **volume_filter;
	int (*process_func)(struct keystore *keystore,
			    const char *volume,
			    const char *dmname,
			    const char *cipher_spec,
			    const char *key_file_name,
			    size_t key_file_size,
			    size_t sector_size,
			    const char *volume_type,
			    const char *passphrase_file,
			    struct crypt_info *info);
};

/**
 * Processing function for the cryptsetup function. Builds a cryptsetup command
 * line and optionally executes it.
 *
 * @param[in] keystore   the keystore (not used here)
 * @param[in] volume     the volume to mount
 * @param[in] dmname     the debice mapper name
 * @param[in] cipher_spec the cipher specification
 * @param[in] key_file_name the key file name
 * @param[in] key_file_size the size of the key file in bytes
 * @param[in] sector_size    the sector size in bytes or 0 if not specified
 * @param[in] volume_type the volume type
 * @param[in] passphrase_file the passphrase file name (can be NULL)
 * @param[in] info       processing info
 *
 * @returns 0 if successful, a negative errno value otherwise
 */
static int _keystore_process_cryptsetup(struct keystore *keystore,
					const char *volume,
					const char *dmname,
					const char *cipher_spec,
					const char *key_file_name,
					size_t key_file_size,
					size_t sector_size,
					const char *volume_type,
					const char *passphrase_file,
					struct crypt_info *info)
{
	char *keyfile_opt = NULL, *offset_opt = NULL;
	char *size_opt = NULL, *tries_opt = NULL;
	char *common_passphrase_options;
	size_t common_len;
	char temp[100];
	int rc = 0;
	char *cmd;

	sprintf(temp, "--sector-size %lu ", sector_size);

	if (info->keyfile) {
		util_asprintf(&keyfile_opt, "--key-file '%s' ", info->keyfile);
		if (info->keyfile_offset > 0)
			util_asprintf(&offset_opt, "--keyfile-offset %lu ",
				      info->keyfile_offset);
		if (info->keyfile_size > 0)
			util_asprintf(&size_opt, "--keyfile-size %lu ",
				      info->keyfile_size);
	} else if (passphrase_file != NULL) {
		util_asprintf(&keyfile_opt, "--key-file '%s' ",
			      passphrase_file);
	}
	if (info->tries > 0)
		util_asprintf(&tries_opt, "--tries %lu ", info->tries);
	util_asprintf(&common_passphrase_options, "%s%s%s%s",
		      keyfile_opt != NULL ? keyfile_opt : "",
		      offset_opt != NULL ? offset_opt : "",
		      size_opt != NULL ? size_opt : "",
		      tries_opt != NULL ? tries_opt : "");
	common_len = strlen(common_passphrase_options);
	free(keyfile_opt);
	free(offset_opt);
	free(size_opt);
	free(tries_opt);

	if (strcasecmp(volume_type, VOLUME_TYPE_PLAIN) == 0) {
		if (info->format)
			return 0;

		util_asprintf(&cmd,
			      "cryptsetup plainOpen %s%s--key-file '%s' "
			      "--key-size %lu --cipher %s %s%s %s",
			      info->batch_mode ? "-q " : "",
			      keystore->verbose ? "-v " : "", key_file_name,
			      key_file_size * 8, cipher_spec,
			      sector_size > 0 ? temp : "", volume, dmname);

		if (info->execute) {
			printf("Executing: %s\n", cmd);
			rc = _keystore_execute_cmd(cmd, "cryptsetup");
		} else {
			printf("%s\n", cmd);
		}
	} else if (strcasecmp(volume_type, VOLUME_TYPE_LUKS2) == 0) {
		if (info->open) {
			util_asprintf(&cmd,
				      "cryptsetup luksOpen %s%s%s%s %s",
				      info->batch_mode ? "-q " : "",
				      keystore->verbose ? "-v " : "",
				      common_len > 0 ?
						common_passphrase_options : "",
				      volume, dmname);

			if (info->execute) {
				printf("Executing: %s\n", cmd);
				rc = _keystore_execute_cmd(cmd, "cryptsetup");
			} else {
				printf("%s\n", cmd);
			}
		} else {
			/*
			 * Use PBKDF2 as key derivation function for LUKS2
			 * volumes. LUKS2 uses Argon2i as default, but this
			 * might cause out-of-memory errors when multiple LUKS2
			 * volumes are opened automatically via /etc/crypttab
			 */
			util_asprintf(&cmd,
				      "cryptsetup luksFormat %s%s--type luks2 "
				      "--master-key-file '%s' --key-size %lu "
				      "--cipher %s --pbkdf pbkdf2 %s%s%s",
				      info->batch_mode ? "-q " : "",
				      keystore->verbose ? "-v " : "",
				      key_file_name, key_file_size * 8,
				      cipher_spec, common_len > 0 ?
						common_passphrase_options : "",
				      sector_size > 0 ? temp : "", volume);

			if (info->execute) {
				printf("Executing: %s\n", cmd);
				rc = _keystore_execute_cmd(cmd, "cryptsetup");
			} else {
				printf("%s\n", cmd);
			}

			free(cmd);
			if (rc != 0)
				return rc;

			util_asprintf(&cmd,
				      "zkey-cryptsetup setvp %s %s%s", volume,
				      common_len > 0 ?
						common_passphrase_options : "",
				      keystore->verbose ? "-V" : "");

			if (info->execute) {
				printf("Executing: %s\n", cmd);
				rc = _keystore_execute_cmd(cmd,
							   "zkey-cryptsetup");
			} else {
				printf("%s\n", cmd);
			}
		}
	} else {
		return -EINVAL;
	}

	free(common_passphrase_options);
	free(cmd);
	return rc;
}

/**
 * Processing function for the crypttab function. Builds a crypttab entry
 * and prints it.
 *
 * @param[in] keystore   the keystore (not used here)
 * @param[in] volume     the volume to mount
 * @param[in] dmname     the debice mapper name
 * @param[in] cipher_spec the cipher specification
 * @param[in] key_file_name the key file name
 * @param[in] key_file_size the size of the key file in bytes
 * @param[in] sector_size the sector size in bytes or 0 if not specified
 * @param[in] volume_type the volume type
 * @param[in] passphrase_file the passphrase file name (can be NULL)
 * @param[in] info       processing info (not used here)
 *
 * @returns 0 if successful, a negative errno value otherwise
 */

static int _keystore_process_crypttab(struct keystore *UNUSED(keystore),
				      const char *volume,
				      const char *dmname,
				      const char *cipher_spec,
				      const char *key_file_name,
				      size_t key_file_size,
				      size_t sector_size,
				      const char *volume_type,
				      const char *passphrase_file,
				      struct crypt_info *info)
{
	char temp[1000];

	if (strcasecmp(volume_type, VOLUME_TYPE_PLAIN) == 0) {
		sprintf(temp, ",sector-size=%lu", sector_size);
		printf("%s\t%s\t%s\tplain,cipher=%s,size=%lu%s\n",
		       dmname, volume, key_file_name, cipher_spec,
		       key_file_size * 8, sector_size > 0 ? temp : "");
	} else if (strcasecmp(volume_type, VOLUME_TYPE_LUKS2) == 0) {
		if (info->keyfile != NULL) {
			printf("%s\t%s\t%s\tluks", dmname, volume,
			       info->keyfile);
			if (info->keyfile_offset > 0)
				printf(",keyfile-offset=%lu",
				       info->keyfile_offset);
			if (info->keyfile_size > 0)
				printf(",keyfile-size=%lu", info->keyfile_size);
		} else if (passphrase_file != NULL) {
			printf("%s\t%s\t%s\tluks", dmname, volume,
			       passphrase_file);
		} else {
			printf("%s\t%s\tnone\tluks", dmname, volume);
		}
		if (info->tries > 0)
			printf(",tries=%lu", info->tries);
		printf("\n");
	} else {
		return -EINVAL;
	}

	return 0;
}

/**
 * Builds a cipher specification for cryptsetup/crypttab
 *
 * @param properties    the key properties
 * @param is_xts	if true, the key is an XTS key
 *
 * @returns the cipher spec string (must be freed by the caller)
 */
static char *_keystore_build_cipher_spec(struct properties *properties,
					 bool is_xts)
{
	char *cipher_spec = NULL;
	char *cipher = NULL;
	char *ivmode = NULL;

	cipher = properties_get(properties, PROP_NAME_CIPHER);
	if (cipher == NULL)
		goto out;

	ivmode = properties_get(properties, PROP_NAME_IV_MODE);
	if (ivmode == NULL)
		goto out;

	util_asprintf(&cipher_spec, "%s-%s-%s", cipher, is_xts ? "xts" : "cbc",
		     ivmode);

out:
	if (cipher != NULL)
		free(cipher);
	if (ivmode != NULL)
		free(ivmode);

	return cipher_spec;
}

/**
 * Processing function for the cryptsetup and crypttab functions.
 * Extracts the required information and calls the secondary processing function
 * contained in struct crypt_info.
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] properties the properties object of the key
 * @param[in] file_names the file names used by this key
 * @param[in] private    private data: struct crypt_info
 *
 * @returns 0 if the validation is successful, a negative errno value otherwise
 */
static int _keystore_process_crypt(struct keystore *keystore,
				   const char *name,
				   struct properties *properties,
				   struct key_filenames *file_names,
				   void *private)
{
	struct crypt_info *info = (struct crypt_info *)private;
	char **volume_list = NULL;
	char *cipher_spec = NULL;
	char *volume_type = NULL;
	size_t secure_key_size;
	size_t sector_size = 0;
	char *volumes = NULL;
	u8 *secure_key = NULL;
	char *dmname;
	char *temp;
	int rc = 0;
	char *vol;
	char *ch;
	int i;

	secure_key = read_secure_key(file_names->skey_filename,
				     &secure_key_size, keystore->verbose);
	if (secure_key == NULL)
		return -EIO;

	cipher_spec = _keystore_build_cipher_spec(properties,
						  is_xts_key(secure_key,
							     secure_key_size));
	if (cipher_spec == NULL) {
		rc = -EINVAL;
		goto out;
	}

	volumes = properties_get(properties, PROP_NAME_VOLUMES);
	if (volumes == NULL)
		return -EINVAL;
	volume_list = str_list_split(volumes);

	temp = properties_get(properties, PROP_NAME_SECTOR_SIZE);
	if (temp != NULL) {
		util_assert(sscanf(temp, "%lu", &sector_size) == 1,
			   "Internal error: sscanf failed");
		free(temp);
	}

	volume_type = _keystore_get_volume_type(properties);

	for (i = 0; volume_list[i] != NULL && rc == 0; i++) {
		vol = volume_list[i];
		if (_keystore_match_filter(vol, info->volume_filter,
					   NULL) != 0) {
			ch = strchr(vol, ':');
			if (ch == NULL) {
				warnx("Volume does not contain a dm-name part."
				      " Key: '%s'", name);
				rc = -EINVAL;
				break;
			}
			*ch = '\0';
			dmname = ch + 1;

			rc = info->process_func(keystore, vol, dmname,
					cipher_spec, file_names->skey_filename,
					secure_key_size, sector_size,
					volume_type,
				_keystore_passphrase_file_exists(file_names) ?
					file_names->pass_filename : NULL,
					info);
			if (rc != 0)
				break;
		}
	}

out:
	if (volumes != NULL)
		free(volumes);
	if (volume_list != NULL)
		str_list_free_string_array(volume_list);
	if (cipher_spec != NULL)
		free(cipher_spec);
	if (volume_type != NULL)
		free(volume_type);
	if (secure_key != NULL)
		free(secure_key);
	return rc;
}

/**
 * Generates cryptsetup commands for one or multiple volumes.
 *
 * @param[in] keystore       the key store
 * @param[in] volume_filter  the volume filter. Can contain wild cards, and
 *                           mutliple volume filters separated by commas.
 *                           The ':dm-name' part of the volume is optional
 *                           for the volume filter. If not specified, the filter
 *                           checks the volume part only.
 * @param[in] execute        If TRUE the cryptsetup command is executed,
 *                           otherwise it is printed to stdout
 * @param[in] volume_type the type of volume to generate cryptsetup cmds for
 * @param[in] keyfile        If non-NULL, specifies the name of the file to
 *                           read the passphrase from.
 * @param[in] keyfile_offset the offset in bytes for reading from keyfile
 * @param[in] keyfile_size   the size in bytes for reading from keyfile
 * @param[in] tries          the number of tries for passphrase entry
 * @param[in] batch_mode     If TRUE, suppress cryptsetup confirmation questions
 * @param[in] open           If TRUE, generate luksOpen/plainOpen commands
 * @param[in] format         If TRUE, generate luksFormat commands
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_cryptsetup(struct keystore *keystore, const char *volume_filter,
			bool execute, const char *volume_type,
			const char *keyfile, size_t keyfile_offset,
			size_t keyfile_size, size_t tries, bool batch_mode,
			bool open, bool format)
{
	struct crypt_info info = { 0 };
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	if (volume_filter == NULL)
		volume_filter = "*";

	if (volume_type != NULL &&
	    !_keystore_valid_volume_type(volume_type)) {
		warnx("Invalid volume-type specified");
		return -EINVAL;
	}

	info.execute = execute;
	info.open = open;
	info.format = format;
	info.batch_mode = batch_mode;
	info.keyfile = keyfile;
	info.keyfile_offset = keyfile_offset;
	info.keyfile_size = keyfile_size;
	info.tries = tries;
	info.volume_filter = str_list_split(volume_filter);
	info.process_func = _keystore_process_cryptsetup;

	rc = _keystore_process_filtered(keystore, NULL, volume_filter, NULL,
					volume_type, NULL, false, false,
					_keystore_process_crypt, &info);

	str_list_free_string_array(info.volume_filter);

	if (rc < 0)
		pr_verbose(keystore, "Cryptsetup failed with: %s",
			   strerror(-rc));
	else if (rc > 0)
		pr_verbose(keystore, "Cryptsetup failed with: %d", rc);
	else
		pr_verbose(keystore,
			   "Successfully generated cryptsetup commands");

	return rc;
}

/**
 * Generates crypttab entries for one or multiple volumes.
 *
 * @param[in] keystore       the key store
 * @param[in] volume_filter  the volume filter. Can contain wild cards, and
 *                           mutliple volume filters separated by commas.
 *                           The ':dm-name' part of the volume is optional
 *                           for the volume filter. If not specified, the filter
 *                           checks the volume part only.
 * @param[in] volume_type    the type of volume to generate crypttab entries for
 * @param[in] keyfile        If non-NULL, specifies the name of the file to
 *                           read the passphrase from.
 * @param[in] keyfile_offset the offset in bytes for reading from keyfile
 * @param[in] keyfile_size   the size in bytes for reading from keyfile
 * @param[in] tries          the number of tries for passphrase entry
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_crypttab(struct keystore *keystore, const char *volume_filter,
		      const char *volume_type, const char *keyfile,
		      size_t keyfile_offset, size_t keyfile_size, size_t tries)
{
	struct crypt_info info = { 0 };
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	if (volume_filter == NULL)
		volume_filter = "*";

	if (volume_type != NULL &&
	    !_keystore_valid_volume_type(volume_type)) {
		warnx("Invalid volume-type specified");
		return -EINVAL;
	}

	info.keyfile = keyfile;
	info.keyfile_offset = keyfile_offset;
	info.keyfile_size = keyfile_size;
	info.tries = tries;
	info.volume_filter = str_list_split(volume_filter);
	info.process_func = _keystore_process_crypttab;

	rc = _keystore_process_filtered(keystore, NULL, volume_filter, NULL,
					volume_type, NULL, false, false,
					_keystore_process_crypt, &info);

	str_list_free_string_array(info.volume_filter);

	if (rc != 0)
		pr_verbose(keystore, "Cryptsetup failed with: %s",
			   strerror(-rc));
	else
		pr_verbose(keystore, "Successfully generated crypttab entries");

	return rc;
}

/**
 * Converts a secure keys in the keystore
 *
 * @param[in] keystore the key store
 * @param[in] name         the name of the key to convert
 * @param[in] key_type     the type of the key to convert it to
 * @param[in] noapqncheck  if true, the specified APQN(s) are not checked for
 *                         existence and type.
 * @param[in] pkey_fd      the file descriptor of /dev/pkey
 * @param[in] lib          the external library struct
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_convert_key(struct keystore *keystore, const char *name,
			 const char *key_type, bool noapqncheck, bool quiet,
			 int pkey_fd, struct ext_lib *lib)
{
	struct key_filenames file_names = { 0 };
	u8 output_key[2 * MAX_SECURE_KEY_SIZE];
	struct properties *properties = NULL;
	int rc, min_level, selected = 1;
	unsigned int output_key_size;
	char *cur_key_type = NULL;
	char **apqn_list = NULL;
	size_t secure_key_size;
	u8 *secure_key = NULL;
	u8 mkvp[MKVP_LENGTH];
	char *apqns = NULL;
	char *temp;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out;

	rc = _keystore_ensure_keyfiles_exist(&file_names, name);
	if (rc != 0)
		goto out;

	properties = properties_new();
	rc = properties_load(properties, file_names.info_filename, 1);
	if (rc != 0) {
		warnx("Key '%s' does not exist or is invalid", name);
		goto out;
	}

	if (_keystore_is_kms_bound_key(properties, NULL)) {
		rc = -EINVAL;
		warnx("A KMS-bound key can not be converted");
		goto out;
	}

	cur_key_type = _keystore_get_key_type(properties);
	if (strcasecmp(cur_key_type, key_type) == 0) {
		warnx("The secure key '%s' is already of type %s", name,
		      cur_key_type);
		rc = 0;
		goto out;
	}
	if (strcasecmp(cur_key_type, KEY_TYPE_CCA_AESDATA) != 0) {
		warnx("Only secure keys of type %s can "
		      "be converted. The secure key '%s' is of type %s",
		      KEY_TYPE_CCA_AESDATA, name, cur_key_type);
		rc = 0;
		goto out;
	}

	secure_key = read_secure_key(file_names.skey_filename,
				     &secure_key_size, keystore->verbose);
	if (secure_key == NULL) {
		rc = -ENOENT;
		goto out;
	}

	min_level = get_min_card_level_for_keytype(key_type);
	if (min_level < 0) {
		warnx("Invalid key-type specified: %s", key_type);
		rc = -EINVAL;
		goto out;
	}

	apqns = properties_get(properties, PROP_NAME_APQNS);
	if (apqns != NULL)
		apqn_list = str_list_split(apqns);

	rc = cross_check_apqns(apqns, NULL, min_level,
			       get_min_fw_version_for_keytype(key_type),
			       get_card_type_for_keytype(key_type),
			       true, keystore->verbose);
	if (rc == -EINVAL)
		goto out;
	if (rc != 0 && rc != -ENOTSUP && !noapqncheck) {
		warnx("Your master key setup is improper for converting key "
		      "'%s'", name);
		goto out;
	}

	rc = validate_secure_key(pkey_fd, secure_key, secure_key_size,
				 NULL, NULL, (const char **)apqn_list,
				 keystore->verbose);
	if (rc != 0)
		goto out;

	rc = get_master_key_verification_pattern(secure_key, secure_key_size,
						 mkvp, keystore->verbose);
	if (rc)
		goto out;

	rc = select_cca_adapter_by_mkvp(lib->cca, mkvp, apqns,
					FLAG_SEL_CCA_MATCH_CUR_MKVP,
					keystore->verbose);
	if (rc == -ENOTSUP) {
		rc = 0;
		selected = 0;
	}
	if (rc != 0) {
		warnx("No APQN found that is suitable for "
		      "converting the secure AES key '%s'", name);
		goto out;
	}

	if (!quiet) {
		util_print_indented("ATTENTION: Converting a secure key is "
				    "irreversible, and might have an effect "
				    "on the volumes encrypted with it!", 0);
		_keystore_msg_for_volumes("The following volumes are encrypted "
					  "with this key:", properties, NULL);
		printf("%s: Convert key '%s [y/N]'? ",
		       program_invocation_short_name, name);
		if (!prompt_for_yes(keystore->verbose)) {
			warnx("Operation aborted");
			rc = -ECANCELED;
			goto out;
		}
	}

	memset(output_key, 0, sizeof(output_key));
	output_key_size = sizeof(output_key);
	rc = convert_aes_data_to_cipher_key(lib->cca, secure_key,
					    secure_key_size, output_key,
					    &output_key_size,
					    keystore->verbose);
	if (rc != 0) {
		warnx("Converting the secure key '%s' from %s to %s has failed",
		      name, KEY_TYPE_CCA_AESDATA, key_type);
		if (!selected)
			print_msg_for_cca_envvars("secure AES key");
		goto out;
	}

	rc = restrict_key_export(lib->cca, output_key, output_key_size,
				 keystore->verbose);
	if (rc != 0) {
		warnx("Export restricting the converted secure key '%s' has "
		      "failed", name);
		if (!selected)
			print_msg_for_cca_envvars("secure AES key");
		goto out;
	}

	rc = properties_set2(properties, PROP_NAME_KEY_TYPE, key_type, true);
	if (rc != 0) {
		warnx("Invalid characters in key-type");
		goto out;
	}

	rc = properties_save(properties, file_names.info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Failed to write key info file '%s': %s",
			   file_names.info_filename, strerror(-rc));
		goto out;
	}

	rc = write_secure_key(file_names.skey_filename, output_key,
			      output_key_size, keystore->verbose);
	if (rc != 0)
		goto out;

	pr_verbose(keystore, "Secure key '%s' was converted successfully",
		   name);

	util_asprintf(&temp, "The following LUKS2 volumes are "
		      "encrypted with key '%s'. These volumes still contain "
		      "the secure AES volume key of type CCA-AESDATA. To "
		      "change the secure AES volume key in the LUKS2 header, "
		      "run command 'zkey-cryptsetup setkey <device> "
		      "--master-key-file %s':", name,
		      file_names.skey_filename);
	_keystore_msg_for_volumes(temp, properties, VOLUME_TYPE_LUKS2);
	free(temp);
	util_asprintf(&temp, "The following plain mode volumes are "
		      "encrypted with key '%s'. You must adapt the crypttab "
		      "entries for this volumes and change the key size "
		      "parameter to 'size=%u' or run command 'zkey crypttab "
		      "--volumes <device>' for each volume to re-generate the "
		      "crypttab entries:", name, output_key_size * 8, name);
	_keystore_msg_for_volumes(temp, properties, VOLUME_TYPE_PLAIN);
	free(temp);

out:
	_keystore_free_key_filenames(&file_names);
	if (properties != NULL)
		properties_free(properties);
	if (secure_key != NULL)
		free(secure_key);
	if (apqns != NULL)
		free(apqns);
	if (apqn_list != NULL)
		str_list_free_string_array(apqn_list);
	if (cur_key_type != NULL)
		free(cur_key_type);

	if (rc != 0)
		pr_verbose(keystore, "Failed to convert key '%s': %s",
			   name, strerror(-rc));
	return rc;
}

struct kms_process {
	process_key_t process_func;
	void *process_private;
};

struct kms_set_prop {
	const char *prop_name;
	const char *prop_value;
	unsigned long num_keys;
};

/**
 * Processing function for setting properties of KMS-bound keys
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] properties the properties object of the key (not used here)
 * @param[in] file_names the file names used by this key
 * @param[in] private    private data: struct reencipher_info
 *
 * @returns 0 for success, or a negative errno value in case of an error
 */
static int _keystore_process_kms_key_set_prop(struct keystore *keystore,
					      const char *name,
					      struct properties *properties,
					      struct key_filenames *file_names,
					      void *private)
{
	struct kms_set_prop *set_prop = private;
	int rc;

	pr_verbose(keystore, "Setting property for KMS-bound key '%s'", name);

	if (set_prop->prop_value != NULL) {
		rc = properties_set(properties, set_prop->prop_name,
				    set_prop->prop_value);

		if (rc != 0) {
			pr_verbose(keystore, "Invalid characters in property: "
				   "%s: %s", set_prop->prop_name,
				   set_prop->prop_value);
			goto out;
		}

	} else {
		rc = properties_remove(properties, set_prop->prop_name);
		if (rc != 0 && rc != -ENOENT) {
			pr_verbose(keystore, "Failed to remove  property: "
				   "%s: %s", set_prop->prop_name,
				   strerror(-rc));
			goto out;
		}
	}

	rc = properties_save(properties, file_names->info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   file_names->info_filename, strerror(-rc));
		goto out;
	}

	set_prop->num_keys++;

out:
	return rc;
}

/**
 * Iterates over all keys stored in the keystore. For every key that is bound
 * to a KMS plugin the specified property is set to the specified value.
 * If value is NULL, then the property is removed from the key.
 *
 * @param[in] keystore   the keystore
 * @param[in] key_type   the key type. NULL means no key type filter.
 * @param[in] prop_name  the name of the property to set
 * @param[in] prop_value the value of the property to set or NULL if the proerty
 *                       is to be removed.
 *
 * @returns 0 for success, or a negative errno value in case of an error
 */
int keystore_kms_keys_set_property(struct keystore *keystore,
				   const char *key_type,
				   const char *prop_name,
				   const char *prop_value)
{
	struct kms_set_prop set_prop;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(prop_name != NULL, "Internal error: prop_name is NULL");

	set_prop.prop_name = prop_name;
	set_prop.prop_value = prop_value;
	set_prop.num_keys = 0;

	rc = _keystore_process_filtered(keystore, NULL, NULL, NULL, NULL,
					key_type, false, true,
					_keystore_process_kms_key_set_prop,
					&set_prop);
	if (rc != 0)
		pr_verbose(keystore, "Failed to set properties of kms keys: %s",
			   strerror(-rc));
	else
		pr_verbose(keystore, "Successfully set properties of %lu kms "
			   "keys", set_prop.num_keys);

	return rc;
}

static const char * const kms_props[] = {
	PROP_NAME_KMS,
	PROP_NAME_KMS_KEY_ID,
	PROP_NAME_KMS_KEY_LABEL,
	PROP_NAME_KMS_XTS_KEY1_ID,
	PROP_NAME_KMS_XTS_KEY1_LABEL,
	PROP_NAME_KMS_XTS_KEY2_ID,
	PROP_NAME_KMS_XTS_KEY2_LABEL,
	NULL,
};

/**
 * Unbinds the key by removing the KMS specific properties
 *
 * @param[in] keystore   the keystore
 * @param[in] properties the properties object of the key
 *
 * @returns 0 for success, or a negative errno value in case of an error
 */
static int _keystore_kms_key_unbind(struct keystore *keystore,
				    struct properties *properties)
{
	int i, rc;

	for (i = 0; kms_props[i] != NULL; i++) {
		rc = properties_remove(properties, kms_props[i]);
		if (rc != 0 && rc != -ENOENT) {
			pr_verbose(keystore, "Failed to remove property: "
				   "%s: %s", kms_props[i], strerror(-rc));
			return rc;
		}
	}

	return 0;
}

/**
 * Processing function for unbinding of KMS-bound keys
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] properties the properties object of the key
 * @param[in] file_names the file names used by this key
 * @param[in] private    private data: struct reencipher_info
 *
 * @returns 0 for success, or a negative errno value in case of an error
 */
static int _keystore_process_kms_key_unbind(struct keystore *keystore,
					    const char *name,
					    struct properties *properties,
					    struct key_filenames *file_names,
					    void *private)
{
	unsigned long *num_keys = private;
	int rc;

	pr_verbose(keystore, "Unbinding KMS-bound key '%s'", name);

	rc = _keystore_kms_key_unbind(keystore, properties);
	if (rc != 0)
		goto out;

	rc = properties_save(properties, file_names->info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   file_names->info_filename, strerror(-rc));
		goto out;
	}

	(*num_keys)++;

out:
	return rc;
}

/**
 * Iterates over all keys stored in the keystore. For every key that is bound
 * to a KMS plugin the KMS specific properties are deleted, and thus these keys
 * are unbound from the KMS plugin.
 *
 * @param[in] keystore   the keystore
 *
 * @returns 0 for success, or a negative errno value in case of an error
 */
int keystore_kms_keys_unbind(struct keystore *keystore)
{
	unsigned long num_keys = 0;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	rc = _keystore_process_filtered(keystore, NULL, NULL, NULL, NULL,
					NULL, false, true,
					_keystore_process_kms_key_unbind,
					&num_keys);

	if (rc != 0)
		pr_verbose(keystore, "Failed to unbinds kms keys: %s",
			   strerror(-rc));
	else
		pr_verbose(keystore, "Successfully unbound of %lu kms keys",
			   num_keys);

	return rc;
}

struct kms_msg_for_key {
	const char *msg;
	unsigned long num_keys;
};

/**
 * Processing function for issuing a message for KMS-bound keys
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] properties the properties object of the key (not used here)
 * @param[in] file_names the file names used by this key
 * @param[in] private    private data: struct reencipher_info
 *
 * @returns 0 for success, or a negative errno value in case of an error
 */
static int _keystore_process_kms_msg_for_key(struct keystore *UNUSED(keystore),
					     const char *name,
					     struct properties *
							UNUSED(properties),
					     struct key_filenames *
							UNUSED(file_names),
					     void *private)
{
	struct kms_msg_for_key *msg_for_key = private;

	if (msg_for_key->num_keys == 0)
		util_print_indented(msg_for_key->msg, 0);

	printf("  %s\n", name);
	msg_for_key->num_keys++;

	return 0;
}

/**
 * Iterates over all keys stored in the keystore. Every key that is bound
 * to a KMS plugin and has the specified key type is listed together with the
 * message. If no KMS-bound keys with the specified key type exist in the
 * keystore, then no message is printed, and -ENOENT is returned.
 *
 * @param[in] keystore   the keystore
 * @param[in] key_type   the key type. NULL means no key type filter.
 * @param[in] msg        the message to print
 *
 * @returns 0 for success, or a negative errno value in case of an error.
 * -ENOENT if no key macthed
 */
int keystore_msg_for_kms_key(struct keystore *keystore, const char *key_type,
			     const char *msg)
{
	struct kms_msg_for_key msg_for_key;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(msg != NULL, "Internal error: msg is NULL");

	msg_for_key.msg = msg;
	msg_for_key.num_keys = 0;

	rc = _keystore_process_filtered(keystore, NULL, NULL, NULL, NULL,
					key_type, false, true,
					_keystore_process_kms_msg_for_key,
					&msg_for_key);
	if (rc != 0)
		return rc;
	return msg_for_key.num_keys == 0 ? -ENOENT : 0;
}

struct kms_import {
	struct keystore *keystore;
	bool batch_mode;
	bool novolcheck;
	unsigned long num_imported;
	unsigned long num_skipped;
	unsigned long num_failed;
};

/**
 * Callback used with the keystore_import_kms_keys() function. Called for each
 * key.
 *
 * @param[in] key1_id           the key-ID of the key (1st key of an XTS key)
 * @param[in] key1_label        the label of the key (1st key of an XTS key)
 * @param[in] key2_id           the key-ID of the 2nd XTS key, NULL if not XTS
 * @param[in] key2_label        the label of the 2nd XTS key, NULL if not XTS
 * @param[in] xts               if true, this is an XTS key pair
 * @param[in] name              the zkey name of the key
 * @param[in] key_type          the type of the key (CCA-AESDATA, etc)
 * @param[in] key_bits          the key size in bits
 * @param[in] description       the description of the key (can be NULL)
 * @param[in] cipher            the cipher of the key (can be NULL)
 * @param[in] iv_mode           the IV-mode of the key (can be NULL)
 * @param[in] volumes           the associated volumes of the key (can be NULL)
 * @param[in] volume_type       the volume type of the volume (can be NULL)
 * @param[in] sector_size       the sector size of the volume (0 means default)
 * @param[in] passphrase        the passphrase of the key (can be NULL)
 * @param[in] addl_info_argz    an argz string containing additional KMS plugin
 *                              specific infos to be displayed, or NULL if none.
 * @param[in] addl_info_len     length of the argz string in addl_info_argz
 * @param[in] private_data      the private data pointer
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
static int _keystore_process_kms_import(const char *key1_id,
					const char *key1_label,
					const char *key2_id,
					const char *key2_label,
					bool xts, const char *name,
					const char *UNUSED(key_type),
					size_t UNUSED(key_bits),
					const char *description,
					const char *UNUSED(cipher),
					const char *UNUSED(iv_mode),
					const char *volumes,
					const char *volume_type,
					size_t sector_size,
					const char *passphrase,
					const char *UNUSED(addl_info_argz),
					size_t UNUSED(addl_info_len),
					void *private_data)
{
	struct kms_import *import_data = private_data;
	struct key_filenames file_names = { 0 };
	u8 secure_key[2 * MAX_SECURE_KEY_SIZE];
	struct properties *key_props = NULL;
	char vp[VERIFICATION_PATTERN_LEN];
	const char *key_name = name;
	struct keystore *keystore;
	size_t alt_name_len = 0;
	size_t secure_key_size;
	bool fatal_err = false;
	char *alt_name = NULL;
	const char *key_type;
	char *apqns = NULL;
	int rc;

	keystore = import_data->keystore;

	rc = _keystore_get_key_filenames(keystore, key_name, &file_names);
	if (rc != 0)
		goto out;

check_duplicate_key:
	rc = _keystore_ensure_keyfiles_not_exist(&file_names, key_name);
	if (rc == -EEXIST) {
		if (import_data->batch_mode) {
			rc = 1;
			goto out;
		}

		printf("%s: Do you want to enter an alternate name [y/N]? ",
		       program_invocation_short_name);
		if (!prompt_for_yes(keystore->verbose)) {
			rc = 1;
			goto out;
		}

prompt_alt_name:
		printf("%s: Alternate name: ", program_invocation_short_name);
		rc = getline(&alt_name, &alt_name_len, stdin);
		if (rc <= 1) {
			rc = 1;
			goto out;
		}

		if (alt_name[strlen(alt_name) - 1] == '\n')
			alt_name[strlen(alt_name) - 1] = '\0';

		key_name = alt_name;
		_keystore_free_key_filenames(&file_names);
		rc = _keystore_get_key_filenames(keystore, key_name,
						 &file_names);
		if (rc != 0)
			goto prompt_alt_name;

		goto check_duplicate_key;
	} else if (rc != 0) {
		goto out;
	}

	secure_key_size = sizeof(secure_key);
	rc = import_kms_key(keystore->kms_info, key1_id, key2_id, xts, key_name,
			    secure_key, &secure_key_size, keystore->verbose);
	if (rc != 0) {
		warnx("KMS plugin '%s' failed to import key '%s': %s",
		      keystore->kms_info->plugin_name, key_name, strerror(-rc));
		print_last_kms_error(keystore->kms_info);
		if (rc == -ENOTSUP)
			fatal_err = true;
		goto out;
	}

	key_type = get_key_type(secure_key, secure_key_size);
	if (key_type == NULL) {
		warnx("Key '%s' is not a valid secure key", key_name);
		rc = -EINVAL;
		goto out;
	}

	rc = get_kms_apqns_for_key_type(keystore->kms_info, key_type, true,
					&apqns, keystore->verbose);
	if (rc != 0) {
		if (rc == -ENOTSUP)
			warnx("Key-type not supported by the KMS plugin '%s'",
			      keystore->kms_info->plugin_name);
		goto out;
	}

	pr_verbose(keystore, "APQNs for keytype %s: '%s'", key_type, apqns);

	rc = _keystore_create_info_props(keystore, key_name, description,
					 volumes, apqns, false,
					 import_data->novolcheck,
					 sector_size, volume_type, key_type,
					 keystore->kms_info->plugin_name,
					 &key_props);
	if (rc != 0)
		goto out;

	if (passphrase != NULL && volume_type != NULL &&
	    strcasecmp(volume_type, VOLUME_TYPE_LUKS2) == 0) {
		rc = store_passphrase_from_base64(passphrase,
						  file_names.pass_filename,
						  keystore->verbose);
		if (rc != 0) {
			pr_verbose(keystore, "Failed to parse passphrase: %s",
				   strerror(-rc));
			goto out;
		}

		rc = _keystore_set_file_permission(keystore,
						   file_names.pass_filename);
		if (rc != 0)
			goto out_remove;
	}

	rc = properties_set(key_props, xts ? PROP_NAME_KMS_XTS_KEY1_ID :
			    PROP_NAME_KMS_KEY_ID, key1_id);
	if (rc != 0) {
		pr_verbose(keystore, "Failed to set key id of key #1: %s",
			   strerror(-rc));
		goto out;
	}

	rc = properties_set(key_props, xts ? PROP_NAME_KMS_XTS_KEY1_LABEL :
			    PROP_NAME_KMS_KEY_LABEL, key1_label);
	if (rc != 0) {
		pr_verbose(keystore, "Failed to set key label of key #1: %s",
			   strerror(-rc));
		goto out;
	}

	if (xts) {
		rc = properties_set(key_props, PROP_NAME_KMS_XTS_KEY2_ID,
				    key2_id);
		if (rc != 0) {
			pr_verbose(keystore, "Failed to set key id of key #2: "
				   "%s", strerror(-rc));
			goto out;
		}

		rc = properties_set(key_props, PROP_NAME_KMS_XTS_KEY2_LABEL,
				    key2_label);
		if (rc != 0) {
			pr_verbose(keystore, "Failed to set key label of key "
				   "#2: %s", strerror(-rc));
			goto out;
		}
	}

	rc = write_secure_key(file_names.skey_filename, secure_key,
			      secure_key_size, keystore->verbose);
	if (rc != 0)
		goto out;

	rc = _keystore_set_file_permission(keystore, file_names.skey_filename);
	if (rc != 0)
		goto out_remove;

	rc = generate_key_verification_pattern(secure_key, secure_key_size,
					       vp, sizeof(vp),
					       keystore->verbose);
	if (rc != 0) {
		warnx("Failed to generate the key verification pattern: %s",
		      strerror(-rc));
		warnx("Make sure that kernel module 'paes_s390' is loaded and "
		      "that the 'paes' cipher is available");
		fatal_err = true;
		goto out_remove;
	}

	rc = properties_set(key_props, PROP_NAME_KEY_VP, vp);
	if (rc != 0) {
		pr_verbose(keystore, "Failed to set verification pattern of "
			   "key: %s", strerror(-rc));

		goto out_remove;
	}

	rc = properties_save(key_props, file_names.info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   file_names.info_filename, strerror(-rc));
		goto out;
	}

	rc = _keystore_set_file_permission(keystore, file_names.info_filename);
	if (rc != 0) {
		remove(file_names.info_filename);
		goto out_remove;
	}

out_remove:
	if (rc != 0) {
		remove(file_names.skey_filename);
		remove(file_names.info_filename);
	}

out:
	if (rc == 0) {
		printf("Successfully imported key '%s'\n", key_name);
		import_data->num_imported++;
	} else if (rc < 0) {
		warnx("Failed to import key '%s': %s", key_name, strerror(-rc));
		import_data->num_failed++;
	} else {
		warnx("Skipping key '%s'", key_name);
		import_data->num_skipped++;
	}

	_keystore_free_key_filenames(&file_names);
	if (alt_name != NULL)
		free(alt_name);
	if (apqns != NULL)
		free(apqns);
	if (key_props != NULL)
		properties_free(key_props);

	return fatal_err ? rc : 0;
}

/**
 * Imports secure keys from the KMS and adds it to the key store
 *
 * @param[in] keystore        the key store
 * @param[in] label_filter    the KMS label filter. Can contain wild cards.
 *                            NULL means no name filter.
 * @param[in] name_filter     the name filter. Can contain wild cards.
 *                            NULL means no name filter.
 * @param[in] volume_filter   the volume filter. Can contain wild cards, and
 *                            mutliple volume filters separated by commas.
 *                            If the filter does not contain the ':dm-name'
 *                            part, then the volumes are matched without the
 *                            dm-name part. If the filter contains the
 *                            ':dm-name' part, then the filter is matched
 *                            including the dm-name part.
 *                            NULL means no volume filter.
 * @param[in] volume_type     If not NULL, specifies the volume type.
 * @param[in] kms_options     an array of KMS options specified, or NULL if no
 *                            KMS options have been specified
 * @param[in] num_kms_options the number of options in above array
 * @param[in] batch_mode      if true, suppress alternate name prompts if a key
 *                            with an already existing name is to be imported.
 * @param[in] novolcheck      if true, do not check the associated volumes for
 *                            existence and duplicate use
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_import_kms_keys(struct keystore *keystore,
			     const char *label_filter,
			     const char *name_filter,
			     const char *volume_filter,
			     const char *volume_type,
			     struct kms_option *kms_options,
			     size_t num_kms_options,
			     bool batch_mode, bool novolcheck)
{
	struct kms_import import_data = { 0 };
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	if (keystore->kms_info->plugin_lib == NULL) {
		warnx("The repository is not bound to a KMS plugin");
		return -ENOENT;
	}

	if (volume_type != NULL &&
	    !_keystore_valid_volume_type(volume_type)) {
		warnx("Invalid volume-type specified");
		return -EINVAL;
	}

	import_data.keystore = keystore;
	import_data.batch_mode = batch_mode;
	import_data.novolcheck = novolcheck;
	import_data.num_imported = 0;
	import_data.num_skipped = 0;
	import_data.num_failed = 0;

	rc = process_kms_keys(keystore->kms_info, label_filter, name_filter,
			       volume_filter, volume_type,
			       kms_options, num_kms_options,
			       _keystore_process_kms_import, &import_data,
			       keystore->verbose);
	if (rc != 0) {
		pr_verbose(keystore, "Failed to import kms keys: %s",
			   strerror(-rc));
	} else {
		printf("%lu keys imported, %lu keys skipped, %lu keys "
		       "failed to import\n",
		       import_data.num_imported, import_data.num_skipped,
		       import_data.num_failed);
		if (import_data.num_failed > 0)
			rc = -EIO;
	}

	return rc;
}

struct kms_refresh {
	bool refresh_properties;
	bool novolcheck;
	unsigned long num_refreshed;
	unsigned long num_failed;
};

/**
 * Processing function for the key refresh function.
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] properties the properties object of the key
 * @param[in] file_names the file names used by this key
 * @param[in] private    private data: struct reencipher_info
 *
 * @returns 0 if the display is successful, a negative errno value otherwise
 */
static int _keystore_refresh_kms_key(struct keystore *keystore,
				     const char *name,
				     struct properties *properties,
				     struct key_filenames *file_names,
				     void *private)
{
	struct volume_check vol_check = { .keystore = keystore, .name = name,
					  .set = 1, .nocheck = 0 };
	char *description = NULL, *cipher = NULL, *iv_mode = NULL;
	struct kms_refresh *refresh_data = private;
	char *volumes = NULL, *volume_type = NULL;
	ssize_t sector_size = -1;
	bool fatal_err = false;
	char sect_size[30];
	char *msg;
	int rc;

	vol_check.nocheck = refresh_data->novolcheck;

	rc = refresh_kms_key(keystore->kms_info, properties,
			     &description, &cipher, &iv_mode, &volumes,
			     &volume_type, &sector_size,
			     file_names->skey_filename,
			     file_names->pass_filename,
			     keystore->verbose);
	if (rc != 0) {
		warnx("KMS plugin '%s' failed to refresh key '%s': %s",
		      keystore->kms_info->plugin_name, name, strerror(-rc));
		print_last_kms_error(keystore->kms_info);
		if (rc == -ENOTSUP)
			fatal_err = true;
		goto out;
	}

	rc = _keystore_set_file_permission(keystore, file_names->skey_filename);
	if (rc != 0)
		goto out;

	if (_keystore_passphrase_file_exists(file_names)) {
		rc = _keystore_set_file_permission(keystore,
						   file_names->pass_filename);
		if (rc != 0)
			goto out;
	}

	if (!refresh_data->refresh_properties)
		goto save_props;

	if (description != NULL) {
		rc = properties_set(properties, PROP_NAME_DESCRIPTION,
				    description);
		if (rc != 0) {
			warnx("Invalid characters in description");
			goto out;
		}
	}

	if (volumes != NULL) {
		rc = _keystore_change_association(properties, PROP_NAME_VOLUMES,
						  volumes, "volume",
						  _keystore_volume_check,
						  &vol_check);
		if (rc != 0)
			goto out;
	}

	if (sector_size >= 0) {
		if (!_keystore_valid_sector_size(sector_size)) {
			warnx("Invalid sector-size specified");
			rc = -EINVAL;
			goto out;
		}

		sprintf(sect_size, "%lu", sector_size);
		rc = properties_set(properties, PROP_NAME_SECTOR_SIZE,
				    sect_size);
		if (rc != 0) {
			warnx("Invalid characters in sector-size");
			goto out;
		}
	}

	if (volume_type != NULL) {
		if (!_keystore_valid_volume_type(volume_type)) {
			warnx("Invalid volume-type specified");
			rc = -EINVAL;
			goto out;
		}

		rc = properties_set2(properties, PROP_NAME_VOLUME_TYPE,
				     volume_type, true);
		if (rc != 0) {
			warnx("Invalid characters in volume-type");
			goto out;
		}
	}

save_props:
	rc = _keystore_set_timestamp_property(properties,
					      PROP_NAME_CHANGE_TIME);
	if (rc != 0) {
		warnx("Failed to set the update timestamp property");
		goto out;
	}

	rc = properties_save(properties, file_names->info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   file_names->info_filename, strerror(-rc));
		goto out;
	}

	rc = _keystore_set_file_permission(keystore, file_names->info_filename);
	if (rc != 0)
		goto out;

out:
	if (rc == 0) {
		printf("Successfully refreshed key '%s'\n", name);
		refresh_data->num_refreshed++;

		util_asprintf(&msg, "The following LUKS2 volumes are "
			      "encrypted with key '%s'. To update the secure "
			      "AES volume key in the LUKS2 header, run command "
			      "'zkey-cryptsetup setkey <device> "
			      "--master-key-file %s':", name,
			      file_names->skey_filename);
		_keystore_msg_for_volumes(msg, properties, VOLUME_TYPE_LUKS2);
		free(msg);
	} else {
		warnx("Failed to refresh key '%s': %s", name, strerror(-rc));
		refresh_data->num_failed++;
	}

	if (description != NULL)
		free(description);
	if (cipher != NULL)
		free(cipher);
	if (iv_mode != NULL)
		free(iv_mode);
	if (volumes != NULL)
		free(volumes);
	if (volume_type != NULL)
		free(volume_type);

	return fatal_err ? rc : 0;
}

/**
 * Refreshes secure KMS-bound secure key and updates them from the KMS
 *
 * @param[in] keystore        the key store
 * @param[in] name_filter     the name filter. Can contain wild cards.
 *                            NULL means no name filter.
 * @param[in] volume_filter   the volume filter. Can contain wild cards, and
 *                            mutliple volume filters separated by commas.
 *                            If the filter does not contain the ':dm-name'
 *                            part, then the volumes are matched without the
 *                            dm-name part. If the filter contains the
 *                            ':dm-name' part, then the filter is matched
 *                            including the dm-name part.
 *                            NULL means no volume filter.
 * @param[in] volume_type     If not NULL, specifies the volume type.
 * @param[in] key_type       The key type. NULL means no key type filter.
 * @param[in] refresh_properties   if true, also refresh the key's properties
 * @param[in] novolcheck      if true, do not check the associated volumes for
 *                            existence and duplicate use
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_refresh_kms_keys(struct keystore *keystore,
			     const char *name_filter,
			     const char *volume_filter,
			     const char *volume_type, const char *key_type,
			     bool refresh_properties, bool novolcheck)
{
	struct kms_refresh refresh_data = { 0 };
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	if (keystore->kms_info->plugin_lib == NULL) {
		warnx("The repository is not bound to a KMS plugin");
		return -ENOENT;
	}

	if (volume_type != NULL &&
	    !_keystore_valid_volume_type(volume_type)) {
		warnx("Invalid volume-type specified");
		return -EINVAL;
	}

	if (key_type != NULL &&
	    !_keystore_valid_key_type(key_type)) {
		warnx("Invalid key-type specified");
		return -EINVAL;
	}

	refresh_data.refresh_properties = refresh_properties;
	refresh_data.novolcheck = novolcheck;
	refresh_data.num_refreshed = 0;
	refresh_data.num_failed = 0;

	rc = _keystore_process_filtered(keystore, name_filter, volume_filter,
					NULL, volume_type, key_type, false,
					true, _keystore_refresh_kms_key,
					&refresh_data);

	if (rc != 0) {
		pr_verbose(keystore, "Failed to refresh kms keys: %s",
			   strerror(-rc));
	} else {
		printf("%lu keys refreshed, %lu keys failed to refresh\n",
		       refresh_data.num_refreshed, refresh_data.num_failed);
		if (refresh_data.num_failed > 0)
			rc = -EIO;
	}

	return rc;
}

/**
 * Frees a keystore object
 *
 * @param[in] keystore the key store
 */
void keystore_free(struct keystore *keystore)
{
	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	_keystore_unlock_repository(keystore);
	free(keystore->directory);
	free(keystore);
}
