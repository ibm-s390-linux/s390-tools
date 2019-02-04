/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Keystore handling functions
 *
 * Copyright IBM Corp. 2018
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
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_rec.h"

#include "keystore.h"
#include "pkey.h"
#include "properties.h"

struct key_filenames {
	char *skey_filename;
	char *info_filename;
	char *renc_filename;
};

#define FILE_EXTENSION_LEN	5
#define SKEY_FILE_EXTENSION	".skey"
#define INFO_FILE_EXTENSION	".info"
#define RENC_FILE_EXTENSION	".renc"

#define LOCK_FILE_NAME		".lock"

#define PROP_NAME_KEY_TYPE	"key-type"
#define PROP_NAME_CIPHER	"cipher"
#define PROP_NAME_IV_MODE	"iv-mode"
#define PROP_NAME_DESCRIPTION	"description"
#define PROP_NAME_VOLUMES	"volumes"
#define PROP_NAME_APQNS		"apqns"
#define PROP_NAME_SECTOR_SIZE	"sector-size"
#define PROP_NAME_CREATION_TIME	"creation-time"
#define PROP_NAME_CHANGE_TIME	"update-time"
#define PROP_NAME_REENC_TIME	"reencipher-time"
#define PROP_NAME_KEY_VP	"verification-pattern"
#define PROP_NAME_VOLUME_TYPE	"volume-type"

#define VOLUME_TYPE_PLAIN	"plain"
#define VOLUME_TYPE_LUKS2	"luks2"
#ifdef HAVE_LUKS2_SUPPORT
	#define DEFAULT_VOLUME_TYPE	VOLUME_TYPE_LUKS2
#else
	#define DEFAULT_VOLUME_TYPE	VOLUME_TYPE_PLAIN
#endif

#define IS_XTS(secure_key_size) (secure_key_size > SECURE_KEY_SIZE ? 1 : 0)

#define REC_KEY			"Key"
#define REC_DESCRIPTION		"Description"
#define REC_SEC_KEY_SIZE	"Secure key size"
#define REC_CLR_KEY_SIZE	"Clear key size"
#define REC_XTS			"XTS type key"
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

#define pr_verbose(keystore, fmt...)	do {				\
						if (keystore->verbose)	\
							warnx(fmt);	\
					} while (0)

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
	struct stat sb;
	int rc;

	rc = stat(file_names->renc_filename, &sb);
	if (rc == 0 && !S_ISREG(sb.st_mode))
		rc = 1;

	return !rc;
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
	struct stat sb_skey, sb_info;
	int rc_skey, rc_info;

	rc_skey = stat(file_names->skey_filename, &sb_skey);
	if (rc_skey == 0 && !S_ISREG(sb_skey.st_mode))
		rc_skey = 1;

	rc_info = stat(file_names->info_filename, &sb_info);
	if (rc_info == 0 && !S_ISREG(sb_info.st_mode))
		rc_info = 1;

	if (rc_skey == 0 && rc_info == 0)
		return 1;
	if (rc_skey != 0 && rc_info != 0 &&
	    _keystore_reencipher_key_exists(file_names) == 0)
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

typedef int (*check_association_t)(const char *value, bool remove,
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
			rc = check_func(newvals[i], 0, &normalized,
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
			rc = check_func(newvals[i], 0, &normalized,
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
			rc = check_func(delvals[i], 1, &normalized,
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
	char *modified;
	char *pattern_domain;
	char *pattern_card;
	char *copy;
	int card, domain;
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

	if (dirent->d_type != DT_REG)
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
				      process_key_t process_func,
				      void *process_private)
{
	struct key_filenames file_names = { NULL, NULL, NULL };
	char **apqn_filter_list = NULL;
	char **vol_filter_list = NULL;
	struct properties *key_props;
	struct dirent **namelist;
	int n, i, rc = 0;
	bool skip = 0;
	char *name;
	int len;

	pr_verbose(keystore, "Process_filtered: name_filter = '%s', "
		   "volume_filter = '%s', apqn_filter = '%s'", name_filter,
		   volume_filter, apqn_filter);

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

/**
 * Checks if the specified APQN is of type CCA and is online
 *
 * @param[in] card      card number
 * @param[in] domain    the domain
 *
 * @returns 1 if its a CCA card and is online, 0 if offline and -1 if its
 *          not a CCA card.
 */
static int _keystore_is_apqn_online(int card, int domain)
{
	long int online;
	char *dev_path;
	char type[20];
	int rc = 1;

	dev_path = util_path_sysfs("bus/ap/devices/card%02x", card);
	if (!util_path_is_dir(dev_path)) {
		rc = 0;
		goto out;
	}
	if (util_file_read_l(&online, 10, "%s/online", dev_path) != 0) {
		rc = 0;
		goto out;
	}
	if (online == 0) {
		rc = 0;
		goto out;
	}
	if (util_file_read_line(type, sizeof(type), "%s/type", dev_path) != 0) {
		rc = 0;
		goto out;
	}
	if (strncmp(type, "CEX", 3) != 0 || strlen(type) < 5) {
		rc = 0;
		goto out;
	}
	if (type[4] != 'C') {
		rc = -1;
		goto out;
	}
	free(dev_path);

	dev_path = util_path_sysfs("bus/ap/devices/card%02x/%02x.%04x", card,
				   card, domain);
	if (!util_path_is_dir(dev_path)) {
		rc = 0;
		goto out;
	}
	if (util_file_read_l(&online, 10, "%s/online", dev_path) != 0) {
		rc = 0;
		goto out;
	}
	if (online == 0) {
		rc = 0;
		goto out;
	}

out:
	free(dev_path);
	return rc;
}

/**
 * Checks an APQN value for its syntax. This is a callback function for
 * function _keystore_change_association().
 *
 * @param[in] apqn     the APQN value to check
 * @param[in] remove   if true the apqn is removed
 * @param[out] normalized normalized value on return or NULL if no change
 * @param[in] private  private data (not used here)
 *
 * @returns 0 if successful, a negative errno value otherwise
 */
static int _keystore_apqn_check(const char *apqn, bool remove,
				char **normalized, void *UNUSED(private))
{
	int rc, card, domain;
	regmatch_t pmatch[1];
	regex_t reg_buf;

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

	if (sscanf(apqn, "%x.%x", &card, &domain) != 2) {
		warnx("the APQN '%s' is not valid", apqn);
		rc = -EINVAL;
		goto out;
	}

	util_asprintf(normalized, "%02x.%04x", card, domain);

	if (remove) {
		rc = 0;
		goto out;
	}

	rc = _keystore_is_apqn_online(card, domain);
	if (rc != 1) {
		warnx("The APQN %02x.%04x is %s", card, domain,
		      rc == -1 ? "not a CCA card" : "not online");
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
 * @param[out] normalized normalized value on return or NULL if no change
 * @param[in] private    private data: struct volume_check
 *
 * @returns 0 if successful, a negative errno value otherwise
 */
static int _keystore_volume_check(const char *volume, bool remove,
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

	if (remove) {
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

	rc = _keystore_process_filtered(info->keystore, NULL, info->volume,
					NULL, NULL,
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
 * @param[in]    verbose       if true, verbose messages are printed
 *
 * @returns a new keystore object
 */
struct keystore *keystore_new(const char *directory, bool verbose)
{
	struct keystore *keystore;
	struct stat sb;
	int rc;

	util_assert(directory != NULL, "Internal error: directory is NULL");

	if (stat(directory, &sb) != 0) {
		warnx("Can not access '%s': %s", directory, strerror(errno));
		return NULL;
	}
	if (!(sb.st_mode & S_IFDIR)) {
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

	rc = generate_key_verification_pattern((const char *)key, key_size,
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

	rc = properties_set(key_props, PROP_NAME_KEY_TYPE, "CCA-AESDATA");
	if (rc != 0)
		return rc;

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
 * Creates an initial .info file for a key
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] info_filename  the file name of the key info file
 * @param[in] description textual description of the key (optional, can be NULL)
 * @param[in] volumes     a comma separated list of volumes associated with this
 *                        key (optional, can be NULL)
 * @param[in] apqns       a comma separated list of APQNs associated with this
 *                        key (optional, can be NULL)
 * @param[in] sector_size the sector size to use with dm-crypt. It must be power
 *                        of two and in range 512 - 4096 bytes. 0 means that
 *                        the sector size is not specified and the system
 *                        default is used.
 * @param[in] volume_type the type of volume
 */
static int _keystore_create_info_file(struct keystore *keystore,
				      const char *name,
				      const struct key_filenames *filenames,
				      const char *description,
				      const char *volumes, const char *apqns,
				      size_t sector_size,
				      const char *volume_type)
{
	struct volume_check vol_check = { .keystore = keystore, .name = name };
	struct properties *key_props;
	char temp[10];
	int rc;

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

	rc = _keystore_change_association(key_props, PROP_NAME_VOLUMES,
					  volumes != NULL ? volumes : "",
					  "volume", _keystore_volume_check,
					  &vol_check);
	if (rc != 0)
		goto out;

	rc = _keystore_change_association(key_props, PROP_NAME_APQNS,
					  apqns != NULL ? apqns : "",
					  "APQN", _keystore_apqn_check, NULL);
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
	rc = properties_set(key_props, PROP_NAME_VOLUME_TYPE, volume_type);
	if (rc != 0) {
		warnx("Invalid characters in volume-type");
		goto out;
	}

	rc = _keystore_ensure_vp_exists(keystore, filenames, key_props);
	if (rc != 0) {
		warnx("Failed to generate the key verification pattern: %s",
		      strerror(-rc));
		warnx("Make sure that kernel module 'paes_s390' is loaded and "
		      "that the 'paes' cipher is available");
		return rc;
	}

	rc = properties_save(key_props, filenames->info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   filenames->info_filename, strerror(-rc));
		goto out;
	}

	rc = _keystore_set_file_permission(keystore, filenames->info_filename);
	if (rc != 0) {
		remove(filenames->info_filename);
		goto out;
	}

out:
	properties_free(key_props);
	return rc;
}

/**
 * Extracts a card/domain pair from the specified APQns, or uses AUTOSELECT
 * if no APQNs are specified.
 */
static int _keystore_get_card_domain(const char *apqns, unsigned int *card,
				     unsigned int *domain)
{
	char **apqn_list;
	char *normalized = NULL;
	int rc = 0;

	*card = AUTOSELECT;
	*domain = AUTOSELECT;

	if (apqns == NULL)
		return 0;

	apqn_list = str_list_split(apqns);
	if (apqn_list[0] == NULL)
		goto out;

	rc = _keystore_apqn_check(apqn_list[0], 0, &normalized, NULL);
	if (normalized != NULL)
		free(normalized);
	if (rc != 0)
		goto out;

	if (sscanf(apqn_list[0], "%x.%x", card, domain) != 2) {
		rc = -EINVAL;
		goto out;
	}

out:
	str_list_free_string_array(apqn_list);
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
 * @param[in] pkey_fd     the file descriptor of /dev/pkey
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_generate_key(struct keystore *keystore, const char *name,
			  const char *description, const char *volumes,
			  const char *apqns, size_t sector_size,
			  size_t keybits, bool xts, const char *clear_key_file,
			  const char *volume_type, int pkey_fd)
{
	struct key_filenames file_names = { NULL, NULL, NULL };
	struct properties *key_props = NULL;
	unsigned int card, domain;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");
	util_assert(name != NULL, "Internal error: name is NULL");

	rc = _keystore_get_key_filenames(keystore, name, &file_names);
	if (rc != 0)
		goto out_free_key_filenames;

	rc = _keystore_ensure_keyfiles_not_exist(&file_names, name);
	if (rc != 0)
		goto out_free_key_filenames;

	rc = _keystore_get_card_domain(apqns, &card, &domain);
	if (rc != 0)
		goto out_free_key_filenames;

	if (clear_key_file == NULL)
		rc = generate_secure_key_random(pkey_fd,
						file_names.skey_filename,
						keybits, xts, card, domain,
						keystore->verbose);
	else
		rc = generate_secure_key_clear(pkey_fd,
					       file_names.skey_filename,
					       keybits, xts, clear_key_file,
					       card, domain,
					       keystore->verbose);
	if (rc != 0)
		goto out_free_props;

	rc = _keystore_set_file_permission(keystore, file_names.skey_filename);
	if (rc != 0)
		goto out_free_props;

	rc = _keystore_create_info_file(keystore, name, &file_names,
					description, volumes, apqns,
					sector_size, volume_type);
	if (rc != 0)
		goto out_free_props;

	pr_verbose(keystore,
		   "Successfully generated a secure key in '%s' and key info "
		   "in '%s'", file_names.skey_filename,
		   file_names.info_filename);

out_free_props:
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
 * Imports a secure key from a file and adds it to the key store
 *
 * @param[in] keystore    the key store
 * @param[in] name        the name of the key
 * @param[in] description textual description of the key (optional, can be NULL)
 * @param[in] volumes     a comma separated list of volumes associated with this
 *                        key (optional, can be NULL)
 * @param[in] apqns       a comma separated list of APQNs associated with this
 *                        key (optional, can be NULL)
 * @param[in] sector_size the sector size to use with dm-crypt. It must be power
 *                        of two and in range 512 - 4096 bytes. 0 means that
 *                        the sector size is not specified and the system
 *                        default is used.
 * @param[in] import_file The name of a secure key containing the key to import
 * @param[in] volume_type the type of volume
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_import_key(struct keystore *keystore, const char *name,
			const char *description, const char *volumes,
			const char *apqns, size_t sector_size,
			const char *import_file, const char *volume_type)
{
	struct key_filenames file_names = { NULL, NULL, NULL };
	struct properties *key_props = NULL;
	size_t secure_key_size;
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

	rc = write_secure_key(file_names.skey_filename, secure_key,
			      secure_key_size, keystore->verbose);
	free(secure_key);
	if (rc != 0)
		goto out_free_props;

	rc = _keystore_set_file_permission(keystore, file_names.skey_filename);
	if (rc != 0)
		goto out_free_props;

	rc = _keystore_create_info_file(keystore, name, &file_names,
					description, volumes, apqns,
					sector_size, volume_type);
	if (rc != 0)
		goto out_free_props;

	pr_verbose(keystore,
		   "Successfully imported a secure key in '%s' and key info in '%s'",
		   file_names.skey_filename, file_names.info_filename);

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
 * @param[in] sector_size the sector size to use with dm-crypt. It must be power
 *                        of two and in range 512 - 4096 bytes. 0 means that
 *                        the sector size is not specified and the system
 *                        default is used. Specify -1 if this property should
 *                        not be changed.
 * @param[in] volume_type the type of volume. If NULL then the volume type is
 *                        not changed.
 * *
 * @returns 0 for success or a negative errno in case of an error
 *
 */
int keystore_change_key(struct keystore *keystore, const char *name,
			const char *description, const char *volumes,
			const char *apqns, long int sector_size,
			const char *volume_type)
{
	struct volume_check vol_check = { .keystore = keystore, .name = name };
	struct key_filenames file_names = { NULL, NULL, NULL };
	struct properties *key_props = NULL;
	char temp[30];
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
	}

	if (apqns != NULL) {
		rc = _keystore_change_association(key_props, PROP_NAME_APQNS,
						  apqns, "APQN",
						  _keystore_apqn_check, NULL);
		if (rc != 0)
			goto out;
	}

	if (sector_size >= 0) {
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
	}

	if (volume_type != NULL) {
		if (!_keystore_valid_volume_type(volume_type)) {
			warnx("Invalid volume-type specified");
			rc = -EINVAL;
			goto out;
		}

		rc = properties_set(key_props, PROP_NAME_VOLUME_TYPE,
				    volume_type);
		if (rc != 0) {
			warnx("Invalid characters in volume-type");
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
	_keystore_free_key_filenames(&file_names);
	if (key_props != NULL)
		properties_free(key_props);

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
	struct key_filenames file_names = { NULL, NULL, NULL };
	struct key_filenames new_names = { NULL, NULL, NULL };
	struct properties *key_props = NULL;
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
		rename(new_names.skey_filename, file_names.skey_filename);
	}
	if (_keystore_reencipher_key_exists(&file_names)) {
		if (rename(file_names.renc_filename,
			   new_names.renc_filename) != 0) {
			rc = -errno;
			pr_verbose(keystore, "Failed to rename '%s': %s",
				   file_names.renc_filename, strerror(-rc));
			rename(new_names.skey_filename,
			       file_names.skey_filename);
			rename(new_names.info_filename,
			       file_names.info_filename);
		}
	}

	key_props = properties_new();
	rc = properties_load(key_props, new_names.info_filename, 1);
	if (rc != 0) {
		warnx("Key '%s' does not exist or is invalid", newname);
		goto out;
	}

	util_asprintf(&msg, "The following volumes are associated with the "
		      "renamed key '%s'. You should adjust the corresponding "
		      "crypttab entries and 'cryptsetup plainOpen' commands to "
		      "use the new name.", newname);
	_keystore_msg_for_volumes(msg, key_props, VOLUME_TYPE_PLAIN);
	free(msg);

	pr_verbose(keystore, "Successfully renamed key '%s' to '%s'", name,
		   newname);

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
				   size_t secure_key_size,
				   size_t clear_key_bitsize, bool valid,
				   bool is_old_mk, bool reenc_pending)
{
	char temp_vp[VERIFICATION_PATTERN_LEN + 2];
	char *volumes_argz = NULL;
	size_t volumes_argz_len;
	char *apqns_argz = NULL;
	size_t sector_size = 0;
	size_t apqns_argz_len;
	char *description;
	char *volume_type;
	char *reencipher;
	char *creation;
	char *volumes;
	char *change;
	char *apqns;
	char *temp;
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

	util_rec_set(rec, REC_KEY, name);
	if (validation)
		util_rec_set(rec, REC_STATUS, valid ? "Valid" : "Invalid");
	util_rec_set(rec, REC_DESCRIPTION,
		     description != NULL ? description : "");
	util_rec_set(rec, REC_SEC_KEY_SIZE, "%lu bytes", secure_key_size);
	if (!validation || valid)
		util_rec_set(rec, REC_CLR_KEY_SIZE, "%lu bits",
			     clear_key_bitsize);
	else
		util_rec_set(rec, REC_CLR_KEY_SIZE, "(unknown)");
	util_rec_set(rec, REC_XTS,
		     IS_XTS(secure_key_size) ? "Yes" : "No");
	if (validation) {
		if (valid)
			util_rec_set(rec, REC_MASTERKEY,
				     is_old_mk ? "OLD CCA master key" :
						     "CURRENT CCA master key");
		else
			util_rec_set(rec, REC_MASTERKEY, "(unknown)");
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
}

struct validate_info {
	struct util_rec *rec;
	int pkey_fd;
	unsigned long int num_valid;
	unsigned long int num_invalid;
	unsigned long int num_warnings;
};

/**
 * Displays the status of the associated APQNs.
 *
 * @param[in] properties  the properties of the key
 * @param[in] name        the name of the key
 *
 * @returns 0 in case of success, 1 if at least one of the APQNs is not
 *          available
 */
static int _keystore_display_apqn_status(struct properties *properties,
					 const char *name)
{
	int i, rc, card, domain, warning = 0;
	char **apqn_list;
	char *apqns;

	apqns = properties_get(properties, PROP_NAME_APQNS);
	if (apqns == NULL)
		return 0;
	apqn_list = str_list_split(apqns);

	for (i = 0; apqn_list[i] != NULL; i++) {

		if (sscanf(apqn_list[i], "%x.%x", &card, &domain) != 2)
			continue;

		rc = _keystore_is_apqn_online(card, domain);
		if (rc != 1) {
			printf("WARNING: The APQN %02x.%04x associated with "
			       "key '%s' is %s\n", card, domain, name,
			       rc == -1 ? "not a CCA card" : "not online");
			warning = 1;
		}
	}

	if (warning)
		printf("\n");

	free(apqns);
	str_list_free_string_array(apqn_list);
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
	size_t clear_key_bitsize;
	size_t secure_key_size;
	u8 *secure_key;
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

	rc = validate_secure_key(info->pkey_fd, secure_key, secure_key_size,
				 &clear_key_bitsize, &is_old_mk,
				 keystore->verbose);
	if (rc != 0) {
		valid = 0;
		info->num_invalid++;
		rc = 0;
	} else {
		info->num_valid++;
		valid = 1;
	}
	free(secure_key);

	_keystore_print_record(info->rec, name, properties, 1,
			       file_names->skey_filename, secure_key_size,
			       clear_key_bitsize, valid, is_old_mk,
			       _keystore_reencipher_key_exists(file_names));

	if (valid && is_old_mk) {
		util_print_indented("WARNING: The secure key is currently "
				    "enciphered with the OLD CCA master key. "
				    "To mitigate the danger of data loss "
				    "re-encipher it with the CURRENT CCA "
				    "master key\n", 0);
		info->num_warnings++;
	}
	if (_keystore_display_apqn_status(properties, name) != 0)
		info->num_warnings++;
	if (_keystore_display_volume_status(properties, name) != 0)
		info->num_warnings++;

out:
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
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_validate_key(struct keystore *keystore, const char *name_filter,
			  const char *apqn_filter, int pkey_fd)
{
	struct validate_info info;
	struct util_rec *rec;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	rec = _keystore_setup_record(1);

	info.pkey_fd = pkey_fd;
	info.rec = rec;
	info.num_valid = 0;
	info.num_invalid = 0;
	info.num_warnings = 0;

	rc = _keystore_process_filtered(keystore, name_filter, NULL,
					apqn_filter, NULL,
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
	t_CSNBKTC dll_CSNBKTC;
	unsigned long num_reenciphered;
	unsigned long num_failed;
	unsigned long num_skipped;
};

/**
 * Perform the reencipherment of a key
 *
 * @param[in] keystore   the keystore
 * @param[in] name       the name of the key
 * @param[in] dll_CSNBKTC the CCA key token change function
 * @param[in] params     reenciphering parameters
 * @param[in] secure_key a buffer containing the secure key
 * @param[in] secure_key_size the size of the secure key
 * @param[in] is_old_mk  if true the key is currently re-enciphered with the
 *            OLD master key
 * @returns 0 if the re-enciphering is successful, a negative errno value
 *          otherwise, 1 if it was skipped
 */
static int _keystore_perform_reencipher(struct keystore *keystore,
					const char *name,
					t_CSNBKTC dll_CSNBKTC,
					struct reencipher_params *params,
					u8 *secure_key, size_t secure_key_size,
					bool is_old_mk)
{
	int rc;

	if (!params->from_old && !params->to_new) {
		/* Autodetect reencipher mode */
		if (is_old_mk) {
			params->from_old = 1;
			util_print_indented("The secure key is currently "
					    "enciphered with the OLD CCA "
					    "master key and is being "
					    "re-enciphered with the CURRENT "
					    "CCA master key\n", 0);
		} else {
			params->to_new = 1;
			util_print_indented("The secure key is currently "
					    "enciphered with the CURRENT CCA "
					    "master key and is being "
					    "re-enciphered with the NEW CCA "
					    "master key\n", 0);
		}
	}

	if (params->from_old) {
		if (!is_old_mk) {
			printf("The secure key '%s' is already enciphered "
			       "with the CURRENT CCA master key\n", name);
			return 1;
		}

		if (params->inplace == -1)
			params->inplace = 1;

		pr_verbose(keystore,
			   "Secure key '%s' will be re-enciphered from OLD "
			   "to the CURRENT CCA master key", name);

		rc = key_token_change(dll_CSNBKTC,
				      secure_key, secure_key_size,
				      METHOD_OLD_TO_CURRENT,
				      keystore->verbose);
		if (rc != 0) {
			warnx("Failed to re-encipher '%s' from OLD to "
			      "CURRENT CCA master key", name);
			return rc;
		}
	}
	if (params->to_new) {
		pr_verbose(keystore,
			   "Secure key '%s' will be re-enciphered from "
			   "CURRENT to the NEW CCA master key", name);

		if (params->inplace == -1)
			params->inplace = 0;

		rc = key_token_change(dll_CSNBKTC,
				      secure_key, secure_key_size,
				      METHOD_CURRENT_TO_NEW,
				      keystore->verbose);
		if (rc != 0) {
			warnx("Failed to re-encipher '%s' from CURRENT to "
			      "NEW CCA master key", name);
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
	u8 *secure_key = NULL;
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

	rc = validate_secure_key(info->pkey_fd, secure_key, secure_key_size,
				 &clear_key_bitsize, &is_old_mk,
				 keystore->verbose);
	if (rc != 0) {
		if (params.complete) {
			warnx("Key '%s' is not valid, re-enciphering is not "
			      "completed", name);
			warnx("The new CCA master key might yet have to be set "
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

		rc = _keystore_perform_reencipher(keystore, name,
						  info->dll_CSNBKTC, &params,
						  secure_key, secure_key_size,
						  is_old_mk);
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
			      "key '%s'. After the NEW CCA master key has been "
			      "set to become the CURRENT master key run "
			      "'zkey reencipher' with option '--complete' to "
			      "complete the re-enciphering process", name);
		util_print_indented(temp, 0);
		free(temp);
	}

	info->num_reenciphered++;

out:
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
 *                         CURRENT CCA master key.
 * @param[in] to_new       If true the key is reenciphered from the CURRENT to
 *                         the OLD CCA master key.
 * @param[in] inplace      if true, the key will be re-enciphere in-place
 * @param[in] staged       if true, the key will be re-enciphere not in-place
 * @param[in] complete     if true, a pending re-encipherment is completed
 * Note: if both from Old and toNew are FALSE, then the reencipherement mode is
 *       detected automatically. If both are TRUE then the key is reenciphered
 *       from the OLD to the NEW CCA master key.
 * Note: if both inplace and staged are FLASE, then the key is re-enciphered
 *       inplace when for OLD-to-CURRENT, and is reenciphered staged for
 *       CURRENT-to-NEW.
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_reencipher_key(struct keystore *keystore, const char *name_filter,
			    const char *apqn_filter,
			    bool from_old, bool to_new, bool inplace,
			    bool staged, bool complete, int pkey_fd,
			    t_CSNBKTC dll_CSNBKTC)
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
	info.dll_CSNBKTC = dll_CSNBKTC;
	info.num_failed = 0;
	info.num_reenciphered = 0;
	info.num_skipped = 0;

	rc = _keystore_process_filtered(keystore, name_filter, NULL,
					apqn_filter, NULL,
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
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_copy_key(struct keystore *keystore, const char *name,
		      const char *newname, const char *volumes)
{
	struct volume_check vol_check = { .keystore = keystore,
					  .name = newname };
	struct key_filenames file_names = { NULL, NULL, NULL };
	struct key_filenames new_names = { NULL, NULL, NULL };
	struct properties *key_prop = NULL;
	size_t secure_key_size;
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

	key_prop = properties_new();
	rc = properties_load(key_prop, file_names.info_filename, 1);
	if (rc != 0) {
		warnx("Key '%s' does not exist or is invalid", name);
		remove(file_names.skey_filename);
		goto out;
	}

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

	rc = properties_save(key_prop, new_names.info_filename, 1);
	if (rc != 0) {
		pr_verbose(keystore,
			   "Key info file '%s' could not be written: %s",
			   new_names.info_filename, strerror(-rc));
		remove(new_names.skey_filename);
		goto out;
	}

	rc = _keystore_set_file_permission(keystore, new_names.info_filename);
	if (rc != 0)
		goto out;

	pr_verbose(keystore, "Successfully copied key '%s' to '%s'", name,
		   newname);

out:
	if (rc != 0) {
		remove(new_names.skey_filename);
		remove(new_names.info_filename);
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
	struct key_filenames file_names = { NULL, NULL, NULL };
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
static int _keystore_propmp_for_remove(struct keystore *keystore,
				       const char *name,
				       struct key_filenames *file_names)
{
	struct properties *key_prop;
	char str[20];
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

	printf("%s: Remove key '%s'? ", program_invocation_short_name, name);
	if (fgets(str, sizeof(str), stdin) == NULL) {
		rc = -EIO;
		goto out;
	}
	if (str[strlen(str) - 1] == '\n')
		str[strlen(str) - 1] = '\0';
	pr_verbose(keystore, "Prompt reply: '%s'", str);
	if (strcasecmp(str, "y") != 0 && strcasecmp(str, "yes") != 0) {
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
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_remove_key(struct keystore *keystore, const char *name,
			bool quiet)
{
	struct key_filenames file_names = { NULL, NULL, NULL };
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
		if (_keystore_propmp_for_remove(keystore, name,
						&file_names) != 0)
			goto out;
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
	pr_verbose(keystore, "Successfully removed key '%s'", name);

out:
	_keystore_free_key_filenames(&file_names);

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
	struct secaeskeytoken *secure_key;
	size_t secure_key_size;
	int rc = 0;

	secure_key = (struct secaeskeytoken *)
		     read_secure_key(file_names->skey_filename,
				     &secure_key_size, keystore->verbose);
	if (secure_key == NULL)
		return -EIO;

	if (secure_key_size < SECURE_KEY_SIZE) {
		pr_verbose(keystore,
			   "Size of secure key is too small: %lu expected %lu",
			   secure_key_size, SECURE_KEY_SIZE);
		rc = -EIO;
		goto out;
	}

	_keystore_print_record(rec, name, properties, 0,
			       file_names->skey_filename, secure_key_size,
			       IS_XTS(secure_key_size) ? secure_key->bitsize * 2
						       : secure_key->bitsize,
			       0, 0,
			       _keystore_reencipher_key_exists(file_names));

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
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_list_keys(struct keystore *keystore, const char *name_filter,
		       const char *volume_filter, const char *apqn_filter,
		       const char *volume_type)
{
	struct util_rec *rec;
	int rc;

	util_assert(keystore != NULL, "Internal error: keystore is NULL");

	if (volume_type != NULL &&
	    !_keystore_valid_volume_type(volume_type)) {
		warnx("Invalid volume-type specified");
		return -EINVAL;
	}

	rec = _keystore_setup_record(0);

	rc = _keystore_process_filtered(keystore, name_filter, volume_filter,
					apqn_filter, volume_type,
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
	char **volume_filter;
	int (*process_func)(struct keystore *keystore,
			    const char *volume,
			    const char *dmname,
			    const char *cipher_spec,
			    const char *key_file_name,
			    size_t key_file_size,
			    size_t sector_size,
			    const char *volume_type,
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
					struct crypt_info *info)
{
	char temp[100];
	int rc = 0;
	char *cmd;

	sprintf(temp, "--sector-size %lu ", sector_size);

	if (strcasecmp(volume_type, VOLUME_TYPE_PLAIN) == 0) {
		util_asprintf(&cmd,
			      "cryptsetup plainOpen %s--key-file '%s' "
			      "--key-size %lu --cipher %s %s%s %s",
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
		/*
		 * Use PBKDF2 as key derivation function for LUKS2 volumes.
		 * LUKS2 uses Argon2i as default, but this might cause
		 * out-of-memory errors when multiple LUKS2 volumes are opened
		 * automatically via /etc/crypttab
		 */
		util_asprintf(&cmd,
			      "cryptsetup luksFormat %s--type luks2 "
			      "--master-key-file '%s' --key-size %lu "
			      "--cipher %s --pbkdf pbkdf2 %s%s",
			      keystore->verbose ? "-v " : "", key_file_name,
			      key_file_size * 8, cipher_spec,
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
			      "zkey-cryptsetup setvp %s%s", volume,
			      keystore->verbose ? " -V " : "");

		if (info->execute) {
			printf("Executing: %s\n", cmd);
			rc = _keystore_execute_cmd(cmd, "zkey-cryptsetup");
		} else {
			printf("%s\n", cmd);
		}
	} else {
		return -EINVAL;
	}

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
				      struct crypt_info *UNUSED(info))
{
	char temp[1000];

	if (strcasecmp(volume_type, VOLUME_TYPE_PLAIN) == 0) {
		if (sector_size > 0) {
			sprintf(temp,
				"WARNING: volume '%s' is using a sector size "
				"of %lu. At the time this utility was "
				"developed, systemd's support of crypttab did "
				"not support to specify a sector size with "
				"plain dm-crypt devices. The generated "
				"crypttab entry might or might not work, and "
				"might need manual adoptions.", volume,
				sector_size);
			util_print_indented(temp, 0);
		}

		sprintf(temp, ",sector-size=%lu", sector_size);
		printf("%s\t%s\t%s\tplain,cipher=%s,size=%lu,hash=plain%s\n",
		       dmname, volume, key_file_name, cipher_spec,
		       key_file_size * 8, sector_size > 0 ? temp : "");
	} else if (strcasecmp(volume_type, VOLUME_TYPE_LUKS2) == 0) {
		printf("%s\t%s\n", dmname, volume);
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
 * Returns the size of the secure key file
 *
 * @param[in] keystore   the keystore
 * @param[in] skey_filename the file name of the secure key
 *
 * @returns the size of the secure key, or -1 in case of an error
 */
static size_t _keystore_get_key_file_size(struct keystore *keystore,
					  const char *skey_filename)
{
	size_t secure_key_size;
	struct stat sb;

	if (stat(skey_filename, &sb)) {
		pr_verbose(keystore, "Key file '%s': %s",
			   skey_filename, strerror(errno));
		return -1;
	}

	secure_key_size = sb.st_size;
	if (secure_key_size < SECURE_KEY_SIZE) {
		pr_verbose(keystore,
			   "Size of secure key is too small: %lu expected %lu",
			   secure_key_size, SECURE_KEY_SIZE);
		return -1;
	}

	return secure_key_size;
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
	char *dmname;
	char *temp;
	int rc = 0;
	char *vol;
	char *ch;
	int i;

	secure_key_size = _keystore_get_key_file_size(keystore,
						file_names->skey_filename);
	if (secure_key_size < SECURE_KEY_SIZE) {
		pr_verbose(keystore,
			   "Size of secure key is too small: %lu expected %lu",
			   secure_key_size, SECURE_KEY_SIZE);
		rc = -EIO;
		goto out;
	}

	cipher_spec = _keystore_build_cipher_spec(properties,
						  IS_XTS(secure_key_size));
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
					volume_type, info);
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
 * *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_cryptsetup(struct keystore *keystore, const char *volume_filter,
			bool execute, const char *volume_type)
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
	info.volume_filter = str_list_split(volume_filter);
	info.process_func = _keystore_process_cryptsetup;

	rc = _keystore_process_filtered(keystore, NULL, volume_filter, NULL,
					volume_type, _keystore_process_crypt,
					&info);

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
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int keystore_crypttab(struct keystore *keystore, const char *volume_filter,
		      const char *volume_type)
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

	info.volume_filter = str_list_split(volume_filter);
	info.process_func = _keystore_process_crypttab;

	rc = _keystore_process_filtered(keystore, NULL, volume_filter, NULL,
					volume_type, _keystore_process_crypt,
					&info);

	str_list_free_string_array(info.volume_filter);

	if (rc != 0)
		pr_verbose(keystore, "Cryptsetup failed with: %s",
			   strerror(-rc));
	else
		pr_verbose(keystore, "Successfully generated crypttab entries");

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
