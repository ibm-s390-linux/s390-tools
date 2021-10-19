/*
 * zkey-kmip - KMIP zkey KMS plugin
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#define _DEFAULT_SOURCE
#include <dirent.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <regex.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include "lib/zt_common.h"
#include "lib/util_libc.h"

#include "zkey-kmip.h"
#include "../properties.h"

#define _set_error(ph, fmt...)	plugin_set_error(&(ph)->pd, fmt)

/**
 * Returns the profile directory. If environment variable ZKEY_KMIP_PROFILES
 * is set, then its value specifies the profile directory, otherwise the
 * default profile directory '/etc/zkey/kmip/profiles' is returned.
 */
static const char *get_profiles_directory(void)
{
	const char *dir;

	dir = secure_getenv(KMIP_PROFILES_LOCATION_ENVVAR);

	return dir != NULL ? dir : KMIP_PROFILES_LOCATION;
}

static int profile_get_bool(struct plugin_handle *ph, struct properties *props,
			    const char *file_name, const char *prop_name,
			    bool default_val, bool *bool_var)
{
	int rc = 0;
	char *val;

	val = properties_get(props, prop_name);
	if (val == NULL) {
		*bool_var = default_val;
		goto ret;
	}

	if (strcasecmp(val, KMIP_PROFILES_BOOLEAN_FALSE) == 0) {
		*bool_var = false;
	} else if (strcasecmp(val, KMIP_PROFILES_BOOLEAN_TRUE) == 0) {
		*bool_var = true;
	} else {
		_set_error(ph, "Profile '%s': Invalid value for '%s': '%s'",
			   file_name, prop_name,
			   val);
		rc = -EINVAL;
		goto out;
	}

out:
	free(val);

ret:
	if (rc == 0)
		pr_verbose(&ph->pd, "Profile: '%s': '%s'", prop_name,
			   *bool_var ? "True" : "False");

	return rc;
}

/**
 * Reads a profile from a file
 *
 * @param ph                the plugin handle
 * @param profile_dir       the directory containing the profiles. If NULL, then
 *                          the default profile directory or the one specified
 *                          by environment variable ZKEY_KMIP_PROFILES is used.
 * @param profile_file      name of the profile file to read
 * @param profile           On return: the allocated profile. The caller must
 *                          free the profile with profile_free.
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int profile_read(struct plugin_handle *ph, const char *profile_dir,
		 const char *profile_file, struct kmip_profile **profile)
{
	struct kmip_profile *prof = NULL;
	struct properties *props;
	char *file_name = NULL;
	char *val = NULL, *tok;
	int rc;

	if (profile_dir == NULL)
		profile_dir = get_profiles_directory();

	util_asprintf(&file_name, "%s/%s", profile_dir, profile_file);
	pr_verbose(&ph->pd, "Read profile from '%s'", file_name);

	props = properties_new();
	rc = properties_load(props, file_name, false);
	if (rc != 0) {
		_set_error(ph, "Failed to read profile from file '%s': %s",
			   file_name, strerror(-rc));
		goto out;
	}

	prof = util_zalloc(sizeof(struct kmip_profile));

	tok = strrchr(profile_file, '/');
	if (tok == NULL)
		tok = (char *)profile_file;
	prof->name = util_strdup(tok);
	tok = strchr(prof->name, '.');
	if (tok != NULL)
		*tok = 0;

	pr_verbose(&ph->pd, "Profile name: '%s'", prof->name);

	prof->server_regex = properties_get(props, KMIP_PROFILES_SERVER_REGEX);
	if (prof->server_regex == NULL) {
		_set_error(ph, "Profile '%s': Missing value for '%s'",
			   file_name, KMIP_PROFILES_SERVER_REGEX);
		rc = -EINVAL;
		goto out;
	}
	pr_verbose(&ph->pd, "Profile: '%s': '%s'", KMIP_PROFILES_SERVER_REGEX,
		   prof->server_regex);

	val = properties_get(props, KMIP_PROFILES_KMIP_VERSION);
	if (val == NULL)
		val = util_strdup(KMIP_PROFILES_VERSION_AUTO);
	pr_verbose(&ph->pd, "Profile: '%s': '%s'", KMIP_PROFILES_KMIP_VERSION,
		   val);
	if (strcasecmp(val, KMIP_PROFILES_VERSION_AUTO) == 0) {
		prof->kmip_version.major = 0;
		prof->kmip_version.minor = 0;
	} else {
		if (sscanf(val, "%u.%u", &prof->kmip_version.major,
			   &prof->kmip_version.minor) != 2) {
			_set_error(ph, "Profile '%s': Invalid value for '%s': "
				   "'%s'", file_name,
				   KMIP_PROFILES_KMIP_VERSION, val);
			rc = -EINVAL;
			goto out;
		}
		if (prof->kmip_version.major == 0) {
			_set_error(ph, "Profile '%s': Invalid value for '%s': "
				   "'%s'", file_name,
				   KMIP_PROFILES_KMIP_VERSION, val);
			rc = -EINVAL;
			goto out;
		}
	}
	free(val);

	val = properties_get(props, KMIP_PROFILES_TRANSPORT);
	if (val == NULL)
		val = util_strdup(KMIP_PROFILES_TRANSPORT_TLS);
	pr_verbose(&ph->pd, "Profile: '%s': '%s'", KMIP_PROFILES_TRANSPORT,
		   val);
	if (strcasecmp(val, KMIP_PROFILES_TRANSPORT_TLS) == 0) {
		prof->transport = KMIP_TRANSPORT_PLAIN_TLS;
	} else if (strcasecmp(val, KMIP_PROFILES_TRANSPORT_HTTPS) == 0) {
		prof->transport = KMIP_TRANSPORT_HTTPS;
	} else {
		_set_error(ph, "Profile '%s': Invalid value for '%s': '%s'",
			   file_name, KMIP_PROFILES_TRANSPORT, val);
		rc = -EINVAL;
		goto out;
	}
	free(val);


	val = properties_get(props, KMIP_PROFILES_ENCODING);
	if (val == NULL)
		val = util_strdup(KMIP_PROFILES_ENCODING_TTLV);
	pr_verbose(&ph->pd, "Profile: '%s': '%s'", KMIP_PROFILES_ENCODING,
		   val);
	if (strcasecmp(val, KMIP_PROFILES_ENCODING_TTLV) == 0) {
		prof->encoding = KMIP_ENCODING_TTLV;
	} else if (strcasecmp(val, KMIP_PROFILES_ENCODING_JSON) == 0) {
		if (prof->transport != KMIP_TRANSPORT_HTTPS) {
			_set_error(ph, "Profile '%s': JSON encoding is only "
				   "possible with HTTP transport",
				   file_name);
			rc = -EINVAL;
			goto out;
		}
		prof->encoding = KMIP_ENCODING_JSON;
	} else if (strcasecmp(val, KMIP_PROFILES_ENCODING_XML) == 0) {
		prof->encoding = KMIP_ENCODING_XML;
		if (prof->transport != KMIP_TRANSPORT_HTTPS) {
			_set_error(ph, "Profile '%s': XML encoding is only "
				   "possible with HTTP transport",
				   file_name);
			rc = -EINVAL;
			goto out;
		}
	} else {
		_set_error(ph, "Profile '%s': Invalid value for '%s': '%s'",
			   file_name, KMIP_PROFILES_ENCODING, val);
		rc = -EINVAL;
		goto out;
	}
	free(val);

	val = properties_get(props, KMIP_PROFILES_HTTPS_URI);
	switch (prof->transport) {
	case KMIP_TRANSPORT_HTTPS:
		if (val == NULL)
			val = util_strdup(KMIP_PROFILES_HTTPS_URI_DEFAULT);
		prof->https_uri = val;
		pr_verbose(&ph->pd, "Profile: '%s': '%s'",
			   KMIP_PROFILES_HTTPS_URI, prof->https_uri);
		break;
	default:
		if (val != NULL) {
			pr_verbose(&ph->pd, "Profile: '%s': ignored '%s'",
				   KMIP_PROFILES_HTTPS_URI, val);
			free(val);
		}
		break;
	}

	val = properties_get(props, KMIP_PROFILES_AUTH_SCHEME);
	if (val == NULL)
		val = util_strdup(KMIP_PROFILES_AUTH_TLS_CLIENT_CERT);
	pr_verbose(&ph->pd, "Profile: '%s': '%s'", KMIP_PROFILES_AUTH_SCHEME,
		   val);
	if (strcasecmp(val, KMIP_PROFILES_AUTH_TLS_CLIENT_CERT) == 0) {
		prof->auth_scheme = KMIP_PROFILE_AUTH_TLS_CLIENT_CERT;
	} else {
		_set_error(ph, "Profile '%s': Invalid value for '%s': '%s'",
			   file_name, KMIP_PROFILES_AUTH_SCHEME, val);
		rc = -EINVAL;
		goto out;
	}
	free(val);

	val = properties_get(props, KMIP_PROFILES_WRAP_KEY_ALGORITHM);
	if (val == NULL)
		val = util_strdup(KMIP_PROFILES_WRAP_KEY_ALGORITHM_RSA);
	pr_verbose(&ph->pd, "Profile: '%s': '%s'",
		   KMIP_PROFILES_WRAP_KEY_ALGORITHM, val);
	if (strcasecmp(val, KMIP_PROFILES_WRAP_KEY_ALGORITHM_RSA) == 0) {
		prof->wrap_key_algo = KMIP_CRYPTO_ALGO_RSA;
	} else {
		_set_error(ph, "Profile '%s': Invalid value for '%s': '%s'",
			   file_name, KMIP_PROFILES_WRAP_KEY_ALGORITHM, val);
		rc = -EINVAL;
		goto out;
	}
	free(val);

	val = properties_get(props, KMIP_PROFILES_WRAP_KEY_PARAMS);
	if (prof->wrap_key_algo == KMIP_CRYPTO_ALGO_RSA) {
		if (val == NULL) {
			_set_error(ph, "Profile '%s': Missing value for '%s'",
				   file_name, KMIP_PROFILES_WRAP_KEY_PARAMS);
			rc = -EINVAL;
			goto out;
		}
		pr_verbose(&ph->pd, "Profile: '%s': '%s'",
			   KMIP_PROFILES_WRAP_KEY_PARAMS, val);
		prof->wrap_key_size = atoi(val);
		if (prof->wrap_key_size == 0) {
			_set_error(ph, "Profile '%s': Invalid value for '%s' "
				   "(RSA modulus size): '%s'", file_name,
				   KMIP_PROFILES_WRAP_KEY_PARAMS, val);
			rc = -EINVAL;
			goto out;
		}
	} else if (val != NULL) {
		pr_verbose(&ph->pd, "Profile: '%s': ignored '%s'",
			   KMIP_PROFILES_WRAP_KEY_PARAMS, val);
	}
	free(val);

	val = properties_get(props, KMIP_PROFILES_WRAP_KEY_FORMAT);
	switch (prof->wrap_key_algo) {
	case KMIP_CRYPTO_ALGO_RSA:
		if (val == NULL)
			val = util_strdup(KMIP_PROFILES_WRAP_KEY_FORMAT_PKCS1);
		pr_verbose(&ph->pd, "Profile: '%s': '%s'",
				KMIP_PROFILES_WRAP_KEY_FORMAT, val);
		if (strcasecmp(val, KMIP_PROFILES_WRAP_KEY_FORMAT_PKCS1) == 0) {
			prof->wrap_key_format = KMIP_KEY_FORMAT_TYPE_PKCS_1;
		} else if (strcasecmp(val,
				KMIP_PROFILES_WRAP_KEY_FORMAT_PKCS8) == 0) {
			prof->wrap_key_format = KMIP_KEY_FORMAT_TYPE_PKCS_8;
		} else if (strcasecmp(val,
				KMIP_PROFILES_WRAP_KEY_FORMAT_TRANSP) == 0) {
			prof->wrap_key_format =
				KMIP_KEY_FORMAT_TYPE_TRANSPARENT_RSA_PUBLIC_KEY;
		} else {
			_set_error(ph, "Profile '%s': Invalid value for '%s': "
				   "'%s'", file_name,
				   KMIP_PROFILES_WRAP_KEY_FORMAT, val);
			rc = -EINVAL;
			goto out;
		}
		break;
	default:
		if (val != NULL)
			pr_verbose(&ph->pd, "Profile: '%s': ignored '%s'",
				   KMIP_PROFILES_WRAP_KEY_FORMAT, val);
		break;
	}
	free(val);

	val = properties_get(props, KMIP_PROFILES_WRAP_PADDING_METHOD);
	switch (prof->wrap_key_algo) {
	case KMIP_CRYPTO_ALGO_RSA:
		if (val == NULL)
			val = util_strdup(KMIP_PROFILES_WRAP_PADDING_PKCS1_5);
		pr_verbose(&ph->pd, "Profile: '%s': '%s'",
			   KMIP_PROFILES_WRAP_PADDING_METHOD, val);
		if (strcasecmp(val, KMIP_PROFILES_WRAP_PADDING_PKCS1_5) == 0) {
			prof->wrap_padding_method =
					KMIP_PADDING_METHOD_PKCS_1_5;
		} else if (strcasecmp(val,
				      KMIP_PROFILES_WRAP_PADDING_OAEP) == 0) {
			prof->wrap_padding_method = KMIP_PADDING_METHOD_OAEP;
		} else {
			_set_error(ph, "Profile '%s': Invalid value for '%s': "
				   "'%s'", file_name,
				   KMIP_PROFILES_WRAP_PADDING_METHOD, val);
			rc = -EINVAL;
			goto out;
		}
		break;
	default:
		if (val != NULL)
			pr_verbose(&ph->pd, "Profile: '%s': ignored '%s'",
				   KMIP_PROFILES_WRAP_PADDING_METHOD, val);
		break;
	}
	free(val);

	val = properties_get(props, KMIP_PROFILES_WRAP_HASHING_ALOGRITHM);
	switch (prof->wrap_padding_method) {
	case KMIP_PADDING_METHOD_OAEP:
		if (val == NULL)
			val = util_strdup(KMIP_PROFILES_WRAP_HASHING_ALGO_SHA1);
		pr_verbose(&ph->pd, "Profile: '%s': '%s'",
			   KMIP_PROFILES_WRAP_HASHING_ALOGRITHM, val);
		if (strcasecmp(val,
			       KMIP_PROFILES_WRAP_HASHING_ALGO_SHA1) == 0) {
			prof->wrap_hashing_algo = KMIP_HASHING_ALGO_SHA_1;
		} else if (strcasecmp(val,
				KMIP_PROFILES_WRAP_HASHING_ALGO_SHA256) == 0) {
			prof->wrap_hashing_algo = KMIP_HASHING_ALGO_SHA_256;
		} else {
			_set_error(ph, "Profile '%s': Invalid value for '%s': "
				   "'%s'", file_name,
				   KMIP_PROFILES_WRAP_PADDING_METHOD, val);
			rc = -EINVAL;
			goto out;
		}
		break;
	default:
		if (val != NULL)
			pr_verbose(&ph->pd, "Profile: '%s': ignored '%s'",
				   KMIP_PROFILES_WRAP_HASHING_ALOGRITHM, val);
		break;
	}
	free(val);

	rc = profile_get_bool(ph, props, file_name,
			      KMIP_PROFILES_SUPPORTS_LINK_ATTR, false,
			      &prof->supports_link_attr);
	if (rc != 0)
		goto out;

	rc = profile_get_bool(ph, props, file_name,
			      KMIP_PROFILES_SUPPORTS_DESCRIPTION_ATTR, false,
			      &prof->supports_description_attr);
	if (rc != 0)
		goto out;

	rc = profile_get_bool(ph, props, file_name,
			      KMIP_PROFILES_SUPPORTS_COMMENT_ATTR, false,
			      &prof->supports_comment_attr);
	if (rc != 0)
		goto out;

	val = properties_get(props, KMIP_PROFILES_CUSTOM_ATTR_SCHEME);
	if (val == NULL)
		val = util_strdup(KMIP_PROFILES_CUST_ATTR_SCHEME_V1);
	pr_verbose(&ph->pd, "Profile: '%s': '%s'",
		  KMIP_PROFILES_CUSTOM_ATTR_SCHEME, val);
	if (strcasecmp(val, KMIP_PROFILES_CUST_ATTR_SCHEME_V1) == 0) {
		prof->cust_attr_scheme = KMIP_PROFILE_CUST_ATTR_V1_STYLE;
	} else if (strcasecmp(val, KMIP_PROFILES_CUST_ATTR_SCHEME_V2) == 0) {
		prof->cust_attr_scheme = KMIP_PROFILE_CUST_ATTR_V2_STYLE;
	} else {
		_set_error(ph, "Profile '%s': Invalid value for '%s': '%s'",
			   file_name, KMIP_PROFILES_CUSTOM_ATTR_SCHEME, val);
		rc = -EINVAL;
		goto out;
	}
	free(val);

	rc = profile_get_bool(ph, props, file_name,
			      KMIP_PROFILES_SUPPORTS_SENSITIVE_ATTR, false,
			      &prof->supports_sensitive_attr);
	if (rc != 0)
		goto out;

	rc = profile_get_bool(ph, props, file_name,
			      KMIP_PROFILES_CHECK_ALWAYS_SENS_ATTR, false,
			      &prof->check_always_sensitive_attr);
	if (rc != 0)
		goto out;

	val = NULL;

out:
	properties_free(props);
	if (file_name != NULL)
		free(file_name);
	if (val != NULL)
		free(val);

	if (rc != 0)
		profile_free(prof);
	else
		*profile = prof;

	return rc;
}

/**
 * Frees a profile
 *
 * @param profile           On return: the allocated profile
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
void profile_free(struct kmip_profile *profile)
{
	if (profile == NULL)
		return;

	if (profile->name != NULL)
		free((char *)profile->name);
	if (profile->server_regex != NULL)
		free((char *)profile->server_regex);
	if (profile->https_uri != NULL)
		free((char *)profile->https_uri);

	free(profile);
}

/**
 * Filters directory entries for scanfile(). Only entries that are regular
 * files and who's name ends with '.info' are matched.
 */
static int profile_file_filter(const struct dirent *dirent)
{
	size_t len;

	if (dirent->d_type != DT_REG && dirent->d_type != DT_UNKNOWN)
		return 0;

	len = strlen(dirent->d_name);
	if (len > KMIP_PROFILES_FILE_TYPE_LEN &&
	    strcmp(&dirent->d_name[len - KMIP_PROFILES_FILE_TYPE_LEN],
		   KMIP_PROFILES_FILE_TYPE) == 0)
		return 1;

	return 0;
}

/**
 * Scans the default profile directory or the one specified by environment
 * variable ZKEY_KMIP_PROFILES for profiles that match the server info.
 * Returns the first profile that matches, or the default profile if none
 * matches.
 *
 * @param ph                the plugin handle
 * @param server_info       the server info string to match the profiles against
 * @param profile           On return: the matched profile. The caller must free
 *                          the profile with profile_free.
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int profile_find_by_server_info(struct plugin_handle *ph,
				const char *server_info,
				struct kmip_profile **profile)
{
	struct kmip_profile *prof = NULL;
	struct dirent **namelist;
	const char *profile_dir;
	regmatch_t pmatch[1];
	char err_buf[256];
	int i, n, rc = 0;
	regex_t reg_buf;

	profile_dir = get_profiles_directory();
	pr_verbose(&ph->pd, "profile_dir: %s", profile_dir);

	n = scandir(profile_dir, &namelist, profile_file_filter, alphasort);
	if (n < 0) {
		rc = -errno;
		pr_verbose(&ph->pd, "scandir failed with: %s", strerror(-rc));
		return rc;
	}

	for (i = 0; i < n; i++) {
		if (strcmp(namelist[i]->d_name,
			   KMIP_PROFILES_DEFAULT_PROFILE) == 0)
			continue;

		pr_verbose(&ph->pd, "Found profile '%s'", namelist[i]->d_name);

		rc = profile_read(ph, profile_dir, namelist[i]->d_name, &prof);
		if (rc != 0) {
			pr_verbose(&ph->pd, "profile_read failed with: %s",
				   strerror(-rc));
			goto out;
		}

		rc = regcomp(&reg_buf, prof->server_regex, REG_EXTENDED);
		if (rc != 0) {
			regerror(rc, &reg_buf, err_buf, sizeof(err_buf));
			_set_error(ph, "Profile '%s': Regular expression "
				   "error: '%s'", namelist[i]->d_name, err_buf);
			rc = -EINVAL;
			goto out;
		}

		rc = regexec(&reg_buf, server_info, (size_t)1, pmatch, 0);
		regfree(&reg_buf);
		if (rc == 0)
			break;

		profile_free(prof);
		prof = NULL;
	}

	if (prof == NULL) {
		rc = profile_read(ph, profile_dir,
				  KMIP_PROFILES_DEFAULT_PROFILE, &prof);
		if (rc != 0) {
			pr_verbose(&ph->pd, "default profile_read failed with: "
				   "%s", strerror(-rc));
			goto out;
		}
	}

	*profile = prof;

out:
	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);

	return rc;
}

/**
 * Reads a profile by its name. Tries to find a profile with the specified name
 * in the default profile directory or the one specified by environment
 * variable ZKEY_KMIP_PROFILES and loads it.
 *
 * @param ph                the plugin handle
 * @param profile_name      name of the profile to read
 * @param profile           On return: the allocated profile. The caller must
 *                          free the profile with profile_free.
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int profile_find_by_name(struct plugin_handle *ph, const char *profile_name,
			 struct kmip_profile **profile)
{
	char *profile_file;
	int rc;

	util_asprintf(&profile_file, "%s%s", profile_name,
		      KMIP_PROFILES_FILE_TYPE);

	rc = profile_read(ph, NULL, profile_file, profile);

	free(profile_file);
	return rc;
}
