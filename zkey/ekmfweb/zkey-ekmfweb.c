/*
 * zkey-ekmfweb - EKMFWeb zkey KMS plugin
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <argz.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <sys/utsname.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "lib/zt_common.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_base.h"
#include "lib/util_rec.h"

#include "zkey-ekmfweb.h"
#include "../kms-plugin.h"
#include "../cca.h"
#include "../utils.h"
#include "../pkey.h"
#include "../properties.h"

#define pr_verbose(handle, fmt...)				\
	do {							\
		if (handle->verbose) {				\
			fprintf(stderr, "zkey-ekmfweb: ");	\
			fprintf(stderr, fmt);			\
			fprintf(stderr, "\n");			\
		}						\
	} while (0)

#define FREE_AND_SET_NULL(ptr)					\
	do {							\
		if ((ptr) != NULL)				\
			free((void *)ptr);			\
		(ptr) = NULL;					\
	} while (0)

/**
 * Clears the error message in the plugin handle
 *
 * @param ph                the plugin handle
 */
static void _clear_error(struct plugin_handle *ph)
{
	memset(ph->error_msg, 0, sizeof(ph->error_msg));
}

/**
 * Sets the error message in the plugin handle
 *
 * @param ph                the plugin handle
 * @param fmt               the format string for sprintf
 */
static void _set_error(struct plugin_handle *ph, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(ph->error_msg, sizeof(ph->error_msg), fmt, ap);
	va_end(ap);
}

/**
 * Informs a KMS plugin that it is bound to a zkey repository.
 *
 * Note: This function is called before kms_initialize()!
 *
 * @param config_path       name of a directory where the KMS plugin can store
 *                          its configuration and other files it needs to store
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
int kms_bind(const char *UNUSED(config_path))
{
	return 0;
}

/**
 * Load the EKMFWeb plugin config file
 *
 * @param ph                the plugin handle
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _load_config(struct plugin_handle *ph)
{
	char *file_name = NULL;
	int rc;

	util_asprintf(&file_name, "%s/%s", ph->config_path,
		      EKMFWEB_CONFIG_FILE);

	rc = properties_load(ph->properties, file_name, true);
	if (rc != 0)
		pr_verbose(ph, "Failed to load plugin config file '%s': %s",
			   file_name, strerror(-rc));
	else
		pr_verbose(ph, "Config file '%s' loaded", file_name);

	free(file_name);
	return rc;
}

/**
 * Sets the file permissions of the file to the permissions and the group
 * of configuration directory
 *
 * @param ph                the plugin handle
 * @param filename           the name of the file to set permissions for
 *
 * @returns 0 on success, or a negative errno value on failure
 */
static int _set_file_permission(struct plugin_handle *ph, const char *filename)
{
	int rc;

	if (chmod(filename, ph->config_path_mode) != 0) {
		rc = -errno;
		_set_error(ph, "chmod failed on file '%s': %s", filename,
			   strerror(-rc));
		return rc;
	}

	if (chown(filename, geteuid(), ph->config_path_owner) != 0) {
		rc = -errno;
		_set_error(ph, "chown failed on file '%s': %s", filename,
			   strerror(-rc));
		return rc;
	}

	return 0;
}

/**
 * Makes a temporary file an active file, by first removing the current active
 * file (if existent), and then renaming the temporary file to the active file.
 * The active file permissions are also set to the permissions and the group of
 * configuration directory.
 *
 * @param ph                the plugin handle
 * @param temp_file         the name of the temporary file
 * @param active_file       the name of the active file
 *
 * @returns 0 on success, or a negative errno value on failure
 */
static int _activate_temp_file(struct plugin_handle *ph, const char *temp_file,
			       const char *active_file)
{
	int rc;

	if (util_path_exists(active_file)) {
		rc = remove(active_file);
		if (rc != 0) {
			rc = -errno;
			_set_error(ph, "remove failed on file '%s': %s",
				   active_file, strerror(-rc));
			return rc;
		}
	}

	rc = rename(temp_file, active_file);
	if (rc != 0) {
		rc = -errno;
		_set_error(ph, "rename failed on file '%s': %s",
			   temp_file, strerror(-rc));
		return rc;
	}

	return _set_file_permission(ph, active_file);
}

/**
 * Save the EKMFWeb plugin config file
 *
 * @param ph                the plugin handle
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _save_config(struct plugin_handle *ph)
{
	char *file_name = NULL;
	int rc;

	util_asprintf(&file_name, "%s/%s", ph->config_path,
		      EKMFWEB_CONFIG_FILE);

	pr_verbose(ph, "Saving '%s'", file_name);

	rc = properties_save(ph->properties, file_name, true);
	if (rc != 0) {
		_set_error(ph, "Failed to save plugin config file '%s': %s",
			   file_name, strerror(-rc));
		goto out;
	}

	rc = _set_file_permission(ph, file_name);
	if (rc != 0)
		goto out;

out:
	free(file_name);
	return rc;
}

/**
 * Base64-encodes the passphrase to make it unreadable.
 *
 * @param passphrase        the passphrase to encode
 *
 * @returns the encoded passphrase or NULL in case of an error.
 * The caller must free the string when no longer needed.
 */
static char *_encode_passphrase(const char *passphrase)
{
	int inlen, outlen, len;
	char *out;

	inlen = strlen(passphrase);
	outlen = (inlen / 3) * 4;
	if (inlen % 3 > 0)
		outlen += 4;

	out = util_malloc(outlen + 1);
	memset(out, 0, outlen + 1);

	len = EVP_EncodeBlock((unsigned char *)out, (unsigned char *)passphrase,
			      inlen);
	if (len != outlen) {
		free(out);
		return NULL;
	}

	out[outlen] = '\0';
	return out;
}

/**
 * Base64-decodes the passphrase
 *
 * @param passphrase        the passphrase to decode
 *
 * @returns the decoded passphrase or NULL in case of an error.
 * The caller must free the string when no longer needed.
 */
static char *_decode_passphrase(const char *passphrase)
{
	int inlen, outlen, len;
	char *out;

	inlen = strlen(passphrase);
	outlen = (inlen / 4) * 3;
	if (inlen % 4 > 0)
		outlen += 3;

	out = util_malloc(outlen + 1);
	memset(out, 0, outlen + 1);

	len = EVP_DecodeBlock((unsigned char *)out, (unsigned char *)passphrase,
			      inlen);
	if (len != outlen) {
		free(out);
		return NULL;
	}

	out[outlen] = '\0';
	return out;
}

/**
 * Sets or removes a property. If value is NULL it is removed, otherwise it
 * is set.
 *
 * @param ph                the plugin handle
 * @param name              the name of the property
 * @param value             the value of the property or NULL
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _set_or_remove_property(struct plugin_handle *ph, const char *name,
				   const char *value)
{
	int rc = 0;

	if (value != NULL) {
		rc = properties_set(ph->properties, name, value);
		if (rc != 0) {
			_set_error(ph, "Failed to set property '%s': %s", name,
				   strerror(-rc));
			goto out;
		}
	} else {
		rc = properties_remove(ph->properties, name);
		if (rc != 0 && rc != -ENOENT) {
			_set_error(ph, "Failed to remove property '%s': %s",
				   name, strerror(-rc));
			goto out;
		}
		rc = 0;
	}

out:
	return rc;
}

/**
 * Checks if a plugin config propertiy is set and not empty
 *
 * @param ph                the plugin handle
 * @param name              the name of the property
 *
 * @returns true if the property is set and is not empty, false otherwise
 */
static bool _check_property(struct plugin_handle *ph, const char *name)
{
	bool ok = true;
	char *value;

	value = properties_get(ph->properties, name);
	pr_verbose(ph, "Property '%s': %s", name,
		   value != NULL ? value : "(missing)");

	ok &= (value != NULL && strlen(value) > 0);

	if (value != NULL)
		free(value);

	return ok;
}

/**
 * Checks if the plugin configuration is complete. Sets the appropriate flags
 * in the plugin handle
 *
 * @param ph                the plugin handle
 */
static void _check_config_complete(struct plugin_handle *ph)
{
	ph->apqns_configured = _check_property(ph, EKMFWEB_CONFIG_APQNS);

	ph->connection_configured =
		_check_property(ph, EKMFWEB_CONFIG_URL) &&
		_check_property(ph, EKMFWEB_CONFIG_VERIFY_SERVER_CERT) &&
		_check_property(ph, EKMFWEB_CONFIG_VERIFY_HOSTNAME);

	ph->settings_retrieved =
		_check_property(ph, EKMFWEB_CONFIG_EKMFWEB_PUBKEY);

	ph->templates_retrieved =
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_XTS1) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_XTS2) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_NONXTS) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_IDENTITY) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_XTS1_LABEL) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_XTS2_LABEL) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_NONXTS_LABEL) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_IDENTITY_LABEL) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_XTS1_ID) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_XTS2_ID) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_NONXTS_ID) &&
		_check_property(ph, EKMFWEB_CONFIG_TEMPLATE_IDENTITY_ID);

	ph->identity_key_generated =
		_check_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY) &&
		_check_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY_ALGORITHM) &&
		_check_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY_PARAMS);

	ph->registered =
		_check_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY_LABEL) &&
		_check_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY_ID);

	ph->config_complete = ph->apqns_configured &&
			      ph->connection_configured &&
			      ph->settings_retrieved &&
			      ph->templates_retrieved &&
			      ph->identity_key_generated &&
			      ph->registered;
}

/**
 * Gets the EKMF config structure contents from the plugin properties
 *
 * @param ph                the plugin handle
 *
 * @returns a KMS plugin handle, or NULL in case of an error.
 */
static int _get_ekmf_config(struct plugin_handle *ph)
{
	char *tmp;

	ph->ekmf_config.identity_secure_key = properties_get(ph->properties,
						EKMFWEB_CONFIG_IDENTITY_KEY);

	ph->ekmf_config.base_url = properties_get(ph->properties,
						  EKMFWEB_CONFIG_URL);
	ph->ekmf_config.tls_ca = properties_get(ph->properties,
						EKMFWEB_CONFIG_CA_BUNDLE);
	ph->ekmf_config.tls_client_cert = properties_get(ph->properties,
						EKMFWEB_CONFIG_CLIENT_CERT);
	ph->ekmf_config.tls_client_key = properties_get(ph->properties,
						EKMFWEB_CONFIG_CLIENT_KEY);

	tmp = properties_get(ph->properties,
			    EKMFWEB_CONFIG_CLIENT_KEY_PASSPHRASE);
	if (tmp != NULL) {
		ph->ekmf_config.tls_client_key_passphrase =
				_decode_passphrase(tmp);
		free(tmp);
	}
	ph->ekmf_config.tls_issuer_cert = NULL;
	ph->ekmf_config.tls_pinned_pubkey = properties_get(ph->properties,
						EKMFWEB_CONFIG_SERVER_PUBKEY);
	ph->ekmf_config.tls_server_cert = properties_get(ph->properties,
						EKMFWEB_CONFIG_SERVER_CERT);
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_VERIFY_SERVER_CERT);
	ph->ekmf_config.tls_verify_peer =
				(tmp != NULL && strcasecmp(tmp, "yes") == 0);
	if (tmp != NULL)
		free(tmp);
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_VERIFY_HOSTNAME);
	ph->ekmf_config.tls_verify_host =
				(tmp != NULL && strcasecmp(tmp, "yes") == 0);
	if (tmp != NULL)
		free(tmp);
	ph->ekmf_config.max_redirs = 0;

	ph->ekmf_config.login_token = properties_get(ph->properties,
						EKMFWEB_CONFIG_LOGIN_TOKEN);

	ph->ekmf_config.ekmf_server_pubkey = properties_get(ph->properties,
						EKMFWEB_CONFIG_EKMFWEB_PUBKEY);

	return 0;
}

/**
 * Frees the EKMF config structure contents
 *
 * @param ph                the plugin handle
 */
static void _free_ekmf_config(struct plugin_handle *ph)
{
	if (ph->ekmf_config.base_url != NULL)
		free((void *)ph->ekmf_config.base_url);
	if (ph->ekmf_config.tls_ca != NULL)
		free((void *)ph->ekmf_config.tls_ca);
	if (ph->ekmf_config.tls_client_cert != NULL)
		free((void *)ph->ekmf_config.tls_client_cert);
	if (ph->ekmf_config.tls_client_key != NULL)
		free((void *)ph->ekmf_config.tls_client_key);
	if (ph->ekmf_config.tls_client_key_passphrase != NULL)
		free((void *)ph->ekmf_config.tls_client_key_passphrase);
	if (ph->ekmf_config.tls_issuer_cert != NULL)
		free((void *)ph->ekmf_config.tls_issuer_cert);
	if (ph->ekmf_config.tls_pinned_pubkey != NULL)
		free((void *)ph->ekmf_config.tls_pinned_pubkey);
	if (ph->ekmf_config.tls_server_cert != NULL)
		free((void *)ph->ekmf_config.tls_server_cert);
	if (ph->ekmf_config.login_token != NULL)
		free((void *)ph->ekmf_config.login_token);
	if (ph->ekmf_config.identity_secure_key != NULL)
		free((void *)ph->ekmf_config.identity_secure_key);
	if (ph->ekmf_config.ekmf_server_pubkey != NULL)
		free((void *)ph->ekmf_config.ekmf_server_pubkey);
}

/**
 * Removes the login token file, if the error indicates an authorization or
 * authentication error (-EACCES or -EPERM)
 *
 * @param ph                the plugin handle
 * @param error             the negative errno value of the last error
 */
static void _remove_login_token_if_error(struct plugin_handle *ph, int error)
{
	switch (error) {
	case -EACCES:
	case -EPERM:
		remove(ph->ekmf_config.login_token);
		FREE_AND_SET_NULL(ph->ekmf_config.login_token);
		break;
	default:
		break;
	}

	return;
}

/**
 * UnlLoads the CCA library
 *
 * @param ph                the plugin handle
 */
static void _unload_cca_library(struct plugin_handle *ph)
{
	if (ph->cca.cca_lib != NULL)
		dlclose(ph->cca.cca_lib);
	ph->cca.cca_lib = NULL;

	ph->ext_lib.type = 0;
	ph->ext_lib.cca = NULL;
}

/**
 * Selects one the CCA APQNs associated with this plugin, and loads the CCA
 * library and sets up the external library field in the plugin handle.
 *
 * @param ph                the plugin handle
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _select_cca_adapter(struct plugin_handle *ph)
{
	struct cca_lib cca = { 0 };
	unsigned int card, domain;
	char **apqn_list = NULL;
	bool selected = false;
	int rc = 0, i;
	char *apqns;

	apqns = properties_get(ph->properties, EKMFWEB_CONFIG_APQNS);
	if (apqns == NULL) {
		_set_error(ph, "No APQN are associated with the plugin.");
		rc = -ENODEV;
		goto out;
	}

	pr_verbose(ph, "Associated APQNs: %s", apqns);

	_unload_cca_library(ph);

	apqn_list = str_list_split(apqns);
	for (i = 0; apqn_list[i] != NULL; i++) {
		if (sscanf(apqn_list[i], "%x.%x", &card, &domain) != 2)
			continue;

		if (sysfs_is_apqn_online(card, domain, CARD_TYPE_CCA) != 1)
			continue;

		rc = select_cca_adapter(&cca, card, domain, ph->verbose);
		if (rc != 0) {
			_set_error(ph, "Failed to select APQN %02x.%04x: %s",
				   card, domain, strerror(-rc));
			goto out;
		}

		selected = true;
		break;
	}

	if (!selected) {
		_set_error(ph, "None of the associated APQNs is available: %s",
			   apqns);
		rc = -ENODEV;
		goto out;
	}

	pr_verbose(ph, "Selected APQN %02x.%04x", card, domain);

	ph->cca.cca_lib = cca.lib_csulcca;
	ph->ext_lib.type = EKMF_EXT_LIB_CCA;
	ph->ext_lib.cca = &ph->cca;

out:
	if (apqns != NULL)
		free(apqns);
	if (apqn_list != NULL)
		str_list_free_string_array(apqn_list);

	if (rc != 0 && cca.lib_csulcca != NULL)
		dlclose(cca.lib_csulcca);

	return rc;
}

/**
 * Initializes a KMS plugin for usage by zkey. When a repository is bound to a
 * KMS plugin, zkey calls this function when opening the repository.
 *
 * @param config_path       name of a directory where the KMS plugin can store
 *                          its configuration and other files it needs to store
 * @param verbose           if true, the plugin should write verbose or debug
 *                          messages to stderr during further processing.
 *
 * @returns a KMS plugin handle, or NULL in case of an error.
 */
kms_handle_t kms_initialize(const char *config_path, bool verbose)
{
	struct plugin_handle *ph;
	struct stat sb;
	int rc;

	util_assert(config_path != NULL, "Internal error: config_path is NULL");

	ph = util_malloc(sizeof(struct plugin_handle));
	memset(ph, 0, sizeof(struct plugin_handle));

	ph->config_path = util_strdup(config_path);
	ph->verbose = verbose;

	pr_verbose(ph, "Plugin initializing, config_path: '%s'", config_path);

	if (stat(config_path, &sb) != 0) {
		warnx("Can not access '%s': %s", config_path, strerror(errno));
		goto error;
	}
	if (!S_ISDIR(sb.st_mode)) {
		warnx("'%s' is not a directory", config_path);
		goto error;
	}
	if (!util_path_is_readable(config_path) ||
	    !util_path_is_writable(config_path)) {
		warnx("Permission denied for '%s'", config_path);
		goto error;
	}
	if (sb.st_mode & S_IWOTH) {
		warnx("Directory '%s' is writable for others, this is not "
		      "accepted", config_path);
		goto error;
	}

	ph->config_path_owner = sb.st_gid;
	ph->config_path_mode = sb.st_mode & (S_IRUSR | S_IWUSR |
					     S_IRGRP  | S_IWGRP |
					     S_IROTH);

	ph->properties = properties_new();
	rc = _load_config(ph);
	if (rc != 0 && rc != -EIO) {
		warnx("Failed to load plugin config file: %s", strerror(-rc));
		goto error;
	}

	rc = _get_ekmf_config(ph);
	if (rc != 0)
		goto error;

	_check_config_complete(ph);
	pr_verbose(ph, "Plugin configuration is %scomplete",
		   ph->config_complete ? "" : "in");

	return (kms_handle_t)ph;

error:
	kms_terminate(ph);
	return NULL;
}

/**
 * Terminates the use of a KMS plugin. When a repository is bound to a KMS
 * plugin, zkey calls this function when closing the repository.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_terminate(const kms_handle_t handle)
{
	struct plugin_handle *ph = handle;

	util_assert(handle != NULL, "Internal error: handle is NULL");

	pr_verbose(ph, "Plugin terminated");

	_free_ekmf_config(ph);
	_unload_cca_library(ph);

	if (ph->curl_handle != NULL)
		ekmf_curl_destroy(ph->curl_handle);

	if (ph->config_path != NULL)
		free((void *)ph->config_path);
	if (ph->properties != NULL)
		properties_free(ph->properties);
	free(ph);

	return 0;
}

/**
 * Returns a textual message about the last occurred error that occurred in the
 * last called KMS plugin function. If no error occurred (i.e. the last plugin
 * function returned rc = 0), then NULL is returned.
 * The returned string is static or contained within the handle. It is valid
 * only until the next KMS plugin function is called.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns an error message of NULL
 */
const char *kms_get_last_error(const kms_handle_t handle)
{
	struct plugin_handle *ph = handle;

	util_assert(handle != NULL, "Internal error: handle is NULL");

	pr_verbose(ph, "Last error: '%s'", ph->error_msg);

	if (strlen(ph->error_msg) == 0)
		return NULL;

	return ph->error_msg;
}

/**
 * Returns true if the KMS plugin supports the specified key type.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_type          the zkey key type, euch as 'CCA-AESDATA',
 *                          'CCA-AESCIPHER', 'EP11-AES'.
 *
 * @returns true if the KMS plugin supports the key type, false otherwise.
 */
bool kms_supports_key_type(const kms_handle_t handle,
			   const char *key_type)
{
	struct plugin_handle *ph = handle;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(key_type != NULL, "Internal error: key_type is NULL");

	_clear_error(ph);

	if (strcasecmp(key_type, KEY_TYPE_CCA_AESCIPHER) == 0)
		return true;

	return false;
}

/**
 * Returns information about the public key in the PEM file
 *
 * @param ph               the plugin handle
 * @param pem_file         the name of a PEM file containing the public key
 * @param pkey_type        on return: If not NULL, the PKEY type (EVP_PKEY_EC
 *                         or EVP_PKEY_RSA)
 * @param ecc_curve_nid    on return: If not NULL and it is an ECC key, the
 *                         OpenSSL NID of the curve of the ECC key.
 * @param rsa_mod_bits     on return: If not NULL and it is an RSA key, the
 *                         modulus bit size of the RSA key.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
static int _get_pub_key_info(struct plugin_handle *ph, const char *pem_file,
			     int *pkey_type, int *ecc_curve_nid,
			     int *rsa_mod_bits)
{
	int rc = 0, curve_nid, mod_len;
	EVP_PKEY *pkey;
	FILE *fp;

	fp = fopen(pem_file, "r");
	if (fp == NULL) {
		rc = -errno;
		_set_error(ph, "Failed to open pubkey PEM file '%s': %s",
			   pem_file, strerror(-rc));
		return rc;
	}

	pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

	fclose(fp);

	if (pkey == NULL) {
		rc = -EIO;
		_set_error(ph, "Failed to read pubkey from PEM file '%s': %s",
			   pem_file, strerror(-rc));
		return rc;
	}

	if (pkey_type != NULL)
		*pkey_type = EVP_PKEY_id(pkey);

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_EC:
		curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(
						EVP_PKEY_get0_EC_KEY(pkey)));
		if (ecc_curve_nid != NULL)
			*ecc_curve_nid = curve_nid;
		break;

	case EVP_PKEY_RSA:
		mod_len = BN_num_bits(RSA_get0_n(EVP_PKEY_get0_RSA(pkey)));
		if (rsa_mod_bits != NULL)
			*rsa_mod_bits = mod_len;
		break;

	default:
		rc = -EIO;
		_set_error(ph, "Unknown pubkey type: %d", EVP_PKEY_id(pkey));
		break;
	}

	EVP_PKEY_free(pkey);
	return rc;
}

/**
 * Displays information about the KMS Plugin and its current configuration on
 * stdout.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_display_info(const kms_handle_t handle)
{
	int rc, type = 0, curve = 0, mod_bits = 0;
	struct plugin_handle *ph = handle;
	char *tmp = NULL;
	bool rsa = false;
#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
	char *info;
#endif

	util_assert(handle != NULL, "Internal error: handle is NULL");

	pr_verbose(ph, "Display Info");

	_clear_error(ph);

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_URL);
	printf("  EKMF Web server:      %s\n", tmp != NULL ? tmp :
			"(configuration required)");
	if (tmp != NULL)
		free(tmp);
	else
		return 0;
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_CA_BUNDLE);
	printf("  CA-bundle:            %s\n", tmp != NULL ? tmp :
			"System's CA certificates");
	if (tmp != NULL)
		free(tmp);
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_CLIENT_CERT);
	printf("  Client certificate:   %s\n", tmp != NULL ? tmp : "(none)");
	if (tmp != NULL)
		free(tmp);
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_CLIENT_KEY);
	printf("  Client private key:   %s\n", tmp != NULL ? tmp : "(none)");
	if (tmp != NULL) {
		free(tmp);
		tmp = properties_get(ph->properties,
				     EKMFWEB_CONFIG_CLIENT_KEY_PASSPHRASE);
		if (tmp != NULL) {
			printf("                        "
			       "(passphrase protected)\n");
			free(tmp);
		}
	}
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_SERVER_CERT);
	if (tmp != NULL) {
		printf("  Trusting the server certificate\n");
		free(tmp);
	}
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_SERVER_PUBKEY);
	if (tmp != NULL) {
		printf("  Using server public key pinning\n");
		free(tmp);
	}
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_VERIFY_SERVER_CERT);
	if (tmp != NULL) {
		if (strcasecmp(tmp, "yes") == 0)
			printf("  The server's certificate must be valid\n");
		free(tmp);
	} else {
		printf("  The server's certificate is not verified\n");
	}
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_VERIFY_HOSTNAME);
	if (tmp != NULL) {
		if (strcasecmp(tmp, "yes") == 0)
			printf("  The server's certificate must match the "
			       "hostname\n");
		free(tmp);
	}

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_EKMFWEB_PUBKEY);
	if (tmp != NULL) {
		rc = _get_pub_key_info(ph, tmp, &type, &curve, &mod_bits);
		if (rc == 0) {
			switch (type) {
			case EVP_PKEY_EC:
				printf("  EKMF Web public key:  ECC (%s)\n",
				       OBJ_nid2sn(curve));
				break;
			case EVP_PKEY_RSA:
				printf("  EKMF Web public key:  RSA "
				       "(%d bits)\n", mod_bits);
				break;
			default:
				printf("  EKMF Web public key:  "
				       "(unknown key type)\n");
				break;
			}
		} else {
			printf("  EKMF Web public key:  (not available)\n");
		}
		free(tmp);
	} else {
		printf("  EKMF Web public key:  (configuration required)\n");
	}

	printf("  Key templates:\n");
	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_TEMPLATE_IDENTITY);
	printf("    Identity:           %s\n", tmp != NULL ? tmp :
			"(configuration required)");
	if (tmp != NULL)
		free(tmp);
	tmp = properties_get(ph->properties,
			     EKMFWEB_CONFIG_TEMPLATE_IDENTITY_LABEL);
	if (tmp != NULL) {
		printf("      Label template:   %s\n", tmp);
		free(tmp);
	}

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_TEMPLATE_XTS1);
	printf("    XTS-Key1:           %s\n", tmp != NULL ? tmp :
			"(configuration required)");
	if (tmp != NULL)
		free(tmp);
	tmp = properties_get(ph->properties,
			     EKMFWEB_CONFIG_TEMPLATE_XTS1_LABEL);
	if (tmp != NULL) {
		printf("      Label template:   %s\n", tmp);
		free(tmp);
	}

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_TEMPLATE_XTS2);
	printf("    XTS-Key2:           %s\n", tmp != NULL ? tmp :
			"(configuration required)");
	if (tmp != NULL)
		free(tmp);
	tmp = properties_get(ph->properties,
			     EKMFWEB_CONFIG_TEMPLATE_XTS2_LABEL);
	if (tmp != NULL) {
		printf("      Label template:   %s\n", tmp);
		free(tmp);
	}

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_TEMPLATE_NONXTS);
	printf("    Non-XTS:            %s\n", tmp != NULL ? tmp :
			"(configuration required)");
	if (tmp != NULL)
		free(tmp);
	tmp = properties_get(ph->properties,
			     EKMFWEB_CONFIG_TEMPLATE_NONXTS_LABEL);
	if (tmp != NULL) {
		printf("      Label template:   %s\n", tmp);
		free(tmp);
	}

	tmp = properties_get(ph->properties,
			     EKMFWEB_CONFIG_IDENTITY_KEY_ALGORITHM);
	if (tmp != NULL) {
		printf("  Identity key:         %s", tmp);
		rsa = strcmp(tmp, EKMFWEB_KEY_ALGORITHM_RSA) == 0;
		free(tmp);
		tmp = properties_get(ph->properties,
				     EKMFWEB_CONFIG_IDENTITY_KEY_PARAMS);
		if (tmp != NULL) {
			printf(" (%s%s)", tmp, rsa ? " bits" : "");
			free(tmp);
		}
		printf("\n");
	} else {
		printf("  Identity key:         (configuration required)\n");
	}

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_IDENTITY_KEY_REENC);
	if (tmp != NULL) {
		printf("                        (re-enciphering pending)\n");
		free(tmp);
	}

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_IDENTITY_KEY_LABEL);
	printf("  Registered key label: %s\n", tmp != NULL ?
			tmp : "(registration required)");
	if (tmp != NULL)
		free(tmp);

#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
	printf("  Key transport settings:\n");

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_SESSION_KEY_CURVE);
	printf("    Session Key:        ECC (%s)\n",
	       tmp != NULL ? tmp : "secp521r1");
	if (tmp != NULL)
		free(tmp);

	info = properties_get(ph->properties, EKMFWEB_CONFIG_IDENTITY_KEY_INFO);
	if (info != NULL && strncmp(info, "RSA", 3) == 0) {
		tmp = properties_get(ph->properties,
				     EKMFWEB_CONFIG_SESSION_RSA_SIGN_DIGEST);
		printf("    RSA sign digest:    %s\n",
		       tmp != NULL ? tmp : "SHA512");
		if (tmp != NULL)
			free(tmp);
		tmp = properties_get(ph->properties,
				     EKMFWEB_CONFIG_SESSION_RSA_SIGN_PSS);
		printf("    RSA sign alorithm:  %s\n",
		       tmp != NULL && strcasecmp(tmp, "yes") == 0 ?
							"RSA-PSS" : "RSA");
		if (tmp != NULL)
			free(tmp);
	}
	if (info != NULL)
		free(info);
#endif

	return 0;
}
#define OPT_TLS_CLIENT_CERT			256
#define OPT_TLS_CLIENT_KEY			257
#define OPT_TLS_CLIENT_KEY_PASSPHRASE		258
#define OPT_TLS_PIN_SERVER_PUBKEY		259
#define OPT_TLS_TRUST_SERVER_CERT		260
#define OPT_TLS_DONT_VERIFY_SERVER_CERT		261
#define OPT_TLS_VERIFY_HOSTNAME			262
#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
#define OPT_KT_RSA_SIGNATURE_DIGEST		263
#define OPT_KT_RSA_PSS_SIGNATURE		264
#endif

static const struct util_opt configure_options[] = {
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "EKMFWEB SPECIFIC OPTIONS FOR THE SERVER CONNECTION",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "ekmfweb-url", required_argument, NULL, 'u'},
		.argument = "URL",
		.desc = "The URL of the EKMF Web server. The URL should start "
			"with 'https://', and may contain a port number "
			"separated by a colon. If no port number is specified, "
			"443 is used for HTTPS.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "tls-ca-bundle", required_argument, NULL, 'b'},
		.argument = "CA-BUNDLE",
		.desc = "The CA bundle PEM file or directory containing the CA "
			"certificates used to verify the EKMF Web server "
			"certificate during TLS handshake. If this specifies a "
			"directory path, then this directory must have been "
			"prepared with OpenSSL's c_rehash utility. Default are "
			"the system CA certificates.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "tls-client-cert", required_argument, NULL,
							OPT_TLS_CLIENT_CERT },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.argument = "PEM-FILE",
		.desc = "The PEM file containing the client's TLS certificate "
			"for use with TLS client authentication.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "tls-client-key", required_argument, NULL,
							OPT_TLS_CLIENT_KEY },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.argument = "PEM-FILE",
		.desc = "The PEM file containing the client's private key "
			"for use with TLS client authentication.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "tls-client-key-passphrase", required_argument,
					NULL, OPT_TLS_CLIENT_KEY_PASSPHRASE },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.argument = "PASSPHRASE",
		.desc = "If the PEM file is passphrase protected, this option "
			"specifies the passphrase to unlock the PEM file that "
			"is specified with option '--tls-client-key'.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "tls-pin-server-pubkey", 0, NULL,
				OPT_TLS_PIN_SERVER_PUBKEY },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Pin the EKMF Web server's public key to verify on "
			"every connection that the public key of the EKMF Web "
			"server's certificate is the same that was used when "
			"the connection to the EKMF Web server was configured. "
			"This option can only be used with CA signed EKMF Web "
			"server certificates.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "tls-trust-server-cert", 0, NULL,
				OPT_TLS_TRUST_SERVER_CERT },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Trust the EKMF Web server's certificate even if it is "
			"a self signed certificate, or could not be verified "
			"due to other reasons. This option can be used instead "
			"of option '--tls-pin-server-pubkey' with self signed "
			"EKMF Web server certificates.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "tls-dont-verify-server-cert", 0, NULL,
					OPT_TLS_DONT_VERIFY_SERVER_CERT },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Do not verify the authenticity of the EKMF Web "
			"server's certificate. For self signed EKMF Web server "
			"certificates, this is the default. Use option "
			"'--tls-pin-server-cert' to ensure the self signed "
			"certificate's authenticity explicitely. CA signed "
			"EKMF Web server certificates are verified by default. "
			"This option disables the verification.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "tls-verify-hostname", 0, NULL,
						OPT_TLS_VERIFY_HOSTNAME },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Verify that the EKMF Web server certificate's 'Common "
			"Name' field or a 'Subject Alternate Name' field "
			"matches the host name used to connect to the EKMF "
			"Web server.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "refresh-settings", 0, NULL, 'R' },
		.desc = "Refresh the EKMF Web server settings. This is "
			"automatically performed when the connection to the "
			"EKMF Web server is (re-)configured. Use this option "
			"when the settings of the already configured EKMF Web "
			"server have changed",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "EKMFWEB SPECIFIC OPTIONS FOR IDENTITY KEY GENERATION",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "gen-identity-key", 0, NULL, 'i'},
		.desc = "Generate an identity key for the EKMF Web plugin. "
			"An identity key is automatically generated when the "
			"EKMF Web server connection has been configured. Use "
			"this option to generate a new identity key. You need "
			"to re-generate a registration certificate with the "
			"newly generated identity key, and re-register this "
			"zkey client with the EKMF Web server.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "EKMFWEB SPECIFIC OPTIONS FOR CERTIFICATE GENERATION",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "gen-csr", required_argument, NULL, 'c'},
		.argument = "CSR-PEM-FILE",
		.desc = "Generate a certificate signing request (CSR) with the "
			"identity key and store it into the specified PEM "
			"file. You pass this CSR to a certificate authority "
			"(CA) to have it issue a CA signed certificate for the "
			"EKMF Web plugin. You need to register the certificate "
			"with EKMF Web before you can access EKMF Web.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "gen-self-signed-cert", required_argument, NULL,
			    'C'},
		.argument = "CERT-PEM-FILE",
		.desc = "Generate a self signed certificate with the "
			"identity key and store it into the specified PEM "
			"file. You need to register the certificate with EKMF "
			"Web before you can access EKMF Web.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "cert-subject", required_argument, NULL, 's'},
		.argument = "SUBJECT-RDNS",
		.desc = "The subject name for generating a certificate signing "
			"request (CSR) or self signed certificate, in the form "
			"'<type>=<value>(;<type>=<value>)*[;]' with types "
			"recognized by OpenSSL.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "cert-extensions", required_argument, NULL, 'e'},
		.argument = "EXTENSIONS",
		.desc = "The certificate extensions for generating a "
			"certificate signing request (CSR) or self signed "
			"certificate, in the form '<name>=[critical,]<value(s)>"
			" (;<name>=[critical,]<value(s)>)*[;]' with extension "
			"names and values recognized by OpenSSL.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "renew-cert", required_argument, NULL, 'N'},
		.argument = "CERT-PEM-FILE",
		.desc = "An existing PEM file containing the certificate to be "
			"renewed. The certificate's subject name and extensions"
			" are used to generate the certificate signing request "
			"(CSR) or renewed self signed certificate.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "csr-new-header", 0, NULL, 'n'},
		.desc = "Adds the word NEW to the PEM file header and footer "
			"lines on the certificate signing request. Some "
			"software and some CAs need this.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "cert-validity-days", required_argument, NULL, 'd'},
		.argument = "DAYS",
		.desc = "The number of days to certify the self signed "
			"certificate. The default is 30 days.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "cert-digest", required_argument, NULL, 'D'},
		.argument = "DIGEST",
		.desc = "The digest algorithm to use when generating a "
			"certificate signing request or self signed "
			"certificate. The default is determined by OpenSSL.",
		.command = KMS_COMMAND_CONFIGURE,
	},
#ifdef EKMF_SUPPORTS_RSA_PSS_CERTIFICATES
	{
		.option = { "cert-rsa-pss", 0, NULL, 'P'},
		.desc = "Use the RSA-PSS algorithm to sign the certificate "
			"signing request or the self signed certificate. This "
			"option is only honored when the identity key type is "
			"RSA, it is ignored otherwise.",
		.command = KMS_COMMAND_CONFIGURE,
	},
#endif
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "EKMFWEB SPECIFIC OPTIONS FOR REGISTRATION",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "register", required_argument, NULL, 'r'},
		.argument = "CERT-FILE",
		.desc = "Register the zkey client with EKMF Web by generating "
			"an identity key in EKMF Web using the certificate "
			"from the specified file. Supported certificate files "
			"formats are .pem, .crt, .cert, .cer, and .der (i.e. "
			"either base64 or DER encoded). If you want to "
			"register a self signed certificate that you are about "
			"to generate using option '--gen-self-signed-cert', "
			"then specify the same certificate file name here, "
			"and the generated certificate is registered "
			"right away.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "label-tags", required_argument, NULL, 'T'},
		.argument = "LABEL-TAGS",
		.desc = "The label tags for generating the identity key in "
			"EKMF Web when registering the zkey client, in the "
			"form '<tag>=<value>(,<tag>=<value>)*[,]' with tags as "
			"defined by the key template. Use 'zkey kms info' to "
			"display the key templates used by zkey. For "
			"registration, the template for identity keys is used.",
		.command = KMS_COMMAND_CONFIGURE,
	},
#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "EKMFWEB SPECIFIC OPTIONS FOR KEY TRANSPORT",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "session-rsa-sign-digest", required_argument, NULL,
						OPT_KT_RSA_SIGNATURE_DIGEST },
		.argument = "DIGEST",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "The digest algorithm to use for signing the key "
			"transport request, when the identity key type is "
			"RSA. Ignored otherwise. The default is SHA512.",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "session-rsa-sign-algo", required_argument, NULL,
						OPT_KT_RSA_PSS_SIGNATURE },
		.argument = "ALGORITHM",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "The algorithm to use for signing the key transport "
			"request, when the identity key type is RSA, ignored "
			"otherwise. Supported algorithms are 'RSA'and "
			"'RSA-PSS'.",
		.command = KMS_COMMAND_CONFIGURE,
	},
#endif
	UTIL_OPT_END,
};

static const struct util_opt generate_options[] = {
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "EKMFWEB SPECIFIC OPTIONS",
		.command = KMS_COMMAND_GENERATE,
	},
	{
		.option = { "label-tags", required_argument, NULL, 'T'},
		.argument = "LABEL-TAGS",
		.desc = "The label tags for generating a secure key in EKMF "
			"Web, in the form '<tag>=<value>(,<tag>=<value>)*[,]' "
			"with tags as defined by the key template. Use 'zkey "
			"kms info' to display the key templates used by zkey. "
			"For XTS type keys the two templates for XTS-Key1 and "
			"XTS-Key2 are used. For non-XTS type keys, the "
			"template for Non-XTS keys is used.",
		.command = KMS_COMMAND_GENERATE,
	},
	UTIL_OPT_END,
};

static const struct util_opt remove_options[] = {
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "EKMFWEB SPECIFIC OPTIONS",
		.command = KMS_COMMAND_REMOVE,
	},
	{
		.option = { "state", required_argument, NULL, 's'},
		.argument = "STATE",
		.desc = "The state to which to change the key in EKMF Web, "
			"after removing the secure key from the local secure "
			"key repository. Possible states are 'DEACTIVATED', "
			"'COMPROMISED', 'DESTROYED', and "
			"'DESTROYED-COMPROMISED'. If this option is not "
			"specified, the state of the key in EKMF Web is not "
			"changed, but the key is removed from the local "
			"secure key repository only.",
		.command = KMS_COMMAND_REMOVE,
	},
	UTIL_OPT_END,
};

static const struct util_opt list_options[] = {
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "EKMFWEB SPECIFIC OPTIONS",
		.command = KMS_COMMAND_LIST,
	},
	{
		.option = { "states", required_argument, NULL, 's'},
		.argument = "STATES",
		.desc = "The states of the keys that are to be listed. "
			"Multiple states can be separated by comma. Possible "
			"states are 'PRE-ACTIVATION', 'ACTIVE', 'DEACTIVATED', "
			"'COMPROMISED', 'DESTROYED', and "
			"'DESTROYED-COMPROMISED'. If this "
			"option is not specified, only keys in state 'ACTIVE' "
			"are listed.",
		.command = KMS_COMMAND_LIST,
	},
	{
		.option = { "all", 0, NULL, 'a'},
		.desc = "List all keys that can be used for volume encryption. "
			"If this option is not specified, then only volume "
			"encryption keys that are allowed to be exported by "
			"EKMF Web using the identity key of this zkey client "
			"are listed.",
		.command = KMS_COMMAND_LIST,
	},
	UTIL_OPT_END,
};

/**
 * Returns a list of KMS specific command line options that zkey should accept
 * and pass to the appropriate KMS plugin function. The option list must be
 * terminated by an UTIL_OPT_END entry (see util_opt.h). The options returned
 * must not interfere with the already defined options of the zkey command.
 * Field 'command' of the returned options should either be NULL or specify
 * the command that it is for.
 *
 * If max_opts is not -1, then only up to max_opts options are allowed. If more
 * options are returned, only up to max_opts options are used by zkey.
 *
 * @param command           the command for which the KMS-specific options are
 *                          to be returned, see KMS_COMMAND_xxx defines
 * @param max_opts          maximum number of options allowed. If -1 then there
 *                          is no limit.
 *
 * @returns a list of options terminated by an UTIL_OPT_END entry, or NULL in
 * case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
const struct util_opt *kms_get_command_options(const char *command,
					       int UNUSED(max_opts))
{
	util_assert(command != NULL, "Internal error: command is NULL");

	if (strcasecmp(command, KMS_COMMAND_CONFIGURE) == 0)
		return configure_options;
	if (strcasecmp(command, KMS_COMMAND_GENERATE) == 0)
		return generate_options;
	if (strcasecmp(command, KMS_COMMAND_REMOVE) == 0)
		return remove_options;
	if (strcasecmp(command, KMS_COMMAND_LIST) == 0)
		return list_options;

	return NULL;
}

/**
 * Queries the APKA master key states and verification patterns of the current
 * CCA adapter
 *
 * @param ph               the plugin handle
 * @param cca              the CCA library structure
 * @param apka_mk_info     the master key info of the APKA master key
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _get_cca_apka_mk_info(struct plugin_handle *ph, struct cca_lib *cca,
				 struct mk_info *apka_mk_info)
{
	long exit_data_len = 0, rule_array_count, verb_data_length = 0;
	unsigned char rule_array[16 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;
	struct cca_staticsb {
		u16	sym_old_mk_mdc4_len;
		u16	sym_old_mk_mdc4_id;
		u8	sym_old_mk_mdc4_hp[16];
		u16	sym_cur_mk_mdc4_len;
		u16	sym_cur_mk_mdc4_id;
		u8	sym_cur_mk_mdc4_hp[16];
		u16	sym_new_mk_mdc4_len;
		u16	sym_new_mk_mdc4_id;
		u8	sym_new_mk_mdc4_hp[16];
		u16	asym_old_mk_mdc4_len;
		u16	asym_old_mk_mdc4_id;
		u8	asym_old_mk_mdc4_hp[16];
		u16	asym_cur_mk_mdc4_len;
		u16	asym_cur_mk_mdc4_id;
		u8	asym_cur_mk_mdc4_hp[16];
		u16	asym_new_mk_mdc4_len;
		u16	asym_new_mk_mdc4_id;
		u8	asym_new_mk_mdc4_hp[16];
		u16	sym_old_mk_vp_len;
		u16	sym_old_mk_vp_id;
		u8	sym_old_mk_vp[8];
		u16	sym_cur_mk_vp_len;
		u16	sym_cur_mk_vp_id;
		u8	sym_cur_mk_vp[8];
		u16	sym_new_mk_vp_len;
		u16	sym_new_mk_vp_id;
		u8	sym_new_mk_vp[8];
		u16	sym_new_mk_mkap_len;
		u16	sym_new_mk_mkap_id;
		u8	sym_new_mk_mkap[8];
		u16	aes_old_mk_vp_len;
		u16	aes_old_mk_vp_id;
		u8	aes_old_mk_vp[8];
		u16	aes_cur_mk_vp_len;
		u16	aes_cur_mk_vp_id;
		u8	aes_cur_mk_vp[8];
		u16	aes_new_mk_vp_len;
		u16	aes_new_mk_vp_id;
		u8	aes_new_mk_vp[8];
		u16	apka_old_mk_vp_len;
		u16	apka_old_mk_vp_id;
		u8	apka_old_mk_vp[8];
		u16	apka_cur_mk_vp_len;
		u16	apka_cur_mk_vp_id;
		u8	apka_cur_mk_vp[8];
		u16	apka_new_mk_vp_len;
		u16	apka_new_mk_vp_id;
		u8	apka_new_mk_vp[8];
	} statis_csb = { 0 };

	util_assert(cca != NULL, "Internal error: cca is NULL");
	util_assert(apka_mk_info != NULL,
		    "Internal error: apka_mk_info is NULL");

	memset(apka_mk_info, 0, sizeof(struct mk_info));

	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "STATICSB", 8);
	rule_array_count = 1;

	verb_data_length = sizeof(statis_csb);

	cca->dll_CSUACFQ(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &verb_data_length, (unsigned char *)&statis_csb);

	pr_verbose(ph, "CSUACFQ (Cryptographic Facility Query) returned: "
		   "return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0)
		return -EIO;

	switch (rule_array[10 * 8]) {
	case '3':
		apka_mk_info->new_mk.mk_state = MK_STATE_FULL;
		break;
	case '2':
		apka_mk_info->new_mk.mk_state = MK_STATE_PARTIAL;
		break;
	case '1':
	default:
		apka_mk_info->new_mk.mk_state = MK_STATE_EMPTY;
		break;
	}
	memcpy(apka_mk_info->new_mk.mkvp, statis_csb.apka_new_mk_vp,
	       sizeof(statis_csb.apka_new_mk_vp));

	switch (rule_array[11 * 8]) {
	case '2':
		apka_mk_info->cur_mk.mk_state = MK_STATE_VALID;
		break;
	case '1':
	default:
		apka_mk_info->cur_mk.mk_state = MK_STATE_INVALID;
		break;
	}
	memcpy(apka_mk_info->cur_mk.mkvp, statis_csb.apka_cur_mk_vp,
	       sizeof(statis_csb.apka_cur_mk_vp));

	switch (rule_array[12 * 8]) {
	case '2':
		apka_mk_info->old_mk.mk_state = MK_STATE_VALID;
		break;
	case '1':
	default:
		apka_mk_info->old_mk.mk_state = MK_STATE_INVALID;
		break;
	}
	memcpy(apka_mk_info->old_mk.mkvp, statis_csb.apka_old_mk_vp,
	       sizeof(statis_csb.apka_old_mk_vp));

	return 0;
}

/**
 * Print the APKA master key infos of the selected APQNs
 *
 * @param ph                the plugin handle
 * @param cca               CCA library structure
 * @param apqns             a list of APQNs
 * @param num_apqns         number of APQNs in above array
 *
 * @returns 0 on success, a negative errno in case of an error.
 */

static int _print_apka_mks(struct plugin_handle *ph, struct cca_lib *cca,
			   const struct kms_apqn *apqns, size_t num_apqns)
{
	struct mk_info mk_info;
	struct util_rec *rec;
	enum card_type type;
	int rc = 0, level;
	size_t i;

	rec = util_rec_new_wide("-");
	util_rec_def(rec, "APQN", UTIL_REC_ALIGN_LEFT, 11, "CARD.DOMAIN");
	util_rec_def(rec, "NEW", UTIL_REC_ALIGN_LEFT, 16, "NEW APKA MK");
	util_rec_def(rec, "CUR", UTIL_REC_ALIGN_LEFT, 16, "CURRENT APKA MK");
	util_rec_def(rec, "OLD", UTIL_REC_ALIGN_LEFT, 16, "OLD APKA MK");
	util_rec_def(rec, "TYPE", UTIL_REC_ALIGN_LEFT, 6, "TYPE");
	util_rec_print_hdr(rec);

	for (i = 0; i < num_apqns; i++) {
		rc = select_cca_adapter(cca, apqns[i].card, apqns[i].domain,
					ph->verbose);
		if (rc != 0) {
			_set_error(ph, "Failed to select APQN %02x.%04x: %s",
				   apqns[i].card, apqns[i].domain,
				   strerror(-rc));
			goto out;
		}

		rc = _get_cca_apka_mk_info(ph, cca, &mk_info);
		if (rc != 0) {
			_set_error(ph, "Failed to get the APKA master key "
				   "infos for APQN %02x.%04x: %s",
				   apqns[i].card, apqns[i].domain,
				   strerror(-rc));
			goto out;
		}

		level = sysfs_get_card_level(apqns[i].card);
		type = sysfs_get_card_type(apqns[i].card);

		util_rec_set(rec, "APQN", "%02x.%04x", apqns[i].card,
			     apqns[i].domain);

		if (mk_info.new_mk.mk_state == MK_STATE_FULL ||
		    mk_info.new_mk.mk_state == MK_STATE_COMMITTED)
			util_rec_set(rec, "NEW", "%s",
				     printable_mkvp(type, mk_info.new_mk.mkvp));
		else if (mk_info.new_mk.mk_state == MK_STATE_PARTIAL)
			util_rec_set(rec, "NEW", "partially loaded");
		else if (mk_info.new_mk.mk_state == MK_STATE_UNCOMMITTED)
			util_rec_set(rec, "NEW", "uncommitted");
		else
			util_rec_set(rec, "NEW", "-");

		if (mk_info.cur_mk.mk_state ==  MK_STATE_VALID)
			util_rec_set(rec, "CUR", "%s",
				     printable_mkvp(type, mk_info.cur_mk.mkvp));
		else
			util_rec_set(rec, "CUR", "-");

		if (mk_info.old_mk.mk_state ==  MK_STATE_VALID)
			util_rec_set(rec, "OLD", "%s",
				     printable_mkvp(type, mk_info.old_mk.mkvp));
		else
			util_rec_set(rec, "OLD", "-");

		if (level > 0 && type != CARD_TYPE_ANY)
			util_rec_set(rec, "TYPE", "CEX%d%c", level,
				     type == CARD_TYPE_CCA ? 'C' : 'P');
		else
			util_rec_set(rec, "TYPE", "?");

		util_rec_print(rec);
	}

out:
	util_rec_free(rec);

	return rc;
}

/**
 * Cross checks the APQNs associated with the plugin. Checks if the CCA master
 * keys of all APQNs for the APKA master key are the same.
 *
 * @param ph                the plugin handle
 * @param apqns             a list of APQNs
 * @param num_apqns         number of APQNs in above array
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _cross_check_apqns(struct plugin_handle *ph,
			      const struct kms_apqn *apqns, size_t num_apqns)
{
	u8 new_mkvp[MKVP_LENGTH] = { 0, };
	u8 mkvp[MKVP_LENGTH] = { 0, };
	struct cca_lib cca = { 0 };
	struct mk_info mk_info;
	bool mismatch = false;
	bool print = false;
	int rc = -ENODEV;
	char temp[200];
	size_t i;

	for (i = 0; i < num_apqns; i++) {
		rc = select_cca_adapter(&cca, apqns[i].card, apqns[i].domain,
					ph->verbose);
		if (rc != 0) {
			_set_error(ph, "Failed to select APQN %02x.%04x: %s",
				   apqns[i].card, apqns[i].domain,
				   strerror(-rc));
			goto out;
		}

		rc = _get_cca_apka_mk_info(ph, &cca, &mk_info);
		if (rc != 0) {
			_set_error(ph, "Failed to get the APKA master key "
				   "infos for APQN %02x.%04x: %s",
				   apqns[i].card, apqns[i].domain,
				   strerror(-rc));
			goto out;
		}

		if (mk_info.new_mk.mk_state == MK_STATE_PARTIAL) {
			print = true;
			sprintf(temp, "INFO: APQN %02x.%04x: The NEW APKA "
				"master key register is only partially loaded.",
				apqns[i].card, apqns[i].domain);
			util_print_indented(temp, 0);
		}

		if (MKVP_ZERO(new_mkvp) &&
		    mk_info.new_mk.mk_state == MK_STATE_FULL)
			memcpy(new_mkvp, mk_info.new_mk.mkvp, sizeof(new_mkvp));

		if (mk_info.new_mk.mk_state == MK_STATE_FULL &&
		    !MKVP_EQ(mk_info.new_mk.mkvp, new_mkvp)) {
			print = true;
			sprintf(temp, "WARNING: APQN %02x.%04x: The NEW APKA "
				"master key register contains a different "
				"master key than the NEW APKA register of "
				"other APQNs.", apqns[i].card, apqns[i].domain);
			util_print_indented(temp, 0);
		}

		if (mk_info.cur_mk.mk_state != MK_STATE_VALID) {
			mismatch = true;
			print = true;
			printf("WARNING: APQN %02x.%04x: No APKA master key is "
			       "set.\n", apqns[i].card, apqns[i].domain);
			continue;
		}

		if (mk_info.old_mk.mk_state == MK_STATE_VALID &&
		    MKVP_EQ(mk_info.old_mk.mkvp, mk_info.cur_mk.mkvp)) {
			print = true;
			sprintf(temp, "INFO: APQN %02x.%04x: The OLD APKA "
				"master key register contains the same master "
				"key as the CURRENT APKA master key register.",
				apqns[i].card, apqns[i].domain);
			util_print_indented(temp, 0);
		}

		if (mk_info.new_mk.mk_state == MK_STATE_FULL &&
		    MKVP_EQ(mk_info.new_mk.mkvp, mk_info.cur_mk.mkvp)) {
			print = true;
			sprintf(temp, "INFO: APQN %02x.%04x: The NEW APKA "
				"master key register contains the same master "
				"key as the CURRENT APKA master key register.",
				apqns[i].card, apqns[i].domain);
			util_print_indented(temp, 0);
		}

		if (mk_info.new_mk.mk_state == MK_STATE_FULL &&
		    mk_info.old_mk.mk_state == MK_STATE_VALID &&
		    MKVP_EQ(mk_info.new_mk.mkvp, mk_info.old_mk.mkvp)) {
			print = true;
			sprintf(temp, "INFO: APQN %02x.%04x: The NEW APKA "
				"master key register contains the same master "
				"key as the OLD APKA master key register.",
				apqns[i].card, apqns[i].domain);
			util_print_indented(temp, 0);
		}

		if (MKVP_ZERO(mkvp))
			memcpy(mkvp, mk_info.cur_mk.mkvp, sizeof(mkvp));

		if (!MKVP_EQ(mk_info.cur_mk.mkvp, mkvp)) {
			mismatch = true;
			print = true;
			sprintf(temp, "WARNING: APQN %02x.%04x: The CURRENT "
				"APKA master key register contains a different "
				"master key than the CURRENT APKA register of "
				"other APQNs.", apqns[i].card, apqns[i].domain);
			util_print_indented(temp, 0);
		}
	}

	if (mismatch) {
		_set_error(ph, "Your APKA master key setup is improper");
		rc = -ENODEV;
	}

	if (print)
		_print_apka_mks(ph, &cca, apqns, num_apqns);

out:
	if (cca.lib_csulcca != NULL)
		dlclose(cca.lib_csulcca);

	return rc;
}

/**
 * Build an APQN string from an APQN array
 *
 * @param apqns           An array of APQNs
 * @param num_apqns       The number of elements in above array
 *
 * @return an allocated string with the APQNs
 */
static char *_build_apqn_string(const struct kms_apqn *apqns, size_t num_apqns)
{
	char *apqn_str, *str;
	size_t size, i;

	if (num_apqns == 0) {
		apqn_str = util_malloc(1);
		*apqn_str = '\0';
		return apqn_str;
	}

	size = num_apqns * 8; /* 'cc.dddd' plus ',' or '\0' */
	apqn_str = util_malloc(size);

	str = apqn_str;
	for (i = 0; i < num_apqns; i++) {
		if (i != 0) {
			*str = ',';
			str++;
		}

		sprintf(str, "%02x.%04x", apqns[i].card, apqns[i].domain);
		str += 7;
	}

	return apqn_str;
}

/**
 * Gets the OpenSSL curve NID from the infos from the identity template.
 *
 * @param ph                the plugin handle
 * @param curve             the name of the curve from the template
 * @param key_size          the size of the key in bits
 *
 * @returns the OpenSSL NID for the curve, or NID_undef in case of an error
 */
static int _get_curve_nid(struct plugin_handle *ph, const char *curve,
			  size_t key_size)
{
	int nid = NID_undef;

	if (strcmp(curve, EKMFWEB_CURVE_PRIME) == 0) {
		switch (key_size) {
		case 192:
			nid = NID_X9_62_prime192v1;
			break;
		case 224:
			nid = NID_secp224r1;
			break;
		case 256:
			nid = NID_X9_62_prime256v1;
			break;
		case 384:
			nid = NID_secp384r1;
			break;
		case 521:
			nid = NID_secp521r1;
			break;
		default:
			_set_error(ph, "Unsupported bit size %u of curve '%s'",
				   key_size, curve);
			goto out;
		}
	} else if (strcmp(curve, EKMFWEB_CURVE_BAINPOOL) == 0) {
		switch (key_size) {
		case 160:
			nid = NID_brainpoolP160r1;
			break;
		case 192:
			nid = NID_brainpoolP192r1;
			break;
		case 224:
			nid = NID_brainpoolP224r1;
			break;
		case 256:
			nid = NID_brainpoolP256r1;
			break;
		case 320:
			nid = NID_brainpoolP320r1;
			break;
		case 384:
			nid = NID_brainpoolP384r1;
			break;
		case 512:
			nid = NID_brainpoolP512r1;
			break;
		default:
			_set_error(ph, "Unsupported bit size %u of curve '%s'",
				   key_size, curve);
			goto out;
		}
	} else {
		_set_error(ph, "Unsupported curve '%s'", curve);
		goto out;
	}

out:
	return nid;
}

struct template_cb_data {
	const char *template;
	struct ekmf_template_info **info;
};

/**
 * Callback for ekmf_list_templates function to get template info by name
 *
 * @param curl_handle      a CURL handle that can be used to perform further
 *                         EKMFWeb functions within the callback.
 * @param template_info    a struct containing information about the template.
 *                         If any of the information needs to be kept, then the
 *                         callback function must make a copy of the
 *                         information. The memory holding the information
 *                         passed to the callback is no longer valid after the
 *                         callback has returned.
 * @param private          the private pointer that was specified with the
 *                         ekmf_list_templates invocation.
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _template_cb(CURL *UNUSED(curl_handle),
			struct ekmf_template_info *template_info,
			void *private)
{
	struct template_cb_data *data = private;
	int rc;

	if (*data->info != NULL)
		return 0;

	if (strcmp(template_info->name, data->template) != 0)
		return 0;

	rc = ekmf_clone_template_info(template_info, data->info);

	return rc;
}

/**
 * Get information about a template by name
 *
 * @param ph                the plugin handle
 * @param template          the name of the template
 * @param info              On return: the template info. Must be freed by the
 *                          caller via ekmf_free_template_info.
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _get_template_by_name(struct plugin_handle *ph, const char *template,
				 struct ekmf_template_info **info)
{
	struct template_cb_data data;
	char *error_msg = NULL;
	int rc;

	*info = NULL;

	data.template = template;
	data.info = info;

	rc = ekmf_list_templates(&ph->ekmf_config, &ph->curl_handle,
				 _template_cb, &data, template,
				 EKMFWEB_TEMPLATE_STATE_ACTIVE,
				 &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to get the template '%s': %s", template,
			   error_msg != NULL ? error_msg : strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}
	if (*info == NULL) {
		rc = -ENOENT;
		_set_error(ph, "Template '%s' does not exist", template);
		goto out;
	}

out:
	if (error_msg != NULL)
		free(error_msg);

	return rc;
}

/**
 * Check a template if it is using the desired settings
 *
 * @param ph                the plugin handle
 * @param info              the template info
 * @param keystore_type     the expected keystore type
 * @param no_warnig         if true, do not issue warning messages
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _check_template(struct plugin_handle *ph,
			   struct ekmf_template_info *info,
			   const char *keystore_type, bool no_warning)
{
	char *identity_key_param = NULL;
	char *identity_key_alg = NULL;
	size_t modulus_bits;
	char *msg = NULL;
	int curve_nid;
	int rc = 0;

	if (strcmp(info->state, EKMFWEB_TEMPLATE_STATE_ACTIVE) != 0) {
		if (strcmp(info->state, EKMFWEB_TEMPLATE_STATE_HISTORY) == 0)
			_set_error(ph, "Template '%s' is in state '%s'. "
				   "If the template has been recently changed, "
				   "run 'zkey kms configure --refresh-settings'"
				   " to refresh the templates.", info->name,
				   EKMFWEB_TEMPLATE_STATE_HISTORY);
		else
			_set_error(ph, "Template '%s' is in state '%s', "
				   "but only templates in state '%s' can "
				   "be used.", info->name, info->state,
				   EKMFWEB_TEMPLATE_STATE_ACTIVE);
		rc = -EINVAL;
		goto out;
	}

	if (strcmp(info->key_state, EKMFWEB_KEY_STATE_ACTIVE) != 0) {
		_set_error(ph, "Template '%s' generates key in state '%s', but "
			   "only templates that generate keys in state '%s' "
			   "are supported.", info->name, info->key_state,
			   EKMFWEB_KEY_STATE_ACTIVE);
		rc = -EINVAL;
		goto out;
	}

	if (strcmp(info->keystore_type, keystore_type) != 0) {
		_set_error(ph, "Template '%s' uses key store type '%s', but "
			   "only key store type '%s' is supported for %s.",
			   info->name, info->keystore_type, keystore_type,
			   strcmp(keystore_type,
				  EKMFWEB_KEYSTORE_TYPE_PERV_ENCR) == 0 ?
				"volume encryption keys" : "identity keys");
		rc = -EINVAL;
		goto out;
	}

	if (strcmp(info->keystore_type, EKMFWEB_KEYSTORE_TYPE_PERV_ENCR) == 0) {
		if (strcmp(info->key_type, EKMFWEB_KEY_TYPE_CIPHER) != 0) {
			_set_error(ph, "Template '%s' generates keys of type "
				   "'%s', but only key type '%s' is supported "
				   "for volume encryption keys.",
				   info->name, info->key_type,
				   EKMFWEB_KEY_TYPE_CIPHER);
			rc = -EINVAL;
			goto out;
		}

		if (strcmp(info->algorithm, EKMFWEB_KEY_ALGORITHM_AES) != 0) {
			_set_error(ph, "Template '%s' generates keys with "
				   "algorithm '%s', but only algorithm '%s' is "
				   "supported for volume encryption keys.",
				   info->name, info->algorithm,
				   EKMFWEB_KEY_ALGORITHM_AES);
			rc = -EINVAL;
			goto out;
		}

		if (info->export_allowed == false) {
			_set_error(ph, "Template '%s' generates key that are "
				   "not allowed to be exported, but only "
				   "templates that generate keys that are "
				   "allowed to be exported are supported for "
				   "volume encryption keys.",
				   info->name);
			rc = -EINVAL;
			goto out;
		}
	}

	if (strcmp(info->keystore_type, EKMFWEB_KEYSTORE_TYPE_IDENTITY) == 0) {
		if (strcmp(info->algorithm, EKMFWEB_KEY_ALGORITHM_ECC) != 0 &&
		    strcmp(info->algorithm, EKMFWEB_KEY_ALGORITHM_RSA) != 0) {
			_set_error(ph, "Template '%s' generates keys with "
				   "algorithm '%s', but only algorithms '%s' "
				   "and '%s' are supported for identity keys.",
				   info->name, info->algorithm,
				   EKMFWEB_KEY_ALGORITHM_ECC,
				   EKMFWEB_KEY_ALGORITHM_RSA);
			rc = -EINVAL;
			goto out;
		}

		if (no_warning)
			goto out;

		identity_key_alg = properties_get(ph->properties,
					EKMFWEB_CONFIG_IDENTITY_KEY_ALGORITHM);
		if (identity_key_alg == NULL)
			goto out;

		if (strcmp(info->algorithm, identity_key_alg) != 0) {
			util_asprintf(&msg, "WARNING: Template '%s' uses "
				      "algorithm '%s', but the existing "
				      "identity key uses algorithm '%s'. You "
				      "may need to generate a new identity "
				      "key and re-register this zkey client.",
				      info->name, info->algorithm,
				      identity_key_alg);
			util_print_indented(msg, 0);
			free(msg);
			goto out;
		}

		identity_key_param = properties_get(ph->properties,
					EKMFWEB_CONFIG_IDENTITY_KEY_PARAMS);
		if (identity_key_param == NULL)
			goto out;

		if (strcmp(identity_key_alg, EKMFWEB_KEY_ALGORITHM_ECC) == 0) {
			curve_nid = _get_curve_nid(ph, info->curve,
						   info->key_size);
			if (curve_nid == NID_undef) {
				rc = -EINVAL;
				goto out;
			}
			if (OBJ_txt2nid(identity_key_param) != curve_nid) {
				util_asprintf(&msg, "WARNING: Template '%s' "
					      "uses algorithm ECC with curve "
					      "'%s', but the existing identity "
					      "key uses curve '%s'. You may "
					      "need to generate a new identity "
					      "key and re-register this zkey "
					      "client.", info->name,
					      OBJ_nid2sn(curve_nid),
					      identity_key_param);
				util_print_indented(msg, 0);
				free(msg);
			}
		} else if (strcmp(identity_key_alg, EKMFWEB_KEY_ALGORITHM_RSA)
									== 0) {
			modulus_bits = strtoul(identity_key_param, NULL, 10);
			if (modulus_bits != info->key_size) {
				util_asprintf(&msg, "WARNING: Template '%s' "
					      "uses algorithm RSA with a "
					      "modulus bit size of %lu, but "
					      "the existing identity key uses "
					      "%lu bits. You may need to "
					      "generate a new identity key and "
					      "re-register this zkey client.",
					      info->name, info->key_size,
					      modulus_bits);
				util_print_indented(msg, 0);
				free(msg);
			}
		}
	}

out:
	if (identity_key_alg != NULL)
		free(identity_key_alg);
	if (identity_key_param != NULL)
		free(identity_key_param);

	return rc;
}

/**
 * Check the 2 XTS templates
 *
 * @param ph                the plugin handle
 * @param xts1_info         the template info if XTS key 1
 * @param xts2_info         the template info if XTS key 2
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _check_xts_templates(struct plugin_handle *ph,
				struct ekmf_template_info *xts1_info,
				struct ekmf_template_info *xts2_info)
{
	size_t i;

	if (strcasecmp(xts1_info->label_template,
		       xts2_info->label_template) == 0) {
		_set_error(ph, "The 2 XTS templates can not have the same "
			   "label template.");
		return -EINVAL;
	}

	if (xts1_info->key_size != xts2_info->key_size) {
		_set_error(ph, "The 2 XTS templates must have the same key "
			   "size.");
		return -EINVAL;
	}

	if (xts1_info->label_tags.num_tag_defs !=
				xts2_info->label_tags.num_tag_defs) {
		_set_error(ph, "The 2 XTS templates must have the same label "
			   "tags. The templates differ in the number of label "
			   "tags: '%s' '%s'", xts1_info->label_template,
			   xts2_info->label_template);
		return -EINVAL;
	}

	for (i = 0; i < xts1_info->label_tags.num_tag_defs; i++) {
		if (strcasecmp(xts1_info->label_tags.tag_defs[i].name,
			       xts2_info->label_tags.tag_defs[i].name) != 0) {
			_set_error(ph, "The 2 XTS templates must have the same "
				   "label tags. Mismatch in tag '%s': "
				   "'%s' '%s'",
				   xts1_info->label_tags.tag_defs[i].name,
				   xts1_info->label_template,
				   xts2_info->label_template);
			return -EINVAL;
		}
	}

	return 0;
}

struct template_infos {
	char *template;
	struct ekmf_template_info *info;
	const char *name_prop;
	const char *label_prop;
	const char *id_prop;
	const char *keystore_type;
};

#define NUM_TEMPLATES		4
#define IDENTITY		0
#define XTS1			1
#define XTS2			2
#define NONXTS			3

/**
 * Retrieves the key templates to be used by the plugin
 *
 * @param ph                the plugin handle
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _get_templates(struct plugin_handle *ph)
{
	struct template_infos tmpl[NUM_TEMPLATES] = {
		{ .template = NULL, .info = NULL,
		  .name_prop = EKMFWEB_CONFIG_TEMPLATE_IDENTITY,
		  .label_prop = EKMFWEB_CONFIG_TEMPLATE_IDENTITY_LABEL,
		  .id_prop = EKMFWEB_CONFIG_TEMPLATE_IDENTITY_ID,
		  .keystore_type = EKMFWEB_KEYSTORE_TYPE_IDENTITY, },
		{ .template = NULL, .info = NULL,
		  .name_prop = EKMFWEB_CONFIG_TEMPLATE_XTS1,
		  .label_prop = EKMFWEB_CONFIG_TEMPLATE_XTS1_LABEL,
		  .id_prop = EKMFWEB_CONFIG_TEMPLATE_XTS1_ID,
		  .keystore_type = EKMFWEB_KEYSTORE_TYPE_PERV_ENCR, },
		{ .template = NULL, .info = NULL,
		  .name_prop = EKMFWEB_CONFIG_TEMPLATE_XTS2,
		  .label_prop = EKMFWEB_CONFIG_TEMPLATE_XTS2_LABEL,
		  .id_prop = EKMFWEB_CONFIG_TEMPLATE_XTS2_ID,
		  .keystore_type = EKMFWEB_KEYSTORE_TYPE_PERV_ENCR, },
		{ .template = NULL, .info = NULL,
		  .name_prop = EKMFWEB_CONFIG_TEMPLATE_NONXTS,
		  .label_prop = EKMFWEB_CONFIG_TEMPLATE_NONXTS_LABEL,
		  .id_prop = EKMFWEB_CONFIG_TEMPLATE_NONXTS_ID,
		  .keystore_type = EKMFWEB_KEYSTORE_TYPE_PERV_ENCR, },
	};
	char *error_msg = NULL;
	int t, rc;

	rc = ekmf_get_settings(&ph->ekmf_config, &ph->curl_handle,
			       &tmpl[IDENTITY].template, &tmpl[XTS1].template,
			       &tmpl[XTS2].template, &tmpl[NONXTS].template,
			       &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to get settings from EKMF Web: %s",
			   error_msg != NULL ? error_msg : strerror(-rc));
		goto out;
	}

	for (t = 0; t < NUM_TEMPLATES; t++) {
		rc = _get_template_by_name(ph, tmpl[t].template, &tmpl[t].info);
		if (rc != 0)
			goto out;
	}

	rc = _check_xts_templates(ph, tmpl[XTS1].info, tmpl[XTS2].info);
	if (rc != 0)
		goto out;

	for (t = 0; t < NUM_TEMPLATES; t++) {
		rc = _check_template(ph, tmpl[t].info, tmpl[t].keystore_type,
				     false);
		if (rc != 0)
			goto out;

		rc = _set_or_remove_property(ph, tmpl[t].name_prop,
					     tmpl[t].template);
		if (rc != 0)
			goto out;
		rc = _set_or_remove_property(ph, tmpl[t].label_prop,
					     tmpl[t].info->label_template);
		if (rc != 0)
			goto out;
		rc = _set_or_remove_property(ph, tmpl[t].id_prop,
					     tmpl[t].info->uuid);
		if (rc != 0)
			goto out;
	}

out:
	for (t = 0; t < NUM_TEMPLATES; t++) {
		if (tmpl[t].info != NULL)
			ekmf_free_template_info(tmpl[t].info);
		if (tmpl[t].template != NULL)
			free(tmpl[t].template);
	}
	if (error_msg != NULL)
		free(error_msg);

	return rc;
}

/**
 * Retrieves the EKMF Web system settings. This requires a login. If no
 * valid login token is available, a login is performed.
 *
 * @param ph                the plugin handle
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _get_ekmfweb_settings(struct plugin_handle *ph)
{
	int rc, type = 0, curve = NID_undef;
	char *error_msg = NULL;

	_check_config_complete(ph);

	if (ph->ekmf_config.login_token != NULL) {
		remove(ph->ekmf_config.login_token);
		FREE_AND_SET_NULL(ph->ekmf_config.login_token);
	}
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_LOGIN_TOKEN, NULL);
	if (rc != 0)
		goto out;
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_PASSCODE_URL, NULL);
	if (rc != 0)
		goto out;

	rc = ekmf_check_feature(&ph->ekmf_config, &ph->curl_handle,
				&error_msg, ph->verbose);
	if (rc != 0) {
		if (rc == -ENOTSUP)
			_set_error(ph, "%s", error_msg);
		else
			_set_error(ph, "Failed to check the features of the "
				   "EKMF Web server at '%s': %s",
				   ph->ekmf_config.base_url,
				   error_msg != NULL ? error_msg :
							   strerror(-rc));
		goto out;
	}

	rc = kms_login((kms_handle_t)ph);
	if (rc != 0)
		goto out;

	if (ph->ekmf_config.ekmf_server_pubkey != NULL)
		remove(ph->ekmf_config.ekmf_server_pubkey);
	FREE_AND_SET_NULL(ph->ekmf_config.ekmf_server_pubkey);

	util_asprintf((char **)&ph->ekmf_config.ekmf_server_pubkey,
		      "%s/%s", ph->config_path,
		      EKMFWEB_CONFIG_EKMFWEB_PUBKEY_FILE);

	rc = ekmf_get_public_key(&ph->ekmf_config, &ph->curl_handle,
				 &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to get the public key of the EKMF Web "
			   "server at '%s': %s", ph->ekmf_config.base_url,
			   error_msg != NULL ? error_msg : strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	rc = _set_file_permission(ph, ph->ekmf_config.ekmf_server_pubkey);
	if (rc != 0)
		goto out;

	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_EKMFWEB_PUBKEY,
				     ph->ekmf_config.ekmf_server_pubkey);
	if (rc != 0)
		goto out;

	rc = _get_pub_key_info(ph, ph->ekmf_config.ekmf_server_pubkey, &type,
			       &curve, NULL);
	if (rc != 0)
		goto out;
	if (type != EVP_PKEY_EC || curve == NID_undef)
		curve = NID_secp521r1;

	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_SESSION_KEY_CURVE,
				     OBJ_nid2sn(curve));
	if (rc != 0)
		goto out;

	rc = _get_templates(ph);
	if (rc != 0)
		goto out;

out:
	if (error_msg != NULL)
		free(error_msg);

	return rc;
}

/**
 * Check if the certificate is a self signed certificate, and if it is expired
 * or not yet valid.
 *
 * @param ph                the plugin handle
 * @param cert_file         the file name of the PEM file containing the cert
 * @param self_signed       on return: true if the cetr is a self signed cert
 * @param valid             on return: false if the cert is expired or not yet
 *                          valid
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _check_certificate(struct plugin_handle *ph,
			      const char *cert_file, bool *self_signed,
			      bool *valid)
{
	X509 *cert;
	FILE *fp;
	int rc;

	fp = fopen(cert_file, "r");
	if (fp == NULL) {
		rc = -errno;
		_set_error(ph, "Failed to open certificate PEM file '%s': %s",
			   cert_file, strerror(-rc));
		return rc;
	}

	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (cert == NULL) {
		_set_error(ph, "Failed to read certificate PEM file '%s'",
			   cert_file);
		return -EIO;
	}


	*self_signed = (X509_NAME_cmp(X509_get_subject_name(cert),
				      X509_get_issuer_name(cert)) == 0);

	*valid = (X509_cmp_current_time(X509_get0_notBefore(cert)) < 0 &&
		  X509_cmp_current_time(X509_get0_notAfter(cert)) > 0);

	X509_free(cert);

	return 0;
}

/**
 * Configures the connection to the EKMF Web server
 *
 * @param ph                the plugin handle
 * @param ekmfweb_url       the URL of the EKMF Web server
 * @param tls_ca_bundle     the file or directory name of the CA bundle to use
 * @param tls_client_cert   the file name of the client certificate
 * @param tls_client_key   the file name of the client private key
 * @param tls_client_key_passphrase   the passphrase to unlock the key
 * @param tls_pin_server_pubkey if true, pin the server public key
 * @param tls_trust_server_cert if true, trust the server certificate
 * @param tls_dont_verify_server_cert if true, don't verify the server cert
 * @param tls_verify_hostname if true verify the server's hostname
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _configure_connection(struct plugin_handle *ph,
				 const char *ekmfweb_url,
				 const char *tls_ca_bundle,
				 const char *tls_client_cert,
				 const char *tls_client_key,
				 const char *tls_client_key_passphrase,
				 bool tls_pin_server_pubkey,
				 bool tls_trust_server_cert,
				 bool tls_dont_verify_server_cert,
				 bool tls_verify_hostname)
{
	char *server_pubkey_temp = NULL;
	char *server_pubkey_file = NULL;
	char *server_cert_file = NULL;
	char *server_cert_temp = NULL;
	bool self_signed = false;
	bool add_https = false;
	bool verified = false;
	bool valid = false;
	char *error = NULL;
	char *url = NULL;
	int rc = 0;
	char *tmp;

	if (tls_client_cert != NULL && tls_client_key == NULL) {
		_set_error(ph, "Option '--tls-client-key' is required when "
			   "option '--tls-client-cert' is specified.");
		return -EINVAL;
	}
	if (tls_client_key != NULL && tls_client_cert == NULL) {
		_set_error(ph, "Option '--tls-client-cert' is required when "
			   "option '--tls-client-key' is specified.");
		return -EINVAL;
	}
	if (tls_client_key_passphrase != NULL && tls_client_key == NULL) {
		_set_error(ph, "Option '--tls-client-key-passphrase' is only "
			   "valid together with option "
			   "'--tls-client-key'.");
		return -EINVAL;
	}
	if (tls_pin_server_pubkey && tls_trust_server_cert) {
		_set_error(ph, "Option ' --tls-pin-server-pubkey' is not valid "
			   "together with option '--tls-pin-server-cert");
		return -EINVAL;
	}

	if (ph->ekmf_config.base_url != NULL) {
		util_print_indented("ATTENTION: The EKMF Web server connection "
				    "has already been configured!\n"
				    "When you re-configure the EKMF Web server "
				    "connection, you may need to re-register "
				    "this zkey client with the changed EKMF "
				    "Web server.", 0);
		printf("%s: Re-configure the EKMF Web server connection "
		       "[y/N]? ",
		       program_invocation_short_name);
		if (!prompt_for_yes(ph->verbose)) {
			_set_error(ph, "Operation aborted by user");
			return -ECANCELED;
		}
	}

	if (strncmp(ekmfweb_url, "http://", 6) == 0) {
		_set_error(ph, "The use of insecured HTTP is not allowed.");
		return -EINVAL;
	}

	if (strncmp(ekmfweb_url, "https://", 7) != 0)
		add_https = true;

	util_asprintf(&url, "%s%s", add_https ? "https://" : "", ekmfweb_url);
	if (url[strlen(url) - 1] == '/')
		url[strlen(url) - 1] = '\0';

	pr_verbose(ph, "url: '%s'", url);

	FREE_AND_SET_NULL(ph->ekmf_config.base_url);
	ph->ekmf_config.base_url = url;

	rc = properties_set(ph->properties, EKMFWEB_CONFIG_URL, url);
	if (rc != 0) {
		_set_error(ph, "Failed to set URL property: "
			   "%s", strerror(-rc));
		goto out;
	}

	FREE_AND_SET_NULL(ph->ekmf_config.tls_ca);
	if (tls_ca_bundle != NULL)
		ph->ekmf_config.tls_ca = util_strdup(tls_ca_bundle);
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_CA_BUNDLE,
				     tls_ca_bundle);

	FREE_AND_SET_NULL(ph->ekmf_config.tls_client_cert);
	if (tls_client_cert != NULL)
		ph->ekmf_config.tls_client_cert = util_strdup(tls_client_cert);
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_CLIENT_CERT,
				     tls_client_cert);
	if (rc != 0)
		goto out;

	FREE_AND_SET_NULL(ph->ekmf_config.tls_client_key);
	if (tls_client_key != NULL)
		ph->ekmf_config.tls_client_key = util_strdup(tls_client_key);
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_CLIENT_KEY,
				     tls_client_key);
	if (rc != 0)
		goto out;

	tmp = NULL;
	FREE_AND_SET_NULL(ph->ekmf_config.tls_client_key_passphrase);
	if (tls_client_key_passphrase != NULL) {
		ph->ekmf_config.tls_client_key_passphrase =
				util_strdup(tls_client_key_passphrase);
		tmp = _encode_passphrase(tls_client_key_passphrase);
		if (tmp == NULL) {
			_set_error(ph, "Failed to encode the passphrase");
			rc = -EIO;
			goto out;
		}
	}
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_CLIENT_KEY_PASSPHRASE,
				     tmp);
	if (tmp != NULL)
		free(tmp);
	if (rc != 0)
		goto out;

	util_asprintf(&server_cert_temp, "%s/%s-tmp", ph->config_path,
		      EKMFWEB_CONFIG_SERVER_CERT_FILE);
	util_asprintf(&server_pubkey_temp, "%s/%s-tmp", ph->config_path,
		      EKMFWEB_CONFIG_SERVER_PUBKEY_FILE);

	rc = ekmf_get_server_cert_chain(&ph->ekmf_config,
					server_cert_temp,
					server_pubkey_temp,
					NULL, &verified,
					&error, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to connect to EKMF Web server at '%s': "
			   "%s", ph->ekmf_config.base_url,
			   error != NULL ? error : strerror(-rc));
		goto out;
	}

	rc = _check_certificate(ph, server_cert_temp, &self_signed, &valid);
	if (rc != 0)
		goto out;

	pr_verbose(ph, "verified: %d", verified);
	pr_verbose(ph, "self signed: %d", self_signed);
	pr_verbose(ph, "valid: %d", valid);

	util_print_indented("The EKMF Web server presented the following "
			    "certificate to identify itself:", 0);

	rc = ekmf_print_certificates(server_cert_temp, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to print the server certificate: %s",
			   strerror(-rc));
		goto out;
	}

	printf("\n");
	if (!valid)
		printf("ATTENTION: The certificate is expired or not yet "
		       "valid.\n");
	if (self_signed) {
		printf("ATTENTION: The certificate is self signed "
			      "and thus could not be verified.\n");
	} else if (!verified) {
		if (!tls_dont_verify_server_cert) {
			if (tls_ca_bundle != NULL)
				_set_error(ph, "The certificate could not be "
					   "verified using the specified CA "
					   "bundle '%s'. Use option "
					   "'--tls-dont-verify-server-cert' to "
					   "connect to this server anyway.",
					   tls_ca_bundle);
			else
				_set_error(ph, "The certificate could not be "
					   "verified using the system's "
					   "CA certificates. Use option "
					   "'--tls-dont-verify-server-cert' to "
					   "connect to this server anyway.");
			rc = -EINVAL;
			goto out;
		}
	}
	printf("%s: Is this the EKMF Web server you intend to work with "
	      "[y/N]? ", program_invocation_short_name);
	if (!prompt_for_yes(ph->verbose)) {
		_set_error(ph, "Operation aborted by user");
		rc = -ECANCELED;
		goto out;
	}

	ph->ekmf_config.tls_verify_peer = !self_signed || tls_trust_server_cert;
	if (tls_dont_verify_server_cert)
		ph->ekmf_config.tls_verify_peer = false;
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_VERIFY_SERVER_CERT,
				     ph->ekmf_config.tls_verify_peer ?
						     "yes" : "no");
	if (rc != 0)
		goto out;

	ph->ekmf_config.tls_verify_host = tls_verify_hostname;
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_VERIFY_HOSTNAME,
				     ph->ekmf_config.tls_verify_host ?
						     "yes" : "no");
	if (rc != 0)
		goto out;

	rc = _get_ekmfweb_settings(ph);
	if (rc != 0) {
		util_print_indented("The server you are connected with is not "
				     "a valid EKMF Web server, or is not "
				     "configured properly", 0);
		goto out;
	}

	FREE_AND_SET_NULL(ph->ekmf_config.tls_server_cert);
	util_asprintf(&server_cert_file, "%s/%s", ph->config_path,
		      EKMFWEB_CONFIG_SERVER_CERT_FILE);
	if (tls_trust_server_cert) {
		ph->ekmf_config.tls_server_cert = util_strdup(server_cert_file);
		rc = _activate_temp_file(ph, server_cert_temp,
					 server_cert_file);
		if (rc != 0)
			goto out;
	} else {
		remove(server_cert_file);
	}
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_SERVER_CERT,
				     tls_trust_server_cert ?
						server_cert_file : NULL);
	if (rc != 0)
		goto out;

	FREE_AND_SET_NULL(ph->ekmf_config.tls_pinned_pubkey);
	util_asprintf(&server_pubkey_file, "%s/%s", ph->config_path,
		      EKMFWEB_CONFIG_SERVER_PUBKEY_FILE);
	if (tls_pin_server_pubkey) {
		ph->ekmf_config.tls_pinned_pubkey =
				util_strdup(server_pubkey_file);
		rc = _activate_temp_file(ph, server_pubkey_temp,
					 server_pubkey_file);
		if (rc != 0)
			goto out;
	} else {
		remove(server_pubkey_file);
	}
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_SERVER_PUBKEY,
				     tls_pin_server_pubkey ?
						server_pubkey_file : NULL);
	if (rc != 0)
		goto out;

out:
	if (server_cert_temp != NULL) {
		remove(server_cert_temp);
		free(server_cert_temp);
	}
	if (server_cert_file != NULL)
		free(server_cert_file);
	if (server_pubkey_temp != NULL) {
		remove(server_pubkey_temp);
		free(server_pubkey_temp);
	}
	if (server_pubkey_file != NULL)
		free(server_pubkey_file);
	if (error != NULL)
		free(error);

	return rc;
}

struct config_options {
	const char *ekmfweb_url;
	const char *tls_ca_bundle;
	const char *tls_client_cert;
	const char *tls_client_key;
	const char *tls_client_key_passphrase;
	bool tls_pin_server_pubkey;
	bool tls_trust_server_cert;
	bool tls_dont_verify_server_cert;
	bool tls_verify_hostname;
	bool refresh_settings;
	bool generate_identity_key;
	const char *sscert_pem_file;
	const char *csr_pem_file;
	const char *cert_subject;
	const char *cert_extensions;
	const char *renew_cert_pem_file;
	bool csr_new_header;
	const char *cert_validity_days;
	const char *cert_digest;
#ifdef EKMF_SUPPORTS_RSA_PSS_CERTIFICATES
	bool cert_rsa_pss;
#endif
	const char *register_cert_file;
	const char *register_label_tags;
#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
	const char *session_rsa_sign_digest;
	const char *session_rsa_sign_algo;
#endif
};

/**
 * Checks that none of the options for seting up a connection  is specified,
 * and sets up the error message and return code if
 * so.
 *
 * @param ph                the plugin handle
 * @param opts              the config options structure
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _error_connection_opts(struct plugin_handle *ph,
				  struct config_options *opts)
{
	int rc = 0;

	if (opts->tls_ca_bundle != NULL) {
		_set_error(ph, "Option '--tls-ca-bundle' is only valid "
			   "together with option '--ekmfweb-url'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->tls_client_cert != NULL) {
		_set_error(ph, "Option '--tls-client-cert' is only valid "
			   "together with option '--ekmfweb-url'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->tls_client_key != NULL) {
		_set_error(ph, "Option '--tls-client-key' is only valid "
			   "together with option '--ekmfweb-url'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->tls_client_key_passphrase != NULL) {
		_set_error(ph, "Option '--tls-client-key-passphrase' is only "
			   "valid together with option '--ekmfweb-url'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->tls_pin_server_pubkey) {
		_set_error(ph, "Option '--tls-pin-server-pubkey' is only valid "
			   "together with option '--ekmfweb-url'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->tls_trust_server_cert) {
		_set_error(ph, "Option '--tls-trust-server-cert' is only valid "
			   "together with option '--ekmfweb-url'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->tls_dont_verify_server_cert) {
		_set_error(ph, "Option '--tls-dont-verify-server-cert' is only "
			   "valid together with option '--ekmfweb-url'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->tls_verify_hostname) {
		_set_error(ph, "Option '--tls-verify-hostname' is only valid "
			   "together with option '--ekmfweb-url'.");
		rc = -EINVAL;
		goto out;
	}

out:
	return rc;
}

/**
 * Generates (or re-generates) a identity key for the plugin using the
 * settings from the identity template
 *
 * @param ph                the plugin handle
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _generate_identity_key(struct plugin_handle *ph)
{
	struct ekmf_template_info *template_info = NULL;
	struct ekmf_key_gen_info gen_info;
	char *template_uuid = NULL;
	char *reenc_file = NULL;
	char *error_msg = NULL;
	char key_params[200];
	int rc = 0;

	_check_config_complete(ph);

	if (!ph->apqns_configured) {
		_set_error(ph, "The configuration is incomplete, you must "
			   "first configure the APQNs used with this plugin.");
		return -EINVAL;
	}
	if (!ph->templates_retrieved) {
		_set_error(ph, "The configuration is incomplete, you must "
			   "first configure the EKMF Web server connection.");
		return -EINVAL;
	}

	rc = kms_login((kms_handle_t)ph);
	if (rc != 0)
		goto out;

	template_uuid = properties_get(ph->properties,
				       EKMFWEB_CONFIG_TEMPLATE_IDENTITY_ID);
	if (template_uuid == NULL) {
		rc = -EIO;
		_set_error(ph, "No identity key template configured");
		goto out;
	}

	rc = ekmf_get_template(&ph->ekmf_config, &ph->curl_handle,
			       template_uuid, &template_info,
			       &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to get identity key template '%s': %s",
			   template_uuid, error_msg != NULL ? error_msg :
			   strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	rc = _check_template(ph, template_info, EKMFWEB_KEYSTORE_TYPE_IDENTITY,
			     true);
	if (rc != 0)
		goto out;

	pr_verbose(ph, "Identity template algorithm: '%s'",
			template_info->algorithm);
	pr_verbose(ph, "Identity template key size: %lu",
			template_info->key_size);

	if (strcmp(template_info->algorithm, EKMFWEB_KEY_ALGORITHM_ECC) == 0) {
		pr_verbose(ph, "Identity template curve: '%s'",
					template_info->curve);

		gen_info.type = EKMF_KEY_TYPE_ECC;
		gen_info.params.ecc.curve_nid =
				_get_curve_nid(ph, template_info->curve,
					       template_info->key_size);
		if (gen_info.params.ecc.curve_nid == NID_undef)
			return -EINVAL;

		strcpy(key_params, OBJ_nid2sn(gen_info.params.ecc.curve_nid));
	} else if (strcmp(template_info->algorithm,
			  EKMFWEB_KEY_ALGORITHM_RSA) == 0) {
		gen_info.type = EKMF_KEY_TYPE_RSA;
		switch (template_info->key_size) {
		case 512:
		case 1024:
		case 2048:
		case 4096:
			gen_info.params.rsa.modulus_bits =
					template_info->key_size;
			break;
		default:
			_set_error(ph, "Invalid modulus bits: '%s'",
				   template_info->key_size);
			return -EINVAL;
		}
		gen_info.params.rsa.pub_exp =
					DEFAULT_IDENTITY_KEY_PUBLIC_EXPONENT;

		sprintf(key_params, "%lu", gen_info.params.rsa.modulus_bits);
	} else {
		_set_error(ph, "Invalid identity template algorithm type '%s'",
			   template_info->algorithm);
		return -EINVAL;
	}

	if (ph->ekmf_config.identity_secure_key != NULL) {
		printf("ATTENTION: An identity key already exists!\n");
		util_print_indented("When you generate a new identity key, "
				    "you will need to re-register this zkey "
				    "client with the EKMF Web server.", 0);
		printf("%s: Re-generate the identity key [y/N]? ",
		       program_invocation_short_name);
		if (!prompt_for_yes(ph->verbose)) {
			_set_error(ph, "Operation aborted by user");
			return -ECANCELED;
		}
	} else {
		util_asprintf((char **)&ph->ekmf_config.identity_secure_key,
			      "%s/%s", ph->config_path,
			      EKMFWEB_CONFIG_IDENTITY_KEY_FILE);

		rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY,
					ph->ekmf_config.identity_secure_key);
		if (rc != 0)
			goto out;
	}

	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY_ALGORITHM,
				     template_info->algorithm);
	if (rc != 0)
		goto out;
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY_PARAMS,
				     key_params);
	if (rc != 0)
		goto out;

	rc = _select_cca_adapter(ph);
	if (rc != 0)
		goto out;

	rc = ekmf_generate_identity_key(&ph->ekmf_config, &gen_info,
					&ph->ext_lib, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to generate the identity key: %s",
			   strerror(-rc));
		goto out;
	}

	rc = _set_file_permission(ph, ph->ekmf_config.identity_secure_key);
	if (rc != 0)
		goto out;

	reenc_file = properties_get(ph->properties,
				    EKMFWEB_CONFIG_IDENTITY_KEY_REENC);
	if (reenc_file != NULL) {
		remove(reenc_file);
		free(reenc_file);
		properties_remove(ph->properties,
				  EKMFWEB_CONFIG_IDENTITY_KEY_REENC);
	}

	properties_remove(ph->properties, EKMFWEB_CONFIG_IDENTITY_KEY_LABEL);
	properties_remove(ph->properties, EKMFWEB_CONFIG_IDENTITY_KEY_ID);

	pr_verbose(ph, "Generated identity key into '%s'",
		   ph->ekmf_config.identity_secure_key);

out:
	if (template_uuid != NULL)
		free(template_uuid);
	if (error_msg != NULL)
		free(error_msg);
	if (template_info != NULL)
		ekmf_free_template_info(template_info);

	return rc;
}

/**
 * Parses an unsigned number from a string.
 *
 * @param str                the string to parse
 *
 * @returns the parsed number, or -1 in case of an error.
 */
static long _parse_unsigned(const char *str)
{
	long val;
	char *endp;

	val = strtol(str, &endp, 0);
	if (*str == '\0' || *endp != '\0' ||
	    (val == LONG_MAX && errno == ERANGE))
		return -1;

	return val;
}

/**
 * Parse a semi-colon separated list and return an allocated array of the
 * elements.
 *
 * @param list              the semi-colon separated list
 * @param elements          on return, an allocated array of elements
 * @param num_elements      on return, the number of elements in the array
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _parse_list(const char *list, char ***elements,
		       size_t *num_elements)
{
	char *copy, *tok;
	size_t count;
	int i;

	for (i = 0, count = 1; list[i] != '\0'; i++)
		if (list[i] == ';')
			count++;

	*elements = util_zalloc(count * sizeof(char *));

	copy = util_strdup(list);
	tok = strtok(copy, ";");
	i = 0;
	while (tok != NULL) {
		if (strlen(tok) > 0) {
			(*elements)[i] = util_strdup(tok);
			i++;
		}
		tok = strtok(NULL, ";");
	}
	*num_elements = i;

	free(copy);

	return 0;
}

/**
 * Generates certificate signing request or self signed certificate using the
 * identity key
 *
 * @param ph                the plugin handle
 * @param csr_pem_file      name of the PEM file to store a CSR to. NULL if no
 *                          CSR is to be generated.
 * @param sscert_pem_file   name of the PEM file to store a self signed
 *                          certificate to. NULL if no certificate is to be
 *                          generated.
 * @param subject           the subject RNDs separated by semicolon (;). Can be
 *                          NULL if a renew certificate is specified.
 * @param extensions        the extensions separated by semicolon (;). Can be
 *                          NULL.
 * @param renew_cert_pem_file name of a PEM file containing a certificate to
 *                          renew. Can be NULL.
 * @param csr_new_header    if true output NEW header and footer lines in CSR
 * @param validity_days     the number of days the certificate is valid. Only
 *                          valid when generating a self signed certificate.
 *                          Can be NULL.
 * @param digest            the digest to use with CSR and certificates. Can be
 *                          NULL
 * @param rsa_pss           if true, RSA-PSS is used with RSA-based identity
 *                          keys
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _generate_csr_sscert(struct plugin_handle *ph,
				const char *csr_pem_file,
				const char *sscert_pem_file,
				const char *subject, const char *extensions,
				const char *renew_cert_pem_file,
				bool csr_new_header, const char *validity_days,
				const char *digest, bool rsa_pss)
{
	struct ekmf_rsa_pss_params rsa_pss_parms = {
		.salt_len = RSA_PSS_SALTLEN_MAX, .mgf_digest_nid = 0 };
	char **subject_rdn_list = NULL;
	char **extension_list = NULL;
	size_t num_subject_rdns = 0;
	int digest_nid = NID_undef;
	size_t num_extensions = 0;
	int days = 30;
	int rc = 0;
	size_t i;

	_check_config_complete(ph);

	if (!ph->apqns_configured) {
		_set_error(ph, "The configuration is incomplete, you must "
			   "first configure the APQNs used with this plugin.");
		return -EINVAL;
	}
	if (!ph->identity_key_generated) {
		_set_error(ph, "The configuration is incomplete, you must "
			   "first configure the EKMF Web server connection.");
		return -EINVAL;
	}

	if (csr_pem_file != NULL && sscert_pem_file != NULL) {
		_set_error(ph, "Either '--gen-csr' or option "
			   "'--gen-self-signed-cert' can be specified.");
		return -EINVAL;
	}
	if (csr_new_header && csr_pem_file == NULL) {
		_set_error(ph, "Option '--csr-new-header' is only valid with "
			   "option '--gen-csr'.");
		return -EINVAL;
	}
	if (validity_days != NULL && sscert_pem_file == NULL) {
		_set_error(ph, "Option '--cert-validity-days' is only valid "
			   "with option '--gen-self-signed-cert'.");
		return -EINVAL;
	}
	if (subject == NULL && renew_cert_pem_file == NULL) {
		_set_error(ph, "Option '--cert-subject' is required, unless "
			   " option '--renew-cert' is specified.");
		return -EINVAL;
	}

	if (validity_days != NULL) {
		days = _parse_unsigned(validity_days);
		if (days <= 0) {
			_set_error(ph, "Invalid validity days: '%s'",
				   validity_days);
			return -EINVAL;
		}
	}

	if (digest != NULL) {
		digest_nid = OBJ_txt2nid(digest);
		if (digest_nid == NID_undef) {
			_set_error(ph, "Invalid digest: '%s'", digest);
			return -EINVAL;
		}
	}

	if (subject != NULL) {
		rc = _parse_list(subject, &subject_rdn_list,
				 &num_subject_rdns);
		if (rc != 0)
			goto out;
	}

	if (extensions != NULL) {
		rc = _parse_list(extensions, &extension_list, &num_extensions);
		if (rc != 0)
			goto out;
	}

	rc = _select_cca_adapter(ph);
	if (rc != 0)
		goto out;

	if (csr_pem_file != NULL) {
		rc = ekmf_generate_csr(&ph->ekmf_config,
				       (const char **)subject_rdn_list,
				       num_subject_rdns, true,
				       renew_cert_pem_file,
				       (const char **)extension_list,
				       num_extensions, digest_nid,
				       rsa_pss ? &rsa_pss_parms : NULL,
				       csr_pem_file, csr_new_header,
				       &ph->ext_lib, ph->verbose);
	} else {
		rc = ekmf_generate_ss_cert(&ph->ekmf_config,
				       (const char **)subject_rdn_list,
				       num_subject_rdns, true,
				       renew_cert_pem_file,
				       (const char **)extension_list,
				       num_extensions, days, digest_nid,
				       rsa_pss ? &rsa_pss_parms : NULL,
				       sscert_pem_file, &ph->ext_lib,
				       ph->verbose);
	}
	switch (rc) {
	case 0:
		break;
	case -EBADMSG:
		_set_error(ph, "The subject or extensions could not be parsed "
			   "or are not recognized by OpenSSL.");
		rc = -EINVAL;
		goto out;
	case -EEXIST:
		_set_error(ph, "One of the subject name entries or extensions "
			   "is a duplicate.");
		rc = -EINVAL;
		goto out;
	case -ENOTSUP:
		_set_error(ph, "The specified digest is not supported.");
		rc = -EINVAL;
		goto out;
	default:
		_set_error(ph, "Failed to generate the %s: %s",
			   csr_pem_file != NULL ? "certificate signing request"
					   : "self signed certificate",
			   strerror(-rc));
		goto out;
	}

	if (csr_pem_file != NULL)
		pr_verbose(ph, "Generated certificate signing request into "
			   "'%s'", csr_pem_file);
	else
		pr_verbose(ph, "Generated self signed certificate into '%s'",
			   sscert_pem_file);

out:
	if (subject_rdn_list != NULL) {
		for (i = 0; i < num_subject_rdns; i++)
			free(subject_rdn_list[i]);
		free(subject_rdn_list);
	}
	if (extension_list != NULL) {
		for (i = 0; i < num_extensions; i++)
			free(extension_list[i]);
		free(extension_list);
	}

	return rc;
}

/**
 * Checks that none of the options for generating a CSR or self signed
 * certificate is specified, and sets up the error message and return code if
 * so.
 *
 * @param ph                the plugin handle
 * @param opts              the config options structure
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _error_gen_csr_sscert_opts(struct plugin_handle *ph,
				      struct config_options *opts)
{
	int rc = 0;

	if (opts->cert_subject != NULL) {
		_set_error(ph, "Option '--cert-subject' is only valid "
			   "together with options '--gen-csr' or "
			   "'--gen-self-signed-cert'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->cert_extensions != NULL) {
		_set_error(ph, "Option '--cert-extensions' is only "
			   "valid together with options '--gen-csr' or "
			   "'--gen-self-signed-cert'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->renew_cert_pem_file != NULL) {
		_set_error(ph, "Option '--renew-cert' is only "
			   "valid together with options '--gen-csr' or "
			   "'--gen-self-signed-cert'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->csr_new_header == true) {
		_set_error(ph, "Option '--csr-new-header' is only "
			   "valid together with option '--gen-csr'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->cert_validity_days != NULL) {
		_set_error(ph, "Option '--cert-validity-days' is only "
			   "valid together with option "
			   "'--gen-self-signed-cert'.");
		rc = -EINVAL;
		goto out;
	}
	if (opts->cert_digest != NULL) {
		_set_error(ph, "Option '--cert-digest' is only "
			   "valid together with options '--gen-csr' or "
			   "'--gen-self-signed-cert'.");
		rc = -EINVAL;
		goto out;
	}
#ifdef EKMF_SUPPORTS_RSA_PSS_CERTIFICATES
	if (opts->cert_rsa_pss == true) {
		_set_error(ph, "Option '--cert-rsa-pss' is only "
			   "valid together with option '--gen-csr' or "
			   "'--gen-self-signed-cert'");
		rc = -EINVAL;
		goto out;
	}
#endif

out:
	return rc;
}

/**
 * Frees an EKMF tag list
 *
 * @param ekmf_tag_list     the EKMF tag list
 */
static void _free_ekmf_tags(struct ekmf_tag_list *ekmf_tag_list)
{
	size_t i;

	if (ekmf_tag_list->tags == NULL)
		return;

	for (i = 0;  i < ekmf_tag_list->num_tags; i++) {
		free((char *)ekmf_tag_list->tags[i].name);
		free((char *)ekmf_tag_list->tags[i].value);
	}

	free(ekmf_tag_list->tags);
	ekmf_tag_list->tags = NULL;
	ekmf_tag_list->num_tags = 0;
}

/**
 * Parses the label tags passed in via option (<tag>=<value>;<tag>=<value;....)
 * and allocates an array of KMS properties. The tags must be freed by the
 * caller.
 *
 * @param ph                the plugin handle
 * @param template_info     the template info
 * @param label_tags        the label tags option value (can be NULL)
 * @param ekmf_tag_list     On return: a list of label tags
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
static int _parse_label_tags(struct plugin_handle *ph,
			     const struct ekmf_template_info *template_info,
			     const char *label_tags,
			     struct ekmf_tag_list *ekmf_tag_list)
{
	const struct ekmf_tag_def_list *tag_defs;
	char *tag, *value = NULL;
	char **tag_list = NULL;
	size_t i, k;
	int rc = 0;

	tag_defs = &template_info->label_tags;

	pr_verbose(ph, "Label tags: '%s'", label_tags);

	if (label_tags != NULL && strlen(label_tags) == 0)
		label_tags = NULL;
	tag_list = str_list_split(label_tags != NULL ? label_tags : "");

	ekmf_tag_list->tags = util_malloc(sizeof(struct ekmf_tag) *
						tag_defs->num_tag_defs);
	ekmf_tag_list->num_tags = tag_defs->num_tag_defs;

	memset(ekmf_tag_list->tags, 0,
	       sizeof(struct ekmf_tag) * tag_defs->num_tag_defs);

	for (i = 0, k = 0; i < tag_defs->num_tag_defs; i++) {
		pr_verbose(ph, "Expected tag: '%s'",
			   tag_defs->tag_defs[i].name);
		pr_verbose(ph, "Specified tag: '%s'", tag_list[k]);

		tag = tag_list[k] != NULL ? util_strdup(tag_list[k]) : NULL;
		if (tag != NULL) {
			value = strchr(tag, '=');
			if (value != NULL) {
				*value = '\0';
				value++;
			}
		}

		ekmf_tag_list->tags[i].name =
				util_strdup(tag_defs->tag_defs[i].name);

		if (strcasecmp(tag_defs->tag_defs[i].name,
			       EKMFWEB_SEQNO_TAG) == 0) {
			/* <seqno> tag may or may not be specified */
			if (tag != NULL && strcasecmp(tag,
						      EKMFWEB_SEQNO_TAG) == 0) {
				/* <seqno> tag may or may not have a value */
				if (value != NULL) {
					ekmf_tag_list->tags[i].value =
							util_strdup(value);
					util_str_toupper((char *)
						ekmf_tag_list->tags[i].value);
				} else {
					ekmf_tag_list->tags[i].value =
						util_strdup(EKMFWEB_SEQNO_NEXT);
				}
				k++;
			} else {
				ekmf_tag_list->tags[i].value =
						util_strdup(EKMFWEB_SEQNO_NEXT);
			}
		} else {
			if (tag == NULL) {
				if (label_tags != NULL)
					_set_error(ph, "Failed to parse label "
						   "tags. Expected tag '%s', "
						   "but no more tags are "
						   "specified.",
						   tag_defs->tag_defs[i].name);
				else
					_set_error(ph, "Option '--label-tags' "
						   "is required. Use 'zkey kms "
						   "info' to see which label "
						   "tags are required by the "
						   "key template(s)");
				rc = -EINVAL;
				goto out;
			}
			if (strcasecmp(tag, tag_defs->tag_defs[i].name) != 0) {
				_set_error(ph, "Failed to parse the specified "
					   "label tags: Expected tag '%s', but "
					   "found '%s'.",
					   tag_defs->tag_defs[i].name, tag);
				rc = -EINVAL;
				goto out;
			}
			if (value == NULL) {
				_set_error(ph, "Failed to parse the specified "
					   "label tags: Tag '%s' has no value",
					   tag_defs->tag_defs[i].name);
				rc = -EINVAL;
				goto out;
			}

			ekmf_tag_list->tags[i].value = util_strdup(value);
			util_str_toupper((char *)ekmf_tag_list->tags[i].value);
			k++;
		}

		pr_verbose(ph, "Tag: '%s', Value: '%s'",
			   ekmf_tag_list->tags[i].name,
			   ekmf_tag_list->tags[i].value);

		if (tag != NULL)
			free(tag);
		tag = NULL;
	}

	if (tag_list[k] != NULL) {
		_set_error(ph, "Failed to parse the specified label tags: More "
			   "tags specified than expected: '%s'", tag_list[k]);
		rc = -EINVAL;
		goto out;
	}

out:
	if (tag != NULL)
		free(tag);
	if (tag_list != NULL)
		str_list_free_string_array(tag_list);
	if (rc != 0)
		_free_ekmf_tags(ekmf_tag_list);

	return rc;
}

/**
 * Loads the certificate from a file into memory.
 *
 * @param ph                the plugin handle
 * @param cert_file         the file name of the certificate file
 * @param cert              On return: an allocated buffer containing the data
 * @param cert_size         On return: the size of the certificate data
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
static int _load_certificate(struct plugin_handle *ph, const char *cert_file,
			     unsigned char **cert, size_t *cert_size)
{
	size_t count, size;
	unsigned char *buf;
	struct stat sb;
	int rc = 0;
	FILE *fp;

	if (stat(cert_file, &sb)) {
		rc = -errno;
		_set_error(ph, "Failed to read certificate from file '%s': %s",
			   cert_file, strerror(-rc));
		return rc;
	}
	size = sb.st_size;

	fp = fopen(cert_file, "r");
	if (fp == NULL) {
		rc = -errno;
		_set_error(ph, "Failed to read certificate from file '%s': %s",
			   cert_file, strerror(-rc));
		return rc;
	}

	buf = util_malloc(size);
	count = fread(buf, 1, size, fp);
	if (count != size) {
		rc = ferror(fp) ? -errno : -EIO;
		_set_error(ph, "Failed to read certificate from file '%s': %s",
			   cert_file, strerror(-rc));
		goto out;
	}

	*cert_size = size;
	*cert = buf;

	pr_verbose(ph, "%lu bytes read from file '%s'", size, cert_file);
out:
	if (rc != 0)
		free(buf);
	fclose(fp);

	return rc;
}

/**
 * Registers the client with EKMF Web
 *
 * @param ph                the plugin handle
 * @param cert_file         the certificate file to register
 * @param label_tags        the label tags for generating an identity key
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _register_client(struct plugin_handle *ph, const char *cert_file,
			    const char *label_tags)
{
	struct ekmf_template_info *template_info = NULL;
	struct ekmf_tag_list label_tag_list = { 0 };
	struct ekmf_key_info *key_info = NULL;
	const char *template_uuid = NULL;
	unsigned char *cert = NULL;
	char *description = NULL;
	struct utsname utsname;
	char *error_msg = NULL;
	size_t cert_size = 0;
	char *key_id = NULL;
	int rc;

	_check_config_complete(ph);

	if (!ph->apqns_configured) {
		_set_error(ph, "The configuration is incomplete, you must "
			   "first configure the APQNs used with this plugin.");
		return -EINVAL;
	}
	if (!ph->identity_key_generated) {
		_set_error(ph, "The configuration is incomplete, you must "
			   "first configure the EKMF Web server connection.");
		return -EINVAL;
	}

	rc = kms_login((kms_handle_t)ph);
	if (rc != 0)
		goto out;

	key_id = properties_get(ph->properties,
				EKMFWEB_CONFIG_IDENTITY_KEY_LABEL);
	if (key_id != NULL) {
		free(key_id);
		util_print_indented("ATTENTION: The zkey client has already "
				    "been registered with EKMF Web!\n"
				    "When you re-register with EKMF Web you "
				    "will no longer have access to keys that "
				    "have been generated in EKMF Web with your "
				    "previous registration, until an EKMF Web "
				    "operator approves the export of these "
				    "keys for the identity key that is being "
				    "generated with this registration.", 0);
		printf("%s: Re-register the zkey client [y/N]? ",
		       program_invocation_short_name);
		if (!prompt_for_yes(ph->verbose)) {
			_set_error(ph, "Operation aborted by user");
			return -ECANCELED;
		}
	}

	rc  = _load_certificate(ph, cert_file, &cert, &cert_size);
	if (rc != 0)
		goto out;

	template_uuid = properties_get(ph->properties,
				       EKMFWEB_CONFIG_TEMPLATE_IDENTITY_ID);
	if (template_uuid == NULL) {
		rc = -EIO;
		_set_error(ph, "No identity key template configured");
		goto out;
	}

	rc = ekmf_get_template(&ph->ekmf_config, &ph->curl_handle,
			       template_uuid, &template_info,
			       &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to get identity key template '%s': %s",
			   template_uuid, error_msg != NULL ? error_msg :
			   strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	rc = _check_template(ph, template_info, EKMFWEB_KEYSTORE_TYPE_IDENTITY,
			     false);
	if (rc != 0)
		goto out;

	rc = _parse_label_tags(ph, template_info, label_tags, &label_tag_list);
	if (rc != 0)
		goto out;

	if (uname(&utsname) != 0) {
		rc = -errno;
		_set_error(ph, "Failed to obtain the system's hostname: %s",
			   strerror(-rc));
		goto out;
	}

	util_asprintf(&description, "Identity key for zkey client on system %s",
		      utsname.nodename);

	rc = ekmf_generate_key(&ph->ekmf_config, &ph->curl_handle,
			      template_info->name, description,
			      &label_tag_list, NULL, NULL, cert, cert_size,
			      &key_info, &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to generate identity key in EKMF Web:"
			   " %s", error_msg != NULL ? error_msg :
			   strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY_ID,
				     key_info->uuid);
	if (rc != 0)
		goto out;
	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_IDENTITY_KEY_LABEL,
				     key_info->label);
	if (rc != 0)
		goto out;

	pr_verbose(ph, "Generated identity key id: '%s'", key_info->uuid);
	pr_verbose(ph, "Generated identity key label: '%s'", key_info->label);

out:
	if (template_uuid != NULL)
		free((char *)template_uuid);
	if (error_msg != NULL)
		free(error_msg);
	if (template_info != NULL)
		ekmf_free_template_info(template_info);
	_free_ekmf_tags(&label_tag_list);
	if (key_info != NULL)
		ekmf_free_key_info(key_info);
	if (cert != NULL)
		free(cert);
	if (description != NULL)
		free(description);

	return rc;
}

#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
/*
 * Configures the key transport specific settings
 *
 * @param ph                the plugin handle
 * @param session_rsa_sign_digest the name of the digest for RSA signatures
 * @param session_rsa_sign_algo the signature algorithm for RSA signatures
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _configure_key_transport(struct plugin_handle *ph,
				    const char *session_rsa_sign_digest,
				    const char *session_rsa_sign_algo)
{
	int nid, rc = 0;

	if (session_rsa_sign_digest != NULL) {
		nid = OBJ_txt2nid(session_rsa_sign_digest);
		if (nid == NID_undef) {
			_set_error(ph, "Invalid RSA signature digest '%s'",
				   session_rsa_sign_digest);
			return -EINVAL;
		}

		rc = _set_or_remove_property(ph,
				    EKMFWEB_CONFIG_SESSION_RSA_SIGN_DIGEST,
				    session_rsa_sign_digest);
		if (rc != 0)
			goto out;
	}

	if (session_rsa_sign_algo != NULL) {
		if (strcasecmp(session_rsa_sign_algo, "RSA") == 0) {
			rc = _set_or_remove_property(ph,
					EKMFWEB_CONFIG_SESSION_RSA_SIGN_PSS,
					NULL);
			if (rc != 0)
				goto out;
		} else if (strcasecmp(session_rsa_sign_algo, "RSA-PSS") == 0) {
			rc = _set_or_remove_property(ph,
					EKMFWEB_CONFIG_SESSION_RSA_SIGN_PSS,
					"yes");
			if (rc != 0)
				goto out;
		} else {
			_set_error(ph, "Invalid RSA signature algorithm '%s'",
				   session_rsa_sign_algo);
			return -EINVAL;
		}
	}

out:
	return rc;
}
#endif

/**
 * Configures (or re-configures) a KMS plugin. This function can be called
 * several times to configure a KMS plugin is several steps (if supported by the
 * KMS plugin). In case a configuration is not fully complete, this function
 * may return -EAGAIN to indicate that it has accepted the configuration so far,
 * but the configuration needs to be completed.
 *
 * A KMS plugin must be associated with at least one APQN. Thus, in a multi-step
 * configuration, a list f APQNs must be specified at least once.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param apqns             a list of APQNs to associate with the KMS plugin, or
 *                          NULL if no APQNs are specified.
 * @param num_apqns         number of APQNs in above array. 0 if no APQNs are
 *                          specified.
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_CONFIGURE.
 * @param num_options       number of options in above array.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 * -EAGAIN to indicate that the specified configuration was accepted so far, but
 * the configuration is still incomplete, and needs to be completed.
 */
int kms_configure(const kms_handle_t handle,
		  const struct kms_apqn *apqns, size_t num_apqns,
		  const struct kms_option *options, size_t num_options)
{
	struct config_options opts = { 0 };
	struct plugin_handle *ph = handle;
	bool config_changed = false;
	char *apqn_str = NULL;
	int rc = 0;
	size_t i;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(num_apqns == 0 || apqns != NULL,
		    "Internal error: apqns is NULL  but num_apqns > 0");
	util_assert(num_options == 0 || options != NULL,
		    "Internal error: options is NULL but num_options > 0 ");

	pr_verbose(ph, "Configure");
	for (i = 0; i < num_apqns; i++) {
		pr_verbose(ph, "  APQN: %02x.%04x", apqns[i].card,
			   apqns[i].domain);
	}
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(ph, "  Option '%c': '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(ph, "  Option %d: '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	_clear_error(ph);

	if (apqns != NULL) {
		if (num_apqns > 0) {
			rc = _cross_check_apqns(ph, apqns, num_apqns);
			if (rc != 0)
				goto out;
		}

		apqn_str = _build_apqn_string(apqns, num_apqns);
		rc = properties_set(ph->properties, EKMFWEB_CONFIG_APQNS,
				    apqn_str);
		if (rc != 0) {
			_set_error(ph, "Failed to set APQNs property: %s",
				   strerror(-rc));
			goto out;
		}

		config_changed = true;
	}

	for (i = 0; i < num_options; i++) {
		switch (options[i].option) {
		case 'u':
			opts.ekmfweb_url = options[i].argument;
			break;
		case 'b':
			opts.tls_ca_bundle = options[i].argument;
			break;
		case OPT_TLS_CLIENT_CERT:
			opts.tls_client_cert = options[i].argument;
			break;
		case OPT_TLS_CLIENT_KEY:
			opts.tls_client_key = options[i].argument;
			break;
		case OPT_TLS_CLIENT_KEY_PASSPHRASE:
			opts.tls_client_key_passphrase = options[i].argument;
			break;
		case OPT_TLS_PIN_SERVER_PUBKEY:
			opts.tls_pin_server_pubkey = true;
			break;
		case OPT_TLS_TRUST_SERVER_CERT:
			opts.tls_trust_server_cert = true;
			break;
		case OPT_TLS_DONT_VERIFY_SERVER_CERT:
			opts.tls_dont_verify_server_cert = true;
			break;
		case OPT_TLS_VERIFY_HOSTNAME:
			opts.tls_verify_hostname = true;
			break;
		case 'R':
			opts.refresh_settings = true;
			break;
		case 'i':
			opts.generate_identity_key = true;
			break;
		case 'c':
			opts.csr_pem_file = options[i].argument;
			break;
		case 'C':
			opts.sscert_pem_file = options[i].argument;
			break;
		case 's':
			opts.cert_subject = options[i].argument;
			break;
		case 'e':
			opts.cert_extensions = options[i].argument;
			break;
		case 'N':
			opts.renew_cert_pem_file = options[i].argument;
			break;
		case 'n':
			opts.csr_new_header = true;
			break;
		case 'd':
			opts.cert_validity_days = options[i].argument;
			break;
		case 'D':
			opts.cert_digest = options[i].argument;
			break;
#ifdef EKMF_SUPPORTS_RSA_PSS_CERTIFICATES
		case 'P':
			opts.cert_rsa_pss = true;
			break;
#endif
		case 'r':
			opts.register_cert_file = options[i].argument;
			break;
		case 'T':
			opts.register_label_tags = options[i].argument;
			break;
#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
		case OPT_KT_RSA_SIGNATURE_DIGEST:
			opts.session_rsa_sign_digest = options[i].argument;
			break;
		case OPT_KT_RSA_PSS_SIGNATURE:
			opts.session_rsa_sign_algo = options[i].argument;
			break;
#endif
		default:
			rc = -EINVAL;
			if (isalnum(options[i].option))
				_set_error(ph, "Unsupported option '%c'",
					   options[i].option);
			else
				_set_error(ph, "Unsupported option %d",
					   options[i].option);
			goto out;
		}
	}

	if (opts.ekmfweb_url != NULL) {
		rc = _configure_connection(ph, opts.ekmfweb_url,
					   opts.tls_ca_bundle,
					   opts.tls_client_cert,
					   opts.tls_client_key,
					   opts.tls_client_key_passphrase,
					   opts.tls_pin_server_pubkey,
					   opts.tls_trust_server_cert,
					   opts.tls_dont_verify_server_cert,
					   opts.tls_verify_hostname);
		if (rc == 0) {
			config_changed = true;
			opts.refresh_settings = false; /* Already done */
		}
	} else {
		rc = _error_connection_opts(ph, &opts);
	}
	if (rc != 0)
		goto out;

	if (opts.refresh_settings) {
		rc = _get_ekmfweb_settings(ph);
		if (rc != 0)
			goto out;

		config_changed = true;
	}

	if ((ph->connection_configured && !ph->identity_key_generated) ||
	    opts.generate_identity_key) {
		rc = _generate_identity_key(ph);
		if (rc != 0)
			goto out;

		config_changed = true;
	}

	if (opts.csr_pem_file != NULL || opts.sscert_pem_file != NULL)
		rc = _generate_csr_sscert(ph, opts.csr_pem_file,
					  opts.sscert_pem_file,
					  opts.cert_subject,
					  opts.cert_extensions,
					  opts.renew_cert_pem_file,
					  opts.csr_new_header,
					  opts.cert_validity_days,
					  opts.cert_digest,
#ifdef EKMF_SUPPORTS_RSA_PSS_CERTIFICATES
					  opts.cert_rsa_pss,
#endif
					  false);
	else
		rc = _error_gen_csr_sscert_opts(ph, &opts);
	if (rc != 0)
		goto out;

	if (opts.register_cert_file != NULL) {
		rc = _register_client(ph, opts.register_cert_file,
				      opts.register_label_tags);
		if (rc != 0)
			goto out;

		config_changed = true;
	} else {
		if (opts.register_label_tags != NULL) {
			_set_error(ph, "Option ' --label-tags' is only valid "
				   "together with option '--register'.");
			rc = -EINVAL;
			goto out;
		}
	}

#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
	if (opts.session_rsa_sign_digest != NULL ||
	    opts.session_rsa_sign_algo != NULL) {
		rc = _configure_key_transport(ph, opts.session_rsa_sign_digest,
					      opts.session_rsa_sign_algo);
		if (rc != 0)
			goto out;

		config_changed = true;
	}
#endif

out:
	if (apqn_str != NULL)
		free(apqn_str);

	if (rc == 0) {
		if (config_changed) {
			rc = _save_config(ph);
			if (rc != 0)
				goto ret;

			_check_config_complete(ph);
			pr_verbose(ph, "Plugin configuration is %scomplete",
				   ph->config_complete ? "" : "in");
		}

		if (!ph->config_complete)
			rc = -EAGAIN;
	}

ret:
	return rc;
}

/**
 * De-configures a KMS plugin. This is called by zkey when a repository is
 * unbound from a KMS plugin. It gives the KMS plugin the chance to gracefully
 * remove any files that the plugin has stored in its config directory. zkey
 * will unconditionally remove all left over files when this function returns.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_deconfigure(const kms_handle_t handle)
{
	struct plugin_handle *ph = handle;

	util_assert(handle != NULL, "Internal error: handle is NULL");

	pr_verbose(ph, "Deconfigure");

	_clear_error(ph);

	return 0;
}

/**
 * Prompts the user for input on stdin, and returns the entered value.
 * The returned string must be freed by the caller.
 *
 * @param ph                the plugin handle
 * @param msg               the message to prompt for the input (can be NULL)
 *
 * @returns the entered value, or NULL in case of an error.
 */
static char *_prompt_for_input(struct plugin_handle *ph, const char *msg)
{
	size_t input_len = 0;
	char *input = NULL;
	int rc;

	while (input_len == 0 || input == NULL || strlen(input) < 1) {
		if (msg != NULL)
			printf("%s: %s: ", program_invocation_short_name, msg);

		rc = getline(&input, &input_len, stdin);
		if (rc < 0) {
			_set_error(ph, "Failed to read from stdin: %s",
				   strerror(errno));
			if (input != NULL)
				free(input);
			return NULL;
		}

		if (input != NULL && input[strlen(input) - 1] == '\n')
			input[strlen(input) - 1] = '\0';
	}

	return input;
}

/**
 * Allows the KMS plugin to perform a login to the KMS (if required). This
 * function is called at least once before any key operation function, typically
 * shortly after opening the repository.
 * The KMS plugin may prompt the user (by reading from stdin) for its
 * credentials, if needed.
 *
 * It is suggested that a KMS plugin performs a login with the KMS once, and
 * stores a login token (or similar) in its config directory. The next time
 * the kms_login function is called, the login token can be reused (if still
 * valid). This avoids to prompt the user for every key operation.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_login(const kms_handle_t handle)
{
	struct plugin_handle *ph = handle;
	char *passcode_url = NULL;
	char *error_msg = NULL;
	char *passcode = NULL;
	char *user_id = NULL;
	bool valid = false;
	int rc;

	util_assert(handle != NULL, "Internal error: handle is NULL");

	pr_verbose(ph, "Login");

	_clear_error(ph);

	if (!ph->connection_configured) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	if (ph->ekmf_config.login_token != NULL) {
		rc = ekmf_check_login_token(&ph->ekmf_config, &valid, NULL,
					    ph->verbose);
		pr_verbose(ph, "Login token valid: %d", valid);

		if (rc == 0 && valid)
			return 0;

		remove(ph->ekmf_config.login_token);
		FREE_AND_SET_NULL(ph->ekmf_config.login_token);

		rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_LOGIN_TOKEN,
					     NULL);
		if (rc != 0)
			goto out;
	}

	passcode_url = properties_get(ph->properties,
				      EKMFWEB_CONFIG_PASSCODE_URL);
	if (passcode_url == NULL) {
		util_asprintf(&passcode_url, "%s%s", ph->ekmf_config.base_url,
			      EKMFWEB_PASSCODE_URL);

		rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_PASSCODE_URL,
					     passcode_url);
		if (rc != 0)
			goto out;
	}

	pr_verbose(ph, "passcode url: '%s'", passcode_url);

	user_id = _prompt_for_input(ph, "EKMF Web user ID");
	if (user_id == NULL) {
		rc = -EIO;
		goto out;
	}

	pr_verbose(ph, "User-id: '%s'", user_id);

	util_print_indented("Go to the following web page in your web browser, "
			    "login with the same user ID as entered above and "
			    "your password, and obtain a one time passcode and "
			    "enter it here.", 0);
	printf("%s\n", passcode_url);

	passcode = _prompt_for_input(ph, "Passcode");
	if (passcode == NULL) {
		rc = -EIO;
		goto out;
	}

	pr_verbose(ph, "Passcode: '%s'", passcode);

	util_asprintf((char **)&ph->ekmf_config.login_token, "%s/%s",
		      ph->config_path, EKMFWEB_CONFIG_LOGIN_TOKEN_FILE);

	rc = ekmf_login(&ph->ekmf_config, &ph->curl_handle, user_id, passcode,
			&error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to login to EKMF Web server at '%s': "
			   "%s", ph->ekmf_config.base_url,
			   error_msg != NULL ? error_msg : strerror(-rc));
		goto out;
	}

	rc = _set_file_permission(ph, ph->ekmf_config.login_token);
	if (rc != 0)
		goto out;

	rc = _set_or_remove_property(ph, EKMFWEB_CONFIG_LOGIN_TOKEN,
				     ph->ekmf_config.login_token);
	if (rc != 0)
		goto out;

	rc = _save_config(ph);
	if (rc != 0)
		goto out;

out:
	if (passcode_url != NULL)
		free(passcode_url);
	if (user_id != NULL)
		free(user_id);
	if (passcode != NULL)
		free(passcode);
	if (error_msg != NULL)
		free(error_msg);

	return rc;
}

/**
 * Called when the master keys of an APQN associated with the KMS plugin has
 * been changed. The KMS plugin can then re-encipher all its secure keys (if
 * any) that it has stored in its config directory.
 *
 * Keys that have been generated by the KMS plugin and stored in the zkey
 * repository do not need to be re-enciphered by the KMS plugin. Those are
 * re-enciphered by zkey without the help of the KMS plugin.
 *
 * HSM have different master key registers. Typically a CURRENT and a NEW master
 * key register exists. The NEW register may be loaded with the new to be set
 * master key, and secure keys can be re-enciphered with it proactively.
 *
 * CCA also supports an OLD master key register, that contains the previously
 * used master key. You thus can re-encipher a secure key that is currently
 * enciphered with the master key from the OLD register with the master key
 * from the CURRENT register.
 *
 * HSMs may also support different master keys for different key types or
 * algorithms. It is up to the KMS plugin to know which master key registers
 * are used for its secure keys
 *
 * A staged re-encipherment is performed by re-enciphering a secure key with
 * the new HSM master key, without making it available for use in the first
 * stage. Only when the staged re-encipherment is completed, then the previously
 * re-enciphered secure key is make available for use and the old on is removed.
 *
 * An in-place re-encipherment replaces the secure key right away with its
 * re-enciphered version.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param mode              Re-encipherment mode
 * @param mkreg             Re-encipherment register selection
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_REENCIPHER.
 * @param num_options       number of options in above array.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_reenciper(const kms_handle_t handle, enum kms_reencipher_mode mode,
		  enum kms_reenc_mkreg mkreg,
		  const struct kms_option *options, size_t num_options)
{
	struct plugin_handle *ph = handle;
	char *reenc_file = NULL;
	const char *tmp = NULL;
	size_t i;
	int rc;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(num_options == 0 || options != NULL,
		    "Internal error: options is NULL but num_options > 0 ");

	pr_verbose(ph, "Re-encipher mode: %d, kmreg=%d", mode, mkreg);
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(ph, "  Option '%c': '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(ph, "  Option %d: '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	_clear_error(ph);

	if (ph->ekmf_config.identity_secure_key == NULL)
		return 0;

	reenc_file = properties_get(ph->properties,
				    EKMFWEB_CONFIG_IDENTITY_KEY_REENC);
	if (reenc_file != NULL && mode == KMS_REENC_MODE_AUTO)
		mode = KMS_REENC_MODE_STAGED_COMPLETE;

	if (mode == KMS_REENC_MODE_STAGED_COMPLETE) {
		if (reenc_file == NULL) {
			_set_error(ph, "Staged re-enciphering is not pending");
			rc = -EINVAL;
			goto out;
		}

		printf("Completing re-enciphering of identity key.\n");

		rc = remove(ph->ekmf_config.identity_secure_key);
		if (rc != 0) {
			rc = -errno;
			_set_error(ph, "Failed to remove file '%s': %s",
				   ph->ekmf_config.identity_secure_key,
				   strerror(-rc));
			goto out;
		}

		rc = rename(reenc_file, ph->ekmf_config.identity_secure_key);
		if (rc != 0) {
			rc = -errno;
			_set_error(ph, "Failed to rename file '%s' to '%s': %s",
				   reenc_file,
				   ph->ekmf_config.identity_secure_key,
				   strerror(-rc));
			goto out;
		}

		rc = properties_remove(ph->properties,
				       EKMFWEB_CONFIG_IDENTITY_KEY_REENC);
		if (rc != 0) {
			_set_error(ph, "Failed to remove property %s: %s",
				   EKMFWEB_CONFIG_IDENTITY_KEY_REENC,
				   strerror(-rc));
			goto out;
		}

		rc = _save_config(ph);
		if (rc != 0)
			goto out;

		printf("Successfully completed re-enciphering of identity "
		       "key.\n");

		rc = 0;
		goto out;
	}

	if (reenc_file != NULL)
		free(reenc_file);
	reenc_file = NULL;

	rc = _select_cca_adapter(ph);
	if (rc != 0)
		goto out;

	switch (mkreg) {
	case KMS_REENC_MKREG_AUTO:
	case KMS_REENC_MKREG_TO_NEW:
		if (mode == KMS_REENC_MODE_AUTO)
			mode = KMS_REENC_MODE_STAGED;

		if (mode == KMS_REENC_MODE_STAGED)
			util_asprintf(&reenc_file, "%s/%s", ph->config_path,
				      EKMFWEB_CONFIG_IDENTITY_KEY_REENC_FILE);

		printf("Re-enciphering the identity key with the APKA master "
		       "key in the NEW register.\n");

		rc = ekmf_reencipher_identity_key(&ph->ekmf_config, true,
						  reenc_file, &ph->ext_lib,
						  ph->verbose);
		if (rc != 0) {
			_set_error(ph, "Failed to re-encipher identity key "
				   "'%s': %s",
				   ph->ekmf_config.identity_secure_key,
				   strerror(-rc));
			goto out;
		}
		break;

	case KMS_REENC_MKREG_FROM_OLD:
		if (mode == KMS_REENC_MODE_AUTO)
			mode = KMS_REENC_MODE_IN_PLACE;

		if (mode == KMS_REENC_MODE_STAGED)
			util_asprintf(&reenc_file, "%s/%s", ph->config_path,
				      EKMFWEB_CONFIG_IDENTITY_KEY_REENC_FILE);

		printf("Re-enciphering the identity key with the APKA master "
		       "key in the CURRENT register.\n");

		rc = ekmf_reencipher_identity_key(&ph->ekmf_config, false,
						  reenc_file, &ph->ext_lib,
						  ph->verbose);
		if (rc != 0) {
			_set_error(ph, "Failed to re-encipher identity key "
				   "'%s': %s",
				   ph->ekmf_config.identity_secure_key,
				   strerror(-rc));
			goto out;
		}
		break;

	case KMS_REENC_MKREG_FROM_OLD_TO_NEW:
		if (mode == KMS_REENC_MODE_AUTO)
			mode = KMS_REENC_MODE_STAGED;

		if (mode == KMS_REENC_MODE_STAGED)
			util_asprintf(&reenc_file, "%s/%s", ph->config_path,
				      EKMFWEB_CONFIG_IDENTITY_KEY_REENC_FILE);

		printf("Re-enciphering the identity key with the APKA master "
		       "key in the CURRENT and then the NEW register.\n");

		rc = ekmf_reencipher_identity_key(&ph->ekmf_config, false,
						  reenc_file, &ph->ext_lib,
						  ph->verbose);
		if (rc != 0) {
			_set_error(ph, "Failed to re-encipher identity key "
				   "'%s': %s",
				   ph->ekmf_config.identity_secure_key,
				   strerror(-rc));
			goto out;
		}

		if (reenc_file != NULL) {
			tmp = ph->ekmf_config.identity_secure_key;
			ph->ekmf_config.identity_secure_key = reenc_file;
		}

		rc = ekmf_reencipher_identity_key(&ph->ekmf_config, true,
						  reenc_file, &ph->ext_lib,
						  ph->verbose);

		if (tmp != NULL)
			ph->ekmf_config.identity_secure_key = tmp;

		if (rc != 0) {
			_set_error(ph, "Failed to re-encipher identity key "
				   "'%s': %s",
				   ph->ekmf_config.identity_secure_key,
				   strerror(-rc));
			goto out;
		}

		break;

	default:
		_set_error(ph, "Invalid re-encipher MK register selection");
		rc = -EINVAL;
		goto out;
	}

	if (mode == KMS_REENC_MODE_STAGED) {
		rc = _set_file_permission(ph, reenc_file);
		if (rc != 0)
			goto out;

		rc = properties_set(ph->properties,
				    EKMFWEB_CONFIG_IDENTITY_KEY_REENC,
				    reenc_file);
		if (rc != 0) {
			_set_error(ph, "Failed to set property %s: %s",
				   EKMFWEB_CONFIG_IDENTITY_KEY_REENC,
				   strerror(-rc));
			goto out;
		}

	} else {
		rc = properties_remove(ph->properties,
				       EKMFWEB_CONFIG_IDENTITY_KEY_REENC);
		if (rc != 0 && rc != -ENOENT) {
			_set_error(ph, "Failed to remove property %s: %s",
				   EKMFWEB_CONFIG_IDENTITY_KEY_REENC,
				   strerror(-rc));
			goto out;
		}
	}

	rc = _save_config(ph);
	if (rc != 0)
		goto out;

	rc = 0;

	if (mode == KMS_REENC_MODE_STAGED)
		util_print_indented("Staged re-enciphering is initiated for "
				    "the identity key. After the NEW master "
				    "key has been set to become the CURRENT "
				    "master key run 'zkey kms reencipher' with "
				    "option '--complete' to complete the "
				    "re-enciphering process.", 0);
	else
		printf("Successfully re-enciphered the identity key\n");

out:
	if (rc != 0 && reenc_file != NULL)
		remove(reenc_file);
	if (reenc_file != NULL)
		free(reenc_file);

	return rc;
}

/**
 * Converts a list of KMS properties into a EKMF tag list
 *
 * @param ph                the plugin handle
 * @param properties        a list of properties to associate the key with
 * @param num_properties    the number of properties in above array
 * @param ekmf_tag_list     On return: a list of tags
 * @param null_values_only  if true, only properties with a NULL-value are
 *                          converted. If false, only properties with a non-NULL
 *                          value are converted.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
static int _properties_to_ekmf_tags(struct plugin_handle *UNUSED(ph),
				    const struct kms_property *properties,
				    size_t num_properties,
				    struct ekmf_tag_list *ekmf_tag_list,
				    bool null_values_only)
{
	size_t i, k;

	ekmf_tag_list->num_tags = 0;
	ekmf_tag_list->tags = util_malloc(
				sizeof(struct ekmf_tag) * num_properties);

	for (i = 0, k = 0; i < num_properties; i++) {
		if (!null_values_only && properties[i].value == NULL)
			continue;
		if (null_values_only && properties[i].value != NULL)
			continue;

		ekmf_tag_list->tags[k].name = util_strdup(properties[i].name);
		ekmf_tag_list->tags[k].value = properties[i].value != NULL ?
				util_strdup(properties[i].value) : NULL;
		ekmf_tag_list->num_tags++;
		k++;
	}

	return 0;
}

/**
 * Converts an EKMF tag list into a list of KMS properties
 *
 * @param ph                the plugin handle
 * @param ekmf_tag_list     The list of tags
 * @param properties        On return: a list of properties
 * @param num_properties    On return: the number of properties in above array
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
static int _ekmf_tags_to_properties(struct plugin_handle *UNUSED(ph),
				    const struct ekmf_tag_list *ekmf_tag_list,
				    struct kms_property **properties,
				    size_t *num_properties)
{
	struct kms_property *props;
	size_t i;

	props = util_malloc(sizeof(struct kms_property) *
						ekmf_tag_list->num_tags);

	for (i = 0; i < ekmf_tag_list->num_tags; i++) {
		props[i].name = util_strdup(ekmf_tag_list->tags[i].name);
		props[i].value = ekmf_tag_list->tags[i].value != NULL ?
			util_strdup(ekmf_tag_list->tags[i].value) : NULL;
	}

	*properties = props;
	*num_properties = ekmf_tag_list->num_tags;

	return 0;
}

/**
 * Restricts an retrieved secure key from further export and checks the
 * required key attributes. If the secure key is not as expected, the user
 * is prompted to confirm the use of the key.
 *
 * @param ph                the plugin handle
 * @param key_blob          the secure key to restrict
 * @param key_blob_length   the size of the the secure key
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
static int _restrict_key(struct plugin_handle *ph, unsigned char *key_blob,
			 size_t key_blob_length)
{
	struct cca_lib cca = { 0 };
	int rc;

	cca.lib_csulcca = ph->cca.cca_lib;
	cca.dll_CSNBRKA = (t_CSNBRKA)dlsym(cca.lib_csulcca, "CSNBRKA");
	if (cca.dll_CSNBRKA == NULL) {
		_set_error(ph, "Failed to get CCA verb CSNBRKA");
		return -ELIBACC;
	}

	rc = restrict_key_export(&cca, key_blob, key_blob_length,
				 ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to export-restrict the retrieved secure "
			   "key: %s", strerror(-rc));
		return rc;
	}

	rc = check_aes_cipher_key(key_blob, key_blob_length);
	if (rc != 0) {
		warnx("The secure key retrieved from EKMF Web might not be "
		      "secure");
		printf("%s: Do you want to use it anyway [y/N]? ",
		       program_invocation_short_name);
		if (!prompt_for_yes(ph->verbose)) {
			warnx("Operation aborted");
			return -ECANCELED;
		}
	}

	return 0;
}

/**
 * Generates a key in or with the KMS and returns a secure key that is
 * enciphered under the current HSM master key.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_type          the zkey key type, euch as 'CCA-AESDATA',
 *                          'CCA-AESCIPHER', 'EP11-AES'.
 * @param key_bits          the key bit size (e.g. 256 for an AES 256 bit key).
 * @param properties        a list of properties to associate the key with
 * @param num_properties    the number of properties in above array
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_GENERATE.
 * @param num_options       number of options in above array.
 * @param key_blob          a buffer to return the key blob. The size of the
 *                          buffer is specified in key_blob_length
 * @param key_blob_length   on entry: the size of the key_blob buffer.
 *                          on exit: the size of the key blob returned.
 * @param key_id            a buffer to return the key-ID of the generated key.
 *                          The key-id is a textual identifier uniquely
 *                          identifying a key in the KMS and the KMS plugin.
 *                          The returned key-id contains the terminating zero.
 * @paran key_id_size       size of the key_id buffer. It should be at least
 *                          KMS_KEY_ID_SIZE + 1 bytes large.
 * @param key_label         a buffer to return the key-label of the generated
 *                          key. The key-label is a textual identifier used to
 *                          identify a key in the user interface of the KMS.
 *                          A key label may be equal to the key-ID, or it may
 *                          different. The returned key-label contains the
 *                          terminating zero.
 * @paran key_label_size    size of the key_lanble buffer. It should be at least
 *                          KMS_KEY_LABEL_SIZE + 1 bytes large.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_generate_key(const kms_handle_t handle, const char *key_type,
		     size_t key_bits, enum kms_key_mode key_mode,
		     const struct kms_property *properties,
		     size_t num_properties,
		     const struct kms_option *options, size_t num_options,
		     unsigned char *key_blob, size_t *key_blob_length,
		     char *key_id, size_t key_id_size,
		     char *key_label, size_t key_label_size)
{
	struct ekmf_template_info *template_info = NULL;
	struct ekmf_tag_list custom_tag_list = { 0 };
	struct ekmf_tag_list label_tag_list = { 0 };
	struct ekmf_key_info *key_info = NULL;
	int curve_nid = 0, digest_nid = 0;
	struct plugin_handle *ph = handle;
	const char *template_uuid = NULL;
	char *identity_key_uuid = NULL;
	const char *label_tags = NULL;
	const char *tmpl_prop_name;
	char *error_msg = NULL;
	bool rsa_pss = false;
	char *tmp;
	size_t i;
	int rc;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(num_properties == 0 || properties != NULL,
		    "Internal error: properties is NULL but num_properties"
		    " > 0 ");
	util_assert(num_options == 0 || options != NULL,
		    "Internal error: options is NULL but num_options > 0 ");
	util_assert(key_blob != NULL, "Internal error: key_blob is NULL");
	util_assert(key_blob_length != NULL, "Internal error: key_blob_length "
		    "is NULL");
	util_assert(key_id != NULL, "Internal error: key_id is NULL");
	util_assert(key_label != NULL, "Internal error: key_label is NULL");

	pr_verbose(ph, "Generate key: key-type: '%s', keybits: %lu, mode: %d",
			key_type, key_bits, key_mode);
	for (i = 0; i < num_properties; i++) {
		util_assert(properties[i].name != NULL,
			    "Internal error: property name is NULL");
		util_assert(properties[i].value != NULL,
			    "Internal error: property value is NULL");
		pr_verbose(ph, "  Property '%s': '%s", properties[i].name,
			   properties[i].value);
	}
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(ph, "  Option '%c': '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(ph, "  Option %d: '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	_clear_error(ph);

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	if (strcasecmp(key_type, KEY_TYPE_CCA_AESCIPHER) != 0) {
		_set_error(ph, "Key type '%s' is not supported by EKMF Web",
			   key_type);
		return -ENOTSUP;
	}

	switch (key_mode) {
	case KMS_KEY_MODE_NON_XTS:
		tmpl_prop_name = EKMFWEB_CONFIG_TEMPLATE_NONXTS_ID;
		break;
	case KMS_KEY_MODE_XTS_1:
		tmpl_prop_name = EKMFWEB_CONFIG_TEMPLATE_XTS1_ID;
		break;
	case KMS_KEY_MODE_XTS_2:
		tmpl_prop_name = EKMFWEB_CONFIG_TEMPLATE_XTS2_ID;
		break;
	default:
		_set_error(ph, "Unsupported key mode: %d", key_mode);
		return -EINVAL;
	}

	identity_key_uuid = properties_get(ph->properties,
					   EKMFWEB_CONFIG_IDENTITY_KEY_ID);
	if (identity_key_uuid == NULL) {
		_set_error(ph, "The zkey client is not registered with EKMF "
			  "Web, run 'zkey kms configure --register CERT-FILE' "
			  "to register the zkey client.");
		return -EINVAL;
	}

	pr_verbose(ph, "identity_key_uuid: '%s'", identity_key_uuid);

	rc = _select_cca_adapter(ph);
	if (rc != 0)
		goto out;

	for (i = 0; i < num_options; i++) {
		switch (options[i].option) {
		case 'T':
			label_tags = options[i].argument;
			break;
		default:
			rc = -EINVAL;
			if (isalnum(options[i].option))
				_set_error(ph, "Unsupported option '%c'",
					   options[i].option);
			else
				_set_error(ph, "Unsupported option %d",
					   options[i].option);
			goto out;
		}
	}

	template_uuid = properties_get(ph->properties, tmpl_prop_name);
	if (template_uuid == NULL) {
		rc = -EIO;
		_set_error(ph, "No key template configured");
		goto out;
	}

	rc = ekmf_get_template(&ph->ekmf_config, &ph->curl_handle,
			       template_uuid, &template_info,
			       &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to get key template '%s': %s",
			   template_uuid, error_msg != NULL ? error_msg :
			   strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	rc = _check_template(ph, template_info,
			     EKMFWEB_KEYSTORE_TYPE_PERV_ENCR, true);
	if (rc != 0)
		goto out;

	if (key_bits == 0)
		key_bits = template_info->key_size;
	if (key_bits != template_info->key_size) {
		_set_error(ph, "Key size %u bits is not allowed by the "
			   "template used to generate the key. The template "
			   "uses a key size of %u bits.", key_bits,
			   template_info->key_size);
		return -EINVAL;
	}

	rc = _parse_label_tags(ph, template_info, label_tags, &label_tag_list);
	if (rc != 0)
		goto out;

	rc = _properties_to_ekmf_tags(ph, properties, num_properties,
				      &custom_tag_list, false);
	if (rc != 0)
		goto out;

	rc = ekmf_generate_key(&ph->ekmf_config, &ph->curl_handle,
			      template_info->name, "Generated by zkey",
			      &label_tag_list, &custom_tag_list,
			      identity_key_uuid, NULL, 0, &key_info,
			      &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to generate key in EKMF Web: %s",
			   error_msg != NULL ? error_msg : strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_SESSION_KEY_CURVE);
	if (tmp != NULL) {
		curve_nid = OBJ_txt2nid(tmp);
		free(tmp);
	}

#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
	tmp = properties_get(ph->properties,
			     EKMFWEB_CONFIG_SESSION_RSA_SIGN_DIGEST);
	if (tmp != NULL) {
		digest_nid = OBJ_txt2nid(tmp);
		free(tmp);
	}

	tmp = properties_get(ph->properties,
			     EKMFWEB_CONFIG_SESSION_RSA_SIGN_PSS);
	if (tmp != NULL) {
		if (strcasecmp(tmp, "yes") == 0)
			rsa_pss = true;
		free(tmp);
	}
#endif

	rc = ekmf_retrieve_key(&ph->ekmf_config, &ph->curl_handle,
				key_info->uuid, curve_nid, digest_nid, rsa_pss,
				identity_key_uuid, key_blob, key_blob_length,
				&error_msg, &ph->ext_lib, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to retrieve the generated key from EKMF "
			   "Web: %s", error_msg != NULL ? error_msg :
			   strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	rc = _restrict_key(ph, key_blob, *key_blob_length);
	if (rc != 0)
		goto out;

	strncpy(key_id, key_info->uuid, key_id_size);
	key_id[key_id_size - 1] = '\0';

	strncpy(key_label, key_info->label, key_label_size);
	key_label[key_label_size - 1] = '\0';

	pr_verbose(ph, "Generated key id: '%s'", key_id);
	pr_verbose(ph, "Generated key label: '%s'", key_label);

out:
	if (identity_key_uuid != NULL)
		free(identity_key_uuid);
	if (template_uuid != NULL)
		free((char *)template_uuid);
	if (template_info != NULL)
		ekmf_free_template_info(template_info);
	_free_ekmf_tags(&label_tag_list);
	_free_ekmf_tags(&custom_tag_list);
	if (error_msg != NULL)
		free(error_msg);
	if (key_info != NULL)
		ekmf_free_key_info(key_info);

	return rc;
}

/**
 * Sets (adds/replaces/removes) properties of a key. Already existing properties
 * with the same property name are replaced, non-existing properties are added.
 * To remove a property, set the property value to NULL.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_id            the key-ID to set the properties for
 * @param properties        a list of properties to set
 * @param num_properties    the number of properties in above array
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_set_key_properties(const kms_handle_t handle, const char *key_id,
			   const struct kms_property *properties,
			   size_t num_properties)
{
	struct ekmf_tag_list delete_tag_list = { 0 };
	struct ekmf_tag_list set_tag_list = { 0 };
	struct ekmf_key_info *key_info = NULL;
	struct plugin_handle *ph = handle;
	char *updated_on = NULL;
	char *error_msg = NULL;
	size_t i;
	int rc;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(key_id != NULL, "Internal error: key_id is NULL");
	util_assert(num_properties == 0 || properties != NULL,
		    "Internal error: properties is NULL but num_properties"
		    " > 0 ");

	pr_verbose(ph, "Set key properties: key-ID: '%s'", key_id);
	for (i = 0; i < num_properties; i++) {
		util_assert(properties[i].name != NULL,
			    "Internal error: property name is NULL");

		pr_verbose(ph, "  Property '%s': '%s'", properties[i].name,
			   properties[i].value != NULL ? properties[i].value :
			   "(null)");
	}

	_clear_error(ph);

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	rc = _properties_to_ekmf_tags(ph, properties, num_properties,
				      &set_tag_list, false);
	if (rc != 0)
		goto out;

	rc = _properties_to_ekmf_tags(ph, properties, num_properties,
				      &delete_tag_list, true);
	if (rc != 0)
		goto out;

	rc = ekmf_get_key_info(&ph->ekmf_config, &ph->curl_handle,
			       key_id, &key_info, &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to get key '%s': %s", key_id,
			   error_msg != NULL ? error_msg : strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	if (set_tag_list.num_tags > 0) {
		rc = ekmf_set_key_tags(&ph->ekmf_config, &ph->curl_handle,
				       key_id, &set_tag_list,
				       key_info->updated_on, &updated_on,
				       &error_msg, ph->verbose);
		if (rc != 0) {
			_set_error(ph, "Failed to set custom tags for key "
				   "'%s': %s", key_id, error_msg != NULL ?
						   error_msg : strerror(-rc));
			_remove_login_token_if_error(ph, rc);
			goto out;
		}
	}

	if (delete_tag_list.num_tags > 0) {
		rc = ekmf_delete_key_tags(&ph->ekmf_config, &ph->curl_handle,
				       key_id, &delete_tag_list,
				       updated_on != NULL ? updated_on :
						       key_info->updated_on,
				       NULL, &error_msg, ph->verbose);
		if (rc != 0) {
			_set_error(ph, "Failed to delete custom tags for key "
				   "'%s': %s", key_id, error_msg != NULL ?
						   error_msg : strerror(-rc));
			_remove_login_token_if_error(ph, rc);
			goto out;
		}
	}

out:
	_free_ekmf_tags(&set_tag_list);
	_free_ekmf_tags(&delete_tag_list);
	if (key_info != NULL)
		ekmf_free_key_info(key_info);
	if (updated_on != NULL)
		free(updated_on);
	if (error_msg != NULL)
		free(error_msg);

	return rc;
}

/**
 * Gets properties of a key.
 *
 * The returned list of properties must be freed by the caller. Each property
 * name and value must be freed individually (using free()), as well as the
 * complete array.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_id            the key-ID to set the properties for
 * @param properties        On return: a list of properties
 * @param num_properties    On return: the number of properties in above array
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_get_key_properties(const kms_handle_t handle, const char *key_id,
			   struct kms_property **properties,
			   size_t *num_properties)
{
	struct ekmf_key_info *key_info = NULL;
	struct plugin_handle *ph = handle;
	char *error_msg = NULL;
	int rc;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(key_id != NULL, "Internal error: key_id is NULL");
	util_assert(properties != NULL, "Internal error: properties is NULL");
	util_assert(num_properties != NULL,
		    "Internal error: num_properties is NULL");

	pr_verbose(ph, "Get key properties: key-ID: '%s'", key_id);

	_clear_error(ph);

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	rc = ekmf_get_key_info(&ph->ekmf_config, &ph->curl_handle,
			       key_id, &key_info, &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to get key '%s': %s", key_id,
			   error_msg != NULL ? error_msg : strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	rc = _ekmf_tags_to_properties(ph, &key_info->custom_tags, properties,
				      num_properties);
	if (rc != 0)
		goto out;

out:
	if (key_info != NULL)
		ekmf_free_key_info(key_info);
	if (error_msg != NULL)
		free(error_msg);

	return rc;
}

struct key_state {
	const char *state;
	const char *new_states[7];
};

static const struct key_state states[] = {
	{ .state = EKMFWEB_KEY_STATE_PRE_ACTIVATION,
	  .new_states = {
		EKMFWEB_KEY_STATE_ACTIVE,
		EKMFWEB_KEY_STATE_COMPROMISED,
		EKMFWEB_KEY_STATE_DESTROYED,
		NULL },
	},
	{ .state = EKMFWEB_KEY_STATE_ACTIVE,
	  .new_states = {
		EKMFWEB_KEY_STATE_ACTIVE,
		EKMFWEB_KEY_STATE_DEACTIVATED,
		EKMFWEB_KEY_STATE_COMPROMISED,
		EKMFWEB_KEY_STATE_DESTROYED,
		NULL },
	},
	{ .state = EKMFWEB_KEY_STATE_DEACTIVATED,
	  .new_states = {
		EKMFWEB_KEY_STATE_COMPROMISED,
		EKMFWEB_KEY_STATE_DESTROYED,
		NULL },
	},
	{ .state = EKMFWEB_KEY_STATE_COMPROMISED,
	  .new_states = {
		EKMFWEB_KEY_STATE_DESTROYED_COMPROMISED,
		NULL },
	},
	{ .state = EKMFWEB_KEY_STATE_DESTROYED,
	  .new_states = { NULL },
	},
	{ .state = EKMFWEB_KEY_STATE_DESTROYED_COMPROMISED,
	  .new_states = { NULL },
	},
	{ .state = NULL, .new_states = { NULL, }, },
};

/**
 * Checks if the new state is a valid state. If the current state is also
 * specified, then it checks also if the new state can be set from the current
 * state
 *
 * @param ph                the plugin handle
 * @param name              the key name
 * @param new_state         the new state to set
 * @param cur_state         the current state (can be NULL).
 *
 * @returns 0 on success, or a negative errno in case of an error.
 */
static int _check_state(struct plugin_handle *ph, const char *name,
			const char *new_state, const char *cur_state)
{
	bool ok = false;
	int i, k;

	for (i = 0; states[i].state != NULL; i++) {
		if (strcasecmp(new_state, states[i].state) == 0) {
			ok = true;
			break;
		}
	}

	if (!ok) {
		_set_error(ph, "Invalid state specified: '%s'", new_state);
		return -EINVAL;
	}

	if (cur_state == NULL)
		return 0;

	for (i = 0; states[i].state != NULL; i++) {
		if (strcasecmp(cur_state, states[i].state) == 0) {
			for (k = 0; states[i].new_states[k] != NULL; k++) {
				if (strcasecmp(new_state,
					       states[i].new_states[k]) == 0)
					return 0;
			}

			_set_error(ph, "Key '%s' is in state '%s' and can not "
				   "be changed to state '%s'", name,
				   cur_state, new_state);
			return -EINVAL;
		}
	}

	_set_error(ph, "Key '%s' is in an invalid state: '%s'", name,
		   cur_state);
	return -EINVAL;
}

/**
 * Called when zkey removes a KMS-bound key from the zkey repository. The KMS
 * plugin can then set the state of the key in the KMS, or remove it also from
 * the KMS (this is usually not done).
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_id            the key-ID to set the properties for
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_REMOVE.
 * @param num_options       number of options in above array.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_remove_key(const kms_handle_t handle, const char *key_id,
		   const struct kms_option *options, size_t num_options)
{
	struct ekmf_key_info *key_info = NULL;
	struct plugin_handle *ph = handle;
	char *error_msg = NULL;
	char *state = NULL;
	int rc = 0;
	size_t i;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(key_id != NULL, "Internal error: key_id is NULL");
	util_assert(num_options == 0 || options != NULL,
		    "Internal error: options is NULL but num_options > 0 ");

	pr_verbose(ph, "Remove key: key-ID: '%s'", key_id);
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(ph, "  Option '%c': '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(ph, "  Option %d: '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	_clear_error(ph);

	for (i = 0; i < num_options; i++) {
		switch (options[i].option) {
		case 's':
			state = util_strdup(options[i].argument);
			util_str_toupper(state);
			break;
		default:
			rc = -EINVAL;
			if (isalnum(options[i].option))
				_set_error(ph, "Unsupported option '%c'",
					   options[i].option);
			else
				_set_error(ph, "Unsupported option %d",
					   options[i].option);
			goto out;
		}
	}

	if (state == NULL)
		goto out;

	pr_verbose(ph, "State to set: '%s'", state);

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	rc = ekmf_get_key_info(&ph->ekmf_config, &ph->curl_handle,
			       key_id, &key_info, &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to get key '%s': %s", key_id,
			   error_msg != NULL ? error_msg : strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	pr_verbose(ph, "Key state: '%s'", key_info->state);

	rc = _check_state(ph, key_info->label, state, key_info->state);
	if (rc != 0)
		goto out;

	rc = ekmf_set_key_state(&ph->ekmf_config, &ph->curl_handle,
				key_id, state, key_info->updated_on,
				&error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to set key state '%s': %s",
				key_id, error_msg != NULL ? error_msg :
			   strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

out:
	if (key_info != NULL)
		ekmf_free_key_info(key_info);
	if (error_msg != NULL)
		free(error_msg);
	if (state != NULL)
		free(state);

	return rc;
}

struct list_data {
	struct plugin_handle *ph;
	bool list_all;
	const char *exporting_key;
	kms_list_callback callback;
	void *private;
};

/**
 * Check if the key can be exported by the exporting key
 *
 * @param key_info          the key to check
 * @param exporting_key     the exporting key
 *
 * @returns true if export is allowed, false otherwise
 */
static bool _check_exportability(struct ekmf_key_info *key_info,
				 const char *exporting_key)
{
	bool found = false;
	size_t i;

	if (!key_info->export_control.export_allowed || exporting_key == NULL)
		return false;

	for (i = 0; i < key_info->export_control.num_exporting_keys; i++) {
		if (strcmp(key_info->export_control.exporting_keys[i].uuid,
			   exporting_key) == 0) {
			found = true;
			break;
		}
	}

	return found;
}

/*
 * Like argz_add, but formats the string first
 */
static error_t argz_add_fmt(char **argz, size_t *argz_len, const char *fmt, ...)
{
	va_list ap;
	error_t rc;
	char *str;

	va_start(ap, fmt);
	util_vasprintf(&str, fmt, ap);
	va_end(ap);

	rc = argz_add(argz, argz_len, str);

	free(str);
	return rc;
}

/**
 * Callback function used with the ekmf_list_keys function. This
 * callback is called for each key found.
 *
 * @param curl_handle      a CURL handle that can be used to perform further
 *                         EKMFWeb functions within the callback.
 * @param template_info    a struct containing information about the key.
 *                         If any of the information needs to be kept, then the
 *                         callback function must make a copy of the
 *                         information. The memory holding the information
 *                         passed to the callback is no longer valid after the
 *                         callback has returned.
 * @param private          the private pointer that was specified with the
 *                         ekmf_list_keys invocation.
 *
 * @returns zero for success, a negative errno in case of an error.
 * When a nonzero return code is returned, the key listing process stops,
 * and ekmf_list_keys returns the return code from the callback.
 */
static int _list_callback(CURL *curl_handle, struct ekmf_key_info *key_info,
			  void *private)
{
	struct kms_property *properties = NULL;
	struct list_data *data = private;
	size_t i, num_properties = 0;
	size_t addl_info_len = 0;
	char *addl_info = NULL;
	int rc = 0;

	data->ph->curl_handle = curl_handle;

	if (strcmp(key_info->keystore_type,
		   EKMFWEB_KEYSTORE_TYPE_PERV_ENCR) != 0)
		goto out;
	if (strcmp(key_info->key_type, EKMFWEB_KEY_TYPE_CIPHER) != 0)
		goto out;
	if (strcmp(key_info->algorithm, EKMFWEB_KEY_ALGORITHM_AES) != 0)
		goto out;
	if (!data->list_all && !_check_exportability(key_info,
						     data->exporting_key))
		goto out;

	rc = _ekmf_tags_to_properties(data->ph, &key_info->custom_tags,
				      &properties, &num_properties);
	if (rc != 0)
		goto out;

	rc = argz_add_fmt(&addl_info, &addl_info_len, "State: %s",
			  key_info->state);
	if (rc != 0)
		goto out;
	for (i = 0; i < key_info->export_control.num_exporting_keys; i++) {
		rc = argz_add_fmt(&addl_info, &addl_info_len, "%s %s",
			i == 0 ? "Exporting keys:" : "               ",
			key_info->export_control.exporting_keys[i].name);
		if (rc != 0)
			goto out;
	}

	rc = data->callback(key_info->uuid, key_info->label,
			    KEY_TYPE_CCA_AESCIPHER, key_info->key_size,
			    properties, num_properties,
			    addl_info, addl_info_len, data->private);

out:
	if (addl_info != NULL)
		free(addl_info);
	if (properties != NULL) {
		for (i = 0;  i < num_properties; i++) {
			free((char *)properties[i].name);
			free((char *)properties[i].value);
		}
		free(properties);
	}

	return rc;
}

/**
 * List keys managed by the KMS. This list is independent of the zkey key
 * repository. It lists keys as known by the KMS.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param label_pattern     a pattern of the label used to filter the keys, or
 *                          NULL if no label pattern is specified.
 * @param properties        a list of properties used to to filter the keys, or
 *                          NULL if no properties filter is specified.
 * @param num_properties    the number of properties in above array.
 * @param options           a list of options as specified by the user. These
 *                          options are a subset of the possible options as
 *                          returned by kms_get_command_options() with command
 *                          KMS_COMMAND_LIST.
 * @param num_options       number of options in above array.*
 * @param callback          a callback function that is called for each key that
 *                          matches the filter (if any).
 * @private_data            a private pointer passed as is to the callback
 *                          function. Can be used to pass user specific
 *                          information to the callback.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_list_keys(const kms_handle_t handle, const char *label_pattern,
		  const struct kms_property *properties, size_t num_properties,
		  const struct kms_option *options, size_t num_options,
		  kms_list_callback callback, void *private_data)
{
	struct ekmf_tag_list tag_list = { 0 };
	struct plugin_handle *ph = handle;
	struct list_data data = { 0 };
	char **state_list = NULL;
	char *error_msg = NULL;
	char *states = NULL;
	int rc = 0;
	size_t i;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(num_properties == 0 || properties != NULL,
		    "Internal error: properties is NULL but num_properties "
		    "> 0 ");
	util_assert(callback != NULL, "Internal error: callback is NULL");

	pr_verbose(ph, "List Keys, label-pattern: '%s'",
		   label_pattern != NULL ? label_pattern : "(null)");
	for (i = 0; i < num_properties; i++) {
		util_assert(properties[i].name != NULL,
			    "Internal error: property name is NULL");
		util_assert(properties[i].value != NULL,
			    "Internal error: property value is NULL");
		pr_verbose(ph, "  Property '%s': '%s", properties[i].name,
			   properties[i].value);
	}
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(ph, "  Option '%c': '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(ph, "  Option %d: '%s'", options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	_clear_error(ph);

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	data.ph = ph;
	data.list_all = false;
	data.callback = callback;
	data.private = private_data;

	for (i = 0; i < num_options; i++) {
		switch (options[i].option) {
		case 's':
			states = util_strdup(options[i].argument);
			util_str_toupper(states);
			break;
		case 'a':
			data.list_all = true;
			break;
		default:
			rc = -EINVAL;
			if (isalnum(options[i].option))
				_set_error(ph, "Unsupported option '%c'",
					   options[i].option);
			else
				_set_error(ph, "Unsupported option %d",
					   options[i].option);
			goto out;
		}
	}

	pr_verbose(ph, "State filter: '%s'", states != NULL ? states :
		   "(none)");
	pr_verbose(ph, "List all: %d", data.list_all);

	if (states != NULL) {
		state_list = str_list_split(states);
		for (i = 0; state_list[i] != NULL; i++) {
			rc = _check_state(ph, NULL, state_list[i], NULL);
			if (rc != 0)
				goto out;
		}
	}

	data.exporting_key = properties_get(ph->properties,
					    EKMFWEB_CONFIG_IDENTITY_KEY_ID);

	rc = _properties_to_ekmf_tags(ph, properties, num_properties,
				      &tag_list, false);
	if (rc != 0)
		goto out;

	rc = ekmf_list_keys(&ph->ekmf_config, &ph->curl_handle,
			    _list_callback, &data, label_pattern, states,
			    &tag_list, &error_msg, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to list keys: %s",
			   error_msg != NULL ? error_msg : strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

out:
	if (states != NULL)
		free(states);
	if (state_list != NULL)
		str_list_free_string_array(state_list);
	if (error_msg != NULL)
		free(error_msg);
	if (data.exporting_key != NULL)
		free((char *)data.exporting_key);
	_free_ekmf_tags(&tag_list);

	return rc;
}

/**
 * Imports a key from the KMS and returns a secure key that is
 * enciphered under the current HSM master key.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_id            the key-ID of the key to import
 * @param key_blob          a buffer to return the key blob. The size of the
 *                          buffer is specified in key_blob_length
 * @param key_blob_length   on entry: the size of the key_blob buffer.
 *                          on exit: the size of the key blob returned.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_import_key(const kms_handle_t handle, const char *key_id,
		   unsigned char *key_blob, size_t *key_blob_length)
{
	struct plugin_handle *ph = handle;
	int curve_nid = 0, digest_nid = 0;
	char *identity_key_uuid = NULL;
	char *error_msg = NULL;
	bool rsa_pss = false;
	int rc = 0;
	char *tmp;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(key_blob != NULL, "Internal error: key_blob is NULL");
	util_assert(key_blob_length != NULL, "Internal error: key_blob_length "
		    "is NULL");

	pr_verbose(ph, "Import Key, key-ID: '%s'", key_id);

	_clear_error(ph);

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	identity_key_uuid = properties_get(ph->properties,
					   EKMFWEB_CONFIG_IDENTITY_KEY_ID);
	if (identity_key_uuid == NULL) {
		_set_error(ph, "The zkey client is not registered with EKMF "
			  "Web, run 'zkey kms configure --register CERT-FILE' "
			  "to register the zkey client.");
		return -EINVAL;
	}

	pr_verbose(ph, "identity_key_uuid: '%s'", identity_key_uuid);

	rc = _select_cca_adapter(ph);
	if (rc != 0)
		goto out;

	tmp = properties_get(ph->properties, EKMFWEB_CONFIG_SESSION_KEY_CURVE);
	if (tmp != NULL) {
		curve_nid = OBJ_txt2nid(tmp);
		free(tmp);
	}

#ifdef EKMFWEB_SUPPORTS_RSA_DIGESTS_AND_PSS_SIGNATURES
	tmp = properties_get(ph->properties,
			     EKMFWEB_CONFIG_SESSION_RSA_SIGN_DIGEST);
	if (tmp != NULL) {
		digest_nid = OBJ_txt2nid(tmp);
		free(tmp);
	}

	tmp = properties_get(ph->properties,
			     EKMFWEB_CONFIG_SESSION_RSA_SIGN_PSS);
	if (tmp != NULL) {
		if (strcasecmp(tmp, "yes") == 0)
			rsa_pss = true;
		free(tmp);
	}
#endif

	rc = ekmf_retrieve_key(&ph->ekmf_config, &ph->curl_handle,
				key_id, curve_nid, digest_nid, rsa_pss,
				identity_key_uuid, key_blob, key_blob_length,
				&error_msg, &ph->ext_lib, ph->verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to retrieve key '%s' from EKMF "
			   "Web: %s", key_id, error_msg != NULL ? error_msg :
			   strerror(-rc));
		_remove_login_token_if_error(ph, rc);
		goto out;
	}

	rc = _restrict_key(ph, key_blob, *key_blob_length);
	if (rc != 0)
		goto out;

out:
	if (identity_key_uuid != NULL)
		free(identity_key_uuid);

	return rc;
}

static const struct kms_functions kms_functions = {
	.api_version = KMS_API_VERSION_1,
	.kms_bind = kms_bind,
	.kms_initialize = kms_initialize,
	.kms_terminate = kms_terminate,
	.kms_get_last_error = kms_get_last_error,
	.kms_supports_key_type = kms_supports_key_type,
	.kms_display_info = kms_display_info,
	.kms_get_command_options = kms_get_command_options,
	.kms_configure = kms_configure,
	.kms_deconfigure = kms_deconfigure,
	.kms_login = kms_login,
	.kms_reenciper = kms_reenciper,
	.kms_generate_key = kms_generate_key,
	.kms_set_key_properties = kms_set_key_properties,
	.kms_get_key_properties = kms_get_key_properties,
	.kms_remove_key = kms_remove_key,
	.kms_list_keys = kms_list_keys,
	.kms_import_key = kms_import_key,
};

/**
 * Returns an address of a structure containing the KMS plugin functions.
 * This function is exported by the KMS plugin, and its address is obtain
 * via dlsym() after loading the plugin via dlopen().
 * *
 * @returns the address of a structure or NULL in case of an error.
 */
const struct kms_functions *kms_get_functions(void)
{
	return &kms_functions;
}
