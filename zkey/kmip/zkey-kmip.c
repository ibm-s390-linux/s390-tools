/*
 * zkey-kmip - KMIP zkey KMS plugin
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <openssl/objects.h>

#include "lib/zt_common.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_base.h"

#include "zkey-kmip.h"
#include "../kms-plugin.h"
#include "../cca.h"
#include "../utils.h"
#include "../pkey.h"
#include "../properties.h"

#include "libseckey/sk_utilities.h"

#define _set_error(ph, fmt...)	plugin_set_error(&(ph)->pd, fmt)

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
 * Checks if the plugin configuration is complete. Sets the appropriate flags
 * in the plugin handle
 *
 * @param ph                the plugin handle
 */
static void _check_config_complete(struct plugin_handle *ph)
{
	ph->apqns_configured =
		plugin_check_property(&ph->pd, KMIP_CONFIG_APQNS) &&
		plugin_check_property(&ph->pd, KMIP_CONFIG_APQN_TYPE) &&
		ph->card_type != CARD_TYPE_ANY;

	ph->identity_key_generated =
		plugin_check_property(&ph->pd, KMIP_CONFIG_IDENTITY_KEY) &&
		plugin_check_property(&ph->pd,
				      KMIP_CONFIG_IDENTITY_KEY_ALGORITHM) &&
		plugin_check_property(&ph->pd, KMIP_CONFIG_IDENTITY_KEY_PARAMS);

	ph->config_complete = ph->apqns_configured &&
			      ph->identity_key_generated;
}

/**
 * Returns a textual name of the specified card type.
 *
 * @param card_type          the card type
 *
 * @returns a constant string, or NULL if an invalid card type is specified
 */
static const char *_card_type_to_str(enum card_type card_type)
{
	switch (card_type) {
	case CARD_TYPE_CCA:
		return KMIP_APQN_TYPE_CCA;
	case CARD_TYPE_EP11:
		return KMIP_APQN_TYPE_EP11;
	default:
		return NULL;
	}
}

/**
 * Returns the card type for the textual name of the card type.
 *
 * @param card_type          the card type as string
 *
 * @returns the card type value, or CARD_TYPE_ANY if unknown
 */
static enum card_type _card_type_from_str(const char *card_type)
{
	if (strcmp(card_type, KMIP_APQN_TYPE_CCA) == 0)
		return CARD_TYPE_CCA;
	if (strcmp(card_type, KMIP_APQN_TYPE_EP11) == 0)
		return CARD_TYPE_EP11;

	return CARD_TYPE_ANY;
}

/**
 * Unloads the CCA library
 *
 * @param ph                the plugin handle
 */
static void _terminate_cca_library(struct plugin_handle *ph)
{
	if (ph->cca_lib.cca_lib != NULL)
		dlclose(ph->cca_lib.cca_lib);
	ph->cca_lib.cca_lib = NULL;
}

/*
 * Sets up the CCA library structure in the handle. Load the CCA library
 * and selects one of the associated APQNs.
 *
 * @param ph                the plugin handle
 * @param apqns             the associated APQNs
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _setup_cca_library(struct plugin_handle *ph, const char *apqns)
{
	int rc;

	_terminate_cca_library(ph);

	rc = select_cca_adapter_by_apqns(&ph->pd, apqns, &ph->cca);
	if (rc != 0) {
		_set_error(ph, "Failed to select one of the associated APQNs: "
			   "%s", apqns);
		_terminate_cca_library(ph);
	}

	ph->cca_lib.cca_lib = ph->cca.lib_csulcca;

	return rc;
}

/**
 * Unloads the Ep11 library
 *
 * @param ph                the plugin handle
 */
static void _terminate_ep11_library(struct plugin_handle *ph)
{
	if (ph->ep11.lib_ep11 == NULL)
		return;

	if (ph->ep11_lib.target != 0) {
		free_ep11_target_for_apqn(&ph->ep11, ph->ep11_lib.target);
		ph->ep11_lib.target = 0;
	}
	ph->ep11_lib.ep11_lib = NULL;

	if (ph->ep11.lib_ep11 != NULL)
		dlclose(ph->ep11.lib_ep11);
	memset(&ph->ep11, 0, sizeof(ph->ep11));
}

/*
 * Sets up the EP11 library structure in the handle. Load the EP11 library
 * and sets up the EP11 target with the APQNs specified
 *
 * @param ph                the plugin handle
 * @param apqns             the associated APQNs
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _setup_ep11_library(struct plugin_handle *ph, const char *apqns)
{
	unsigned int card, domain;
	bool selected = false;
	char **apqn_list;
	int rc, i;

	rc = load_ep11_library(&ph->ep11, ph->pd.verbose);
	if (rc != 0) {
		_set_error(ph, "Failed load the EP11 host library");
		return rc;
	}

	apqn_list = str_list_split(apqns);
	for (i = 0; apqn_list[i] != NULL; i++) {
		if (sscanf(apqn_list[i], "%x.%x", &card, &domain) != 2)
			continue;

		if (sysfs_is_apqn_online(card, domain, CARD_TYPE_EP11) != 1)
			continue;

		rc = get_ep11_target_for_apqn(&ph->ep11, card, domain,
					      &ph->ep11_lib.target,
					      ph->pd.verbose);
		if (rc != 0) {
			_set_error(ph, "Failed to get EP11 target for "
				   "APQN %02x.%04x: %s", card, domain,
				   strerror(-rc));
			goto out;
		}

		selected = true;
		break;
	}

	if (!selected) {
		_set_error(ph, "None of the associated APQNs is "
			   "available: %s", apqns);
		rc = -ENODEV;
		goto out;
	}

	pr_verbose(&ph->pd, "Selected APQN %02x.%04x", card, domain);

	ph->ep11_lib.ep11_lib = ph->ep11.lib_ep11;

out:
	if (apqn_list != NULL)
		str_list_free_string_array(apqn_list);

	if (rc != 0)
		_terminate_ep11_library(ph);

	return rc;
}

/**
 * Terminates the external secure key library structure in the handle
 * and the OpenSSL secure key interface.
 *
 * @param ph                the plugin handle
 */
static void _terminate_ext_lib(struct plugin_handle *ph)
{
	if (ph->ext_lib.type != 0)
		SK_OPENSSL_term();

	switch (ph->ext_lib.type) {
	case SK_EXT_LIB_CCA:
		_terminate_cca_library(ph);
		ph->ext_lib.cca = NULL;
		break;

	case SK_EXT_LIB_EP11:
		_terminate_ep11_library(ph);
		ph->ext_lib.ep11 = NULL;
		break;

	default:
		break;
	}

	ph->ext_lib.type = 0;
}

/**
 * Initializes the external secure key library structure in the handle
 * with the information from the associated APQNs. Also initializes the
 * OpenSSL secure key interface.
 *
 * @param ph                the plugin handle
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _setup_ext_lib(struct plugin_handle *ph)
{
	char *apqns;
	int rc = 0;

	if (ph->ext_lib.type != 0)
		return 0;

	if (!ph->apqns_configured) {
		_set_error(ph, "The configuration is incomplete, you must "
			   "first configure the APQNs used with this plugin.");
		return -EINVAL;
	}

	apqns = properties_get(ph->pd.properties, KMIP_CONFIG_APQNS);
	if (apqns == NULL) {
		_set_error(ph, "No APQN are associated with the plugin.");
		return -ENODEV;
	}

	pr_verbose(&ph->pd, "Associated APQNs: %s", apqns);

	switch (ph->card_type) {
	case CARD_TYPE_CCA:
		rc = _setup_cca_library(ph, apqns);
		if (rc != 0)
			goto out;

		ph->ext_lib.type = SK_EXT_LIB_CCA;
		ph->ext_lib.cca = &ph->cca_lib;
		break;

	case CARD_TYPE_EP11:
		rc = _setup_ep11_library(ph, apqns);
		if (rc != 0)
			goto out;

		ph->ext_lib.type = SK_EXT_LIB_EP11;
		ph->ext_lib.ep11 = &ph->ep11_lib;
		break;

	default:
		_set_error(ph, "The configuration is incomplete, you must "
			   "first configure the APQNs used with this plugin.");
		return -EINVAL;
	}

	rc = SK_OPENSSL_init(ph->pd.verbose);
	if (rc != 0)
		_terminate_ext_lib(ph);

out:
	free(apqns);

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
	char *apqn_type = NULL;
	int rc;

	util_assert(config_path != NULL, "Internal error: config_path is NULL");

	ph = util_malloc(sizeof(struct plugin_handle));
	memset(ph, 0, sizeof(struct plugin_handle));

	rc = plugin_init(&ph->pd, "zkey-kmip", config_path,
			 KMIP_CONFIG_FILE, verbose);
	if (rc != 0)
		goto error;

	_check_config_complete(ph);
	pr_verbose(&ph->pd, "Plugin configuration is %scomplete",
		   ph->config_complete ? "" : "in");

	ph->card_type = CARD_TYPE_ANY;
	apqn_type = properties_get(ph->pd.properties, KMIP_CONFIG_APQN_TYPE);
	if (apqn_type != NULL) {
		ph->card_type = _card_type_from_str(apqn_type);
		free(apqn_type);
		if (ph->card_type == CARD_TYPE_ANY) {
			pr_verbose(&ph->pd, "APQN type invalid: %s", apqn_type);
			goto error;
		}
	}

	ph->identity_secure_key = properties_get(ph->pd.properties,
						 KMIP_CONFIG_IDENTITY_KEY);

	return (kms_handle_t)ph;

error:
	if (strlen(ph->pd.error_msg) > 0)
		warnx("%s", ph->pd.error_msg);

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

	pr_verbose(&ph->pd, "Plugin terminating");

	if (ph->identity_secure_key != NULL)
		free((void *)ph->identity_secure_key);

	_terminate_ext_lib(ph);
	plugin_term(&ph->pd);
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

	pr_verbose(&ph->pd, "Last error: '%s'", ph->pd.error_msg);

	if (strlen(ph->pd.error_msg) == 0)
		return NULL;

	return ph->pd.error_msg;
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

	plugin_clear_error(&ph->pd);

	switch (ph->card_type) {
	case CARD_TYPE_CCA:
		if (strcasecmp(key_type, KEY_TYPE_CCA_AESDATA) == 0)
			return true;
		if (strcasecmp(key_type, KEY_TYPE_CCA_AESCIPHER) == 0)
			return true;
		break;
	case CARD_TYPE_EP11:
		if (strcasecmp(key_type, KEY_TYPE_EP11_AES) == 0)
			return true;
		break;
	default:
		if (strcasecmp(key_type, KEY_TYPE_CCA_AESDATA) == 0)
			return true;
		if (strcasecmp(key_type, KEY_TYPE_CCA_AESCIPHER) == 0)
			return true;
		if (strcasecmp(key_type, KEY_TYPE_EP11_AES) == 0)
			return true;
		break;
	}

	return false;
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
	struct plugin_handle *ph = handle;
	char *tmp = NULL;
	bool rsa;

	util_assert(handle != NULL, "Internal error: handle is NULL");

	pr_verbose(&ph->pd, "Display Info");

	plugin_clear_error(&ph->pd);

	tmp = properties_get(ph->pd.properties,
			     KMIP_CONFIG_IDENTITY_KEY_ALGORITHM);
	if (tmp != NULL) {
		printf("  Identity key:         %s", tmp);
		rsa = strcmp(tmp, KMIP_KEY_ALGORITHM_RSA) == 0;
		free(tmp);
		tmp = properties_get(ph->pd.properties,
				     KMIP_CONFIG_IDENTITY_KEY_PARAMS);
		if (tmp != NULL) {
			printf(" (%s%s)", tmp, rsa ? " bits" : "");
			free(tmp);
		}
		printf("\n");
	} else {
		printf("  Identity key:         (configuration required)\n");
	}

	return 0;
}

static const struct util_opt configure_options[] = {
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "KMIP SPECIFIC OPTIONS FOR IDENTITY KEY GENERATION",
		.command = KMS_COMMAND_CONFIGURE,
	},
	{
		.option = { "gen-identity-key", required_argument, NULL, 'i'},
		.argument = "KEY-SPEC",
		.desc = "Generates an identity key for the KMIP plugin. The "
			"identity key is a secure ECC or RSA key. The identity "
			"key is automatically generated with the default "
			"values ECC with curve secp521r1 when a certificate "
			"signing request (CSR) or self-signed certificate is "
			"to be generated and no identity key is available. Use "
			"this option to generate or regenerate a new identity "
			"key with with specific parameters. You need to "
			"regenerate a certificate with the newly generated "
			"identity key and reregister this certificate with the "
			"KMIP server.",
		.command = KMS_COMMAND_CONFIGURE,
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

	return NULL;
}

struct config_options {
	const char *generate_identity_key;
};

/**
 * Check the specified APQns and assure that they are all of the right type.
 *
 * @param ph                the plugin handle
 * @param apqns             a list of APQNs to associate with the KMS plugin, or
 *                          NULL if no APQNs are specified.
 * @param num_apqns         number of APQNs in above array. 0 if no APQNs are
 *                          specified.
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _check_apqns(struct plugin_handle *ph, const struct kms_apqn *apqns,
			size_t num_apqns)
{
	size_t i;
	int rc;

	if (num_apqns == 0)
		return 0;

	if (ph->card_type == CARD_TYPE_ANY) {
		/*
		 * No APQNs configured yet, accept any APQN type, but all must
		 * be of the same type.
		 */
		ph->card_type = sysfs_get_card_type(apqns[0].card);
		if (ph->card_type == CARD_TYPE_ANY) {
			_set_error(ph, "The APQN %02x.%04x is not available or "
				   "has an unsupported type", apqns[0].card,
				   apqns[0].domain);
			return -EINVAL;
		}
	}

	pr_verbose(&ph->pd, "Check APQNs for card type %s",
		   _card_type_to_str(ph->card_type));

	for (i = 0; i < num_apqns; i++) {
		rc = sysfs_is_apqn_online(apqns[i].card, apqns[i].domain,
					  ph->card_type);
		if (rc != 1) {
			_set_error(ph, "APQN %02x.%04x is not of the right "
				   "type. The plugin is configured to use "
				   "APQNs of type %s", apqns[i].card,
				   apqns[i].domain,
				   _card_type_to_str(ph->card_type));

			return -EINVAL;
		}
	}

	return 0;
}

/**
 * Parse a key specification and setup the key gen info struct
 *
 * @param ph                the plugin handle
 * @param key_spec          the key specification (ECC:CURVE or RSA:KEYBITS).
 *                          If NULL, the default key specification is used.
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _parse_key_spec(struct plugin_handle *ph, const char *key_spec,
			   struct sk_key_gen_info *gen_info)
{
	char *copy = NULL, *algorithm, *params;
	int rc = 0;

	copy = util_strdup(key_spec);

	algorithm = strtok(copy, ":");
	if (algorithm == NULL) {
		_set_error(ph, "Invalid key specification format: '%s'",
			   key_spec);
		rc = -EINVAL;
		goto out;
	}

	params = strtok(NULL, ":");
	if (params == NULL) {
		_set_error(ph, "Invalid key specification format: '%s'",
			   key_spec);
		rc = -EINVAL;
		goto out;
	}

	if (strcasecmp(algorithm, KMIP_KEY_ALGORITHM_RSA) == 0) {
		gen_info->type = SK_KEY_TYPE_RSA;
	} else if (strcasecmp(algorithm, KMIP_KEY_ALGORITHM_ECC) == 0) {
		gen_info->type = SK_KEY_TYPE_EC;
	} else {
		_set_error(ph, "Invalid key algorithm: '%s'", key_spec);
		rc = -EINVAL;
		goto out;
	}

	switch (gen_info->type) {
	case SK_KEY_TYPE_RSA:
		gen_info->rsa.modulus_bits = atol(params);
		switch (gen_info->rsa.modulus_bits) {
		case 512:
		case 1024:
		case 2048:
		case 4096:
			break;
		default:
			_set_error(ph, "Invalid RSA key bits: '%s'", key_spec);
			rc = -EINVAL;
			goto out;
		}
		gen_info->rsa.pub_exp = 65537;
		gen_info->rsa.x9_31 = false;
		break;

	case SK_KEY_TYPE_EC:
		gen_info->ec.curve_nid = OBJ_txt2nid(params);
		if (gen_info->ec.curve_nid == NID_undef) {
			_set_error(ph, "Invalid ECC curve: '%s'", key_spec);
			rc = -EINVAL;
			goto out;
		}
		break;
	}

out:
	free(copy);
	return rc;
}

/**
 * Generates (or re-generates) a identity key for the plugin using the
 * specified key specification, or the default key specifications, of none
 * is specified.
 *
 * @param ph                the plugin handle
 * @param key_spec          the key specification (ECC:CURVE or RSA:KEYBITS).
 *                          If NULL, the default key specification is used.
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int _generate_identity_key(struct plugin_handle *ph,
				  const char *key_spec)
{
	unsigned char identity_key[KMIP_MAX_KEY_TOKEN_SIZE] = { 0 };
	size_t identity_key_size = sizeof(identity_key);
	struct sk_key_gen_info gen_info = { 0 };
	char *reenc_file = NULL;
	char tmp[200];
	int rc;

	if (key_spec == NULL)
		key_spec = KMIP_DEFAULT_IDENTITY_KEY_SPEC;

	_check_config_complete(ph);

	if (!ph->apqns_configured) {
		_set_error(ph, "The configuration is incomplete, you must "
			   "first configure the APQNs used with this plugin.");
		return -EINVAL;
	}

	rc = _parse_key_spec(ph, key_spec, &gen_info);
	if (rc != 0)
		return rc;

	if (ph->identity_secure_key != NULL) {
		printf("ATTENTION: An identity key already exists\n");
		util_print_indented("When you generate a new identity key, "
				    "you must re-generate a certificate and "
				    "re-register it with the KMIP server.", 0);
		printf("%s: Re-generate the identity key [y/N]? ",
		       program_invocation_short_name);
		if (!prompt_for_yes(ph->pd.verbose)) {
			_set_error(ph, "Operation aborted by user");
			return -ECANCELED;
		}
	} else {
		util_asprintf((char **)&ph->identity_secure_key,
			      "%s/%s", ph->pd.config_path,
			      KMIP_CONFIG_IDENTITY_KEY_FILE);

		rc = plugin_set_or_remove_property(&ph->pd,
						   KMIP_CONFIG_IDENTITY_KEY,
						   ph->identity_secure_key);
		if (rc != 0)
			goto out;
	}

	switch (gen_info.type) {
	case SK_KEY_TYPE_RSA:
		rc = plugin_set_or_remove_property(&ph->pd,
					KMIP_CONFIG_IDENTITY_KEY_ALGORITHM,
					KMIP_KEY_ALGORITHM_RSA);
		if (rc != 0)
			goto out;
		sprintf(tmp, "%lu", gen_info.rsa.modulus_bits);
		rc = plugin_set_or_remove_property(&ph->pd,
					KMIP_CONFIG_IDENTITY_KEY_PARAMS,
					tmp);
		if (rc != 0)
			goto out;
		break;

	case SK_KEY_TYPE_EC:
		rc = plugin_set_or_remove_property(&ph->pd,
					KMIP_CONFIG_IDENTITY_KEY_ALGORITHM,
					KMIP_KEY_ALGORITHM_ECC);
		if (rc != 0)
			goto out;
		rc = plugin_set_or_remove_property(&ph->pd,
					KMIP_CONFIG_IDENTITY_KEY_PARAMS,
					OBJ_nid2sn(gen_info.ec.curve_nid));
		if (rc != 0)
			goto out;
		break;
	default:
		break;
	}

	rc = _setup_ext_lib(ph);
	if (rc != 0)
		goto out;

	rc = SK_OPENSSL_generate_secure_key(identity_key, &identity_key_size,
					    &gen_info, &ph->ext_lib,
					    ph->pd.verbose);
	if (rc != 0) {
		_set_error(ph, "Failed to generate the identity key: %s",
			   strerror(-rc));
		goto out;
	}

	rc = SK_UTIL_write_key_blob(ph->identity_secure_key, identity_key,
				    identity_key_size);
	if (rc != 0) {
		_set_error(ph, "Failed to write the identity key into file "
			   "'%s': %s", ph->identity_secure_key, strerror(-rc));
		goto out;
	}

	rc = plugin_set_file_permission(&ph->pd, ph->identity_secure_key);
	if (rc != 0)
		goto out;

	reenc_file = properties_get(ph->pd.properties,
				    KMIP_CONFIG_IDENTITY_KEY_REENC);
	if (reenc_file != NULL) {
		remove(reenc_file);
		free(reenc_file);
		properties_remove(ph->pd.properties,
				  KMIP_CONFIG_IDENTITY_KEY_REENC);
	}

	pr_verbose(&ph->pd, "Generated identity key into '%s'",
		   ph->identity_secure_key);

out:


	return rc;
}

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

	pr_verbose(&ph->pd, "Configure");
	for (i = 0; i < num_apqns; i++) {
		pr_verbose(&ph->pd, "  APQN: %02x.%04x", apqns[i].card,
			   apqns[i].domain);
	}
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(&ph->pd, "  Option '%c': '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(&ph->pd, "  Option %d: '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	plugin_clear_error(&ph->pd);

	if (apqns != NULL) {
		rc = _check_apqns(ph, apqns, num_apqns);
		if (rc != 0)
			goto out;

		if (num_apqns > 0 && ph->card_type == CARD_TYPE_CCA) {
			rc = cross_check_cca_apka_apqns(&ph->pd, apqns,
							num_apqns);
			if (rc != 0) {
				_set_error(ph, "Your CCA APKA master key setup "
					   "is improper");
				goto out;
			}
		}

		apqn_str = build_kms_apqn_string(apqns, num_apqns);
		rc = properties_set(ph->pd.properties, KMIP_CONFIG_APQNS,
				    apqn_str);
		if (rc != 0) {
			_set_error(ph, "Failed to set APQNs property: %s",
				   strerror(-rc));
			goto out;
		}

		rc = properties_set(ph->pd.properties, KMIP_CONFIG_APQN_TYPE,
				    _card_type_to_str(ph->card_type));
		if (rc != 0) {
			_set_error(ph, "Failed to set APQN-Type property: %s",
				   strerror(-rc));
			goto out;
		}

		config_changed = true;
	}

	for (i = 0; i < num_options; i++) {
		switch (options[i].option) {
		case 'i':
			opts.generate_identity_key = options[i].argument;
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

	if (opts.generate_identity_key != NULL) {
		rc = _generate_identity_key(ph, opts.generate_identity_key);
		if (rc != 0)
			goto out;

		config_changed = true;
	}

out:
	if (apqn_str != NULL)
		free(apqn_str);

	if (rc == 0) {
		if (config_changed) {
			rc = plugin_save_config(&ph->pd);
			if (rc != 0)
				goto ret;

			_check_config_complete(ph);
			pr_verbose(&ph->pd,
				   "Plugin configuration is %scomplete",
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

	pr_verbose(&ph->pd, "Deconfigure");

	plugin_clear_error(&ph->pd);

	return 0;
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

	util_assert(handle != NULL, "Internal error: handle is NULL");

	pr_verbose(&ph->pd, "Login");

	plugin_clear_error(&ph->pd);

	return 0;
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
	size_t i;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(num_options == 0 || options != NULL,
		    "Internal error: options is NULL but num_options > 0 ");

	pr_verbose(&ph->pd, "Re-encipher mode: %d, kmreg=%d", mode, mkreg);
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(&ph->pd, "  Option '%c': '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(&ph->pd, "  Option %d: '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	plugin_clear_error(&ph->pd);

	return -ENOTSUP;
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
	struct plugin_handle *ph = handle;
	size_t i;

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

	pr_verbose(&ph->pd, "Generate key: key-type: '%s', keybits: %lu, "
		   "mode: %d", key_type, key_bits, key_mode);
	for (i = 0; i < num_properties; i++) {
		util_assert(properties[i].name != NULL,
			    "Internal error: property name is NULL");
		util_assert(properties[i].value != NULL,
			    "Internal error: property value is NULL");
		pr_verbose(&ph->pd, "  Property '%s': '%s'", properties[i].name,
			   properties[i].value);
	}
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(&ph->pd, "  Option '%c': '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(&ph->pd, "  Option %d: '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	plugin_clear_error(&ph->pd);

	return -ENOTSUP;
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
	struct plugin_handle *ph = handle;
	size_t i;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(key_id != NULL, "Internal error: key_id is NULL");
	util_assert(num_properties == 0 || properties != NULL,
		    "Internal error: properties is NULL but num_properties"
		    " > 0 ");

	pr_verbose(&ph->pd, "Set key properties: key-ID: '%s'", key_id);
	for (i = 0; i < num_properties; i++) {
		util_assert(properties[i].name != NULL,
			    "Internal error: property name is NULL");

		pr_verbose(&ph->pd, "  Property '%s': '%s'", properties[i].name,
			   properties[i].value != NULL ? properties[i].value :
			   "(null)");
	}

	plugin_clear_error(&ph->pd);

	return -ENOTSUP;
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
	struct plugin_handle *ph = handle;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(key_id != NULL, "Internal error: key_id is NULL");
	util_assert(properties != NULL, "Internal error: properties is NULL");
	util_assert(num_properties != NULL,
		    "Internal error: num_properties is NULL");

	pr_verbose(&ph->pd, "Get key properties: key-ID: '%s'", key_id);

	plugin_clear_error(&ph->pd);

	return -ENOTSUP;
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
	struct plugin_handle *ph = handle;
	size_t i;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(key_id != NULL, "Internal error: key_id is NULL");
	util_assert(num_options == 0 || options != NULL,
		    "Internal error: options is NULL but num_options > 0 ");

	pr_verbose(&ph->pd, "Remove key: key-ID: '%s'", key_id);
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(&ph->pd, "  Option '%c': '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(&ph->pd, "  Option %d: '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	plugin_clear_error(&ph->pd);

	return -ENOTSUP;
}

/**
 * List keys managed by the KMS. This list is independent of the zkey key
 * repository. It lists keys as known by the KMS.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param label_pattern     a pattern of the label used to filter the keys, or
 *                          NULL if no label pattern is specified.
 * @param properties        a list of properties used to filter the keys, or
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
	struct plugin_handle *ph = handle;
	size_t i;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(num_properties == 0 || properties != NULL,
		    "Internal error: properties is NULL but num_properties "
		    "> 0 ");
	util_assert(callback != NULL, "Internal error: callback is NULL");

	pr_verbose(&ph->pd, "List Keys, label-pattern: '%s'",
		   label_pattern != NULL ? label_pattern : "(null)");
	for (i = 0; i < num_properties; i++) {
		util_assert(properties[i].name != NULL,
			    "Internal error: property name is NULL");
		util_assert(properties[i].value != NULL,
			    "Internal error: property value is NULL");
		pr_verbose(&ph->pd, "  Property '%s': '%s'", properties[i].name,
			   properties[i].value);
	}
	for (i = 0; i < num_options; i++) {
		if (isalnum(options[i].option))
			pr_verbose(&ph->pd, "  Option '%c': '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
		else
			pr_verbose(&ph->pd, "  Option %d: '%s'",
				   options[i].option,
				   options[i].argument != NULL ?
					options[i].argument : "(null)");
	}

	plugin_clear_error(&ph->pd);

	return -ENOTSUP;
}

/**
 * Imports a key from the KMS and returns a secure key that is
 * enciphered under the current HSM master key.
 *
 * @param handle            the KMS plugin handle obtained from kms_initialize()
 * @param key_id            the key-ID of the key to import
 * @param key_type          the zkey key type, like 'CCA-AESDATA',
 *                          'CCA-AESCIPHER', 'EP11-AES'.
 * @param key_blob          a buffer to return the key blob. The size of the
 *                          buffer is specified in key_blob_length
 * @param key_blob_length   on entry: the size of the key_blob buffer.
 *                          on exit: the size of the key blob returned.
 *
 * @returns 0 on success, or a negative errno in case of an error.
 * Function kms_get_last_error() can be used to obtain more details about the
 * error.
 */
int kms_import_key2(const kms_handle_t handle, const char *key_id,
		    const char *key_type,
		    unsigned char *key_blob, size_t *key_blob_length)
{
	struct plugin_handle *ph = handle;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(key_blob != NULL, "Internal error: key_blob is NULL");
	util_assert(key_blob_length != NULL, "Internal error: key_blob_length "
		    "is NULL");

	pr_verbose(&ph->pd, "Import Key, key-ID: '%s'", key_id);

	plugin_clear_error(&ph->pd);

	return -ENOTSUP;
}

static const struct kms_functions kms_functions = {
	.api_version = KMS_API_VERSION_2,
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
	.kms_import_key2 = kms_import_key2,
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
