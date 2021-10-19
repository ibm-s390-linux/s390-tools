/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dlfcn.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "lib/zt_common.h"
#include "lib/util_base.h"
#include "lib/util_panic.h"
#include "lib/util_libc.h"
#include "lib/util_path.h"
#include "lib/util_rec.h"

#include "plugin-utils.h"
#include "properties.h"
#include "utils.h"

/**
 * Initializes the plugin and setup the plugin data structure
 *
 * @param pd                address of the plugin data structure
 * @param plugin_name       name of the plugin (used for printing messages)
 * @param config_path       name of a directory where the KMS plugin can store
 *                          its configuration and other files it needs to store
 * @param config_file       name of the config file of the plugin
 * @param verbose           if true, the plugin should write verbose or debug
 *                          messages to stderr during further processing.
 *
 *  @returns 0 on success, a negative errno in case of an error.
 */
int plugin_init(struct plugin_data *pd, const char *plugin_name,
		const char *config_path, const char *config_file,
		bool verbose)
{
	struct stat sb;
	int rc;

	util_assert(pd != NULL, "Internal error: pd is NULL");
	util_assert(plugin_name != NULL, "Internal error: plugin_name is NULL");
	util_assert(config_path != NULL, "Internal error: config_path is NULL");
	util_assert(config_file != NULL, "Internal error: config_file is NULL");

	memset(pd, 0, sizeof(struct plugin_data));

	pd->plugin_name = util_strdup(plugin_name);
	pd->config_path = util_strdup(config_path);
	pd->config_file = util_strdup(config_file);
	pd->verbose = verbose;

	pr_verbose(pd, "Plugin initializing, config_path: '%s'", config_path);

	if (stat(config_path, &sb) != 0) {
		rc = -errno;
		warnx("Can not access '%s': %s", config_path, strerror(-rc));
		goto error;
	}
	if (!S_ISDIR(sb.st_mode)) {
		warnx("'%s' is not a directory", config_path);
		rc = -EIO;
		goto error;
	}
	if (!util_path_is_readable(config_path) ||
	    !util_path_is_writable(config_path)) {
		warnx("Permission denied for '%s'", config_path);
		rc = -EACCES;
		goto error;
	}
	if (sb.st_mode & S_IWOTH) {
		warnx("Directory '%s' is writable for others, this is not "
		      "accepted", config_path);
		rc = -EIO;
		goto error;
	}

	pd->config_path_owner = sb.st_gid;
	pd->config_path_mode = sb.st_mode & (S_IRUSR | S_IWUSR |
					     S_IRGRP  | S_IWGRP |
					     S_IROTH);

	pd->properties = properties_new();
	rc = plugin_load_config(pd);
	if (rc != 0 && rc != -EIO) {
		warnx("Failed to load plugin config file: %s", strerror(-rc));
		goto error;
	}

	return 0;

error:
	plugin_term(pd);
	return rc;
}

/**
 * Terminate the plugin and cleanup the plugin data structure
 *
 * @param pd                address of the plugin data structure
 */
void plugin_term(struct plugin_data *pd)
{
	util_assert(pd != NULL, "Internal error: pd is NULL");

	pr_verbose(pd, "Plugin terminated");

	if (pd->plugin_name != NULL)
		free((void *)pd->plugin_name);
	if (pd->config_path != NULL)
		free((void *)pd->config_path);
	if (pd->config_file != NULL)
		free((void *)pd->config_file);
	if (pd->properties != NULL)
		properties_free(pd->properties);
}

/**
 * Clears the error message in the plugin data
 *
 * @param pd                the plugin data
 */
void plugin_clear_error(struct plugin_data *pd)
{
	memset(pd->error_msg, 0, sizeof(pd->error_msg));
}

/**
 * Sets the error message in the plugin data
 *
 * @param pd                the plugin data
 * @param fmt               the format string for sprintf
 */
void plugin_set_error(struct plugin_data *pd, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(pd->error_msg, sizeof(pd->error_msg), fmt, ap);
	va_end(ap);
}

/**
 * Load the plugin config file
 *
 * @param pd                the plugin data
 * @param config_file       the name of the config file
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int plugin_load_config(struct plugin_data *pd)
{
	char *file_name = NULL;
	int rc;

	util_asprintf(&file_name, "%s/%s", pd->config_path, pd->config_file);

	rc = properties_load(pd->properties, file_name, true);
	if (rc != 0)
		pr_verbose(pd, "Failed to load plugin config file '%s': %s",
			   file_name, strerror(-rc));
	else
		pr_verbose(pd, "Config file '%s' loaded", file_name);

	free(file_name);
	return rc;
}

/**
 * Save the plugin config file
 *
 * @param pd                the plugin data
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int plugin_save_config(struct plugin_data *pd)
{
	char *file_name = NULL;
	int rc;

	util_asprintf(&file_name, "%s/%s", pd->config_path, pd->config_file);

	pr_verbose(pd, "Saving '%s'", file_name);

	rc = properties_save(pd->properties, file_name, true);
	if (rc != 0) {
		plugin_set_error(pd, "Failed to save plugin config file '%s': "
				 "%s", file_name, strerror(-rc));
		goto out;
	}

	rc = plugin_set_file_permission(pd, file_name);
	if (rc != 0)
		goto out;

out:
	free(file_name);
	return rc;
}


/**
 * Sets the file permissions of the file to the permissions and the group
 * of configuration directory
 *
 * @param pd                 the plugin data
 * @param filename           the name of the file to set permissions for
 *
 * @returns 0 on success, or a negative errno value on failure
 */
int plugin_set_file_permission(struct plugin_data *pd, const char *filename)
{
	int rc;

	if (chmod(filename, pd->config_path_mode) != 0) {
		rc = -errno;
		plugin_set_error(pd, "chmod failed on file '%s': %s", filename,
				 strerror(-rc));
		return rc;
	}

	if (chown(filename, geteuid(), pd->config_path_owner) != 0) {
		rc = -errno;
		plugin_set_error(pd, "chown failed on file '%s': %s", filename,
				 strerror(-rc));
		return rc;
	}

	return 0;
}

/**
 * Checks if a plugin config property is set and not empty
 *
 * @param pd                the plugin data
 * @param name              the name of the property
 *
 * @returns true if the property is set and is not empty, false otherwise
 */
bool plugin_check_property(struct plugin_data *pd, const char *name)
{
	bool ok = true;
	char *value;

	value = properties_get(pd->properties, name);
	pr_verbose(pd, "Property '%s': %s", name,
		   value != NULL ? value : "(missing)");

	ok &= (value != NULL && strlen(value) > 0);

	if (value != NULL)
		free(value);

	return ok;
}

/**
 * Sets or removes a property. If value is NULL it is removed, otherwise it
 * is set.
 *
 * @param pd                the plugin data
 * @param name              the name of the property
 * @param value             the value of the property or NULL
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int plugin_set_or_remove_property(struct plugin_data *pd, const char *name,
				  const char *value)
{
	int rc = 0;

	if (value != NULL) {
		rc = properties_set(pd->properties, name, value);
		if (rc != 0) {
			plugin_set_error(pd, "Failed to set property '%s': %s",
					 name, strerror(-rc));
			goto out;
		}
	} else {
		rc = properties_remove(pd->properties, name);
		if (rc != 0 && rc != -ENOENT) {
			plugin_set_error(pd, "Failed to remove property '%s': "
					 "%s", name, strerror(-rc));
			goto out;
		}
		rc = 0;
	}

out:
	return rc;
}


/**
 * Makes a temporary file an active file, by first removing the current active
 * file (if existent), and then renaming the temporary file to the active file.
 * The active file permissions are also set to the permissions and the group of
 * configuration directory.
 *
 * @param pd                the plugin data
 * @param temp_file         the name of the temporary file
 * @param active_file       the name of the active file
 *
 * @returns 0 on success, or a negative errno value on failure
 */
int plugin_activate_temp_file(struct plugin_data *pd, const char *temp_file,
			      const char *active_file)
{
	int rc;

	if (util_path_exists(active_file)) {
		rc = remove(active_file);
		if (rc != 0) {
			rc = -errno;
			plugin_set_error(pd, "remove failed on file '%s': %s",
					 active_file, strerror(-rc));
			return rc;
		}
	}

	rc = rename(temp_file, active_file);
	if (rc != 0) {
		rc = -errno;
		plugin_set_error(pd, "rename failed on file '%s': %s",
				 temp_file, strerror(-rc));
		return rc;
	}

	return plugin_set_file_permission(pd, active_file);
}

/**
 * Check if the certificate is a self signed certificate, and if it is expired
 * or not yet valid.
 *
 * @param pd                the plugin data
 * @param cert_file         the file name of the PEM file containing the cert
 * @param self_signed       on return: true if the cetr is a self signed cert
 * @param valid             on return: false if the cert is expired or not yet
 *                          valid
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int plugin_check_certificate(struct plugin_data *pd, const char *cert_file,
			     bool *self_signed, bool *valid)
{
	X509 *cert;
	FILE *fp;
	int rc;

	fp = fopen(cert_file, "r");
	if (fp == NULL) {
		rc = -errno;
		pr_verbose(pd, "Failed to open certificate PEM file '%s': "
			   "%s", cert_file, strerror(-rc));
		return rc;
	}

	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	if (cert == NULL) {
		pr_verbose(pd, "Failed to read certificate PEM file '%s'",
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
 * Print the certificate(s) contained in the specified PEM file.
 *
 * @param pd                the plugin data
 * @param cert_pem          the file name of the PEM file to print
 *
 * @returns -EIO if the file could not be opened. -ENOENT if the PEM file
 *          does not contain any certificates. 0 if success.
 */
int plugin_print_certificates(struct plugin_data *pd, const char *cert_pem)
{
	int rc = -ENOENT;
	X509 *cert;
	FILE *fp;

	if (cert_pem == NULL)
		return -EINVAL;

	fp = fopen(cert_pem, "r");
	if (fp == NULL) {
		pr_verbose(pd, "File '%s': %s", cert_pem, strerror(errno));
		return -EIO;
	}

	while (1) {
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (cert == NULL)
			break;

		X509_print_ex_fp(stdout, cert, 0, X509_FLAG_NO_EXTENSIONS);

		X509_free(cert);
		rc = 0;
	}

	fclose(fp);
	return rc;
}

/**
 * Queries the APKA master key states and verification patterns of the current
 * CCA adapter
 *
 * @param pd                the plugin data
 * @param cca               the CCA library structure
 * @param apka_mk_info      the master key info of the APKA master key

 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int get_cca_apka_mk_info(struct plugin_data *pd, struct cca_lib *cca,
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

	pr_verbose(pd, "CSUACFQ (Cryptographic Facility Query) returned: "
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
 * @param pd                the plugin data
 * @param cca               CCA library structure
 * @param apqns             a list of APQNs
 * @param num_apqns         number of APQNs in above array
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int print_cca_apka_mks(struct plugin_data *pd, struct cca_lib *cca,
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
					pd->verbose);
		if (rc != 0) {
			pr_verbose(pd, "Failed to select APQN %02x.%04x: "
				   "%s", apqns[i].card, apqns[i].domain,
				   strerror(-rc));
			goto out;
		}

		rc = get_cca_apka_mk_info(pd, cca, &mk_info);
		if (rc != 0) {
			pr_verbose(pd, "Failed to get the APKA master key "
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
 * Cross checks the list of APQNs specified if the CCA master keys of all APQNs
 * for the APKA master key are the same.
 *
 * @param pd                the plugin data
 * @param apqns             a list of APQNs
 * @param num_apqns         number of APQNs in above array
 *
 * @returns 0 on success, a negative errno in case of an error.
 * -ENODEV is returned if at least one APQN has a mismatching master key.
 */
int cross_check_cca_apka_apqns(struct plugin_data *pd,
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
					pd->verbose);
		if (rc != 0) {
			pr_verbose(pd, "Failed to select APQN %02x.%04x: "
				   "%s", apqns[i].card, apqns[i].domain,
				   strerror(-rc));
			goto out;
		}

		rc = get_cca_apka_mk_info(pd, &cca, &mk_info);
		if (rc != 0) {
			pr_verbose(pd, "Failed to get the APKA master key "
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
		pr_verbose(pd, "Your APKA master key setup is improper");
		rc = -ENODEV;
	}

	if (print)
		print_cca_apka_mks(pd, &cca, apqns, num_apqns);

out:
	if (cca.lib_csulcca != NULL)
		dlclose(cca.lib_csulcca);

	return rc;
}

/**
 * Selects one the CCA APQNs of the APQN string and loads the CCA
 * library and returns it.
 *
 * @param pd                the plugin data
 * @param apqns             the APQN string
 * @param cca_lib           On return: filled with CCA library infos
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int select_cca_adapter_by_apqns(struct plugin_data *pd, const char *apqns,
				struct cca_lib *cca_lib)
{
	struct cca_lib cca = { 0 };
	unsigned int card, domain;
	char **apqn_list = NULL;
	bool selected = false;
	int rc = 0, i;

	pr_verbose(pd, "Select an APQN out of %s for the CCA host library",
		   apqns);

	apqn_list = str_list_split(apqns);
	for (i = 0; apqn_list[i] != NULL; i++) {
		if (sscanf(apqn_list[i], "%x.%x", &card, &domain) != 2)
			continue;

		if (sysfs_is_apqn_online(card, domain, CARD_TYPE_CCA) != 1)
			continue;

		rc = select_cca_adapter(&cca, card, domain, pd->verbose);
		if (rc != 0) {
			pr_verbose(pd, "Failed to select APQN %02x.%04x: "
				   "%s", card, domain, strerror(-rc));
			goto out;
		}

		selected = true;
		break;
	}

	if (!selected) {
		pr_verbose(pd, "None of the associated APQNs is "
			   "available: %s", apqns);
		rc = -ENODEV;
		goto out;
	}

	pr_verbose(pd, "Selected APQN %02x.%04x", card, domain);

	*cca_lib = cca;

out:
	if (apqn_list != NULL)
		str_list_free_string_array(apqn_list);

	if (rc != 0 && cca.lib_csulcca != NULL)
		dlclose(cca.lib_csulcca);

	return rc;
}

/**
 * Build an APQN string from an APQN array
 *
 * @param apqns           An array of APQNs
 * @param num_apqns       The number of elements in above array
 *
 * @returns an allocated string with the APQNs
 */
char *build_kms_apqn_string(const struct kms_apqn *apqns, size_t num_apqns)
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
 * Parse a semi-colon separated list and return an allocated array of the
 * elements.
 *
 * @param list              the semi-colon separated list
 * @param elements          on return, an allocated array of elements
 * @param num_elements      on return, the number of elements in the array
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int parse_list(const char *list, char ***elements, size_t *num_elements)
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
