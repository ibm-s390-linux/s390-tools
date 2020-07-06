/*
 * zkey-ekmfweb - EKMFWeb zkey KMS plugin
 *
 * Copyright IBM Corp. 2020
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

	ph->config_complete = ph->apqns_configured;
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

	util_assert(handle != NULL, "Internal error: handle is NULL");

	pr_verbose(ph, "Display Info");

	_clear_error(ph);

	return 0;
}

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

	pr_verbose(ph, "Login");

	_clear_error(ph);

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

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
		     unsigned char *UNUSED(key_blob),
		     size_t *UNUSED(key_blob_length),
		     char *UNUSED(key_id), size_t UNUSED(key_id_size),
		     char *UNUSED(key_label), size_t UNUSED(key_label_size))
{
	struct plugin_handle *ph = handle;
	size_t i;

	util_assert(handle != NULL, "Internal error: handle is NULL");
	util_assert(num_properties == 0 || properties != NULL,
		    "Internal error: properties is NULL but num_properties"
		    " > 0 ");
	util_assert(num_options == 0 || options != NULL,
		    "Internal error: options is NULL but num_options > 0 ");

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

	_set_error(ph, "Not yet implemented");
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

	pr_verbose(ph, "Set key properties: key-ID: '%s'", key_id);
	for (i = 0; i < num_properties; i++) {
		util_assert(properties[i].name != NULL,
			    "Internal error: property name is NULL");
		util_assert(properties[i].value != NULL,
			    "Internal error: property value is NULL");
		pr_verbose(ph, "  Property '%s': '%s", properties[i].name,
			   properties[i].value);
	}

	_clear_error(ph);

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	_set_error(ph, "Not yet implemented");
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

	pr_verbose(ph, "Get key properties: key-ID: '%s'", key_id);

	_clear_error(ph);

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	_set_error(ph, "Not yet implemented");
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

	if (!ph->config_complete) {
		_set_error(ph, "The configuration is incomplete, run 'zkey "
			  "kms configure [OPTIONS]' to complete the "
			  "configuration.");
		return -EINVAL;
	}

	_set_error(ph, "Not yet implemented");
	return -ENOTSUP;
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
		  kms_list_callback callback, void *UNUSED(private_data))
{
	struct plugin_handle *ph = handle;
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

	_set_error(ph, "Not yet implemented");
	return -ENOTSUP;
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

	_set_error(ph, "Not yet implemented");
	return -ENOTSUP;
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
