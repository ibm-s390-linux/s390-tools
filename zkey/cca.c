/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"

#include "cca.h"
#include "pkey.h"
#include "utils.h"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

/*
 * Definitions for the CCA library
 */
#define CCA_LIBRARY_NAME	"libcsulcca.so"
#define CCA_WEB_PAGE		"http://www.ibm.com/security/cryptocards"
#define CCA_DOMAIN_ENVAR	"CSU_DEFAULT_DOMAIN"
#define CCA_ADAPTER_ENVAR	"CSU_DEFAULT_ADAPTER"

/**
 * Prints CCA return and reason code information for certain known CCA
 * error situations.
 *
 * @param return_code  the CCA return code
 * @param reason_code  the CCA reason code
 */
static void print_CCA_error(int return_code, int reason_code)
{
	switch (return_code) {
	case 8:
		switch (reason_code) {
		case 48:
			warnx("The secure key has a CCA master key "
			      "verification pattern that is not valid");
			break;
		case 90:
			warnx("The operation has been rejected due to access "
			      "control checking");
			break;
		case 2143:
			warnx("The operation has been rejected due to key "
			      "export restrictions of the secure key");
			break;
		}
		break;
	case 12:
		switch (reason_code) {
		case 764:
			warnx("The CCA master key is not loaded and "
			      "therefore a secure key cannot be enciphered");
			break;
		}
		break;
	}
}

/**
 * Returns the version, release and modification number of the used CCA library.
 *
 * @param[in] cca           the CCA library structure
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int get_cca_version(struct cca_lib *cca, bool verbose)
{
	unsigned char exit_data[4] = { 0, };
	unsigned char version_data[20];
	long return_code, reason_code;
	long version_data_length;
	long exit_data_len = 0;
	char date[20];

	util_assert(cca != NULL, "Internal error: cca is NULL");

	memset(version_data, 0, sizeof(version_data));
	version_data_length = sizeof(version_data);
	cca->dll_CSUACFV(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &version_data_length, version_data);
	pr_verbose(verbose, "CSUACFV (Cryptographic Facility Version) "
		   "returned: return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	version_data[sizeof(version_data) - 1] = '\0';
	pr_verbose(verbose, "CCA Version string: %s", version_data);

	if (sscanf((char *)version_data, "%u.%u.%uz%s", &cca->version.ver,
		   &cca->version.rel, &cca->version.mod, date) != 4) {
		warnx("CCA library version is invalid: %s", version_data);
		return -EINVAL;
	}

	return 0;
}

/**
 * Loads the CCA library and provides the entry point of the CSNBKTC function.
 *
 * @param[out] cca           on return this contains the address of the CCA
 *                           library and certain CCA symbols. dlclose() should
 *                           be used to free the library when no longer needed.
 * @param verbose            if true, verbose messages are printed
 *
 * @returns 0 on success, -ELIBACC in case of library load errors
 */
int load_cca_library(struct cca_lib *cca, bool verbose)
{
	util_assert(cca != NULL, "Internal error: caa is NULL");

	/* Load the CCA library */
	cca->lib_csulcca = dlopen(CCA_LIBRARY_NAME, RTLD_GLOBAL | RTLD_NOW);
	if (cca->lib_csulcca == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		warnx("The command requires the IBM CCA Host Libraries and "
		      "Tools.\nFor the supported environments and downloads, "
		      "see:\n%s", CCA_WEB_PAGE);
		return  -ELIBACC;
	}

	/* Get the Cryptographic Facility Version function */
	cca->dll_CSUACFV = (t_CSUACFV)dlsym(cca->lib_csulcca, "CSUACFV");

	/* Get the Key Token Change function */
	cca->dll_CSNBKTC = (t_CSNBKTC)dlsym(cca->lib_csulcca, "CSNBKTC");

	/* Get the Key Token Change 2 function */
	cca->dll_CSNBKTC2 = (t_CSNBKTC2)dlsym(cca->lib_csulcca, "CSNBKTC2");

	/* Get the Cryptographic Facility Query function */
	cca->dll_CSUACFQ = (t_CSUACFQ)dlsym(cca->lib_csulcca, "CSUACFQ");

	/* Get the Cryptographic Resource Allocate function */
	cca->dll_CSUACRA = (t_CSUACRA)dlsym(cca->lib_csulcca, "CSUACRA");

	/* Cryptographic Resource Deallocate function */
	cca->dll_CSUACRD = (t_CSUACRD)dlsym(cca->lib_csulcca, "CSUACRD");

	/* Get the Key Token Build 2 function */
	cca->dll_CSNBKTB2 = (t_CSNBKTB2)dlsym(cca->lib_csulcca, "CSNBKTB2");

	/* Get the Key Translate 2 function */
	cca->dll_CSNBKTR2 = (t_CSNBKTR2)dlsym(cca->lib_csulcca, "CSNBKTR2");

	/* Get the Restrict Key Attribute function */
	cca->dll_CSNBRKA = (t_CSNBRKA)dlsym(cca->lib_csulcca, "CSNBRKA");

	if (cca->dll_CSUACFV == NULL ||
	    cca->dll_CSNBKTC == NULL ||
	    cca->dll_CSNBKTC2 == NULL ||
	    cca->dll_CSUACFQ == NULL ||
	    cca->dll_CSUACRA == NULL ||
	    cca->dll_CSUACRD == NULL ||
	    cca->dll_CSNBKTB2 == NULL ||
	    cca->dll_CSNBKTR2 == NULL ||
	    cca->dll_CSNBRKA == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		warnx("The command requires the IBM CCA Host Libraries and "
		      "Tools.\nFor the supported environments and downloads, "
		      "see:\n%s", CCA_WEB_PAGE);
		dlclose(cca->lib_csulcca);
		cca->lib_csulcca = NULL;
		return -ELIBACC;
	}

	pr_verbose(verbose, "CCA library '%s' has been loaded successfully",
		   CCA_LIBRARY_NAME);

	return get_cca_version(cca, verbose);
}

/**
 * Re-enciphers a secure key.
 *
 * @param[in] cca              the CCA libraray structure
 * @param[in] secure_key       a buffer containing the secure key
 * @param[in] secure_key_size  the size of the secure key
 * @param[in] method           the re-enciphering method. METHOD_OLD_TO_CURRENT
 *                             or METHOD_CURRENT_TO_NEW.
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, -EIO in case of an error
 */
int key_token_change(struct cca_lib *cca,
		     u8 *secure_key, unsigned int secure_key_size,
		     char *method, bool verbose)
{
	struct aescipherkeytoken *cipherkey =
				(struct aescipherkeytoken *)secure_key;
	long exit_data_len = 0, rule_array_count;
	unsigned char rule_array[2 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;
	long key_token_length;

	util_assert(cca != NULL, "Internal error: cca is NULL");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");
	util_assert(secure_key_size > 0,
		    "Internal error: secure_key_size is 0");
	util_assert(method != NULL, "Internal error: method is NULL");

	memcpy(rule_array, method, 8);
	memcpy(rule_array + 8, "AES     ", 8);
	rule_array_count = 2;

	if (is_cca_aes_data_key(secure_key, secure_key_size)) {
		cca->dll_CSNBKTC(&return_code, &reason_code,
				 &exit_data_len, exit_data,
				 &rule_array_count, rule_array,
				 secure_key);

		pr_verbose(verbose, "CSNBKTC (Key Token Change) with '%s' "
			   "returned: return_code: %ld, reason_code: %ld",
			   method, return_code, reason_code);
	} else if (is_cca_aes_cipher_key(secure_key, secure_key_size)) {
		key_token_length = cipherkey->length;
		cca->dll_CSNBKTC2(&return_code, &reason_code,
				  &exit_data_len, exit_data,
				  &rule_array_count, rule_array,
				  &key_token_length,
				  (unsigned char *)cipherkey);

		pr_verbose(verbose, "CSNBKTC2 (Key Token Change2) with '%s' "
			   "returned: return_code: %ld, reason_code: %ld",
			   method, return_code, reason_code);

		pr_verbose(verbose, "key_token_length: %lu", key_token_length);
	} else {
		warnx("Invalid key type specified");
		return -EINVAL;
	}

	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	if (is_xts_key(secure_key, secure_key_size)) {
		if (is_cca_aes_data_key(secure_key, secure_key_size)) {
			cca->dll_CSNBKTC(&return_code, &reason_code,
					 &exit_data_len, exit_data,
					 &rule_array_count, rule_array,
					 secure_key + AESDATA_KEY_SIZE);

			pr_verbose(verbose, "CSNBKTC (Key Token Change) with "
				   "'%s' returned: return_code: %ld, "
				   "reason_code: %ld", method, return_code,
				   reason_code);
		} else if (is_cca_aes_cipher_key(secure_key, secure_key_size)) {
			cipherkey = (struct aescipherkeytoken *)(secure_key +
							AESCIPHER_KEY_SIZE);
			key_token_length = cipherkey->length;
			cca->dll_CSNBKTC2(&return_code, &reason_code,
					 &exit_data_len, exit_data,
					 &rule_array_count, rule_array,
					 &key_token_length,
					 (unsigned char *)cipherkey);

			pr_verbose(verbose, "CSNBKTC2 (Key Token Change2) with "
				  "'%s' returned: return_code: %ld, "
				  "reason_code: %ld", method, return_code,
				  reason_code);

			pr_verbose(verbose, "key_token_length: %lu",
				   key_token_length);
		} else {
			warnx("Invalid key type specified");
			return -EINVAL;
		}

		if (return_code != 0) {
			print_CCA_error(return_code, reason_code);
			return -EIO;
		}
	}

	return 0;
}

/**
 * Queries the number of adapters known by the CCA host library
 *
 * @param[in] cca              the CCA library structure
 * @param[out] adapters        the number of adapters
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int get_number_of_cca_adapters(struct cca_lib *cca,
				      unsigned int *adapters, bool verbose)
{
	long exit_data_len = 0, rule_array_count, verb_data_length = 0;
	unsigned char rule_array[16 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;

	util_assert(cca != NULL, "Internal error: cca is NULL");
	util_assert(adapters != NULL, "Internal error: adapters is NULL");

	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "STATCRD2", 8);
	rule_array_count = 1;

	cca->dll_CSUACFQ(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &verb_data_length, NULL);

	pr_verbose(verbose, "CSUACFQ (Cryptographic Facility Query) returned: "
		   "return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	rule_array[8] = '\0';
	if (sscanf((char *)rule_array, "%u", adapters) != 1) {
		pr_verbose(verbose, "Unparsable output: %s", rule_array);
		return -EIO;
	}

	pr_verbose(verbose, "Number of CCA adapters: %u", *adapters);
	return 0;
}

/**
 * Allocate a specific CCA adapter.
 *
 * @param[in] cca              the CCA library structure
 * @param[in] adapter          the adapter number, starting at 1. If 0 is
 *                             specified, then the AUTOSELECT option is
 *                             enabled.
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error. -ENODEV is
 *          returned if the adapter is not available.
 */
static int allocate_cca_adapter(struct cca_lib *cca, unsigned int adapter,
				bool verbose)
{
	long exit_data_len = 0, rule_array_count;
	unsigned char rule_array[8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;
	char res_name[9];
	long res_name_len;

	util_assert(cca != NULL, "Internal error: cca is NULL");

	if (adapter > 0)
		memcpy(rule_array, "DEVICE  ", 8);
	else
		memcpy(rule_array, "DEV-ANY ", 8);
	rule_array_count = 1;

	sprintf(res_name, "CRP%02d", adapter);
	res_name_len = strlen(res_name);

	cca->dll_CSUACRA(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &res_name_len, (unsigned char *)res_name);

	pr_verbose(verbose, "CSUACRA (Cryptographic Resource Allocate) "
		   "returned: return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -ENODEV;
	}

	pr_verbose(verbose, "Adapter %u (%s) allocated", adapter, res_name);
	return 0;
}

/**
 * Deallocate a specific CCA adapter.
 *
 * @param[in] cca              the CCA library structure
 * @param[in] adapter          the adapter number, starting at 1. If 0 is
 *                             specified, then the AUTOSELECT option is
 *                             disabled.
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error. -ENODEV is
 *          returned if the adapter is not available.
 */
static int deallocate_cca_adapter(struct cca_lib *cca, unsigned int adapter,
				  bool verbose)
{
	long exit_data_len = 0, rule_array_count;
	unsigned char rule_array[8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;
	char res_name[9];
	long res_name_len;

	util_assert(cca != NULL, "Internal error: cca is NULL");

	if (adapter > 0)
		memcpy(rule_array, "DEVICE  ", 8);
	else
		memcpy(rule_array, "DEV-ANY ", 8);
	rule_array_count = 1;

	sprintf(res_name, "CRP%02d", adapter);
	res_name_len = strlen(res_name);

	cca->dll_CSUACRD(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &res_name_len, (unsigned char *)res_name);

	pr_verbose(verbose, "CSUACRD (Cryptographic Resource Deallocate) "
		   "returned: return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -ENODEV;
	}

	pr_verbose(verbose, "Adapter %u (%s) deallocated", adapter, res_name);
	return 0;
}

/**
 * Queries the serial number of the current CCA adapter
 *
 * @param[in] cca              the CCA library structure
 * @param[out] serialnr        the buffer where the serial number is returned
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int get_cca_adapter_serialnr(struct cca_lib *cca, char serialnr[9],
				    bool verbose)
{
	long exit_data_len = 0, rule_array_count, verb_data_length = 0;
	unsigned char rule_array[16 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;

	util_assert(cca != NULL, "Internal error: cca is NULL");

	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "STATCRD2", 8);
	rule_array_count = 1;

	cca->dll_CSUACFQ(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &verb_data_length, NULL);

	pr_verbose(verbose, "CSUACFQ (Cryptographic Facility Query) returned: "
		   "return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	memcpy(serialnr, rule_array+14*8, 8);
	serialnr[8] = '\0';

	pr_verbose(verbose, "Serial number of CCA adapter: %s", serialnr);
	return 0;
}

/**
 * Queries the firmware version of the current CCA adapter
 *
 * @param[in] cca              the CCA library structure
 * @param[out] version         the struct where the version is returned
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
static int get_cca_adapter_version(struct cca_lib *cca,
				   struct cca_version *version,
				   bool verbose)
{
	long exit_data_len = 0, rule_array_count, verb_data_length = 0;
	unsigned char rule_array[6 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;
	char version_data[9];

	util_assert(cca != NULL, "Internal error: cca is NULL");

	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "STATCCA ", 8);
	rule_array_count = 1;

	cca->dll_CSUACFQ(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &verb_data_length, NULL);

	pr_verbose(verbose, "CSUACFQ (Cryptographic Facility Query) returned: "
		   "return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	memcpy(version_data, rule_array+3*8, 8);
	version_data[8] = '\0';

	pr_verbose(verbose, "CCA firmware version string: %s", version_data);

	if (sscanf((char *)version_data, "%u.%u.%uz", &version->ver,
		   &version->rel, &version->mod) != 3) {
		warnx("CCA formware version is invalid: %s", version_data);
		return -EINVAL;
	}

	return 0;
}

/**
 * Selects the specified APQN to be used for the CCA host library.
 *
 * @param[in] cca              the CCA library structure
 * @param[in] card             the card number
 * @param[in] domain           the domain number
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error. -ENOTSUP is
 *          returned when the serialnr sysfs attribute is not available,
 *          because the zcrypt kernel module is on an older level. -ENODEV is
 *          returned if the APQN is not available.
 */
int select_cca_adapter(struct cca_lib *cca, unsigned int card,
		       unsigned int domain, bool verbose)
{
	unsigned int adapters, adapter;
	char adapter_serialnr[9];
	char apqn_serialnr[SERIALNR_LENGTH];
	char temp[10];
	int rc, found = 0;

	util_assert(cca != NULL, "Internal error: cca is NULL");

	pr_verbose(verbose, "Select %02x.%04x for the CCA host library", card,
		   domain);

	rc = sysfs_get_serialnr(card, apqn_serialnr, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get the serial number: %s",
			   strerror(-rc));
		return rc;
	}

	sprintf(temp, "%u", domain);
	if (setenv(CCA_DOMAIN_ENVAR, temp, 1) != 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to set the %s environment variable:"
			   " %s", CCA_DOMAIN_ENVAR, strerror(-rc));
		return rc;
	}
	unsetenv(CCA_ADAPTER_ENVAR);

	/*
	 * Unload and reload the CCA host library so that it recognizes the
	 * changed CSU_DEFAULT_DOMAIN environment variable value.
	 */
	if (cca->lib_csulcca != NULL)
		dlclose(cca->lib_csulcca);
	memset(cca, 0, sizeof(struct cca_lib));

	rc = load_cca_library(cca, verbose);
	if (rc != 0)
		return rc;

	rc = get_number_of_cca_adapters(cca, &adapters, verbose);
	if (rc != 0)
		return rc;

	/* Disable the AUTOSELECT option */
	rc = deallocate_cca_adapter(cca, 0, verbose);
	if (rc != 0)
		return rc;

	for (adapter = 1; adapter <= adapters; adapter++) {
		rc = allocate_cca_adapter(cca, adapter, verbose);
		if (rc != 0)
			return rc;

		rc = get_cca_adapter_serialnr(cca, adapter_serialnr, verbose);
		if (rc == 0) {
			if (memcmp(apqn_serialnr, adapter_serialnr, 8) == 0) {
				found = 1;
				break;
			}
		}

		rc = deallocate_cca_adapter(cca, adapter, verbose);
		if (rc != 0)
			return rc;
	}

	if (!found)
		return -ENODEV;

	pr_verbose(verbose, "Selected adapter %u (CRP%02d)", adapter, adapter);
	return 0;
}

struct find_mkvp_info {
	u8		mkvp[MKVP_LENGTH];
	unsigned int	flags;
	bool		found;
	unsigned int	card;
	unsigned int	domain;
	bool		verbose;
};

static int find_mkvp(unsigned int card, unsigned int domain, void *handler_data)
{
	struct find_mkvp_info *info = (struct find_mkvp_info *)handler_data;
	struct mk_info mk_info;
	bool found = false;
	int rc;

	rc = sysfs_get_mkvps(card, domain, &mk_info, info->verbose);
	if (rc == -ENODEV)
		return 0;
	if (rc != 0)
		return rc;

	if (info->flags & FLAG_SEL_CCA_MATCH_CUR_MKVP)
		if (mk_info.cur_mk.mk_state == MK_STATE_VALID &&
		    MKVP_EQ(mk_info.cur_mk.mkvp, info->mkvp))
			found = true;

	if (info->flags & FLAG_SEL_CCA_MATCH_OLD_MKVP)
		if (mk_info.old_mk.mk_state == MK_STATE_VALID &&
		    MKVP_EQ(mk_info.old_mk.mkvp, info->mkvp))
			found = true;

	if (info->flags & FLAG_SEL_CCA_NEW_MUST_BE_SET)
		if (mk_info.new_mk.mk_state != MK_STATE_FULL)
			found = false;


	if (found) {
		info->card = card;
		info->domain = domain;
		info->found = true;

		pr_verbose(info->verbose, "%02x.%04x has the desired mkvp%s",
			   card, domain,
			   info->flags & FLAG_SEL_CCA_NEW_MUST_BE_SET ?
			   " and NEW MK set" : "");

		return 1;
	}

	return 0;
}

/**
 * Selects an APQN to be used for the CCA host library that has the specified
 * master key verification pattern
 *
 * @param[in] cca       the CCA library structure
 * @param[in] mkvp      the master key verification pattern to search for
 * @param[in] apqns     a comma separated list of APQNs. If NULL is specified,
 *                      or an empty string, then all online CCA APQNs are
 *                      checked.
 * @param[in] flags     Flags that control the MKVM matching and NEW register
 *                      checking. Multiple flags can be combined.
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error. -ENOTSUP is
 *          returned when the serialnr sysfs attribute is not available,
 *          because the zcrypt kernel module is on an older level. -ENODEV is
 *          returned if no APQN is available with the desired mkvp.
 */
int select_cca_adapter_by_mkvp(struct cca_lib *cca, u8 *mkvp, const char *apqns,
		 unsigned int flags, bool verbose)
{
	struct find_mkvp_info info;
	int rc;

	util_assert(cca != NULL, "Internal error: cca is NULL");
	util_assert(mkvp != NULL, "Internal error: mkvp is NULL");

	pr_verbose(verbose, "Select mkvp %s in APQNs %s for the CCA host "
		   "library", printable_mkvp(CARD_TYPE_CCA, mkvp),
		   apqns == NULL ? "ANY" : apqns);

	memcpy(info.mkvp, mkvp, sizeof(info.mkvp));
	info.flags = flags;
	info.found = false;
	info.card = 0;
	info.domain = 0;
	info.verbose = verbose;

	rc = handle_apqns(apqns, CARD_TYPE_CCA, find_mkvp, &info, verbose);
	if (rc < 0)
		return rc;

	if (!info.found)
		return -ENODEV;

	rc = select_cca_adapter(cca, info.card, info.domain, verbose);
	return rc;
}

void print_msg_for_cca_envvars(const char *key_name)
{
	char *msg;

	util_asprintf(&msg, "WARNING: You must set environment variables "
			    "%s and %s to the desired card and domain that is "
			    "set up with the AES master key used by this %s. "
			    "%s specifies the domain as decimal number. %s "
			    "specifies the adapter number as 'CRPnn', where "
			    "'nn' is the adapter number. See the CCA "
			    "documentation for more details.\n",
			    CCA_DOMAIN_ENVAR, CCA_ADAPTER_ENVAR, key_name,
			    CCA_DOMAIN_ENVAR, CCA_ADAPTER_ENVAR);
	util_print_indented(msg, 0);
	free(msg);
}

/*
 * Convert a secure key of type CCA-AESDATA into a secure key of type
 * CCA-AESCIPHER.
 *
 * @param[in] cca       the CCA library structure
 * @param[in] input_key the secure key to convert
 * @param[in] input_key_size the size of the secure key to convert
 * @param[in] output_key buffer for the converted secure key
 * @param[in/out] output_key_size on input: size of the output buffer.
 *                                on exit: size of the converted secure key
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int convert_aes_data_to_cipher_key(struct cca_lib *cca,
				   u8 *input_key, unsigned int input_key_size,
				   u8 *output_key,
				   unsigned int *output_key_size,
				   bool verbose)
{
	long input_token_size, output_token_size, zero = 0;
	long exit_data_len = 0, rule_array_count = 0;
	unsigned char *input_token, *output_token;
	unsigned char rule_array[8 * 4] = { 0 };
	unsigned char null_token[64] = { 0, };
	long null_token_len = sizeof(null_token);
	unsigned char exit_data[4] = { 0, };
	struct aescipherkeytoken *cipherkey;
	long return_code, reason_code;
	struct cca_version version;
	unsigned char buffer[800];
	int rc;

	util_assert(cca != NULL, "Internal error: cca is NULL");
	util_assert(input_key != NULL, "Internal error: input_key is NULL");
	util_assert(output_key != NULL, "Internal error: output_key is NULL");
	util_assert(output_key_size != NULL,
		    "Internal error: output_key_size is NULL");

	if (is_cca_aes_cipher_key(input_key, input_key_size)) {
		warnx("Invalid key-type specified");
		return -EINVAL;
	}

	if (*output_key_size < (is_xts_key(input_key, input_key_size) ?
				2 * AESCIPHER_KEY_SIZE : AESCIPHER_KEY_SIZE))
		return -EINVAL;

	/*
	 * We need a CCA firmware version 6.3.27 or later to support
	 * conversion of secure keys that are exportable to CPACF protected keys
	 */
	rc = get_cca_adapter_version(cca, &version, verbose);
	if (rc != 0)
		return rc;
	if (version.ver < 6 ||
	    (version.ver == 6 && version.rel < 3) ||
	    (version.ver == 6 && version.rel < 3 && version.mod < 27)) {
		util_print_indented("The used CCA firmware version does not "
				    "support converting a secure key that can "
				    "be used with the PAES cipher. The "
				    "required CCA firmware version is 6.3.27 "
				    "or later. For the supported environments "
				    "and updates, see: " CCA_WEB_PAGE, 0);
		return -ENOTSUP;
	}

	input_token = input_key;
	input_token_size = AESDATA_KEY_SIZE;
	output_token = buffer;
	output_token_size = sizeof(buffer);
	memset(buffer, 0, sizeof(buffer));

	memcpy(rule_array, "INTERNAL", 8);
	memcpy(rule_array + 8, "AES     ", 8);
	memcpy(rule_array + 16, "XPRTCPAC", 8);
	memcpy(rule_array + 24, "CIPHER  ", 8);
	rule_array_count = 4;

	cca->dll_CSNBKTB2(&return_code, &reason_code,
			  &exit_data_len, exit_data,
			  &rule_array_count, rule_array,
			  &zero, NULL, &zero, NULL,
			  &zero, NULL, &zero, NULL,
			  &zero, NULL,
			  &output_token_size, output_token);

	pr_verbose(verbose, "CSNBKTB2 (Key Token Build2) "
		   "returned: return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	memcpy(rule_array, "AES     ", 8);
	memcpy(rule_array + 8, "REFORMAT", 8);
	rule_array_count = 2;

	output_token_size = sizeof(buffer);

	cca->dll_CSNBKTR2(&return_code, &reason_code,
			  &exit_data_len, exit_data,
			  &rule_array_count, rule_array,
			  &input_token_size, input_token,
			  &null_token_len, null_token,
			  &zero, NULL,
			  &output_token_size, output_token);

	pr_verbose(verbose, "CSNBKTR2 (Key Translate2) "
		   "returned: return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	pr_verbose(verbose, "output_token_size: %lu", output_token_size);
	if (output_token_size > (long)AESCIPHER_KEY_SIZE) {
		pr_verbose(verbose, "Output key token too large");
		return -EINVAL;
	}

	/*
	 * Check if the converted key allows export to CPACF protected key.
	 * If not, then the CCA host library or firmware code level is too low.
	 */
	cipherkey = (struct aescipherkeytoken *)buffer;
	if ((cipherkey->kmf1 & 0x0800) == 0) {
		util_print_indented("The used CCA firmware version does not "
				    "support converting a secure key that can "
				    "be used with the PAES cipher. The "
				    "required CCA firmware version is 6.3.27 "
				    "or later. For the supported environments "
				    "and updates, see: " CCA_WEB_PAGE, 0);
		return -ENOTSUP;
	}

	memset(output_key, 0, *output_key_size);
	memcpy(output_key, buffer, output_token_size);
	*output_key_size = AESCIPHER_KEY_SIZE;

	if (is_xts_key(input_key, input_key_size)) {
		input_token = input_key + AESDATA_KEY_SIZE;
		input_token_size = AESDATA_KEY_SIZE;
		output_token = buffer;
		output_token_size = sizeof(buffer);
		memset(buffer, 0, sizeof(buffer));

		memcpy(rule_array, "INTERNAL", 8);
		memcpy(rule_array + 8, "AES     ", 8);
		memcpy(rule_array + 16, "XPRTCPAC", 8);
		memcpy(rule_array + 24, "CIPHER  ", 8);
		rule_array_count = 4;

		cca->dll_CSNBKTB2(&return_code, &reason_code,
				  &exit_data_len, exit_data,
				  &rule_array_count, rule_array,
				  &zero, NULL, &zero, NULL,
				  &zero, NULL, &zero, NULL,
				  &zero, NULL,
				  &output_token_size, output_token);

		pr_verbose(verbose, "CSNBKTB2 (Key Token Build2) "
			   "returned: return_code: %ld, reason_code: %ld",
			   return_code, reason_code);
		if (return_code != 0) {
			print_CCA_error(return_code, reason_code);
			return -EIO;
		}

		memcpy(rule_array, "AES     ", 8);
		memcpy(rule_array + 8, "REFORMAT", 8);
		rule_array_count = 2;

		output_token_size = sizeof(buffer);

		cca->dll_CSNBKTR2(&return_code, &reason_code,
				  &exit_data_len, exit_data,
				  &rule_array_count, rule_array,
				  &input_token_size, input_token,
				  &null_token_len, null_token,
				  &zero, NULL,
				  &output_token_size, output_token);

		pr_verbose(verbose, "CSNBKTR2 (Key Translate2) "
			   "returned: return_code: %ld, reason_code: %ld",
			   return_code, reason_code);
		if (return_code != 0) {
			print_CCA_error(return_code, reason_code);
			return -EIO;
		}

		pr_verbose(verbose, "output_token_size: %lu",
			   output_token_size);
		if (output_token_size > (long)AESCIPHER_KEY_SIZE) {
			pr_verbose(verbose, "Output key token too large");
			return -EINVAL;
		}

		memcpy(output_key + AESCIPHER_KEY_SIZE, buffer,
		       output_token_size);
		*output_key_size += AESCIPHER_KEY_SIZE;
	}

	return 0;
}

/*
 * Restrict the exportability of an AES CIPHER key. It restricts export by means
 * of NOEX-AES, NOEX-DES, NOEX-RSA, NOEX-SYM, NOEXUASY, NOEXAASY, NOEX-RAW
 * keywords.
 * When this function is called with an AES DATA key, it does nothing and
 * returns 0. AES DATA keys can not be export restricted.
 *
 * @param[in] cca       the CCA library structure
 * @param[in] secure_key the secure key to restrict
 * @param[in] secure_key_size the size of the secure key to restrict
 * @param[in] verbose          if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error.
 */
int restrict_key_export(struct cca_lib *cca, u8 *secure_key,
			unsigned int secure_key_size, bool verbose)
{
	struct aescipherkeytoken *cipherkey =
					(struct aescipherkeytoken *)secure_key;
	long exit_data_len = 0, rule_array_count = 0;
	unsigned char rule_array[8 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;
	long token_length, zero = 0;

	util_assert(cca != NULL, "Internal error: cca is NULL");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");

	if (!is_cca_aes_cipher_key(secure_key, secure_key_size))
		return 0;

	memcpy(rule_array, "AES     ", 8);
	memcpy(rule_array + 8, "NOEX-AES", 8);
	memcpy(rule_array + 16, "NOEX-DES", 8);
	memcpy(rule_array + 24, "NOEX-RSA", 8);
	memcpy(rule_array + 32, "NOEX-SYM", 8);
	memcpy(rule_array + 40, "NOEXUASY", 8);
	memcpy(rule_array + 48, "NOEXAASY", 8);
	memcpy(rule_array + 56, "NOEX-RAW", 8);
	rule_array_count = 8;

	token_length = cipherkey->length;
	cca->dll_CSNBRKA(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &token_length, (unsigned char *)secure_key,
			 &zero, NULL, &zero, NULL, &zero, NULL);

	pr_verbose(verbose, "CSNBRKA (Restrict Key Attribute) "
		   "returned: return_code: %ld, reason_code: %ld", return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	if (is_xts_key(secure_key, secure_key_size)) {
		cipherkey = (struct aescipherkeytoken *)(secure_key +
							 AESCIPHER_KEY_SIZE);
		token_length = cipherkey->length;
		cca->dll_CSNBRKA(&return_code, &reason_code,
				 &exit_data_len, exit_data,
				 &rule_array_count, rule_array,
				 &token_length, (unsigned char *)cipherkey,
				 &zero, NULL, &zero, NULL, &zero, NULL);

		pr_verbose(verbose, "CSNBRKA (Restrict Key Attribute) "
			   "returned: return_code: %ld, reason_code: %ld",
			   return_code, reason_code);
		if (return_code != 0) {
			print_CCA_error(return_code, reason_code);
			return -EIO;
		}
	}

	return 0;
}
