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
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_panic.h"

#include "cca.h"
#include "pkey.h"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

/*
 * Definitions for the CCA library
 */
#define CCA_LIBRARY_NAME	"libcsulcca.so"
#define CCA_WEB_PAGE		"http://www.ibm.com/security/cryptocards"

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

	if (cca->dll_CSUACFV == NULL ||
	    cca->dll_CSNBKTC == NULL) {
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
	long exit_data_len = 0, rule_array_count;
	unsigned char rule_array[2 * 8] = { 0, };
	unsigned char exit_data[4] = { 0, };
	long return_code, reason_code;

	util_assert(cca != NULL, "Internal error: cca is NULL");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");
	util_assert(secure_key_size > 0,
		    "Internal error: secure_key_size is 0");
	util_assert(method != NULL, "Internal error: method is NULL");

	memcpy(rule_array, method, 8);
	memcpy(rule_array + 8, "AES     ", 8);
	rule_array_count = 2;

	cca->dll_CSNBKTC(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 secure_key);

	pr_verbose(verbose, "CSNBKTC (Key Token Change) with '%s' returned: "
		   "return_code: %ld, reason_code: %ld", method, return_code,
		   reason_code);
	if (return_code != 0) {
		print_CCA_error(return_code, reason_code);
		return -EIO;
	}

	if (secure_key_size == 2 * SECURE_KEY_SIZE) {
		cca->dll_CSNBKTC(&return_code, &reason_code,
				 &exit_data_len, exit_data,
				 &rule_array_count, rule_array,
				 secure_key + SECURE_KEY_SIZE);

		pr_verbose(verbose, "CSNBKTC (Key Token Change) with '%s' "
			   "returned: return_code: %ld, reason_code: %ld",
			   method, return_code, reason_code);
		if (return_code != 0) {
			print_CCA_error(return_code, reason_code);
			return -EIO;
		}
	}
	return 0;
}
