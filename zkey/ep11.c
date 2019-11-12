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

#include "ep11.h"
#include "pkey.h"
#include "utils.h"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

/*
 * Definitions for the EP11 library
 */
#define EP11_LIBRARY_NAME	"libep11.so"
#define EP11_LIBRARY_VERSION	3
#define EP11_WEB_PAGE		"http://www.ibm.com/security/cryptocards"

/**
 * Returns the major and minor version of the of the used EP11 host library.
 *
 * @param[in] ep11          the EP11 library structure
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int get_ep11_version(struct ep11_lib *ep11, bool verbose)
{
	unsigned int host_version;
	CK_ULONG version_len = sizeof(host_version);
	CK_RV rc;

	rc = ep11->dll_m_get_xcp_info(&host_version, &version_len,
				      CK_IBM_XCPHQ_VERSION, 0, 0);
	if (rc != CKR_OK) {
		pr_verbose(verbose, "Failed to obtain the EP11 host library "
			   "version: m_get_xcp_info: 0x%lx", rc);
		return -EIO;
	}

	pr_verbose(verbose, "host_version: 0x%08x", host_version);

	ep11->version.major = (host_version & 0x00FF0000) >> 16;
	ep11->version.minor = host_version & 0x000000FF;
	/*
	 * EP11 host library < v2.0 returns an invalid version (i.e. 0x100).
	 * This can safely be treated as version 1.0
	 */
	if (ep11->version.major == 0) {
		ep11->version.major = 1;
		ep11->version.minor = 0;
	}

	pr_verbose(verbose, "EP11 library version: %u.%u",
		   ep11->version.major, ep11->version.minor);

	return 0;
}

/**
 * Loads the EP11 library and provides the entry points of several functions.
 *
 * @param[out] ep11          on return this contains the address of the EP11
 *                           library and certain EP11 symbols. dlclose() should
 *                           be used to free the library when no longer needed.
 * @param verbose            if true, verbose messages are printed
 *
 * @returns 0 on success, -ELIBACC in case of library load errors
 */
int load_ep11_library(struct ep11_lib *ep11, bool verbose)
{
	char lib_name[256];
	int libver;
	int rc;

	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");

	/* Load the EP11 library with highest available version'd SO name */
	for (libver = EP11_LIBRARY_VERSION; libver >= 0; libver--) {
		if (libver > 0)
			sprintf(lib_name, "%s.%d", EP11_LIBRARY_NAME, libver);
		else
			sprintf(lib_name, "%s", EP11_LIBRARY_NAME);

		ep11->lib_ep11 = dlopen(lib_name, RTLD_GLOBAL | RTLD_NOW);
		if (ep11->lib_ep11 != NULL)
			break;
	}
	if (ep11->lib_ep11 == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		warnx("The command requires the IBM Z Enterprise PKCS #11 "
		      "(EP11) Support Program (EP11 host library).\n"
		      "For the supported environments and downloads, see:\n%s",
		      EP11_WEB_PAGE);
		return  -ELIBACC;
	}

	/* Get several EP11 host library functions */
	ep11->dll_m_init = (m_init_t)dlsym(ep11->lib_ep11, "m_init");
	ep11->dll_m_add_module = (m_add_module_t)dlsym(ep11->lib_ep11,
						       "m_add_module");
	ep11->dll_m_rm_module = (m_rm_module_t)dlsym(ep11->lib_ep11,
						     "m_rm_module");
	ep11->dll_m_get_xcp_info = (m_get_xcp_info_t)dlsym(ep11->lib_ep11,
							   "m_get_xcp_info");

	/* dll_m_add_module and dll_m_rm_module may be NULL for V1 EP11 lib */
	if (ep11->dll_m_init == NULL ||
	    ep11->dll_m_get_xcp_info == NULL) {
		pr_verbose(verbose, "%s", dlerror());
		warnx("The command requires the IBM Z Enterprise PKCS #11 "
		      "(EP11) Support Program (EP11 host library).\n"
		      "For the supported environments and downloads, see:\n%s",
		      EP11_WEB_PAGE);
		dlclose(ep11->lib_ep11);
		ep11->lib_ep11 = NULL;
		return -ELIBACC;
	}

	/* Initialize the EP11 library */
	rc = ep11->dll_m_init();
	if (rc != 0) {
		pr_verbose(verbose, "Failed to initialize the EP11 host "
			   "library: m_init: 0x%x", rc);
		dlclose(ep11->lib_ep11);
		ep11->lib_ep11 = NULL;
		return -ELIBACC;
	}

	pr_verbose(verbose, "EP11 library '%s' has been loaded successfully",
			   lib_name);

	return get_ep11_version(ep11, verbose);
}

/**
 * Get an EP11 target handle for a specific APQN (card and domain)
 *
 * @param[in] ep11          the EP11 library structure
 * @param[in] card          the card number
 * @param[in] domain        the domain number
 * @param[out] target       on return: the target handle for the APQN
 * @param verbose            if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of errors
 */
int get_ep11_target_for_apqn(struct ep11_lib *ep11, int card, int domain,
			     target_t *target, bool verbose)
{
	ep11_target_t *target_list;
	struct XCP_Module module;
	CK_RV rc;

	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");
	util_assert(target != NULL, "Internal error: target is NULL");

	*target = XCP_TGT_INIT;

	if (ep11->dll_m_add_module != NULL) {
		memset(&module, 0, sizeof(module));
		module.version = ep11->version.major >= 3 ? XCP_MOD_VERSION_2
							  : XCP_MOD_VERSION_1;
		module.flags = XCP_MFL_MODULE;
		module.module_nr = card;
		XCPTGTMASK_SET_DOM(module.domainmask, domain);
		rc = ep11->dll_m_add_module(&module, target);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to add APQN %02x.%04x: "
				   "m_add_module rc=0x%lx", card, domain, rc);
			return -EIO;
		}
	} else {
		/* Fall back to old target handling */
		target_list = (ep11_target_t *)calloc(1, sizeof(ep11_target_t));
		if (target_list == NULL)
			return -ENOMEM;
		target_list->length = 1;
		target_list->apqns[0] = card;
		target_list->apqns[1] = domain;
		*target = (target_t)target_list;
	}

	return 0;
}

/**
 * Free an EP11 target handle
 *
 * @param[in] ep11          the EP11 library structure
 * @param[in] target        the target handle to free
 *
 * @returns 0 on success, a negative errno in case of errors
 */
void free_ep11_target_for_apqn(struct ep11_lib *ep11, target_t target)
{
	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");

	if (ep11->dll_m_rm_module != NULL) {
		ep11->dll_m_rm_module(NULL, target);
	} else {
		/*
		 * With the old target handling, target is a pointer to
		 * ep11_target_t
		 */
		free((ep11_target_t *)target);
	}
}

struct find_mkvp_info {
	u8		mkvp[MKVP_LENGTH];
	unsigned int	flags;
	bool		found;
	int		card;
	int		domain;
	bool		verbose;
};

static int find_mkvp(int card, int domain, void *handler_data)
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

	if (info->flags & FLAG_SEL_EP11_MATCH_CUR_MKVP)
		if (mk_info.cur_mk.mk_state == MK_STATE_VALID &&
		    MKVP_EQ(mk_info.cur_mk.mkvp, info->mkvp))
			found = true;

	if (info->flags & FLAG_SEL_EP11_NEW_MUST_BE_SET)
		if (mk_info.new_mk.mk_state != MK_STATE_COMMITTED)
			found = false;

	if (found) {
		info->card = card;
		info->domain = domain;
		info->found = true;

		pr_verbose(info->verbose, "%02x.%04x has the desired mkvp%s",
			   card, domain,
			   info->flags & FLAG_SEL_EP11_NEW_MUST_BE_SET ?
			   " and NEW MK set" : "");

		return 1;
	}

	return 0;
}

/**
 * Selects an APQN to be used for the Ep11 host library that has the specified
 * master key verification pattern
 *
 * @param[in] ep11      the EP11 library structure
 * @param[in] mkvp      the master key verification pattern to search for
 * @param[in] apqns     a comma separated list of APQNs. If NULL is specified,
 *                      or an empty string, then all online EP11 APQNs are
 *                      checked.
 * @param[in] flags     Flags that control the MKVM matching and NEW register
 *                      checking. Multiple flags can be combined.
 * @param[out] target   on return: the target handle for the APQN. If this is
 *                      NULL, then no target is built.
 * @param[out] card     on return: the card that was selected (can be NULL)
 * @param[out] domain   on return: the domain that was selected (can be NULL)
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of errors
 */
int select_ep11_apqn_by_mkvp(struct ep11_lib *ep11, u8 *mkvp,
			     const char *apqns,  unsigned int flags,
			     target_t *target, int *card, int *domain,
			     bool verbose)
{
	struct find_mkvp_info info;
	int rc;

	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");
	util_assert(mkvp != NULL, "Internal error: mkvp is NULL");

	pr_verbose(verbose, "Select mkvp %s in APQNs %s for the EP11 host "
		   "library", printable_mkvp(CARD_TYPE_EP11, mkvp),
		   apqns == 0 ? "ANY" : apqns);

	memcpy(info.mkvp, mkvp, sizeof(info.mkvp));
	info.flags = flags;
	info.found = false;
	info.card = 0;
	info.domain = 0;
	info.verbose = verbose;

	rc = handle_apqns(apqns, CARD_TYPE_EP11, find_mkvp, &info, verbose);
	if (rc < 0)
		return rc;

	if (!info.found)
		return -ENODEV;

	if (target != NULL) {
		rc = get_ep11_target_for_apqn(ep11, info.card, info.domain,
					      target, verbose);
		if (rc != 0)
			return rc;
	}

	if (card != NULL)
		*card = info.card;
	if (domain != NULL)
		*domain = info.domain;

	return 0;
}
