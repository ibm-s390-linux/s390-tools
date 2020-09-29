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

	ep11->dll_m_admin = (m_admin_t)dlsym(ep11->lib_ep11, "m_admin");
	ep11->dll_xcpa_cmdblock = (xcpa_cmdblock_t)dlsym(ep11->lib_ep11,
							 "xcpa_cmdblock");
	if (ep11->dll_xcpa_cmdblock == NULL)
		ep11->dll_xcpa_cmdblock = (xcpa_cmdblock_t)dlsym(ep11->lib_ep11,
							"ep11a_cmdblock");
	ep11->dll_xcpa_internal_rv = (xcpa_internal_rv_t)dlsym(ep11->lib_ep11,
							"xcpa_internal_rv");
	if (ep11->dll_xcpa_internal_rv == NULL)
		ep11->dll_xcpa_internal_rv =
				(xcpa_internal_rv_t)dlsym(ep11->lib_ep11,
							  "ep11a_internal_rv");

	/* dll_m_add_module and dll_m_rm_module may be NULL for V1 EP11 lib */
	if (ep11->dll_m_init == NULL ||
	    ep11->dll_m_get_xcp_info == NULL ||
	    ep11->dll_m_admin == NULL ||
	    ep11->dll_xcpa_cmdblock == NULL ||
	    ep11->dll_xcpa_internal_rv == NULL) {
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
int get_ep11_target_for_apqn(struct ep11_lib *ep11, unsigned int card,
		             unsigned int domain, target_t *target,
			     bool verbose)
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
			     target_t *target, unsigned int *card,
			     unsigned int *domain, bool verbose)
{
	struct find_mkvp_info info;
	int rc;

	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");
	util_assert(mkvp != NULL, "Internal error: mkvp is NULL");

	pr_verbose(verbose, "Select mkvp %s in APQNs %s for the EP11 host "
		   "library", printable_mkvp(CARD_TYPE_EP11, mkvp),
		   apqns == NULL ? "ANY" : apqns);

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

/**
 * Performs an EP11 administrative request to Re-encrypt a single EP11 secure
 * key with a new EP11 master key (wrapping key).
 *
 * @param[in] ep11      the EP11 library structure
 * @param[in] target    the target handle to use for the re-encipher operation
 * @param[in] card      the card that corresponds to the target handle
 * @param[in] domain    the domain that corresponds to the target handle
 * @param[in/out] ep11key the EP11 key token to reencipher. The re-enciphered
 *                      secure key will be returned in this buffer.
 * @param[in] ep11key_size the size of the secure key
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of errors
 */
static int ep11_adm_reencrypt(struct ep11_lib *ep11, target_t target,
			      unsigned int card, unsigned int domain,
			      struct ep11keytoken *ep11key,
			      unsigned int ep11key_size, bool verbose)
{
	CK_BYTE resp[MAX_BLOBSIZE];
	CK_BYTE req[MAX_BLOBSIZE];
	char ep11_token_header[sizeof(ep11key->head)];
	struct XCPadmresp lrb;
	struct XCPadmresp rb;
	size_t resp_len;
	size_t blob_len;
	long req_len;
	CK_RV rv;
	int rc;

	blob_len = ep11key->head.length;
	if (blob_len > ep11key_size) {
		pr_verbose(verbose, "Blob length larger than secure key size");
		return -EINVAL;
	}

	rb.domain = domain;
	lrb.domain = domain;

	/* The token header is an overlay over the (all zero) session field */
	memcpy(ep11_token_header, ep11key, sizeof(ep11_token_header));
	memset(ep11key->session, 0, sizeof(ep11key->session));

	resp_len = sizeof(resp);
	req_len = ep11->dll_xcpa_cmdblock(req, sizeof(req), XCP_ADM_REENCRYPT,
					  &rb, NULL, (unsigned char *)ep11key,
					  blob_len);
	if (req_len < 0) {
		pr_verbose(verbose, "Failed to build XCP command block");
		return -EIO;
	}

	rv = ep11->dll_m_admin(resp, &resp_len, NULL, NULL, req, req_len, NULL,
			       0, target);
	if (rv != CKR_OK || resp_len == 0) {
		pr_verbose(verbose, "Command XCP_ADM_REENCRYPT failed. "
			   "rc = 0x%lx, resp_len = %ld", rv, resp_len);
		return -EIO;
	}

	rc = ep11->dll_xcpa_internal_rv(resp, resp_len, &lrb, &rv);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to parse response. rc = %d", rc);
		return -EIO;
	}

	if (rv != CKR_OK) {
		pr_verbose(verbose, "Failed to re-encrypt the EP11 secure key. "
			   "rc = 0x%lx", rv);
		switch (rv) {
		case CKR_IBM_WKID_MISMATCH:
			warnx("The EP11 secure key is currently encrypted "
			      "under a different master that does not match "
			      "the master key in the CURRENT master key "
			      "register of APQN %02X.%04X", card, domain);
			break;
		}
		return -EIO;
	}

	if (blob_len != lrb.pllen) {
		pr_verbose(verbose, "Re-encrypted EP11 secure key size has "
			   "changed: org-len: %lu, new-len: %lu", blob_len,
			   lrb.pllen);
		return -EIO;
	}

	memcpy(ep11key, lrb.payload, blob_len);
	memcpy(ep11key, ep11_token_header, sizeof(ep11_token_header));

	return 0;
}

/**
 * Re-encipher an EP11 secure key with a new EP11 master key (wrapping key).
 *
 * @param[in] ep11      the EP11 library structure
 * @param[in] target    the target handle to use for the re-encipher operation
 * @param[in] card      the card that corresponds to the target handle
 * @param[in] domain    the domain that corresponds to the target handle
 * @param[in/out] secure_key the EP11 key token to reencipher. The re-enciphered
 *                      secure key will be returned in this buffer.
 * @param[in] secure_key_size the size of the secure key
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of errors
 */
int reencipher_ep11_key(struct ep11_lib *ep11, target_t target,
			unsigned int card, unsigned int domain, u8 *secure_key,
			unsigned int secure_key_size, bool verbose)
{
	struct ep11keytoken *ep11key = (struct ep11keytoken *)secure_key;
	CK_IBM_DOMAIN_INFO dinf;
	CK_ULONG dinf_len = sizeof(dinf);
	CK_RV rv;
	int rc;

	util_assert(ep11 != NULL, "Internal error: ep11 is NULL");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");

	rv = ep11->dll_m_get_xcp_info(&dinf, &dinf_len, CK_IBM_XCPQ_DOMAIN, 0,
				      target);
	if (rv != CKR_OK) {
		pr_verbose(verbose, "Failed to query domain information for "
			   "%02X.%04X: m_get_xcp_info rc: 0x%lx", card, domain,
			   rv);
		return -EIO;
	}

	if ((dinf.flags & CK_IBM_DOM_COMMITTED_NWK) == 0) {
		warnx("The NEW master key register of APQN %02X.%04X is not "
		      "in COMMITTED state", card, domain);
		return -ENODEV;
	}

	rc = ep11_adm_reencrypt(ep11, target, card, domain, ep11key,
				secure_key_size, verbose);
	if (rc != 0)
		return rc;

	if (is_xts_key(secure_key, secure_key_size)) {
		secure_key += EP11_KEY_SIZE;
		secure_key_size -= EP11_KEY_SIZE;
		ep11key = (struct ep11keytoken *)secure_key;

		rc = ep11_adm_reencrypt(ep11, target, card, domain, ep11key,
					secure_key_size, verbose);
		if (rc != 0)
			return rc;
	}

	return 0;
}

