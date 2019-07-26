/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"

#include "pkey.h"

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

#define DOUBLE_KEYSIZE_FOR_XTS(keysize, xts) ((xts) ? 2 * (keysize) : (keysize))
#define HALF_KEYSIZE_FOR_XTS(keysize, xts)   ((xts) ? (keysize) / 2 : (keysize))

#define MAX_CIPHER_LEN		32

#define DEFAULT_KEYBITS		256

#define INITIAL_APQN_ENTRIES	16

/**
 * Opens the pkey device and returns its file descriptor.
 *
 * @param verbose            if true, verbose messages are printed
 *
 * @returns the file descriptor or -1 to indicate an error
 */
int open_pkey_device(bool verbose)
{
	int pkey_fd;

	pkey_fd = open(PKEYDEVICE, O_RDWR);
	if (pkey_fd < 0) {
		warnx("File '%s:' %s\nEnsure that the 'pkey' kernel module "
		      "is loaded", PKEYDEVICE, strerror(errno));
		return -1;
	}

	pr_verbose(verbose, "Device '%s' has been opened successfully",
		   PKEYDEVICE);
	return pkey_fd;
}

/**
 * Read a secure key file and return the allocated buffer and size.
 *
 * @param[in]  keyfile     the name of the file to read
 * @param[out] secure_key_size  on return, the size of the secure key read
 * @param[in]  verbose     if true, verbose messages are printed
 *
 * @return a buffer containing the secure key, or NULL in case of an error.
 *         The returned buffer must be freed by the caller.
 */
u8 *read_secure_key(const char *keyfile, size_t *secure_key_size,
		    bool verbose)
{
	size_t count, size;
	struct stat sb;
	char *msg;
	FILE *fp;
	u8 *buf;

	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(secure_key_size != NULL,
		    "Internal error: secure_key_size is NULL");

	if (stat(keyfile, &sb)) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return NULL;
	}
	size = sb.st_size;

	if (size < MIN_SECURE_KEY_SIZE || size > 2 * MAX_SECURE_KEY_SIZE) {
		warnx("File '%s' has an invalid size: %lu", keyfile, size);
		return NULL;
	}

	fp = fopen(keyfile, "r");
	if (fp == NULL) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return NULL;
	}

	buf = util_malloc(size);
	count = fread(buf, 1, size, fp);
	if (count != size) {
		msg = ferror(fp) ? strerror(errno) : "File is too small";
		warnx("File '%s': %s", keyfile, msg);
		free(buf);
		buf = NULL;
		goto out;
	}

	*secure_key_size = size;

	if (verbose) {
		pr_verbose(verbose, "%lu bytes read from file '%s'", size,
			   keyfile);
		util_hexdump_grp(stderr, NULL, buf, 4, size, 0);
	}
out:
	fclose(fp);
	return buf;
}

/**
 * Write a secure key file
 *
 * @param[in] keyfile     the name of the file to write
 * @param[in] secure_key  a buffer containing the secure key
 * @param[in] secure_key_size the size of the secure key
 * @param[in]  verbose     if true, verbose messages are printed
 *
 * @returns 0 in case of success, -EIO in case of an error
 */
int write_secure_key(const char *keyfile, const u8 *secure_key,
		     size_t secure_key_size, bool verbose)
{
	size_t count;
	FILE *fp;

	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");
	util_assert(secure_key_size > 0,
		    "Internal error: secure_key_size is zero");

	fp = fopen(keyfile, "w");
	if (fp == NULL) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return -EIO;
	}

	count = fwrite(secure_key, 1, secure_key_size, fp);
	if (count != secure_key_size) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		fclose(fp);
		return -EIO;
	}

	if (verbose) {
		pr_verbose(verbose, "%lu bytes written to file '%s'",
			   secure_key_size, keyfile);
		util_hexdump_grp(stderr, NULL, secure_key, 4,
				 secure_key_size, 0);
	}
	fclose(fp);
	return 0;
}

/**
 * Read a clear key file and return the allocated buffer and size
 *
 * @param[in]  keyfile     the name of the file to read
 * @param[in]  keybits     the clear key size in bits. When keybits is 0, then
 *                         the file size determines the keybits.
 * @param[in]  xts         if true an XTS key is to be read
 * @param[out] clear_key_size  on return, the size of the clear key read
 * @param[in]  verbose     if true, verbose messages are printed
 *
 * @return a buffer containing the clear key, or NULL in case of an error.
 *         The returned buffer must be freed by the caller.
 */
static u8 *read_clear_key(const char *keyfile, size_t keybits, bool xts,
			  size_t *clear_key_size, bool verbose)
{
	size_t count, size, expected_size;
	struct stat sb;
	char *msg;
	FILE *fp;
	u8 *buf;

	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(clear_key_size != NULL,
		    "Internal error: clear_key_size is NULL");

	if (stat(keyfile, &sb)) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return NULL;
	}
	size = sb.st_size;

	if (keybits != 0) {
		expected_size = DOUBLE_KEYSIZE_FOR_XTS(keybits / 8, xts);
		if (size != expected_size) {
			warnx("File '%s' has an invalid size, "
			      "%lu bytes expected", keyfile, expected_size);
			return NULL;
		}
	} else {
		keybits = HALF_KEYSIZE_FOR_XTS(size * 8, xts);
	}

	switch (keybits) {
	case 128:
		break;
	case 192:
		if (xts) {
			warnx("File '%s' has an invalid size, "
			      "192 bit keys are not supported with XTS",
			      keyfile);
			return NULL;
		}
		break;
	case 256:
		break;
	default:
		if (xts)
			warnx("File '%s' has an invalid size, "
			      "32 or 64 bytes expected", keyfile);
		else
			warnx("File '%s' has an invalid size, 16, 24 "
			      "or 32 bytes expected", keyfile);
		return NULL;
	}

	fp = fopen(keyfile, "r");
	if (fp == NULL) {
		warnx("File '%s': %s", keyfile, strerror(errno));
		return NULL;
	}

	buf = util_malloc(size);
	count = fread(buf, 1, size, fp);
	if (count != size) {
		msg = ferror(fp) ? strerror(errno) : "File is too small";
		warnx("File '%s': %s", keyfile, msg);
		free(buf);
		buf = NULL;
		goto out;
	}

	*clear_key_size = size;

	if (verbose) {
		pr_verbose(verbose, "%lu bytes read from file '%s'", size,
			   keyfile);
		util_hexdump_grp(stderr, NULL, buf, 4, size, 0);
	}
out:
	fclose(fp);
	return buf;
}

/**
 * Returns the PKEY_KEYTYPE_xxx value for the specified key size.
 *
 * @param[in] keysize      the key size in bits
 *
 * @returns the PKEY_KEYTYPE_xxx value or 0 for an unknown key size
 */
static u32 keysize_to_keytype(enum pkey_key_size keysize)
{
	switch (keysize) {
	case PKEY_SIZE_AES_128:
		return PKEY_KEYTYPE_AES_128;
	case PKEY_SIZE_AES_192:
		return PKEY_KEYTYPE_AES_192;
	case PKEY_SIZE_AES_256:
		return PKEY_KEYTYPE_AES_256;
	default:
		return 0;
	}
}

/**
 * Returns the PKEY_SIZE_xxx value for the specified keybits.
 *
 * @param[in] keybits      the key size in bits
 *
 * @returns thePKEY_SIZE_xxx value or 0 for an unknown key size
 */
static enum pkey_key_size keybits_to_keysize(u32 keybits)
{
	switch (keybits) {
	case 128:
		return PKEY_SIZE_AES_128;
	case 192:
		return PKEY_SIZE_AES_192;
	case 256:
		return PKEY_SIZE_AES_256;
	default:
		return PKEY_SIZE_UNKNOWN;
	}
}

/*
 * Wrapper for the PKEY_GENSECK/PKEY_GENSECK2 IOCTL to generate a secure
 * key of any type by random. If the newer PKEY_GENSECK2 IOCTL is not supported
 * by the pkey device, then it falls back to the older PKEY_GENSECK IOCTL
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in/out] genseck   info about key to generate
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int pkey_genseck2(int pkey_fd, struct pkey_genseck2 *genseck2,
			 bool verbose)
{
	struct pkey_genseck genseck;
	int rc;
	u32 i;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(genseck2 != NULL, "Internal error: genseck2 is NULL");

	rc = ioctl(pkey_fd, PKEY_GENSECK2, genseck2);
	if (rc != 0 && errno != ENOTTY)
		return -errno;
	if (rc == 0)
		return 0;

	/* New IOCTL is not available, fall back to old one */
	pr_verbose(verbose, "ioctl PKEY_GENSECK2 not supported, fall back to "
		   "PKEY_GENSECK");

	if (genseck2->type != PKEY_TYPE_CCA_DATA) {
		warnx("Key-type is not supported");
		return -ENOTSUP;
	}

	if (genseck2->keylen < AESDATA_KEY_SIZE)
		return -EINVAL;

	memset(&genseck, 0, sizeof(genseck));

	genseck.keytype = keysize_to_keytype(genseck2->size);
	if (genseck.keytype == 0)
		return -EINVAL;

	for (i = 0; i < genseck2->apqn_entries; i++) {
		genseck.cardnr = genseck2->apqns[i].card;
		genseck.domain = genseck2->apqns[i].domain;

		rc = ioctl(pkey_fd, PKEY_GENSECK, &genseck);
		if (rc != 0)
			continue;

		memcpy(genseck2->key, &genseck.seckey.seckey, AESDATA_KEY_SIZE);
		genseck2->keylen = AESDATA_KEY_SIZE;
		return 0;
	}

	return -errno;
}

/*
 * Wrapper for the PKEY_CLR2SECK/PKEY_CLR2SECK2 IOCTL to generate a secure
 * key of any type from a clear key. If the newer PKEY_CLR2SECK2 IOCTL is not
 * supported by the pkey device, then it falls back to the older PKEY_CLR2SECK
 * IOCTL
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in/out] clr2seck2 info about key to generate
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int pkey_clr2seck2(int pkey_fd, struct pkey_clr2seck2 *clr2seck2,
			  bool verbose)
{
	struct pkey_clr2seck clr2seck;
	int rc;
	u32 i;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(clr2seck2 != NULL, "Internal error: clr2seck2 is NULL");

	rc = ioctl(pkey_fd, PKEY_CLR2SECK2, clr2seck2);
	if (rc != 0 && errno != ENOTTY)
		return -errno;
	if (rc == 0)
		return 0;

	/* New IOCTL is not available, fall back to old one */
	pr_verbose(verbose, "ioctl PKEY_CLR2SECK2 not supported, fall back to "
			   "PKEY_CLR2SECK");

	if (clr2seck2->type != PKEY_TYPE_CCA_DATA) {
		warnx("Key-type is not supported");
		return -ENOTSUP;
	}

	if (clr2seck2->keylen < AESDATA_KEY_SIZE)
		return -EINVAL;

	memset(&clr2seck, 0, sizeof(clr2seck));
	clr2seck.clrkey = clr2seck2->clrkey;

	clr2seck.keytype = keysize_to_keytype(clr2seck2->size);
	if (clr2seck.keytype == 0)
		return -EINVAL;

	for (i = 0; i < clr2seck2->apqn_entries; i++) {
		clr2seck.cardnr = clr2seck2->apqns[i].card;
		clr2seck.domain = clr2seck2->apqns[i].domain;

		rc = ioctl(pkey_fd, PKEY_CLR2SECK, &clr2seck);
		if (rc != 0)
			continue;

		memcpy(clr2seck2->key, &clr2seck.seckey.seckey,
		       AESDATA_KEY_SIZE);
		clr2seck2->keylen = AESDATA_KEY_SIZE;
		return 0;
	}

	return -errno;
}

/*
 * Wrapper for the PKEY_VERIFYKEY/PKEY_VERIFYKEY2 IOCTL to verify a secure
 * key of any type. If the newer PKEY_VERIFYKEY2 IOCTL is not supported
 * by the pkey device, then it falls back to the older PKEY_VERIFYKEY IOCTL
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in/out] verifykey2   info about key to verify
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int pkey_verifyseck2(int pkey_fd, struct pkey_verifykey2 *verifykey2,
			    bool verbose)
{
	struct pkey_verifykey verifykey;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(verifykey2 != NULL, "Internal error: verifyseck2 is NULL");

	rc = ioctl(pkey_fd, PKEY_VERIFYKEY2, verifykey2);
	if (rc != 0 && errno != ENOTTY)
		return -errno;
	if (rc == 0)
		return 0;

	/* New IOCTL is not available, fall back to old one */
	pr_verbose(verbose, "ioctl PKEY_VERIFYKEY2 not supported, fall back to "
			   "PKEY_VERIFYKEY");

	if (!is_cca_aes_data_key(verifykey2->key, verifykey2->keylen))
		return -ENODEV;

	memset(&verifykey, 0, sizeof(verifykey));
	memcpy(&verifykey.seckey, verifykey2->key, sizeof(verifykey.seckey));

	/*
	 * Note: the old IOCTL does not support to check a specific card and
	 * domain. If falling back to the old IOCTL, this input is silently
	 * ignored, and all APQNs currently available in the system are used.
	 */
	rc = ioctl(pkey_fd, PKEY_VERIFYKEY, &verifykey);
	if (rc != 0)
		return -errno;

	if ((verifykey.attributes & PKEY_VERIFY_ATTR_AES) == 0)
		return -ENODEV;

	verifykey2->type = PKEY_TYPE_CCA_DATA;
	verifykey2->cardnr = verifykey.cardnr;
	verifykey2->domain = verifykey.domain;
	verifykey2->size = keybits_to_keysize(verifykey.keysize);

	if (verifykey.attributes & PKEY_VERIFY_ATTR_OLD_MKVP)
		verifykey2->flags = PKEY_FLAGS_MATCH_ALT_MKVP;
	else
		verifykey2->flags = PKEY_FLAGS_MATCH_CUR_MKVP;

	return 0;
}

/**
 * Print a list of APQNs if verbose is set
 */
static void pr_verbose_apqn_list(bool verbose, struct pkey_apqn *list, u32 num)
{
	u32 i;

	if (!verbose)
		return;

	for (i = 0; i < num ; i++)
		warnx("  APQN: %02x.%04x", list[i].card, list[i].domain);
}

/**
 * Filter a n array list of APQNs (struct pkey_apqn) by a list of APQN strings.
 *
 * @param[in] apqn_list     a zero terminated array of pointers to C-strings
 * @param[in/out] apqns     A list of APQNs as array of struct pkey_apqn to
 *                          filter. The list is modified during filtering.
 * @param[in/out] apqn_entries Number of entries in the list of APQNs. The
 *                          number is modified during filtering.
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int filter_apqn_list(const char **apqn_list, struct pkey_apqn **apqns,
			    u32 *apqn_entries)
{
	unsigned int count, i, k, card, domain;
	struct pkey_apqn *list = *apqns;
	bool found;

	if (apqn_list == NULL)
		return 0;

	for (count = 0; apqn_list[count] != NULL; count++)
		;
	if (count == 0)
		return 0;

	for (i = 0; i < *apqn_entries; i++) {
		found = false;
		for (k = 0; apqn_list[k] != NULL; k++) {
			if (sscanf(apqn_list[k], "%x.%x", &card, &domain) != 2)
				return -EINVAL;

			if (list[i].card == card && list[i].domain == domain) {
				found = true;
				break;
			}
		}

		if (!found) {
			if (i < *apqn_entries - 1)
				memmove(&list[i], &list[i+1],
					(*apqn_entries - i - 1) *
						sizeof(struct pkey_apqn));
			(*apqn_entries)--;
			i--;
		}
	}

	return 0;
}

/**
 * Build a list of APQNs in the form accepted by the pkey IOCTLs from the
 * List of APQNs as zero terminated array of pointers to C-strings that
 * are usable for the CCA-AESDATA key type.
 *
 * @param[in] apqn_list     a zero terminated array of pointers to C-strings
 * @param[out] apqns        A list of APQNs as array of struct pkey_apqn. The
 *                          list must be freed by the caller using free().
 * @param[out] apqn_entries Number of entries in the list of APQNs
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int build_apqn_list_for_aes_data(const char **apqn_list,
					struct pkey_apqn **apqns,
					u32 *apqn_entries, bool verbose)
{
	unsigned int card, domain, count = 0;
	struct pkey_apqn *list = NULL;
	u32 list_entries = 0;
	int i;

	pr_verbose(verbose, "Build a list of APQNs for CCA-AESDATA");

	if (apqn_list != NULL)
		for (count = 0; apqn_list[count] != NULL; count++)
			;

	if (count > 0) {
		list = util_malloc(count * sizeof(struct pkey_apqn));
		list_entries = count;

		for (i = 0; apqn_list[i] != NULL; i++) {
			if (sscanf(apqn_list[i], "%x.%x", &card, &domain) != 2)
				return -EINVAL;

			list[i].card = card;
			list[i].domain = domain;
		}

	} else {
		/*
		 * Although the new pkey IOCTLs do not support APQN entries
		 * with ANY indication, build an ANY-list here. If we get here,
		 * then the new IOCTLs are not available, and it will fall back
		 * to the old IOCTL which do support ANY specifications.
		 */
		list = util_malloc(sizeof(struct pkey_apqn));
		list_entries = 1;

		list[0].card = AUTOSELECT;
		list[0].domain = AUTOSELECT;
	}

	*apqns = list;
	*apqn_entries = list_entries;

	pr_verbose(verbose, "%u APQNs found", list_entries);
	pr_verbose_apqn_list(verbose, list, list_entries);
	return 0;
}

/**
 * Build a list of APQNs in the form accepted by the pkey IOCTLs from the
 * List of APQNs as zero terminated array of pointers to C-strings that
 * are usable for the specified key type.
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] type          the key type
 * @param[in] apqn_list     a zero terminated array of pointers to C-strings
 * @param[out] apqns        A list of APQNs as array of struct pkey_apqn. The
 *                          list must be freed by the caller using free().
 * @param[out] apqn_entries Number of entries in the list of APQNs
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int build_apqn_list_for_key_type(int pkey_fd, enum pkey_key_type type,
					const char **apqn_list,
					struct pkey_apqn **apqns,
					u32 *apqn_entries, bool verbose)
{
	struct pkey_apqns4keytype apqns4keytype;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(apqns != NULL, "Internal error: apqns is NULL");
	util_assert(apqn_entries != NULL,
		    "Internal error: apqn_entries is NULL");

	pr_verbose(verbose, "Build a list of APQNs for key type %d", type);

	memset(&apqns4keytype, 0, sizeof(apqns4keytype));
	apqns4keytype.type = type;
	apqns4keytype.apqn_entries = INITIAL_APQN_ENTRIES;
	apqns4keytype.apqns = (struct pkey_apqn *)util_malloc(
			apqns4keytype.apqn_entries * sizeof(struct pkey_apqn));

	do {
		rc = ioctl(pkey_fd, PKEY_APQNS4KT, &apqns4keytype);
		if (rc == 0)
			break;
		rc = -errno;
		pr_verbose(verbose, "ioctl PKEY_APQNS4KT rc: %s",
			   strerror(-rc));

		switch (rc) {
		case -ENOSPC:
			free(apqns4keytype.apqns);
			apqns4keytype.apqns = (struct pkey_apqn *)
				util_malloc(apqns4keytype.apqn_entries *
						sizeof(struct pkey_apqn));
			continue;
		case -ENOTTY:
			/*
			 * New IOCTL is not available: build the list
			 * manually (Key type CCA-AESDATA only)
			 */
			free(apqns4keytype.apqns);

			if (type != PKEY_TYPE_CCA_DATA)
				return -ENOTSUP;

			rc = build_apqn_list_for_aes_data(apqn_list, apqns,
							  apqn_entries,
							  verbose);
			return rc;
		default:
			goto out;
		}
	} while (rc != 0);

	if (apqns4keytype.apqn_entries == 0) {
		pr_verbose(verbose, "No APQN available for key type %d", type);
		rc = -ENODEV;
		goto out;
	}

	rc = filter_apqn_list(apqn_list, &apqns4keytype.apqns,
			      &apqns4keytype.apqn_entries);
	if (rc != 0)
		goto out;

	if (apqns4keytype.apqn_entries == 0) {
		pr_verbose(verbose, "No APQN available for key type %d", type);
		rc = -ENODEV;
		goto out;
	}

	pr_verbose(verbose, "%u APQNs found", apqns4keytype.apqn_entries);
	pr_verbose_apqn_list(verbose, apqns4keytype.apqns,
			     apqns4keytype.apqn_entries);

out:
	if (rc == 0) {
		*apqns = apqns4keytype.apqns;
		*apqn_entries = apqns4keytype.apqn_entries;
	} else {
		*apqns = NULL;
		*apqn_entries = 0;
		free(apqns4keytype.apqns);
	}

	return rc;
}

/**
 * Build a list of APQNs in the form accepted by the pkey IOCTLs from the
 * List of APQNs as zero terminated array of pointers to C-strings that are
 * usable for the specufied key.
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] key           the key
 * @param[in] keylen        the length of the key
 * @param[in] flags         PKEY_FLAGS_MATCH_xxx flags
 * @param[in] apqn_list     a zero terminated array of pointers to C-strings
 * @param[out] apqns        A list of APQNs as array of struct pkey_apqn. The
 *                          list must be freed by the caller using free().
 * @param[out] apqn_entries Number of  entries in the list of APQNs
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int build_apqn_list_for_key(int pkey_fd, u8 *key, u32 keylen, u32 flags,
				   const char **apqn_list,
				   struct pkey_apqn **apqns,
				   u32 *apqn_entries, bool verbose)
{
	struct pkey_apqns4key apqns4key;
	u64 mkvp;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(key != NULL, "Internal error: key is NULL");
	util_assert(apqns != NULL, "Internal error: apqns is NULL");
	util_assert(apqn_entries != NULL,
		    "Internal error: apqn_entries is NULL");

	pr_verbose(verbose, "Build a list of APQNs for the key");

	memset(&apqns4key, 0, sizeof(apqns4key));
	apqns4key.key = key;
	apqns4key.keylen = keylen;
	apqns4key.flags = flags;
	apqns4key.apqn_entries = INITIAL_APQN_ENTRIES;
	apqns4key.apqns = (struct pkey_apqn *)util_malloc(
			apqns4key.apqn_entries * sizeof(struct pkey_apqn));

	do {
		rc = ioctl(pkey_fd, PKEY_APQNS4K, &apqns4key);
		if (rc == 0)
			break;
		rc = -errno;
		pr_verbose(verbose, "ioctl PKEY_APQNS4K rc: %s", strerror(-rc));

		switch (rc) {
		case -ENOSPC:
			free(apqns4key.apqns);
			apqns4key.apqns = (struct pkey_apqn *)
				util_malloc(apqns4key.apqn_entries *
					sizeof(struct pkey_apqn));
			continue;
		case -ENOTTY:
			/*
			 * New IOCTL is not available: build the list manually
			 * (Key type CCA-AESDATA only)
			 */
			free(apqns4key.apqns);

			if (!is_cca_aes_data_key(key, keylen))
				return -ENOTSUP;

			rc = get_master_key_verification_pattern(key, keylen,
								 &mkvp,
								 verbose);
			if (rc != 0)
				return rc;

			rc = build_apqn_list_for_aes_data(apqn_list, apqns,
							  apqn_entries,
							  verbose);
			return rc;
		default:
			goto out;
		}
	} while (rc != 0);

	if (apqns4key.apqn_entries == 0) {
		pr_verbose(verbose, "No APQN available for the key");
		rc = -ENODEV;
		goto out;
	}

	rc = filter_apqn_list(apqn_list, &apqns4key.apqns,
			      &apqns4key.apqn_entries);
	if (rc != 0)
		goto out;

	if (apqns4key.apqn_entries == 0) {
		pr_verbose(verbose, "No APQN available for the key");
		rc = -ENODEV;
		goto out;
	}

	pr_verbose(verbose, "%u APQNs found", apqns4key.apqn_entries);
	pr_verbose_apqn_list(verbose, apqns4key.apqns, apqns4key.apqn_entries);

out:
	if (rc == 0) {
		*apqns = apqns4key.apqns;
		*apqn_entries = apqns4key.apqn_entries;
	} else {
		*apqns = NULL;
		*apqn_entries = 0;
		free(apqns4key.apqns);
	}

	return rc;
}

/**
 * Convert the key type string into the pkey enumeration
 *
 * @param[in] key_type      the type of the key
 *
 * @returns the pkey key type or 0 for an u known key type
 */
static enum pkey_key_type key_type_to_pkey_type(const char *key_type)
{
	if (strcasecmp(key_type, KEY_TYPE_CCA_AESDATA) == 0)
		return PKEY_TYPE_CCA_DATA;
	if (strcasecmp(key_type, KEY_TYPE_CCA_AESCIPHER) == 0)
		return PKEY_TYPE_CCA_CIPHER;

	return 0;
}

/**
 * Return the size of a key blob for a specific type
 *
 * @param[in] type          the type of the key
 *
 * @returns the size of the key or 0 for an invalid key type
 */
static size_t key_size_for_type(enum pkey_key_type type)
{
	switch (type) {
	case PKEY_TYPE_CCA_DATA:
		return AESDATA_KEY_SIZE;
	case PKEY_TYPE_CCA_CIPHER:
		return AESCIPHER_KEY_SIZE;
	default:
		return 0;
	}
}

/**
 * Generate a secure key by random
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] keyfile       the file name of the secure key to generate
 * @param[in] keybits       the cryptographic size of the key in bits
 * @param[in] xts           if true an XTS key is generated
 * @param[in] key_type      the type of the key
 * @param[in] apqns         a zero terminated array of pointers to APQN-strings,
 *                          or NULL for AUTOSELECT
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int generate_secure_key_random(int pkey_fd, const char *keyfile,
			       size_t keybits, bool xts, const char *key_type,
			       const char **apqns, bool verbose)
{
	struct pkey_genseck2 genseck2;
	size_t secure_key_size, size;
	u8 *secure_key = NULL;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(key_type != NULL, "Internal error: key_type is NULL");

	if (keybits == 0)
		keybits = DEFAULT_KEYBITS;

	pr_verbose(verbose, "Generate secure key by random");

	memset(&genseck2, 0, sizeof(genseck2));

	genseck2.type = key_type_to_pkey_type(key_type);
	if (genseck2.type == 0) {
		warnx("Key-type not supported; %s", key_type);
		return -ENOTSUP;
	}

	genseck2.size = keybits_to_keysize(keybits);
	if (genseck2.size == 0) {
		warnx("Invalid value for '--keybits'/'-c': '%lu'", keybits);
		return -EINVAL;
	}
	if (keybits == 192 && xts) {
		warnx("Invalid value for '--keybits'|'-c' "
		      "for XTS: '%lu'", keybits);
		return -EINVAL;
	}

	rc = build_apqn_list_for_key_type(pkey_fd, genseck2.type, apqns,
					  &genseck2.apqns,
					  &genseck2.apqn_entries, verbose);
	if (rc != 0) {
		if (rc == -ENODEV || rc == -ENOTSUP)
			warnx("No APQN is available that can generate a secure "
			      "key of type %s", key_type);
		else
			warnx("Failed to build a list of APQNs that can "
			      "generate a secure key of type %s: %s", key_type,
			      strerror(-rc));
		return rc;
	}

	size = key_size_for_type(genseck2.type);
	secure_key_size = DOUBLE_KEYSIZE_FOR_XTS(size, xts);
	secure_key = util_zalloc(secure_key_size);

	genseck2.key = secure_key;
	genseck2.keylen = size;

	rc = pkey_genseck2(pkey_fd, &genseck2, verbose);
	if (rc != 0) {
		warnx("Failed to generate a secure key: %s", strerror(-rc));
		goto out;
	}

	if (xts) {
		free(genseck2.apqns);
		genseck2.apqns = NULL;
		genseck2.apqn_entries = 0;

		/*
		 * Ensure to generate 2nd key with an APQN that has the same
		 * master key that is used by the 1st key.
		 */
		rc = build_apqn_list_for_key(pkey_fd, secure_key, size,
					     PKEY_FLAGS_MATCH_CUR_MKVP, apqns,
					     &genseck2.apqns,
					     &genseck2.apqn_entries, verbose);
		if (rc != 0) {
			if (rc == -ENODEV || rc == -ENOTSUP)
				warnx("No APQN is available that can generate "
				      "a secure key of type %s", key_type);
			else
				warnx("Failed to build a list of APQNs that "
				      "can generate a secure key of type %s: "
				      "%s", key_type, strerror(-rc));
			goto out;
		}

		genseck2.key = secure_key + size;
		genseck2.keylen = size;

		rc = pkey_genseck2(pkey_fd, &genseck2, verbose);
		if (rc != 0) {
			warnx("Failed to generate a secure key: %s",
			      strerror(-rc));
			goto out;
		}
	}

	pr_verbose(verbose, "Successfully generated a secure key");

	rc = write_secure_key(keyfile, secure_key, secure_key_size, verbose);

out:
	free(genseck2.apqns);
	free(secure_key);
	return rc;
}


/*
 * Generate a secure key from a clear key file
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] keyfile       the file name of the secure key to generate
 * @param[in] keybits       the cryptographic size of the key in bits. When
 *                          keybits is 0, then the clear key file size
 *                          determines the keybits.
 * @param[in] xts           if true an XTS key is generated
 * @param[in] clearkeyfile  the file name of the clear key to read
 * @param[in] key_type      the type of the key
 * @param[in] apqns         a zero terminated array of pointers to APQN-strings,
 *                          or NULL for AUTOSELECT
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int generate_secure_key_clear(int pkey_fd, const char *keyfile,
			      size_t keybits, bool xts,
			      const char *clearkeyfile, const char *key_type,
			      const char **apqns, bool verbose)
{
	struct pkey_clr2seck2 clr2seck2;
	size_t secure_key_size;
	size_t clear_key_size;
	u8 *secure_key;
	u8 *clear_key;
	size_t size;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(keyfile != NULL, "Internal error: keyfile is NULL");
	util_assert(clearkeyfile != NULL,
		    "Internal error: clearkeyfile is NULL");
	util_assert(key_type != NULL, "Internal error: key_type is NULL");

	pr_verbose(verbose, "Generate secure key from a clear key");

	clear_key = read_clear_key(clearkeyfile, keybits, xts, &clear_key_size,
				   verbose);
	if (clear_key == NULL)
		return -EINVAL;

	memset(&clr2seck2, 0, sizeof(clr2seck2));

	memcpy(&clr2seck2.clrkey, clear_key,
	       HALF_KEYSIZE_FOR_XTS(clear_key_size, xts));

	clr2seck2.type = key_type_to_pkey_type(key_type);
	if (clr2seck2.type == 0) {
		warnx("Key-type not supported; %s", key_type);
		return -ENOTSUP;
	}

	clr2seck2.size = keybits_to_keysize(HALF_KEYSIZE_FOR_XTS(
						clear_key_size * 8, xts));
	if (clr2seck2.size == 0) {
		warnx("Invalid clear key size: '%lu' bytes", clear_key_size);
		return -EINVAL;
	}
	if (keybits == 192 && xts) {
		warnx("Invalid clear key size for XTS: '%lu' bytes",
		      clear_key_size);
		return -EINVAL;
	}

	rc = build_apqn_list_for_key_type(pkey_fd, clr2seck2.type, apqns,
					  &clr2seck2.apqns,
					  &clr2seck2.apqn_entries, verbose);
	if (rc != 0) {
		if (rc == -ENODEV || rc == -ENOTSUP)
			warnx("No APQN is available that can generate a secure "
			      "key of type %s", key_type);
		else
			warnx("Failed to build a list of APQNs that can "
			      "generate a secure key of type %s: %s", key_type,
			      strerror(-rc));
		return rc;
	}

	size = key_size_for_type(clr2seck2.type);
	secure_key_size = DOUBLE_KEYSIZE_FOR_XTS(size, xts);
	secure_key = util_zalloc(secure_key_size);

	clr2seck2.key = secure_key;
	clr2seck2.keylen = size;

	rc = pkey_clr2seck2(pkey_fd, &clr2seck2, verbose);
	if (rc != 0) {
		warnx("Failed to generate a secure key: %s", strerror(-rc));
		goto out;
	}

	if (xts) {
		free(clr2seck2.apqns);
		clr2seck2.apqns = NULL;
		clr2seck2.apqn_entries = 0;

		memcpy(&clr2seck2.clrkey, clear_key + clear_key_size / 2,
		       clear_key_size / 2);

		/*
		 * Ensure to generate 2nd key with an APQN that has the same
		 * master key that is used by the 1st key.
		 */
		rc = build_apqn_list_for_key(pkey_fd, secure_key, size,
					     PKEY_FLAGS_MATCH_CUR_MKVP, apqns,
					     &clr2seck2.apqns,
					     &clr2seck2.apqn_entries, verbose);
		if (rc != 0) {
			if (rc == -ENODEV || rc == -ENOTSUP)
				warnx("No APQN is available that can generate "
				      "a secure key of type %s", key_type);
			else
				warnx("Failed to build a list of APQNs that "
				      "can generate a secure key of type %s: "
				      "%s", key_type, strerror(-rc));
			goto out;
		}

		clr2seck2.key = secure_key + size;
		clr2seck2.keylen = size;

		rc = pkey_clr2seck2(pkey_fd, &clr2seck2, verbose);
		if (rc != 0) {
			warnx("Failed to generate a secure key: %s",
			      strerror(-rc));
			goto out;
		}
	}

	pr_verbose(verbose,
		   "Successfully generated a secure key from a clear key");

	rc = write_secure_key(keyfile, secure_key, secure_key_size, verbose);

out:
	memset(&clr2seck2, 0, sizeof(clr2seck2));
	memset(clear_key, 0, clear_key_size);
	free(clear_key);
	free(secure_key);
	free(clr2seck2.apqns);
	return rc;
}

/**
 * Validates an XTS secure key (the second part)
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] apqn          the APQN to verify the key with
 * @param[in] secure_key    a buffer containing the secure key
 * @param[in] secure_key_size the secure key size
 * @param[in] part1_keysize the key size of the first key part
 * @param[in] part1_flags   the flags of the first key part
 * @param[out] clear_key_bitsize on return , the cryptographic size of the
 *                          clear key
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int validate_secure_xts_key(int pkey_fd, struct pkey_apqn *apqn,
				   u8 *secure_key, size_t secure_key_size,
				   enum pkey_key_size part1_keysize,
				   u32 part1_flags, size_t *clear_key_bitsize,
				   bool verbose)
{
	struct pkey_verifykey2 verifykey2;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");
	util_assert(apqn != NULL, "Internal error: apqn is NULL");

	memset(&verifykey2, 0, sizeof(verifykey2));
	verifykey2.key = secure_key + (secure_key_size / 2);
	verifykey2.keylen = secure_key_size / 2;
	verifykey2.cardnr = apqn->card;
	verifykey2.domain = apqn->domain;

	rc = pkey_verifyseck2(pkey_fd, &verifykey2, verbose);
	if (rc < 0) {
		pr_verbose(verbose, "Failed to validate the 2nd part of the "
			   "XTS secure key on APQN %02x.%04x: %s", apqn->card,
			   apqn->domain, strerror(-rc));
		return rc;
	}

	if (verifykey2.size != part1_keysize) {
		pr_verbose(verbose, "XTS secure key contains 2 keys using "
			   "different key sizes");
		return -EINVAL;
	}

	if (verifykey2.flags != part1_flags) {
		pr_verbose(verbose, "XTS secure key contains 2 keys using "
			   "different master keys");
		return -EINVAL;
	}

	if (clear_key_bitsize && verifykey2.size != PKEY_SIZE_UNKNOWN)
		*clear_key_bitsize += verifykey2.size;

	return 0;
}

/**
 * Validates a secure key
 *
 * @param[in] pkey_fd       the pkey file descriptor
 * @param[in] secure_key    a buffer containing the secure key
 * @param[in] secure_key_size the secure key size
 * @param[out] clear_key_bitsize on return , the cryptographic size of the
 *                          clear key
 * @param[out] is_old_mk    in return set to 1 to indicate if the secure key
 *                          is currently enciphered by the OLD CCA master key
 * @param[in] apqns         a zero terminated array of pointers to APQN-strings,
 *                          or NULL for AUTOSELECT
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int validate_secure_key(int pkey_fd,
			u8 *secure_key, size_t secure_key_size,
			size_t *clear_key_bitsize, int *is_old_mk,
			const char **apqns, bool verbose)
{
	struct pkey_verifykey2 verifykey2;
	struct pkey_apqn *list = NULL;
	u32 i, list_entries = 0;
	bool xts, valid;
	int rc;

	util_assert(pkey_fd != -1, "Internal error: pkey_fd is -1");
	util_assert(secure_key != NULL, "Internal error: secure_key is NULL");

	xts = is_xts_key(secure_key, secure_key_size);

	rc = build_apqn_list_for_key(pkey_fd, secure_key,
				     HALF_KEYSIZE_FOR_XTS(secure_key_size, xts),
				     PKEY_FLAGS_MATCH_CUR_MKVP |
						PKEY_FLAGS_MATCH_ALT_MKVP,
				     apqns, &list, &list_entries, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build a list of APQNs that can "
			   "validate this secure key: %s", strerror(-rc));
		return rc;
	}

	if (is_old_mk != NULL)
		*is_old_mk = true;
	if (clear_key_bitsize != NULL)
		*clear_key_bitsize = 0;

	valid = false;
	for (i = 0; i < list_entries; i++) {
		memset(&verifykey2, 0, sizeof(verifykey2));
		verifykey2.key = secure_key;
		verifykey2.keylen = HALF_KEYSIZE_FOR_XTS(secure_key_size, xts);
		verifykey2.cardnr = list[i].card;
		verifykey2.domain = list[i].domain;

		rc = pkey_verifyseck2(pkey_fd, &verifykey2, verbose);
		if (rc < 0) {
			pr_verbose(verbose, "Failed to validate the secure key "
				   "on APQN %02x.%04x: %s", list[i].card,
				   list[i].domain, strerror(-rc));
			continue;
		}

		if (is_xts_key(secure_key, secure_key_size)) {
			rc = validate_secure_xts_key(pkey_fd, &list[i],
						     secure_key,
						     secure_key_size,
						     verifykey2.size,
						     verifykey2.flags,
						     clear_key_bitsize,
						     verbose);
			if (rc != 0)
				continue;

		}

		valid = true;

		if (clear_key_bitsize) {
			if (verifykey2.size != PKEY_SIZE_UNKNOWN)
				*clear_key_bitsize += verifykey2.size;
			clear_key_bitsize = NULL; /* Set it only once */
		}

		/*
		 * If at least one of the APQNs have a matching current MK,
		 * then don't report OLD, even if some match the old MK.
		 */
		if (is_old_mk &&
		    (verifykey2.flags & PKEY_FLAGS_MATCH_CUR_MKVP))
			*is_old_mk = false;
	}

	if (!valid)
		return -ENODEV;

	pr_verbose(verbose, "Secure key validation completed successfully");

	if (list != NULL)
		free(list);
	return rc;
}

/**
 * Generate a key verification pattern of a secure key by encrypting the all
 * zero message with the secure key using the AF_ALG interface
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 * @param[in] vp            buffer where the verification pattern is returned
 * @param[in] vp_len        the size of the buffer
 * @param[in] verbose       if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int generate_key_verification_pattern(const u8 *key, size_t key_size,
				      char *vp, size_t vp_len, bool verbose)
{
	int tfmfd = -1, opfd = -1, rc = 0;
	char null_msg[ENC_ZERO_LEN];
	char enc_zero[ENC_ZERO_LEN];
	struct af_alg_iv *alg_iv;
	struct cmsghdr *header;
	uint32_t *type;
	ssize_t len;
	size_t i;

	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type = "skcipher",
	};
	struct iovec iov = {
		.iov_base = (void *)null_msg,
		.iov_len = sizeof(null_msg),
	};
	int iv_msg_size = CMSG_SPACE(sizeof(*alg_iv) + PAES_BLOCK_SIZE);
	char buffer[CMSG_SPACE(sizeof(*type)) + iv_msg_size];
	struct msghdr msg = {
		.msg_control = buffer,
		.msg_controllen = sizeof(buffer),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	if (vp_len < VERIFICATION_PATTERN_LEN) {
		rc = -EMSGSIZE;
		goto out;
	}

	snprintf((char *)sa.salg_name, sizeof(sa.salg_name), "%s(paes)",
		 is_xts_key(key, key_size) ? "xts" : "cbc");

	tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfmfd < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to open an AF_ALG socket");
		goto out;
	}

	if (bind(tfmfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to bind the AF_ALG socket, "
			   "salg_name='%s' ", sa.salg_name);
		goto out;
	}

	if (setsockopt(tfmfd, SOL_ALG, ALG_SET_KEY, key,
		       key_size) < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to set the key");
		goto out;
	}

	opfd = accept(tfmfd, NULL, 0);
	if (opfd < 0) {
		rc = -errno;
		pr_verbose(verbose, "Failed to accept on the AF_ALG socket");
		goto out;
	}

	memset(null_msg, 0, sizeof(null_msg));
	memset(buffer, 0, sizeof(buffer));

	header = CMSG_FIRSTHDR(&msg);
	if (header == NULL) {
		pr_verbose(verbose, "Failed to obtain control message header");
		rc = -EINVAL;
		goto out;
	}

	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_OP;
	header->cmsg_len = CMSG_LEN(sizeof(*type));
	type = (void *)CMSG_DATA(header);
	*type = ALG_OP_ENCRYPT;

	header = CMSG_NXTHDR(&msg, header);
	if (header == NULL) {
		pr_verbose(verbose, "Failed to obtain control message "
			   "header");
		rc = -EINVAL;
		goto out;
	}
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_IV;
	header->cmsg_len = iv_msg_size;
	alg_iv = (void *)CMSG_DATA(header);
	alg_iv->ivlen = PAES_BLOCK_SIZE;
	memcpy(alg_iv->iv, null_msg, PAES_BLOCK_SIZE);

	len = sendmsg(opfd, &msg, 0);
	if (len != ENC_ZERO_LEN) {
		pr_verbose(verbose, "Failed to send to the AF_ALG socket");
		rc = -errno;
		goto out;
	}

	len = read(opfd, enc_zero, sizeof(enc_zero));
	if (len != ENC_ZERO_LEN) {
		pr_verbose(verbose, "Failed to receive from the AF_ALG socket");
		rc = -errno;
		goto out;
	}

	memset(vp, 0, vp_len);
	for (i = 0; i < sizeof(enc_zero); i++)
		sprintf(&vp[i * 2], "%02x", enc_zero[i]);

	pr_verbose(verbose, "Key verification pattern:  %s", vp);

out:
	if (opfd != -1)
		close(opfd);
	if (tfmfd != -1)
		close(tfmfd);

	if (rc != 0)
		pr_verbose(verbose, "Failed to generate the key verification "
			   "pattern: %s", strerror(-rc));

	return rc;
}

int get_master_key_verification_pattern(const u8 *key, size_t key_size,
					u64 *mkvp, bool UNUSED(verbose))
{
	struct aesdatakeytoken *datakey = (struct aesdatakeytoken *)key;
	struct aescipherkeytoken *cipherkey = (struct aescipherkeytoken *)key;

	util_assert(key != NULL, "Internal error: secure_key is NULL");
	util_assert(mkvp != NULL, "Internal error: mkvp is NULL");

	if (is_cca_aes_data_key(key, key_size))
		*mkvp = datakey->mkvp;
	else if (is_cca_aes_cipher_key(key, key_size))
		memcpy(mkvp, cipherkey->kvp, sizeof(*mkvp));
	else
		return -EINVAL;

	return 0;
}

/**
 * Check if the specified key is a CCA AESDATA key token.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an CCA AESDATA token type
 */
bool is_cca_aes_data_key(const u8 *key, size_t key_size)
{
	struct tokenheader *hdr = (struct tokenheader *)key;

	if (key == NULL || key_size < AESDATA_KEY_SIZE)
		return false;

	if (hdr->type != TOKEN_TYPE_CCA_INTERNAL)
		return false;
	if (hdr->version != TOKEN_VERSION_AESDATA)
		return false;

	return true;
}

/**
 * Check if the specified key is a CCA AESCIPHER key token.
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an CCA AESCIPHER token type
 */
bool is_cca_aes_cipher_key(const u8 *key, size_t key_size)
{
	struct aescipherkeytoken *cipherkey = (struct aescipherkeytoken *)key;

	if (key == NULL || key_size < AESCIPHER_KEY_SIZE)
		return false;

	if (cipherkey->type != TOKEN_TYPE_CCA_INTERNAL)
		return false;
	if (cipherkey->version != TOKEN_VERSION_AESCIPHER)
		return false;
	if (cipherkey->length > key_size)
		return false;

	if (cipherkey->kms != 0x03) /* key wrapped by master key */
		return false;
	if (cipherkey->kwm != 0x02) /* key wrapped using AESKW */
		return false;
	if (cipherkey->pfv != 0x00 && cipherkey->pfv != 0x01) /* V0 or V1 */
		return false;
	if (cipherkey->adv != 0x01) /* Should have ass. data sect. version 1 */
		return false;
	if (cipherkey->at != 0x02) /* Algorithm: AES */
		return false;
	if (cipherkey->kt != 0x0001) /* Key type: CIPHER */
		return false;
	if (cipherkey->adl != 26) /* Ass. data section length should be 26 */
		return false;
	if (cipherkey->kll != 0) /* Should have no key label */
		return false;
	if (cipherkey->eadl != 0) /* Should have no ext associated data */
		return false;
	if (cipherkey->uadl != 0) /* Should have no user associated data */
		return false;
	if (cipherkey->kufc != 2) /* Should have 2 KUFs */
		return false;
	if (cipherkey->kmfc != 3) /* Should have 3 KMFs */
		return false;

	return true;
}

/**
 * Check if the specified key is an XTS type key
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns true if the key is an XTS key type
 */
bool is_xts_key(const u8 *key, size_t key_size)
{
	if (is_cca_aes_data_key(key, key_size)) {
		if (key_size == 2 * AESDATA_KEY_SIZE &&
		    is_cca_aes_data_key(key + AESDATA_KEY_SIZE,
					key_size - AESDATA_KEY_SIZE))
			return true;
	} else if (is_cca_aes_cipher_key(key, key_size)) {
		if (key_size == 2 * AESCIPHER_KEY_SIZE &&
		    is_cca_aes_cipher_key(key + AESCIPHER_KEY_SIZE,
					  key_size - AESCIPHER_KEY_SIZE))
			return true;
	}

	return false;
}

/**
 * Gets the size in bits of the effective key of the specified secure key
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 * @param[out] bitsize      On return, contains the size in bits of the key.
 *                          If the key size can not be determined, then 0 is
 *                          passed back as bitsize.
 *
 * @returns 0 on success, a negative errno in case of an error
 */
int get_key_bit_size(const u8 *key, size_t key_size, size_t *bitsize)
{
	struct aesdatakeytoken *datakey = (struct aesdatakeytoken *)key;
	struct aescipherkeytoken *cipherkey = (struct aescipherkeytoken *)key;

	util_assert(bitsize != NULL, "Internal error: bitsize is NULL");

	if (is_cca_aes_data_key(key, key_size)) {
		*bitsize = datakey->bitsize;
		if (key_size == 2 * AESDATA_KEY_SIZE) {
			datakey = (struct aesdatakeytoken *)key +
					AESDATA_KEY_SIZE;
			*bitsize += datakey->bitsize;
		}
	} else if (is_cca_aes_cipher_key(key, key_size)) {
		if (cipherkey->pfv == 0x00) /* V0 payload */
			*bitsize = cipherkey->pl - 384;
		else
			*bitsize = 0; /* Unknown */
		if (key_size > cipherkey->length) {
			cipherkey = (struct aescipherkeytoken *)key +
					cipherkey->length;
			if (cipherkey->pfv == 0x00) /* V0 payload */
				*bitsize += cipherkey->pl - 384;
		}
	} else {
		return -EINVAL;
	}

	return 0;
}

/**
 * Returns the type of the key
 *
 * @param[in] key           the secure key token
 * @param[in] key_size      the size of the secure key
 *
 * @returns a static string on success, NULL in case of an error
 */
const char *get_key_type(const u8 *key, size_t key_size)
{
	if (is_cca_aes_data_key(key, key_size))
		return KEY_TYPE_CCA_AESDATA;
	if (is_cca_aes_cipher_key(key, key_size))
		return KEY_TYPE_CCA_AESCIPHER;

	return NULL;
}

/**
 * Returns the minimum card level for a specific key type
 *
 * @param[in] key_type       the type of the key
 *
 * @returns the minimum card level, or -1 for unknown key types
 */
int get_min_card_level_for_keytype(const char *key_type)
{
	if (key_type == NULL)
		return -1;

	if (strcasecmp(key_type, KEY_TYPE_CCA_AESDATA) == 0)
		return 3;
	if (strcasecmp(key_type, KEY_TYPE_CCA_AESCIPHER) == 0)
		return 6;

	return -1;
}
