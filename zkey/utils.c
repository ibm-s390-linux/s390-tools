/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_path.h"
#include "lib/util_file.h"
#include "lib/util_scandir.h"
#include "lib/util_libc.h"
#include "lib/util_rec.h"
#include "lib/util_base.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "utils.h"
#include "properties.h"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

/**
 * Checks if the specified card is of the specified type and is online
 *
 * @param[in] card      card number
 * @param[in] cardtype  card type (CCA, EP11 or ANY)
 *
 * @returns 1 if its card of the specified type and is online,
 *          0 if offline,
 *          -1 if its not the specified type.
 */
int sysfs_is_card_online(unsigned int card, enum card_type cardtype)
{
	long int online;
	char *dev_path;
	char type[20];
	int rc = 1;

	dev_path = util_path_sysfs("bus/ap/devices/card%02x", card);
	if (!util_path_is_dir(dev_path)) {
		rc = 0;
		goto out;
	}
	if (util_file_read_l(&online, 10, "%s/online", dev_path) != 0) {
		rc = 0;
		goto out;
	}
	if (online == 0) {
		rc = 0;
		goto out;
	}
	if (util_file_read_line(type, sizeof(type), "%s/type", dev_path) != 0) {
		rc = 0;
		goto out;
	}
	if (strncmp(type, "CEX", 3) != 0 || strlen(type) < 5) {
		rc = 0;
		goto out;
	}
	switch (cardtype) {
	case CARD_TYPE_CCA:
		if (type[4] != 'C') {
			rc = -1;
			goto out;
		}
		break;
	case CARD_TYPE_EP11:
		if (type[4] != 'P') {
			rc = -1;
			goto out;
		}
		break;
	default:
		break;
	}

out:
	free(dev_path);
	return rc;
}

/**
 * Checks if the specified APQN is of the specified type and is online
 *
 * @param[in] card      card number
 * @param[in] domain    the domain
 * @param[in] cardtype  card type (CCA, EP11 or ANY)
 *
 * @returns 1 if its card of the specified type and is online,
 *          0 if offline,
 *          -1 if its not the specified type.
 */
int sysfs_is_apqn_online(unsigned int card, unsigned int domain,
			 enum card_type cardtype)
{
	long int online;
	char *dev_path;
	int rc = 1;

	rc = sysfs_is_card_online(card, cardtype);
	if (rc != 1)
		return rc;

	dev_path = util_path_sysfs("bus/ap/devices/card%02x/%02x.%04x", card,
				   card, domain);
	if (!util_path_is_dir(dev_path)) {
		rc = 0;
		goto out;
	}
	if (util_file_read_l(&online, 10, "%s/online", dev_path) != 0) {
		rc = 0;
		goto out;
	}
	if (online == 0) {
		rc = 0;
		goto out;
	}

out:
	free(dev_path);
	return rc;
}

/**
 * Returns the level of the card. For a CEX3C 3 is returned, for a CEX4C 4,
 * and so on.
 *
 * @param[in] card      card number
 *
 * @returns The card level, or -1 of the level can not be determined.
 */
int sysfs_get_card_level(unsigned int card)
{
	char *dev_path;
	char type[20];
	int rc;

	dev_path = util_path_sysfs("bus/ap/devices/card%02x", card);
	if (!util_path_is_dir(dev_path)) {
		rc = -1;
		goto out;
	}
	if (util_file_read_line(type, sizeof(type), "%s/type", dev_path) != 0) {
		rc = -1;
		goto out;
	}
	if (strncmp(type, "CEX", 3) != 0 || strlen(type) < 5) {
		rc = -1;
		goto out;
	}
	if (type[4] != 'C' && type[4] != 'P') {
		rc = -1;
		goto out;
	}
	if (type[3] < '1' || type[3] > '9') {
		rc = -1;
		goto out;
	}

	rc = type[3] - '0';

out:
	free(dev_path);
	return rc;
}

/**
 * Returns the type of the card. For a CEXnC CARD_TYPE_CCA is returned,
 * for a CEXnP CARD_TYPE_EP11.
 *
 * @param[in] card      card number
 *
 * @returns The card type, or -1 of the type can not be determined.
 */
enum card_type sysfs_get_card_type(unsigned int card)
{
	char *dev_path;
	char type[20];
	enum card_type cardtype;

	dev_path = util_path_sysfs("bus/ap/devices/card%02x", card);
	if (!util_path_is_dir(dev_path)) {
		cardtype = -1;
		goto out;
	}
	if (util_file_read_line(type, sizeof(type), "%s/type", dev_path) != 0) {
		cardtype = -1;
		goto out;
	}
	if (strncmp(type, "CEX", 3) != 0 || strlen(type) < 5) {
		cardtype = -1;
		goto out;
	}
	switch (type[4]) {
	case 'C':
		cardtype = CARD_TYPE_CCA;
		break;
	case 'P':
		cardtype = CARD_TYPE_EP11;
		break;
	default:
		cardtype = -1;
		break;
	}

out:
	free(dev_path);
	return cardtype;
}

/**
 * Gets the 8-16 character ASCII serial number string of an card from the sysfs.
 *
 * @param[in] card      card number
 * @param[out] serialnr Result buffer. Must be at least SERIALNR_LENGTH long.
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 if the serial number was returned. -ENODEV if the APQN is not
 *          available, or is not a CCA or EP11 card.
 *          -ENOTSUP if the serialnr sysfs attribute is not available, because
 *          the zcrypt kernel module is on an older level.
 */
int sysfs_get_serialnr(unsigned int card, char *serialnr, bool verbose)
{
	char *dev_path;
	int rc = 0;

	if (serialnr == NULL)
		return -EINVAL;

	if (sysfs_is_card_online(card, CARD_TYPE_ANY) != 1)
		return -ENODEV;

	dev_path = util_path_sysfs("bus/ap/devices/card%02x", card);
	if (!util_path_is_dir(dev_path)) {
		rc = -ENODEV;
		goto out;
	}
	if (util_file_read_line(serialnr, SERIALNR_LENGTH, "%s/serialnr",
				dev_path) != 0) {
		rc = -ENOTSUP;
		goto out;
	}

	if (strlen(serialnr) == 0) {
		rc = -ENODEV;
		goto out;
	}

	pr_verbose(verbose, "Serial number of %02x: %s", card, serialnr);
out:
	if (rc != 0)
		pr_verbose(verbose, "Failed to get serial number for "
			   "%02x: %s", card, strerror(-rc));

	free(dev_path);
	return rc;
}

/**
 * Gets the firmware version of an card from the sysfs.
 * Currently only EP11 cards provide this information.
 *
 * @param[in] card      card number
 * @param[out] fw_version On return: The firmware version numbers
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 if the firmware version was returned. -ENODEV if the APQN is not
 *          available, or is not a CCA or EP11 card.
 *          -ENOTSUP if the fw_version sysfs attribute is not available, because
 *          the zcrypt kernel module is on an older level, or because the card
 *          type does not provide this information.
 */
int sysfs_get_firmware_version(unsigned int card, struct fw_version *fw_version,
			       bool verbose)
{
	char *dev_path;
	char buf[50];
	int rc = 0;

	if (fw_version == NULL)
		return -EINVAL;

	if (sysfs_is_card_online(card, CARD_TYPE_ANY) != 1)
		return -ENODEV;

	dev_path = util_path_sysfs("bus/ap/devices/card%02x", card);
	if (!util_path_is_dir(dev_path)) {
		rc = -ENODEV;
		goto out;
	}
	if (util_file_read_line(buf, sizeof(buf), "%s/FW_version",
				dev_path) != 0) {
		rc = -ENOTSUP;
		goto out;
	}

	if (sscanf(buf, "%u.%u", &fw_version->major, &fw_version->minor) != 2) {
		rc = -ENODEV;
		goto out;
	}

	if (util_file_read_line(buf, sizeof(buf), "%s/API_ordinalnr",
				dev_path) != 0) {
		rc = -ENOTSUP;
		goto out;
	}

	if (sscanf(buf, "%u", &fw_version->api_ordinal) != 1) {
		rc = -ENODEV;
		goto out;
	}


	pr_verbose(verbose, "Firmware version of %02x: %d.%d (API: %d)", card,
		   fw_version->major, fw_version->minor,
		   fw_version->api_ordinal);
out:
	if (rc != 0)
		pr_verbose(verbose, "Failed to get firmware version for "
			   "%02x: %s", card, strerror(-rc));

	free(dev_path);
	return rc;
}

static int parse_cca_mk_info(char *line, struct mk_info *mk_info)
{
	struct mk_info_reg *mk_reg;
	char *save;
	char *tok;
	u64 mkvp;

	tok = strtok_r(line, " ", &save);
	if (tok == NULL)
		return -EIO;

	if (strcasecmp(tok, "AES") != 0)
		return 0;

	tok = strtok_r(NULL, " ", &save);
	if (tok == NULL)
		return -EIO;

	if (strcasecmp(tok, "NEW:") == 0)
		mk_reg = &mk_info->new_mk;
	else if (strcasecmp(tok, "CUR:") == 0)
		mk_reg = &mk_info->cur_mk;
	else if (strcasecmp(tok, "OLD:") == 0)
		mk_reg = &mk_info->old_mk;
	else
		return -EIO;

	tok = strtok_r(NULL, " ", &save);
	if (tok == NULL)
		return -EIO;

	if (strcasecmp(tok, "empty") == 0)
		mk_reg->mk_state = MK_STATE_EMPTY;
	else if (strcasecmp(tok, "partial") == 0)
		mk_reg->mk_state = MK_STATE_PARTIAL;
	else if (strcasecmp(tok, "full") == 0)
		mk_reg->mk_state = MK_STATE_FULL;
	else if (strcasecmp(tok, "valid") == 0)
		mk_reg->mk_state = MK_STATE_VALID;
	else if (strcasecmp(tok, "invalid") == 0)
		mk_reg->mk_state = MK_STATE_INVALID;
	else
		mk_reg->mk_state = MK_STATE_UNKNOWN;

	tok = strtok_r(NULL, " ", &save);
	if (tok == NULL)
		return -EIO;

	if (sscanf(tok, "%llx", &mkvp) != 1)
		return -EIO;

	memcpy(mk_reg->mkvp, &mkvp, sizeof(mkvp));

	return 0;
}

static int parse_ep11_mk_info(char *line, struct mk_info *mk_info)
{
	struct mk_info_reg *mk_reg;
	unsigned char *buf;
	char *save;
	char *tok;
	long len;

	tok = strtok_r(line, " ", &save);
	if (tok == NULL)
		return -EIO;

	if (strcasecmp(tok, "WK") != 0)
		return 0;

	tok = strtok_r(NULL, " ", &save);
	if (tok == NULL)
		return -EIO;

	if (strcasecmp(tok, "NEW:") == 0)
		mk_reg = &mk_info->new_mk;
	else if (strcasecmp(tok, "CUR:") == 0)
		mk_reg = &mk_info->cur_mk;
	else
		return -EIO;

	tok = strtok_r(NULL, " ", &save);
	if (tok == NULL)
		return -EIO;

	if (strcasecmp(tok, "valid") == 0)
		mk_reg->mk_state = MK_STATE_VALID;
	else if (strcasecmp(tok, "invalid") == 0)
		mk_reg->mk_state = MK_STATE_INVALID;
	else if (strcasecmp(tok, "empty") == 0)
		mk_reg->mk_state = MK_STATE_EMPTY;
	else if (strcasecmp(tok, "uncommitted") == 0)
		mk_reg->mk_state = MK_STATE_UNCOMMITTED;
	else if (strcasecmp(tok, "committed") == 0)
		mk_reg->mk_state = MK_STATE_COMMITTED;
	else
		mk_reg->mk_state = MK_STATE_UNKNOWN;

	tok = strtok_r(NULL, " ", &save);
	if (tok == NULL)
		return -EIO;

	/*
	 * EP11 uses a 32 byte master key verification pattern.
	 * Usually only the first 16 bytes are used, so we store only up to
	 * 16 bytes.
	 */
	if (strlen(tok) >= MKVP_LENGTH * 2) {
		if (strncmp(tok, "0x", 2) == 0)
			tok += 2;

		buf = OPENSSL_hexstr2buf(tok, &len);
		if (buf == NULL)
			return -EIO;
		if (len > MKVP_LENGTH)
			len = MKVP_LENGTH;
		memcpy(mk_reg->mkvp, buf, len);
		OPENSSL_free(buf);
	}

	return 0;
}

/**
 * Gets the master key states and verification patterns of an APQN from the
 * sysfs.
 *
 * @param[in] card      card number
 * @param[in] domain    the domain
 * @param[out] mk_info  structure is filled on return with master key infos
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 if the master key info was returned. -ENODEV if the APQN is not
 *          available, or is not a CCA or EP11 card.
 *          -ENOTSUP if the mkvps sysfs attribute is not available, because the
 *          zcrypt kernel module is on an older level.
 */
int sysfs_get_mkvps(unsigned int card, unsigned int domain,
		    struct mk_info *mk_info, bool verbose)
{
	enum card_type cardtype;
	char *dev_path;
	char *p, *end;
	char buf[100];
	int rc = 0;
	FILE *fp;

	if (mk_info == NULL)
		return -EINVAL;

	memset(mk_info, 0, sizeof(struct mk_info));
	mk_info->new_mk.mk_state = MK_STATE_UNKNOWN;
	mk_info->cur_mk.mk_state = MK_STATE_UNKNOWN;
	mk_info->old_mk.mk_state = MK_STATE_UNKNOWN;

	if (sysfs_is_apqn_online(card, domain, CARD_TYPE_ANY) != 1)
		return -ENODEV;

	cardtype = sysfs_get_card_type(card);

	dev_path = util_path_sysfs("bus/ap/devices/card%02x/%02x.%04x/mkvps",
				   card, card, domain);
	if (!util_path_is_reg_file(dev_path)) {
		rc = -ENOTSUP;
		goto out;
	}

	fp = fopen(dev_path, "r");
	if (fp == NULL) {
		rc = -ENOTSUP;
		goto out;
	}

	/*
	 * Expected contents:
	 * For CCA cards:
	 *     AES NEW: <new_mk_state> <new_mk_mkvp>
	 *     AES CUR: <cur_mk_state> <cur_mk_mkvp>
	 *     AES OLD: <old_mk_state> <old_mk_mkvp>
	 *   with
	 *     <new_mk_state>: 'empty' or 'partial' or 'full'
	 *     <cur_mk_state>, <old_mk_state>: 'valid' or 'invalid'
	 *     <new_mk_mkvp>, <cur_mk_mkvp>, <old_mk_mkvp>:
	 *          8 byte hex string with leading 0x
	 * For EP11 cards:
	 *     WK NEW: <new_wk_state> <new_wk_mkvp>
	 *     WK CUR: <cur_wk_state> <cur_wk_mkvp>
	 *   with
	 *     <wk_cur_state>: 'invalid' or 'valid'
	 *     <wk_new_state>: 'empty' or 'uncommitted' or 'committed'
	 *     <wk_cur_vp> and <wk_new_vp>: '-' or a 32 byte hash pattern
	 */
	while ((p = fgets(buf, sizeof(buf), fp)) != NULL) {
		end = memchr(buf, '\n', sizeof(buf));
		if (end)
			*end = 0;
		else
			buf[sizeof(buf) - 1] = 0;

		pr_verbose(verbose, "mkvp for %02x.%04x: %s", card, domain,
			   buf);

		switch (cardtype) {
		case CARD_TYPE_CCA:
			rc = parse_cca_mk_info(buf, mk_info);
			break;
		case CARD_TYPE_EP11:
			rc = parse_ep11_mk_info(buf, mk_info);
			break;
		default:
			rc = -EINVAL;
			break;
		}
		if (rc != 0)
			break;
	}

	fclose(fp);

	if (mk_info->new_mk.mk_state == MK_STATE_UNKNOWN &&
	    mk_info->cur_mk.mk_state == MK_STATE_UNKNOWN &&
	    (cardtype == CARD_TYPE_CCA &&
	     mk_info->old_mk.mk_state == MK_STATE_UNKNOWN))
		rc = -EIO;
out:
	if (rc != 0)
		pr_verbose(verbose, "Failed to get mkvps for %02x.%04x: %s",
			   card, domain, strerror(-rc));

	free(dev_path);
	return rc;
}

static int scan_for_domains(unsigned int card, enum card_type cardtype,
			    apqn_handler_t handler, void *handler_data,
			    bool verbose)
{
	struct dirent **namelist;
	char fname[290];
	int i, n, rc = 0;
	unsigned int domain;

	sprintf(fname, "/sys/devices/ap/card%02x/", card);
	n = util_scandir(&namelist, alphasort, fname,
			 "[0-9a-fA-F]+\\.[0-9a-fA-F]+");

	if (n < 0)
		return -EIO;

	for (i = 0; i < n; i++) {
		if (sscanf(namelist[i]->d_name, "%x.%x", &card, &domain) != 2)
			continue;

		pr_verbose(verbose, "Found %02x.%04x", card, domain);

		if (sysfs_is_apqn_online(card, domain, cardtype) != 1) {
			pr_verbose(verbose, "APQN %02x.%04x is offline or not "
				   "the correct type", card, domain);
			continue;
		}

		rc = handler(card, domain, handler_data);
		if (rc != 0)
			break;
	}

	util_scandir_free(namelist, n);
	return rc;
}


static int scan_for_apqns(enum card_type cardtype, apqn_handler_t handler,
			  void *handler_data, bool verbose)
{
	struct dirent **namelist;
	int i, n, rc = 0;
	unsigned int card;

	if (handler == NULL)
		return -EINVAL;

	n = util_scandir(&namelist, alphasort, "/sys/devices/ap/",
			 "card[0-9a-fA-F]+");
	if (n < 0)
		return -EIO;

	for (i = 0; i < n; i++) {
		if (sscanf(namelist[i]->d_name, "card%x", &card) != 1)
			continue;

		pr_verbose(verbose, "Found card %02x", card);

		if (sysfs_is_card_online(card, cardtype) != 1) {
			pr_verbose(verbose, "Card %02x is offline or not the "
				   "correct type", card);
			continue;
		}

		rc = scan_for_domains(card, cardtype, handler, handler_data,
				      verbose);
		if (rc != 0)
			break;
	}

	util_scandir_free(namelist, n);
	return rc;
}

/**
 * Calls the handler for all APQNs specified in the apqns parameter, or if this
 * is NULL, for all online CCA or EP11 APQNs found in sysfs. In case sysfs is
 * inspected, the cards and domains are processed in alphabetical order.
 *
 * @param[in] apqns     a comma separated list of APQNs. If NULL is specified,
 *                      or an empty string, then all online CCA or EP11 APQNs
 *                      are handled.
 * @param[in] cardtype  card type (CCA, EP11 or ANY)
 * @param[in] handler   a handler function that is called for each APQN
 * @param[in] handler_data private data that is passed to the handler
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int handle_apqns(const char *apqns, enum card_type cardtype,
		 apqn_handler_t handler, void *handler_data, bool verbose)
{
	unsigned int card, domain;
	char *copy, *tok;
	char *save;
	int rc = 0;

	if (apqns == NULL || (apqns != NULL && strlen(apqns) == 0)) {
		rc = scan_for_apqns(cardtype, handler, handler_data, verbose);
	} else {
		copy = util_strdup(apqns);
		tok = strtok_r(copy, ",", &save);
		while (tok != NULL) {

			if (sscanf(tok, "%x.%x", &card, &domain) != 2) {
				warnx("the APQN '%s' is not valid",
				      tok);
				rc = -EINVAL;
				break;
			}

			pr_verbose(verbose, "Specified: %02x.%04x", card,
				   domain);
			rc = handler(card, domain, handler_data);
			if (rc != 0)
				break;

			tok = strtok_r(NULL, ",", &save);
		}
		free(copy);
	}

	return rc;
}

struct print_apqn_info {
	struct util_rec *rec;
	enum card_type cardtype;
	bool verbose;
};

static int print_apqn_mk_info(unsigned int card, unsigned int domain,
			      void *handler_data)
{
	struct print_apqn_info *info = (struct print_apqn_info *)handler_data;
	struct mk_info mk_info;
	int rc, level;
	enum card_type type;

	rc = sysfs_get_mkvps(card, domain, &mk_info, info->verbose);
	if (rc == -ENOTSUP)
		return rc;

	level = sysfs_get_card_level(card);
	type = sysfs_get_card_type(card);

	util_rec_set(info->rec, "APQN", "%02x.%04x", card, domain);

	if (info->cardtype != CARD_TYPE_ANY && type != info->cardtype)
		rc = -EINVAL;

	if (rc == 0) {
		if (mk_info.new_mk.mk_state == MK_STATE_FULL ||
		    mk_info.new_mk.mk_state == MK_STATE_COMMITTED)
			util_rec_set(info->rec, "NEW", "%s",
				     printable_mkvp(type, mk_info.new_mk.mkvp));
		else if (mk_info.new_mk.mk_state == MK_STATE_PARTIAL)
			util_rec_set(info->rec, "NEW", "partially loaded");
		else if (mk_info.new_mk.mk_state == MK_STATE_UNCOMMITTED)
			util_rec_set(info->rec, "NEW", "uncommitted");
		else
			util_rec_set(info->rec, "NEW", "-");

		if (mk_info.cur_mk.mk_state ==  MK_STATE_VALID)
			util_rec_set(info->rec, "CUR", "%s",
				     printable_mkvp(type, mk_info.cur_mk.mkvp));
		else
			util_rec_set(info->rec, "CUR", "-");

		if (mk_info.old_mk.mk_state ==  MK_STATE_VALID)
			util_rec_set(info->rec, "OLD", "%s",
				     printable_mkvp(type, mk_info.old_mk.mkvp));
		else
			util_rec_set(info->rec, "OLD", "-");
	} else {
		util_rec_set(info->rec, "NEW", "?");
		util_rec_set(info->rec, "CUR", "?");
		util_rec_set(info->rec, "OLD", "?");
	}

	if (level > 0 && type != CARD_TYPE_ANY)
		util_rec_set(info->rec, "TYPE", "CEX%d%c", level,
			     type == CARD_TYPE_CCA ? 'C' : 'P');
	else
		util_rec_set(info->rec, "TYPE", "?");

	util_rec_print(info->rec);

	return 0;
}

/**
 * Prints master key information for all specified APQNs
 *
 * @param[in] apqns     a comma separated list of APQNs. If NULL is specified,
 *                      or an empty string, then all online CCA or EP11 APQNs
 *                      are printed.
 * @param[in] cardtype  card type (CCA, EP11 or ANY)
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error. -ENOTSUP is
 *          returned when the mkvps sysfs attribute is not available, because
 *          the zcrypt kernel module is on an older level.
 */
int print_mk_info(const char *apqns, enum card_type cardtype, bool verbose)
{
	struct print_apqn_info info;
	int rc, mklen;

	info.verbose = verbose;
	info.cardtype = cardtype;
	info.rec = util_rec_new_wide("-");

	if (cardtype == CARD_TYPE_CCA)
		mklen = 16;
	else
		mklen = 32;

	util_rec_def(info.rec, "APQN", UTIL_REC_ALIGN_LEFT, 11, "CARD.DOMAIN");
	util_rec_def(info.rec, "NEW", UTIL_REC_ALIGN_LEFT, mklen, "NEW MK");
	util_rec_def(info.rec, "CUR", UTIL_REC_ALIGN_LEFT, mklen, "CURRENT MK");
	if (cardtype != CARD_TYPE_EP11)
		util_rec_def(info.rec, "OLD", UTIL_REC_ALIGN_LEFT, mklen,
			     "OLD MK");
	util_rec_def(info.rec, "TYPE", UTIL_REC_ALIGN_LEFT, 6, "TYPE");
	util_rec_print_hdr(info.rec);

	rc = handle_apqns(apqns, cardtype, print_apqn_mk_info, &info, verbose);

	util_rec_free(info.rec);
	return rc;
}

struct cross_check_info {
	u8	mkvp[MKVP_LENGTH];
	u8	new_mkvp[MKVP_LENGTH];
	bool	key_mkvp;
	enum card_type cardtype;
	int	min_level;
	const struct fw_version *min_fw_version;
	u32	num_cur_match;
	u32	num_old_match;
	u32	num_new_match;
	bool	mismatch;
	bool	print_mks;
	int	num_checked;
	bool	verbose;
};

static int cross_check_mk_info(unsigned int card, unsigned int domain,
			       void *handler_data)
{
	struct cross_check_info *info = (struct cross_check_info *)handler_data;
	struct fw_version fw_version;
	enum card_type type;
	struct mk_info mk_info;
	char temp[200];
	int rc, level = 0;

	rc = sysfs_get_mkvps(card, domain, &mk_info, info->verbose);
	if (rc == -ENODEV) {
		info->print_mks = 1;
		printf("WARNING: APQN %02x.%04x: Not available or not of "
		       "the correct type\n", card, domain);
		return 0;
	}
	if (rc != 0)
		return rc;

	info->num_checked++;

	if (info->cardtype != CARD_TYPE_ANY) {
		type = sysfs_get_card_type(card);
		if (type != info->cardtype) {
			info->print_mks = 1;
			info->mismatch = 1;
			sprintf(temp, "WARNING: APQN %02x.%04x: The card type "
				"is not CEXn%c.", card, domain,
				info->cardtype == CARD_TYPE_CCA ? 'C' : 'P');
			util_print_indented(temp, 0);
			return 0;
		}
	}

	if (info->min_level >= 0) {
		level = sysfs_get_card_level(card);

		if (level < info->min_level) {
			info->print_mks = 1;
			info->mismatch = 1;
			sprintf(temp, "WARNING: APQN %02x.%04x: The card level "
				"is less than CEX%dn.", card, domain,
				info->min_level);
			util_print_indented(temp, 0);
		}
	}

	if (info->min_fw_version != NULL) {
		rc = sysfs_get_firmware_version(card, &fw_version,
					       info->verbose);
		if (rc == 0) {
			if (fw_version.api_ordinal <
					info->min_fw_version->api_ordinal) {
				info->print_mks = 1;
				info->mismatch = 1;
				sprintf(temp, "WARNING: APQN %02x.%04x: The "
					"firmware version is too less to "
					"support secure keys of that type",
					card, domain);
				util_print_indented(temp, 0);
			}
			if (info->min_level > 0 && info->min_level == level &&
			    (fw_version.major < info->min_fw_version->major ||
			     (fw_version.major == info->min_fw_version->major &&
			      fw_version.minor < info->min_fw_version->minor))) {
				info->print_mks = 1;
				info->mismatch = 1;
				sprintf(temp, "WARNING: APQN %02x.%04x: The "
					"firmware version is too less to "
					"support secure keys of that type",
					card, domain);
				util_print_indented(temp, 0);
			}
		}
	}

	if (mk_info.new_mk.mk_state == MK_STATE_PARTIAL) {
		info->print_mks = 1;
		sprintf(temp, "INFO: APQN %02x.%04x: The NEW master key "
			"register is only partially loaded.", card, domain);
		util_print_indented(temp, 0);
	}
	if (mk_info.new_mk.mk_state == MK_STATE_UNCOMMITTED) {
		info->print_mks = 1;
		sprintf(temp, "INFO: APQN %02x.%04x: The NEW master key "
			"register is loaded but uncommitted.", card, domain);
		util_print_indented(temp, 0);
	}

	if (MKVP_ZERO(info->new_mkvp) &&
	    (mk_info.new_mk.mk_state == MK_STATE_FULL ||
	     mk_info.new_mk.mk_state == MK_STATE_COMMITTED))
		memcpy(info->new_mkvp, mk_info.new_mk.mkvp,
		       sizeof(info->new_mkvp));

	if ((mk_info.new_mk.mk_state == MK_STATE_FULL ||
	     mk_info.new_mk.mk_state == MK_STATE_COMMITTED) &&
	    !MKVP_EQ(mk_info.new_mk.mkvp, info->new_mkvp)) {
		info->print_mks = 1;
		sprintf(temp, "WARNING: APQN %02x.%04x: The NEW master key "
			      "register contains a different master key than "
			      "the NEW register of other APQNs.", card,
			domain);
		util_print_indented(temp, 0);
	}

	if (mk_info.cur_mk.mk_state != MK_STATE_VALID) {
		info->print_mks = 1;
		info->mismatch = 1;
		printf("WARNING: APQN %02x.%04x: No master key is set.\n", card,
		       domain);
		return 0;
	}

	if (mk_info.old_mk.mk_state == MK_STATE_VALID &&
	    MKVP_EQ(mk_info.old_mk.mkvp, mk_info.cur_mk.mkvp)) {
		info->print_mks = 1;
		sprintf(temp, "INFO: APQN %02x.%04x: The OLD master key "
			"register contains the same master key as the CURRENT "
			"master key register.", card, domain);
		util_print_indented(temp, 0);
	}
	if ((mk_info.new_mk.mk_state == MK_STATE_FULL ||
	     mk_info.new_mk.mk_state == MK_STATE_COMMITTED) &&
	    MKVP_EQ(mk_info.new_mk.mkvp, mk_info.cur_mk.mkvp)) {
		info->print_mks = 1;
		sprintf(temp, "INFO: APQN %02x.%04x: The NEW master key "
			"register contains the same master key as the CURRENT "
			"master key register.", card, domain);
		util_print_indented(temp, 0);
	}
	if (mk_info.new_mk.mk_state == MK_STATE_FULL &&
	    mk_info.old_mk.mk_state == MK_STATE_VALID &&
	    MKVP_EQ(mk_info.new_mk.mkvp, mk_info.old_mk.mkvp)) {
		info->print_mks = 1;
		sprintf(temp, "INFO: APQN %02x.%04x: The NEW master key "
			"register contains the same master key as the OLD "
			"master key register.", card, domain);
		util_print_indented(temp, 0);
	}

	if (MKVP_ZERO(info->mkvp))
		memcpy(info->mkvp, mk_info.cur_mk.mkvp, sizeof(info->mkvp));

	if (info->key_mkvp) {
		if (mk_info.cur_mk.mk_state == MK_STATE_VALID &&
		    MKVP_EQ(mk_info.cur_mk.mkvp, info->mkvp))
			info->num_cur_match++;

		if (mk_info.old_mk.mk_state == MK_STATE_VALID &&
		    MKVP_EQ(mk_info.old_mk.mkvp, info->mkvp))
			info->num_old_match++;

		if ((mk_info.new_mk.mk_state == MK_STATE_FULL ||
		     mk_info.new_mk.mk_state == MK_STATE_COMMITTED) &&
		    MKVP_EQ(mk_info.new_mk.mkvp, info->mkvp))
			info->num_new_match++;
	}

	if (!MKVP_EQ(mk_info.cur_mk.mkvp, info->mkvp)) {

		if (info->key_mkvp) {
			if (mk_info.old_mk.mk_state == MK_STATE_VALID &&
			    MKVP_EQ(mk_info.old_mk.mkvp, info->mkvp)) {
				info->print_mks = 1;
				sprintf(temp, "INFO: APQN %02x.%04x: The master"
					" key has been changed to a new "
					"master key, but the secure key has "
					"not yet been re-enciphered.", card,
					domain);
				util_print_indented(temp, 0);
			} else if ((mk_info.new_mk.mk_state == MK_STATE_FULL ||
				    mk_info.new_mk.mk_state ==
							MK_STATE_COMMITTED) &&
				   MKVP_EQ(mk_info.new_mk.mkvp, info->mkvp)) {
				info->print_mks = 1;
				sprintf(temp, "INFO: APQN %02x.%04x: The master"
					" key has been changed but is not "
					"yet been set (made active).", card,
					domain);
				util_print_indented(temp, 0);
			} else {
				info->print_mks = 1;
				info->mismatch = 1;
				sprintf(temp, "WARNING: APQN %02x.%04x: The "
					"CURRENT master key register contains "
					"a master key that is different from "
					"the one used by the secure key.", card,
					domain);
				util_print_indented(temp, 0);
			}
		} else {
			info->print_mks = 1;
			info->mismatch = 1;
		}
	}

	return 0;
}

/**
 * Cross checks the master key information for all specified APQNs. It checks
 * if all specified APQNs have the same current master key, and if it matches
 * the master key specified by the mkvp parameter (optional). If not, it prints
 * out an information message about the APQNs that have a different master key.
 *
 * @param[in] apqns     a comma separated list of APQNs. If NULL is specified,
 *                      or an empty string, then all online APQNs are
 *                      checked.
 * @param[in] mkvp      The master key verification pattern of a secure key.
 *                      If this is all zero or NULL, then the master keys are
 *                      not matched against it.
 * @param[in] min_level The minimum card level required. If min_level is -1 then
 *                      the card level is not checked.
 * @param[in] min_fw_version The minimum firmware version required. If NULL tne
 *                      the firmware version is not checked.
 * @param[in] cardtype  card type (CCA, EP11 or ANY)
 * @param[in] print_mks if true, then a the full master key info of all
 *                      specified APQns is printed, in case of a mismatch.
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error. -ENODEV is
 *          returned if at least one APQN has a mismatching master key.
 *          -ENOTSUP is returned when the mkvps sysfs attribute is not
 *          available, because the zcrypt kernel module is on an older level.
 */
int cross_check_apqns(const char *apqns, u8 *mkvp, int min_level,
		      const struct fw_version *min_fw_version,
		      enum card_type cardtype, bool print_mks, bool verbose)
{
	struct cross_check_info info;
	char temp[250];
	int rc;

	memset(&info, 0, sizeof(info));
	info.key_mkvp = !MKVP_ZERO(mkvp);
	if (mkvp != NULL)
		memcpy(info.mkvp, mkvp, sizeof(info.mkvp));
	info.cardtype = cardtype;
	info.min_level = min_level;
	info.min_fw_version = min_fw_version;
	info.verbose = verbose;

	pr_verbose(verbose, "Cross checking APQNs with mkvp %s, "
		   "min-level %d, and min-fw-version %u.%u (api: %u): %s",
		   printable_mkvp(cardtype, info.mkvp),
		   min_level,
		   min_fw_version != NULL ? min_fw_version->major : 0,
		   min_fw_version != NULL ? min_fw_version->minor : 0,
		   min_fw_version != NULL ? min_fw_version->api_ordinal : 0,
		   apqns != NULL ? apqns : "ANY");

	rc = handle_apqns(apqns, cardtype, cross_check_mk_info, &info, verbose);
	if (rc != 0)
		return rc;

	if (info.mismatch) {
		if (info.key_mkvp)
			printf("WARNING: Not all APQNs have the correct master "
			       "key (%s) or fulfill the requirements.\n",
			       printable_mkvp(cardtype, info.mkvp));
		else
			printf("WARNING: Not all APQNs have the same master "
			       "key or fulfill the requirements.\n");
		rc = -ENODEV;
	}
	if (info.num_checked == 0) {
		printf("WARNING: None of the APQNs is available or of "
		       "the correct type\n");
		rc = -ENODEV;
	}
	if (info.num_old_match > 0 && info.num_new_match > 0) {
		sprintf(temp, "WARNING: On %u APQNs the OLD master key "
			"register contains the master key use by the secure "
			"key, and on %u APQNs the NEW master key register "
			"contains the master key use by the secure key.",
			info.num_old_match, info.num_new_match);
		util_print_indented(temp, 0);
		info.print_mks = 1;
		rc = -ENODEV;
	}

	if (print_mks && info.print_mks) {
		printf("\n");
		print_mk_info(apqns, cardtype, verbose);
		printf("\n");
	}

	return rc;
}

/*
 * Prompts for yes or no. Returns true if 'y' or 'yes' was entered.
 *
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns true if 'y' or 'yes' was entered (case insensitive). Returns false
 * otherwise.
 */
bool prompt_for_yes(bool verbose)
{
	char str[20];

	fflush(stdout);
	if (fgets(str, sizeof(str), stdin) == NULL)
		return false;

	if (str[strlen(str) - 1] == '\n')
		str[strlen(str) - 1] = '\0';
	pr_verbose(verbose, "Prompt reply: '%s'", str);
	if (strcasecmp(str, "y") == 0 || strcasecmp(str, "yes") == 0)
		return true;

	return false;
}

/*
 * Returns a printable version of the specified master key verification pattern
 * (MKVP) for the specified card type. Different card types use different
 * number of bytes for MKVP.
 *
 * @param[in] cardtype  card type (CCA, EP11 or ANY)
 * @param[in] mkvp       the master key verification pattern to print
 *
 * @returns address of a static char array containing the printed MKVP, or NULL
 *          in case of an error.
 */
char *printable_mkvp(enum card_type cardtype, u8 *mkvp)
{
	static char mkvp_print_buf[MKVP_LENGTH * 2 + 1];

	if (mkvp == NULL)
		return NULL;

	switch (cardtype) {
	case CARD_TYPE_CCA:
		/* CCA uses an 8 byte MKVP */
		sprintf(mkvp_print_buf, "%016llx", *((u64 *)mkvp));
		break;
	case CARD_TYPE_EP11:
		/* EP11 uses an 32 byte MKVP, but truncated to 16 bytes*/
		sprintf(mkvp_print_buf, "%016llx%016llx", *((u64 *)&mkvp[0]),
			*((u64 *)&mkvp[8]));
		break;
	default:
		return NULL;
	}

	return mkvp_print_buf;
}

/*
 * Copy the contents of one file into another file. If num_bytes is zero,
 * then all content until EOF of the input file is copied. Otherwise only up to
 * num_bytes is copied.
 *
 * @param[in] in_file_name   the file name of the input file
 * @param[in] out_file_name  the file name of the output file
 * @param[in] num_bytes      the number of  bytes to copy, or 0 to copy until
 *                           EOF of the input file
 *
 * @returns zero for success, or a negative error in case of an error
 */
int copy_file(const char *in_file_name, const char *out_file_name,
	      size_t num_bytes)
{
	FILE *fp_in = NULL, *fp_out = NULL;
	size_t num = 0, len;
	char buff[1024];
	int rc = 0;

	fp_in = fopen(in_file_name, "r");
	if (fp_in == NULL) {
		rc = -errno;
		warnx("Failed to open '%s': %s", in_file_name, strerror(-rc));
		goto out;
	}

	fp_out = fopen(out_file_name, "w");
	if (fp_out == NULL) {
		rc = -errno;
		warnx("Failed to open '%s': %s", out_file_name, strerror(-rc));
		goto out;
	}

	while (!feof(fp_in) && (num_bytes == 0 || num < num_bytes)) {
		len  = fread(buff, 1, num_bytes == 0 ? sizeof(buff) :
			     MIN(num_bytes - num, sizeof(buff)), fp_in);
		if (ferror(fp_in)) {
			rc = -EIO;
			warnx("Failed to read from '%s': %s", in_file_name,
			      strerror(-rc));
			break;
		}

		if (len == 0)
			break;

		if (fwrite(buff, len, 1, fp_out) != 1) {
			rc = -errno;
			warnx("Failed to write to '%s': %s", out_file_name,
			      strerror(-rc));
			break;
		}

		num += len;
	}

out:
	if (fp_in != NULL)
		fclose(fp_in);
	if (fp_out != NULL)
		fclose(fp_out);

	return rc;
}

/**
 * Reads the passphrase from the specified file and returns the passphrase as
 * an base64 encoded string. The returned string must be freed by the caller.
 *
 * @param[in] filename      the file name of the file containing the passphrase
 * @param[in] verbose       if true, additional error messages are printed.
 *
 * @returns an allocated string
 */
char *read_passphrase_as_base64(const char *filename, bool verbose)
{
	unsigned char *ret = NULL, *buf = NULL;
	int outlen, len;
	struct stat sb;
	FILE *fp;

	if (stat(filename, &sb) != 0) {
		pr_verbose(verbose, "stat on file '%s' failed: %s", filename,
			   strerror(errno));
		return NULL;
	}

	if (sb.st_size == 0) {
		pr_verbose(verbose, "File '%s' is empty", filename);
		return NULL;
	}

	fp = fopen(filename, "r");
	if (fp == NULL) {
		pr_verbose(verbose, "Open of file '%s' failed: %s", filename,
			   strerror(errno));
		return NULL;
	}

	buf = malloc(sb.st_size);
	if (buf == NULL) {
		pr_verbose(verbose, "Malloc failed");
		goto out;
	}

	if (fread(buf, sb.st_size, 1, fp) != 1) {
		pr_verbose(verbose, "Reading file '%s' failed: %s", filename,
			   strerror(errno));
		goto out;
	}

	outlen = (sb.st_size / 3) * 4;
	if (sb.st_size % 3 > 0)
		outlen += 4;

	ret = malloc(outlen + 1);
	if (ret == NULL) {
		pr_verbose(verbose, "Malloc failed");
		goto out;
	}

	len = EVP_EncodeBlock(ret, buf, sb.st_size);
	if (len != outlen) {
		pr_verbose(verbose, "EVP_EncodeBlock failed");
		free(ret);
		ret = NULL;
		goto out;
	}

	ret[outlen] = '\0';

out:
	free(buf);
	fclose(fp);

	return (char *)ret;
}

/**
 * Stores the passphrase into the specified file. Decodes the base64 string into
 * bytes.
 *
 * @param[in] b64_string    the passphrase as a base64 string
 * @param[in] filename      the file name of the file containing the passphrase
 * @param[in] verbose       if true, additional error messages are printed.
 *
 * @returns 0 for success or a negative errno in case of an error.
 */
int store_passphrase_from_base64(const char *b64_string, const char *filename,
				 bool verbose)
{
	size_t len, outlen, rawlen, i;
	unsigned char *buf;
	FILE *fp = NULL;
	int rc = 0;

	len = strlen(b64_string);
	rawlen = outlen = (len / 4) * 3;
	for (i = len - 1; b64_string[i] == '='; i--, rawlen--)
		;

	buf = malloc(outlen);
	if (buf == NULL) {
		pr_verbose(verbose, "Malloc failed");
		return -ENOMEM;
	}

	fp = fopen(filename, "w");
	if (fp == NULL) {
		pr_verbose(verbose, "Open of file '%s' failed: %s", filename,
			   strerror(errno));
		rc = -EIO;
		goto out;
	}

	len = EVP_DecodeBlock(buf, (unsigned char *)b64_string, len);
	if (len != outlen) {
		pr_verbose(verbose, "EVP_DecodeBlock failed");
		goto out;
	}

	if (fwrite(buf, rawlen, 1, fp) != 1) {
		pr_verbose(verbose, "Writing file '%s' failed: %s", filename,
			   strerror(errno));
		goto out;
	}

out:
	if (fp != NULL)
		fclose(fp);
	free(buf);
	return rc;
}

