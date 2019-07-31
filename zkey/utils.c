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
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_path.h"
#include "lib/util_file.h"
#include "lib/util_scandir.h"
#include "lib/util_libc.h"
#include "lib/util_rec.h"
#include "lib/util_base.h"

#include "utils.h"
#include "properties.h"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

/**
 * Checks if the specified card is of type CCA and is online
 *
 * @param[in] card      card number
 *
 * @returns 1 if its a CCA card and is online, 0 if offline and -1 if its
 *          not a CCA card.
 */
int sysfs_is_card_online(int card)
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
	if (type[4] != 'C') {
		rc = -1;
		goto out;
	}

out:
	free(dev_path);
	return rc;
}

/**
 * Checks if the specified APQN is of type CCA and is online
 *
 * @param[in] card      card number
 * @param[in] domain    the domain
 *
 * @returns 1 if its a CCA card and is online, 0 if offline and -1 if its
 *          not a CCA card.
 */
int sysfs_is_apqn_online(int card, int domain)
{
	long int online;
	char *dev_path;
	int rc = 1;

	rc = sysfs_is_card_online(card);
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
int sysfs_get_card_level(int card)
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
	if (type[4] != 'C') {
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
 * Gets the 8 character ASCII serial number string of an card from the sysfs.
 *
 * @param[in] card      card number
 * @param[out] serialnr Result buffer
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 if the serial number was returned. -ENODEV if the APQN is not
 *          available, or is not a CCA card. -ENOTSUP if the serialnr sysfs
 *          attribute is not available, because the zcrypt kernel module is
 *          on an older level.
 */
int sysfs_get_serialnr(int card, char serialnr[9], bool verbose)
{
	char *dev_path;
	int rc = 0;

	if (serialnr == NULL)
		return -EINVAL;

	if (sysfs_is_card_online(card) != 1)
		return -ENODEV;

	dev_path = util_path_sysfs("bus/ap/devices/card%02x", card);
	if (!util_path_is_dir(dev_path)) {
		rc = -ENODEV;
		goto out;
	}
	if (util_file_read_line(serialnr, 9, "%s/serialnr", dev_path) != 0) {
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

static int parse_mk_info(char *line, struct mk_info *mk_info)
{
	struct mk_info_reg *mk_reg;
	char *save;
	char *tok;

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

	if (sscanf(tok, "%llx", &mk_reg->mkvp) != 1)
		return -EIO;

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
 *          available, or is not a CCA card. -ENOTSUP if the mkvps sysfs
 *          attribute is not available, because the zcrypt kernel module is
 *          on an older level.
 */
int sysfs_get_mkvps(int card, int domain, struct mk_info *mk_info, bool verbose)
{
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

	if (sysfs_is_apqn_online(card, domain) != 1)
		return -ENODEV;

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
	 *   AES NEW: <new_mk_state> <new_mk_mkvp>
	 *   AES CUR: <cur_mk_state> <cur_mk_mkvp>
	 *   AES OLD: <old_mk_state> <old_mk_mkvp>
	 * with
	 *   <new_mk_state>: 'empty' or 'partial' or 'full'
	 *   <cur_mk_state>, <old_mk_state>: 'valid' or 'invalid'
	 *   <new_mk_mkvp>, <cur_mk_mkvp>, <old_mk_mkvp:
	 *        8 byte hex string with leading 0x
	 */
	while ((p = fgets(buf, sizeof(buf), fp)) != NULL) {
		end = memchr(buf, '\n', sizeof(buf));
		if (end)
			*end = 0;
		else
			buf[sizeof(buf) - 1] = 0;

		pr_verbose(verbose, "mkvp for %02x.%04x: %s", card, domain,
			   buf);

		rc = parse_mk_info(buf, mk_info);
		if (rc != 0)
			break;
	}

	fclose(fp);

	if (mk_info->new_mk.mk_state == MK_STATE_UNKNOWN &&
	    mk_info->cur_mk.mk_state == MK_STATE_UNKNOWN &&
	    mk_info->old_mk.mk_state == MK_STATE_UNKNOWN)
		rc = -EIO;
out:
	if (rc != 0)
		pr_verbose(verbose, "Failed to get mkvps for %02x.%04x: %s",
			   card, domain, strerror(-rc));

	free(dev_path);
	return rc;
}

static int scan_for_domains(int card, apqn_handler_t handler,
			    void *handler_data, bool verbose)
{
	struct dirent **namelist;
	char fname[290];
	int i, n, domain, rc = 0;

	sprintf(fname, "/sys/devices/ap/card%02x/", card);
	n = util_scandir(&namelist, alphasort, fname,
			 "[0-9a-fA-F]+\\.[0-9a-fA-F]+");

	if (n < 0)
		return -EIO;

	for (i = 0; i < n; i++) {
		if (sscanf(namelist[i]->d_name, "%x.%x", &card, &domain) != 2)
			continue;

		pr_verbose(verbose, "Found %02x.%04x", card, domain);

		if (sysfs_is_apqn_online(card, domain) != 1) {
			pr_verbose(verbose, "APQN %02x.%04x is offline or not "
				   "CCA", card, domain);
			continue;
		}

		rc = handler(card, domain, handler_data);
		if (rc != 0)
			break;
	}

	util_scandir_free(namelist, n);
	return rc;
}


static int scan_for_apqns(apqn_handler_t handler, void *handler_data,
			  bool verbose)
{
	struct dirent **namelist;
	int i, n, card, rc = 0;

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

		if (sysfs_is_card_online(card) != 1) {
			pr_verbose(verbose, "Card %02x is offline or not CCA",
				   card);
			continue;
		}

		rc = scan_for_domains(card, handler, handler_data, verbose);
		if (rc != 0)
			break;
	}

	util_scandir_free(namelist, n);
	return rc;
}

/**
 * Calls the handler for all APQNs specified in the apqns parameter, or of this
 * is NULL, for all online CCA APQNs found in sysfs. In case sysfs is inspected,
 * the cards and domains are processed in alphabetical order.
 *
 * @param[in] apqns     a comma separated list of APQNs. If NULL is specified,
 *                      or an empty string, then all online CCA APQNs are
 *                      handled.
 * @param[in] handler   a handler function that is called for each APQN
 * @param[in] handler_data private data that is passed to the handler
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error
 */
int handle_apqns(const char *apqns, apqn_handler_t handler, void *handler_data,
		 bool verbose)
{
	int card, domain;
	char *copy, *tok;
	char *save;
	int rc = 0;

	if (apqns == NULL || (apqns != NULL && strlen(apqns) == 0)) {
		rc = scan_for_apqns(handler, handler_data, verbose);
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
	bool verbose;
};

static int print_apqn_mk_info(int card, int domain, void *handler_data)
{
	struct print_apqn_info *info = (struct print_apqn_info *)handler_data;
	struct mk_info mk_info;
	int rc, level;

	rc = sysfs_get_mkvps(card, domain, &mk_info, info->verbose);
	if (rc == -ENOTSUP)
		return rc;

	level = sysfs_get_card_level(card);

	util_rec_set(info->rec, "APQN", "%02x.%04x", card, domain);

	if (rc == 0) {
		if (mk_info.new_mk.mk_state == MK_STATE_FULL)
			util_rec_set(info->rec, "NEW", "%016llx",
				     mk_info.new_mk.mkvp);
		else if (mk_info.new_mk.mk_state == MK_STATE_PARTIAL)
			util_rec_set(info->rec, "NEW", "partially loaded");
		else
			util_rec_set(info->rec, "NEW", "-");

		if (mk_info.cur_mk.mk_state ==  MK_STATE_VALID)
			util_rec_set(info->rec, "CUR", "%016llx",
				     mk_info.cur_mk.mkvp);
		else
			util_rec_set(info->rec, "CUR", "-");

		if (mk_info.old_mk.mk_state ==  MK_STATE_VALID)
			util_rec_set(info->rec, "OLD", "%016llx",
				     mk_info.old_mk.mkvp);
		else
			util_rec_set(info->rec, "OLD", "-");
	} else {
		util_rec_set(info->rec, "NEW", "?");
		util_rec_set(info->rec, "CUR", "?");
		util_rec_set(info->rec, "OLD", "?");
	}

	if (level > 0)
		util_rec_set(info->rec, "TYPE", "CEX%dC", level);
	else
		util_rec_set(info->rec, "TYPE", "?");

	util_rec_print(info->rec);

	return 0;
}

/**
 * Prints master key information for all specified APQNs
 *
 * @param[in] apqns     a comma separated list of APQNs. If NULL is specified,
 *                      or an empty string, then all online CCA APQNs are
 *                      printed.
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error. -ENOTSUP is
 *          returned when the mkvps sysfs attribute is not available, because
 *          the zcrypt kernel module is on an older level.
 */
int print_mk_info(const char *apqns, bool verbose)
{
	struct print_apqn_info info;
	int rc;

	info.verbose = verbose;
	info.rec = util_rec_new_wide("-");

	util_rec_def(info.rec, "APQN", UTIL_REC_ALIGN_LEFT, 11, "CARD.DOMAIN");
	util_rec_def(info.rec, "NEW", UTIL_REC_ALIGN_LEFT, 16, "NEW MK");
	util_rec_def(info.rec, "CUR", UTIL_REC_ALIGN_LEFT, 16, "CURRENT MK");
	util_rec_def(info.rec, "OLD", UTIL_REC_ALIGN_LEFT, 16, "OLD MK");
	util_rec_def(info.rec, "TYPE", UTIL_REC_ALIGN_LEFT, 6, "TYPE");
	util_rec_print_hdr(info.rec);

	rc = handle_apqns(apqns, print_apqn_mk_info, &info, verbose);

	util_rec_free(info.rec);
	return rc;
}

struct cross_check_info {
	u64	mkvp;
	u64	new_mkvp;
	bool	key_mkvp;
	int	min_level;
	u32	num_cur_match;
	u32	num_old_match;
	u32	num_new_match;
	bool	mismatch;
	bool	print_mks;
	int	num_checked;
	bool	verbose;
};

static int cross_check_mk_info(int card, int domain, void *handler_data)
{
	struct cross_check_info *info = (struct cross_check_info *)handler_data;
	struct mk_info mk_info;
	char temp[200];
	int rc, level;

	rc = sysfs_get_mkvps(card, domain, &mk_info, info->verbose);
	if (rc == -ENODEV) {
		info->print_mks = 1;
		printf("WARNING: APQN %02x.%04x: Not available or not of "
		       "type CCA\n", card, domain);
		return 0;
	}
	if (rc != 0)
		return rc;

	info->num_checked++;

	if (info->min_level >= 0) {
		level = sysfs_get_card_level(card);

		if (level < info->min_level) {
			info->print_mks = 1;
			info->mismatch = 1;
			sprintf(temp, "WARNING: APQN %02x.%04x: The card level "
				"is less than CEX%dC.", card, domain,
				info->min_level);
			util_print_indented(temp, 0);
		}
	}

	if (mk_info.new_mk.mk_state == MK_STATE_PARTIAL) {
		info->print_mks = 1;
		sprintf(temp, "INFO: APQN %02x.%04x: The NEW master key "
			"register is only partially loaded.", card, domain);
		util_print_indented(temp, 0);
	}

	if (info->new_mkvp == 0 &&
	    mk_info.new_mk.mk_state == MK_STATE_FULL)
		info->new_mkvp = mk_info.new_mk.mkvp;

	if (mk_info.new_mk.mk_state == MK_STATE_FULL &&
	    mk_info.new_mk.mkvp != info->new_mkvp) {
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
	    mk_info.old_mk.mkvp == mk_info.cur_mk.mkvp) {
		info->print_mks = 1;
		sprintf(temp, "INFO: APQN %02x.%04x: The OLD master key "
			"register contains the same master key as the CURRENT "
			"master key register.", card, domain);
		util_print_indented(temp, 0);
	}
	if (mk_info.new_mk.mk_state == MK_STATE_FULL &&
	    mk_info.new_mk.mkvp == mk_info.cur_mk.mkvp) {
		info->print_mks = 1;
		sprintf(temp, "INFO: APQN %02x.%04x: The NEW master key "
			"register contains the same master key as the CURRENT "
			"master key register.", card, domain);
		util_print_indented(temp, 0);
	}
	if (mk_info.new_mk.mk_state == MK_STATE_FULL &&
	    mk_info.old_mk.mk_state == MK_STATE_VALID &&
	    mk_info.new_mk.mkvp == mk_info.old_mk.mkvp) {
		info->print_mks = 1;
		sprintf(temp, "INFO: APQN %02x.%04x: The NEW master key "
			"register contains the same master key as the OLD "
			"master key register.", card, domain);
		util_print_indented(temp, 0);
	}

	if (info->mkvp == 0)
		info->mkvp = mk_info.cur_mk.mkvp;

	if (info->key_mkvp) {
		if (mk_info.cur_mk.mk_state == MK_STATE_VALID &&
		    mk_info.cur_mk.mkvp == info->mkvp)
			info->num_cur_match++;

		if (mk_info.old_mk.mk_state == MK_STATE_VALID &&
		    mk_info.old_mk.mkvp == info->mkvp)
			info->num_old_match++;

		if (mk_info.new_mk.mk_state == MK_STATE_FULL &&
		    mk_info.new_mk.mkvp == info->mkvp)
			info->num_new_match++;
	}

	if (mk_info.cur_mk.mkvp != info->mkvp) {

		if (info->key_mkvp) {
			if (mk_info.old_mk.mk_state == MK_STATE_VALID &&
			    mk_info.old_mk.mkvp == info->mkvp) {
				info->print_mks = 1;
				sprintf(temp, "INFO: APQN %02x.%04x: The master"
					" key has been changed to a new "
					"master key, but the secure key has "
					"not yet been re-enciphered.", card,
					domain);
				util_print_indented(temp, 0);
			} else if (mk_info.new_mk.mk_state == MK_STATE_FULL &&
				   mk_info.new_mk.mkvp == info->mkvp) {
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
 *                      or an empty string, then all online CCA APQNs are
 *                      checked.
 * @param[in] mkvp      The master key verification pattern of a secure key.
 *                      If this is all zero, then the master keys are not
 *                      matched against it.
 * @param[in] min_level The minimum card level required. If min_level is -1 then
 *                      the card level is not checked.
 * @param[in] print_mks if true, then a the full master key info of all
 *                      specified APQns is printed, in case of a mismatch.
 * @param[in] verbose   if true, verbose messages are printed
 *
 * @returns 0 for success or a negative errno in case of an error. -ENODEV is
 *          returned if at least one APQN has a mismatching master key.
 *          -ENOTSUP is returned when the mkvps sysfs attribute is not
 *          available, because the zcrypt kernel module is on an older level.
 */
int cross_check_apqns(const char *apqns, u64 mkvp, int min_level,
		      bool print_mks, bool verbose)
{
	struct cross_check_info info;
	char temp[200];
	int rc;

	memset(&info, 0, sizeof(info));
	info.key_mkvp = mkvp != 0;
	info.mkvp = mkvp;
	info.min_level = min_level;
	info.verbose = verbose;

	pr_verbose(verbose, "Cross checking APQNs with mkvp 0x%016llx and "
		   "min-level %d: %s", mkvp, min_level,
		   apqns != NULL ? apqns : "ANY");

	rc = handle_apqns(apqns, cross_check_mk_info, &info, verbose);
	if (rc != 0)
		return rc;

	if (info.mismatch) {
		if (info.key_mkvp)
			printf("WARNING: Not all APQNs have the correct master "
			       "key (%016llx).\n", mkvp);
		else
			printf("WARNING: Not all APQNs have the same master "
			       "key.\n");

		rc = -ENODEV;
	}
	if (info.num_checked == 0) {
		printf("WARNING: None of the APQNs is available or of "
		       "type CCA\n");
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
		print_mk_info(apqns, verbose);
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

	if (fgets(str, sizeof(str), stdin) == NULL)
		return false;

	if (str[strlen(str) - 1] == '\n')
		str[strlen(str) - 1] = '\0';
	pr_verbose(verbose, "Prompt reply: '%s'", str);
	if (strcasecmp(str, "y") == 0 || strcasecmp(str, "yes") == 0)
		return true;

	return false;
}
