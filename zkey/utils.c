/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

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

#include "utils.h"

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
