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
