/*
 * dasd - Library for DASD related functions
 *
 * DASD related helper functions for accessing device information via sysfs
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdlib.h>

#include "lib/dasd_base.h"
#include "lib/dasd_sys.h"
#include "lib/util_file.h"
#include "lib/util_path.h"
#include "lib/util_sys.h"

/**
 * Get raw-track access mode status
 *
 * The "devnode" parameter can be any valid relative or absolute path to
 * a DASD device node, for example:
 *
 * - /dev/dasda
 * - /dev/disk/by-path/ccw-0.0.bf20
 *
 * @param[in]	devnode		Device node of interest
 *
 * @retval	1		Raw-track access mode is enabled
 * @retval	0		Raw-track access mode is disabled or
 *				cannot be determined
 */
int dasd_sys_raw_track_access(char *devnode)
{
	char busid[DASD_BUS_ID_SIZE];
	char *path;
	FILE *fp;
	int rc;

	if (util_sys_get_dev_addr(devnode, busid) != 0)
		return 0;

	path = util_path_sysfs("bus/ccw/devices/%s/raw_track_access", busid);
	fp = fopen(path, "r");
	if (!fp) {
		free(path);
		return 0;
	}

	rc = fgetc(fp) - '0';
	fclose(fp);
	free(path);

	return (rc == 1) ? 1 : 0;
}

/**
 * Is volume extent space efficient a.k.a. thin-provisioned
 *
 * The "devnode" parameter can be any valid relative or absolute path to
 * a DASD device node, for example:
 *
 * - /dev/dasda
 * - /dev/disk/by-path/ccw-0.0.bf20
 *
 * @param[in]	devnode		Device node of interest
 *
 * @retval	1		Volume is extent space efficient
 * @retval	0		Volume is not extent space efficient or
 *				cannot be determined
 */
int dasd_sys_ese(char *devnode)
{
	char busid[DASD_BUS_ID_SIZE];
	char *path;
	FILE *fp;
	int rc;

	if (util_sys_get_dev_addr(devnode, busid) != 0)
		return 0;

	path = util_path_sysfs("bus/ccw/devices/%s/ese", busid);
	fp = fopen(path, "r");
	if (!fp) {
		free(path);
		return 0;
	}

	rc = fgetc(fp) - '0';
	fclose(fp);

	return (rc == 1) ? 1 : 0;
}

int dasd_get_pm_from_chpid(char *busid, unsigned int chpid, int *mask)
{
	unsigned int val;
	int count, i;
	char *path;
	FILE *fp;

	path = util_path_sysfs("bus/ccw/devices/%s/../chpids", busid);
	*mask = 0;
	fp = fopen(path, "r");
	if (!fp) {
		free(path);
		return ENODEV;
	}

	for (i = 0; i < 8; i++) {
		count = fscanf(fp, " %x", &val);
		if (count != 1) {
			fclose(fp);
			return EIO;
		}
		if (val == chpid)
			*mask = 0x80 >> i;
	}
	fclose(fp);
	free(path);

	return 0;
}

/**
 * reset chpid
 *
 * The "devnode" parameter can be any valid relative or absolute path to
 * a DASD device node, for example:
 *
 * - /dev/dasda
 * - /dev/disk/by-path/ccw-0.0.bf20
 *
 * @param[in]	devnode		Device node of interest
 * @param[in]	chpid		The chpid to reset
 *                              If NULL all chpids will be reset
 *
 * @return     0 on success, otherwise one of the following error codes:
 *   - EINVAL  No valid chpid specified.
 *   - ENODEV  Could not open device.
 *   - ENOENT  Specified chpid not found.
 *   - EIO     Other I/O error
 *
 */
int dasd_reset_chpid(char *devnode, char *chpid_char)
{
	unsigned int chpid;
	char busid[DASD_BUS_ID_SIZE];
	int  mask, rc;
	char *endptr;
	char *path;
	FILE *fp;

	if (util_sys_get_dev_addr(devnode, busid) != 0)
		return ENODEV;

	if (!chpid_char) {
		path = util_path_sysfs("bus/ccw/devices/%s/path_reset", busid);
		fp = fopen(path, "w");
		if (!fp) {
			free(path);
			return ENODEV;
		}
		fprintf(fp, "%s", "all\n");
		fclose(fp);
		free(path);
		return 0;
	}

	errno = 0;
	chpid = strtoul(chpid_char, &endptr, 16);
	if (errno || (endptr && (*endptr != '\0')))
		return EINVAL;

	rc = dasd_get_pm_from_chpid(busid, chpid, &mask);
	if (rc)
		return rc;
	if (!mask)
		return ENOENT;

	path = util_path_sysfs("bus/ccw/devices/%s/path_reset", busid);
	fp = fopen(path, "w");
	if (!fp) {
		free(path);
		return ENODEV;
	}
	fprintf(fp, "%02x", mask);
	fclose(fp);
	free(path);

	return 0;
}

/**
 * Read amount of host with access to \p device
 *
 * The \p device can be any valid relative or absolute path to a DASD device
 * node, for example:
 *
 * - /dev/dasda
 * - /dev/disk/by-path/ccw-0.0.bf20
 *
 * @param[in]	device	Device node of interest
 *
 * @retval	n	Number of hosts with access to \p device
 * @retval	0	Value could not be determined
 */
int dasd_get_host_access_count(char *device)
{
	char busid[DASD_BUS_ID_SIZE];
	char *path;
	long value;

	if (util_sys_get_dev_addr(device, busid) != 0)
		return 0;

	path = util_path_sysfs("bus/ccw/devices/%s/host_access_count", busid);
	if (util_file_read_l(&value, 10, path))
		value = 0;
	free(path);

	return value;
}
