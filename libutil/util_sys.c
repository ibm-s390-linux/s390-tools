/*
 * util - Utility function library
 *
 * SysFS helper functions
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <errno.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_path.h"
#include "lib/util_sys.h"

/* lstat() doesn't work for sysfs files, a fixed size is therefore inevitable */
#define READLINK_SIZE	256
#define PAGE_SIZE	4096

/**
 * Return the partition number of a given partition.
 *
 * @param[in]	dev	Device node of interest
 *
 * @retval	int	Partition number of the device
 * @retval	-1	Error when trying to read the partition number.
 */
int util_sys_get_partnum(dev_t dev)
{
	int partnum = -1;
	char *path;

	path = util_path_sysfs("dev/block/%u:%u/partition",
			       major(dev), minor(dev));
	if (util_file_read_i(&partnum, 10, path)) {
		warnx("Could not read from path '%s'", path);
		goto out;
	}
	if (partnum <= 0) {
		warnx("Bad partition number in '%s'", path);
		partnum = -1;
		goto out;
	}

out:
	free(path);
	return partnum;
}

/**
 * Determine if the given device is a partition.
 *
 * @param[in]	dev	Device node of interest
 *
 * @retval	true	Device is partition
 * @retval	false	Device is not a partition
 */
bool util_sys_dev_is_partition(dev_t dev)
{
	bool is_part;
	char *path;

	path = util_path_sysfs("dev/block/%u:%u/partition",
			       major(dev), minor(dev));
	is_part = util_path_exists(path);
	free(path);

	return is_part;
}

/**
 * Determine base device
 *
 * This function determines the base device \p base_dev of a given
 * device \p dev. If \p dev is a base device, \p base_dev becomes \p dev.
 *
 * @param[in]	dev		Device node of interest
 * @param[out]	base_dev	Identified base device
 *
 * @retval	 0		Success
 * @retval	-1		Error while reading device information or
 *				constructed path
 */
int util_sys_get_base_dev(dev_t dev, dev_t *base_dev)
{
	int base_major, base_minor;
	char buf[PAGE_SIZE];
	char *path;

	/* check if the device already is a base device */
	if (!util_sys_dev_is_partition(dev)) {
		*base_dev = makedev(major(dev), minor(dev));
		return 0;
	}
	path = util_path_sysfs("dev/block/%d:%d/../dev",
			       major(dev), minor(dev));
	if (util_file_read_line(buf, sizeof(buf), path)) {
		warnx("Could not read from path '%s'", path);
		free(path);
		return -1;
	}
	free(path);
	if (sscanf(buf, "%i:%i", &base_major, &base_minor) != 2) {
		warn("Could not parse major:minor from string '%s'", buf);
		return -1;
	}
	*base_dev = makedev(base_major, base_minor);

	return 0;
}

/**
 * Identify device address
 *
 * Identifying the device address with this function works for almost any
 * character and block device (e.g. NVMe, SCSI, DASD, etc).
 * The user must provide a buffer that is large enough for the desired device
 * address to be read into \p addr.
 *
 * @param[in]	dev	Device node of interest
 * @param[out]	addr	Identified device address
 *
 * @retval	 0	Success
 * @retval	-1	Error while reading device information or
 *			constructed path
 */
int util_sys_get_dev_addr(const char *dev, char *addr)
{
	char device[READLINK_SIZE], *result;
	unsigned int maj, min;
	struct stat s;
	ssize_t len;
	dev_t base;
	char *path;

	if (stat(dev, &s) != 0)
		return -1;

	if (util_sys_get_base_dev(s.st_rdev, &base))
		return -1;

	maj = major(base);
	min = minor(base);

	if (S_ISBLK(s.st_mode))
		path = util_path_sysfs("dev/block/%u:%u/device", maj, min);
	else if (S_ISCHR(s.st_mode))
		path = util_path_sysfs("dev/char/%u:%u/device", maj, min);
	else
		return -1;

	len = readlink(path, device, READLINK_SIZE - 1);
	free(path);
	if (len != -1)
		device[len] = '\0';
	else
		return -1;

	result = strrchr(device, '/');
	if (result)
		result++;
	else
		result = device;
	strcpy(addr, result);

	return 0;
}
