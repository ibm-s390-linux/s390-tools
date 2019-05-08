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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "lib/util_path.h"
#include "lib/util_sys.h"

/* lstat() doesn't work for sysfs files, a fixed size is therefore inevitable */
#define READLINK_SIZE	256

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
	char *path;

	if (stat(dev, &s) != 0)
		return -1;

	maj = major(s.st_rdev);
	min = minor(s.st_rdev);

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
