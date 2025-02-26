/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * CCW device functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/util_path.h"
#include "lib/util_panic.h"
#include "ipl_tools.h"

/*
 * Look up for the device in /sys/devices/ hierarchy.
 *
 * path must be PATH_MAX large and the value will be replaced in place
 */
static int device_sysfs_path(const char *device, char *path, const size_t path_size)
{
	util_assert(device != NULL, "Internal error: device is NULL");
	util_assert(path != NULL, "Internal error: path is NULL");
	util_assert(path_size == PATH_MAX, "Internal error: path_size is '%zu', but must be '%zu'",
		    path_size, PATH_MAX);
	char *buf = util_path_sysfs("block/%s/device", device);

	if (!realpath(buf, path)) {
		free(buf);
		return -1;
	}
	free(buf);
	return 0;
}

/*
 * Check if the specified device number is a valid device number
 * which can be found in the /sys/bus/ccw/drivers/dasd-eckd/
 * structure.
 *
 * This does not work when booting from tape.
 */
int ccw_is_device(const char *busid)
{
	static const char *const driver_paths[] = { "dasd-eckd", "virtio_ccw", "dasd-fba" };
	char *path;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(driver_paths); i++) {
		path = util_path_sysfs("bus/ccw/drivers/%s/%s", driver_paths[i], busid);
		if (access(path, R_OK) == 0) {
			free(path);
			return 1;
		}
		free(path);
	}

	return 0;
}

/*
 * Check if the specified device is a valid virtio subchannel device
 */
int ccw_is_virtio_device(const char *device)
{
	char path[PATH_MAX] = { '\0' };
	unsigned virtio = 0;
	char *path_pattern;

	if (device_sysfs_path(device, path, sizeof(path)) != 0)
		return -1;

	/*
	 * The output has the following format:
	 * /sys/devices/css0/0.0.0000/0.0.0000/virtio0/block/vda
	 */
	path_pattern = util_path_sysfs("devices/css0/%%*[0-9a-f.]/%%*[0-9a-f.]/virtio%%u");
	if (sscanf(path, path_pattern, &virtio) != 1) {
		free(path_pattern);
		return -1;
	}
	free(path_pattern);
	return 0;
}

/*
 * Return CCW Bus ID
 */
void ccw_busid_get(const char *device, char *busid)
{
	char path[PATH_MAX] = { '\0' };
	char *path_pattern;

	if (device_sysfs_path(device, path, sizeof(path)) != 0)
		ERR_EXIT("Could not lookup device number for \"%s\"", device);

	/*
	 * The output has the following format:
	 * /sys/devices/css0/0.0.0119/0.0.3f19/block/dasda
	 * /sys/devices/css0/0.0.0000/0.0.0000/virtio0/block/vda
	 */
	path_pattern = util_path_sysfs("devices/css0/%%*[0-9a-f.]/%%[0-9a-f.]");
	if (sscanf(path, path_pattern, busid) != 1) {
		free(path_pattern);
		ERR_EXIT("Could not lookup device number for \"%s\"", device);
	}
	free(path_pattern);

	return;
}
