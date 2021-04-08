/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>

#include "lib/util_log.h"

#include "mount.h"

int mount_debugfs(const char *target)
{
	int ret;

	util_log_print(UTIL_LOG_INFO, "Mount debugfs on %s\n", target);

	ret = mount("none", target, "debugfs", 0, NULL);
	if (ret) {
		util_log_print(UTIL_LOG_ERROR, "mount syscall failed (%s)\n",
			       strerror(errno));
		return -1;
	}

	return 0;
}

int bind_mount(const char *src, const char *target)
{
	int ret;

	util_log_print(UTIL_LOG_INFO, "Bind mount %s on %s\n", src, target);

	ret = mount(src, target, "", MS_BIND, NULL);
	if (ret) {
		util_log_print(UTIL_LOG_ERROR, "mount syscall failed (%s)\n",
			       strerror(errno));
		return -1;
	}

	return 0;
}

int unmount_detach(const char *target)
{
	int ret;

	util_log_print(UTIL_LOG_INFO, "Unmount detach %s\n", target);

	ret = umount2(target, MNT_DETACH);
	if (ret) {
		util_log_print(UTIL_LOG_ERROR, "umount2 syscall failed (%s)\n",
			       strerror(errno));
		return -1;
	}

	return 0;
}
