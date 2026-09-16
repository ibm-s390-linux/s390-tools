/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Common functions for debugfs data gatherer
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "dg_debugfs.h"
#include "helper.h"
#include "hyptop.h"

#define HYPFS_SUBDIR "/s390_hypfs/"
#define DEBUGFS_MNT_POINT "/sys/kernel/debug"

static char *l_debugfs_dir;

static void l_check_rc(int rc, int exit_on_err)
{
	if (!exit_on_err)
		return;
	if (rc == -EACCES)
		ERR_EXIT("Permission denied, check \"%s/s390_hypfs/\"\n",
			 l_debugfs_dir);
	if (rc != -ENOENT)
		ERR_EXIT("Could not initialize data gatherer (%s)\n",
			 strerror(-rc));
}

static void l_check_rc_final(int rc, int exit_on_err)
{
	if (!exit_on_err)
		return;
	l_check_rc(rc, exit_on_err);
	ERR_EXIT("Could not initialize data gatherer (%s)\n", strerror(-rc));
}

static char *l_debugfs_mount(void)
{
	if (unshare(CLONE_NEWNS))
		return NULL;
	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
		return NULL;
	if (mount("none", DEBUGFS_MNT_POINT, "debugfs", 0, NULL))
		return NULL;
	return ht_strdup(DEBUGFS_MNT_POINT);
}

/*
 * Initialize debugfs data gatherer backend
 */
int dg_debugfs_init(int exit_on_err)
{
	int rc;

	l_debugfs_dir = ht_mount_point_get("debugfs");
	if (!l_debugfs_dir)
		l_debugfs_dir = l_debugfs_mount();
	if (!l_debugfs_dir) {
		if (!exit_on_err)
			return -ENODEV;
		ERR_EXIT("Debugfs is not mounted, try \"mount none -t debugfs "
				 "/sys/kernel/debug\"\n");
	}
	rc = dg_debugfs_vm_init();
	if (rc == 0)
		return 0;
	else
		l_check_rc(rc, exit_on_err);
	rc = dg_debugfs_lpar_init();
	if (rc == 0)
		return 0;
	else
		l_check_rc_final(rc, exit_on_err);
	return rc;
}

/*
 * Open a debugfs file
 */
int dg_debugfs_open(const char *file)
{
	char *path;
	int fh;

	path = ht_alloc(strlen(l_debugfs_dir) + strlen(HYPFS_SUBDIR) +
			strlen(file) + 1);
	path[0] = 0;
	strcat(path, l_debugfs_dir);
	strcat(path, HYPFS_SUBDIR);
	strcat(path, file);
	fh = open(path, O_RDONLY);
	ht_free(path);
	if (fh == -1)
		return -errno;
	else
		return fh;
}
