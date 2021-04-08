/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include "lib/util_log.h"

#include "common.h"
#include "overlay.h"

#define ROOT_DIR "/"

struct vmcore_overlay {
	struct vmcore_proxy *vmcore_proxy;
	char mount_point[PATH_MAX];
	bool fuse_debug;
};

static int vmcore_fuse_getattr(const char *path, struct stat *stbuf)
{
	struct vmcore_overlay *overlay = fuse_get_context()->private_data;
	int ret = 0;

	memset(stbuf, 0, sizeof(struct stat));

	if (strcmp(path, ROOT_DIR) == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path + 1, VMCORE_FILE) == 0) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = vmcore_proxy_size(overlay->vmcore_proxy);
	} else {
		ret = -ENOENT;
	}

	return ret;
}

static int vmcore_fuse_readdir(const char *path, void *buf,
			       fuse_fill_dir_t filler, off_t offset,
			       struct fuse_file_info *fi)
{
	(void)offset;
	(void)fi;

	if (strcmp(path, ROOT_DIR) != 0)
		return -ENOENT;

	/* We have only one file */
	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, VMCORE_FILE, NULL, 0);

	return 0;
}

static int vmcore_fuse_open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path + 1, VMCORE_FILE) != 0)
		return -ENOENT;

	if ((fi->flags & O_ACCMODE) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int vmcore_fuse_read(const char *path, char *buf, size_t size,
			    off_t offset, struct fuse_file_info *fi)
{
	(void)fi;

	if (strcmp(path + 1, VMCORE_FILE) != 0)
		return -ENOENT;

	struct vmcore_overlay *overlay = fuse_get_context()->private_data;

	return read_vmcore_proxy_at(overlay->vmcore_proxy, offset, buf, size);
}

static int setup_fuse_args(struct fuse_args *args, const char *mount_point,
			   bool debug)
{
	int ret;

	ret = fuse_opt_add_arg(args, NAME);
	if (ret)
		goto done;

	/* Single-threaded */
	ret = fuse_opt_add_arg(args, "-s");
	if (ret)
		goto done;

	/* Foreground */
	ret = fuse_opt_add_arg(args, "-f");
	if (ret)
		goto done;

	/* Debugging */
	if (debug) {
		ret = fuse_opt_add_arg(args, "-d");
		if (ret)
			goto done;
	}

	ret = fuse_opt_add_arg(args, mount_point);
	if (ret)
		goto done;

done:
	if (ret)
		return -1;
	else
		return 0;
}

struct vmcore_overlay *make_vmcore_overlay(struct vmcore_proxy *vmcore_proxy,
					   const char *mount_point,
					   bool fuse_debug)
{
	struct vmcore_overlay *overlay;

	util_log_print(UTIL_LOG_INFO, "vmcore overlay: mountpoint=%s\n",
		       mount_point);

	overlay = malloc(sizeof(struct vmcore_overlay));
	if (!overlay) {
		util_log_print(UTIL_LOG_ERROR, "malloc failed\n");
		return NULL;
	}

	overlay->vmcore_proxy = vmcore_proxy;
	strncpy(overlay->mount_point, mount_point,
		sizeof(overlay->mount_point) - 1);
	/* Ensure null termination */
	overlay->mount_point[sizeof(overlay->mount_point) - 1] = '\0';
	overlay->fuse_debug = fuse_debug;

	return overlay;
}

void destroy_vmcore_overlay(struct vmcore_overlay *overlay)
{
	free(overlay);
}

/*
 * FUSE file system operations
 */
static struct fuse_operations vmcore_fuse_ops = {
	.getattr = vmcore_fuse_getattr,
	.readdir = vmcore_fuse_readdir,
	.open = vmcore_fuse_open,
	.read = vmcore_fuse_read,
};

int serve_vmcore_overlay(struct vmcore_overlay *overlay)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	int ret;

	util_log_print(UTIL_LOG_DEBUG, "vmcore overlay: FUSE main\n");

	ret = setup_fuse_args(&args, overlay->mount_point, overlay->fuse_debug);
	if (ret < 0)
		goto free_args;

	/* Create mount point */
	ret = mkdir(overlay->mount_point, 0755);
	if (ret < 0) {
		util_log_print(UTIL_LOG_ERROR, "mkdir syscall failed (%s)\n",
			       strerror(errno));
		goto free_args;
	}

	/*
	 * Run file system, blocks until a signal has been received or an error
	 * occurred.
	 */
	fuse_main(args.argc, args.argv, &vmcore_fuse_ops, overlay);

	/* Remove mount point */
	rmdir(overlay->mount_point);

	ret = 0;

free_args:

	fuse_opt_free_args(&args);

	return ret;
}
