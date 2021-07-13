/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * FUSE functions
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#define FUSE_USE_VERSION 30

#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "zgetdump.h"

#define DUMP_PATH_MAX	100

/*
 * File local static data
 */
static struct {
	char		path[DUMP_PATH_MAX];
	struct stat	stat_root;
	struct stat	stat_dump;
} l;

/*
 * Initialize default values for stat buffer
 */
static void stat_default_init(struct stat *stat)
{
	if (dfi_attr_time()) {
		stat->st_mtime = dfi_attr_time()->tv_sec;
		stat->st_ctime = dfi_attr_time()->tv_sec;
		stat->st_atime = dfi_attr_time()->tv_sec;
	} else {
		stat->st_mtime = zg_stat(g.fh)->st_mtime;
		stat->st_ctime = zg_stat(g.fh)->st_ctime;
		stat->st_atime = zg_stat(g.fh)->st_atime;
	}
	stat->st_uid = geteuid();
	stat->st_gid = getegid();
}

/*
 * Initialize stat buffer for root directory
 */
static void stat_root_init(void)
{
	stat_default_init(&l.stat_root);
	l.stat_root.st_mode = S_IFDIR | 0500;
	l.stat_root.st_nlink = 2;
}

/*
 * Initialize stat buffer for dump
 */
static void stat_dump_init(void)
{
	stat_default_init(&l.stat_dump);
	l.stat_dump.st_mode = S_IFREG | 0400;
	l.stat_dump.st_nlink = 1;
	l.stat_dump.st_size = dfo_size();
	l.stat_dump.st_blksize = 4096;
	l.stat_dump.st_blocks = l.stat_dump.st_size / 4096;
}

/*
 * FUSE callback: Getattr
 */
static int zfuse_getattr(const char *path, struct stat *stat)
{
	if (strcmp(path, "/") == 0) {
		*stat = l.stat_root;
		return 0;
	}
	if (strcmp(path, l.path) == 0) {
		*stat = l.stat_dump;
		return 0;
	}
	return -ENOENT;
}

/*
 * FUSE callback: Readdir - Return ".", ".." and dump file
 */
static int zfuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);
	filler(buf, &l.path[1], NULL, 0, 0);
	return 0;
}

/*
 * FUSE callback: Open
 */
static int zfuse_open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, l.path) != 0)
		return -ENOENT;
	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;
	l.stat_dump.st_atime = time(NULL);
	return 0;
}

/*
 * FUSE callback: Read
 */
static int zfuse_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;

	if (strcmp(path, l.path) != 0)
		return -ENOENT;
	dfo_seek(offset);
	dfo_read(buf, size);
	return size;
}

/*
 * FUSE callback: Statfs
 */
static int zfuse_statfs(const char *path, struct statvfs *buf)
{
	(void) path;

	buf->f_bsize = buf->f_frsize = 4096;
	buf->f_blocks = dfo_size() / 4096;
	buf->f_bfree = buf->f_bavail = 0;
	buf->f_files = 1;
	buf->f_ffree = 0;
	buf->f_namemax = strlen(l.path) + 1;
	return 0;
}

/*
 * FUSE operations
 */
static struct fuse_operations zfuse_ops = {
	.getattr	= zfuse_getattr,
	.readdir	= zfuse_readdir,
	.open		= zfuse_open,
	.read		= zfuse_read,
	.statfs		= zfuse_statfs,
};

/*
 * Add additional FUSE arguments
 */
static void add_argv_fuse(struct fuse_args *args)
{
	int i;

	if (g.opts.argc_fuse == 0)
		return;
	STDERR("Adding Fuse options: ");
	for (i = 0; i < g.opts.argc_fuse; i++) {
		STDERR("%s ", g.opts.argv_fuse[i]);
		fuse_opt_add_arg(args, g.opts.argv_fuse[i]);
	}
	STDERR("\n");
}

/*
 * Mount dump
 *
 * Add additional FUSE options:
 * - s....................: Disable multi-threaded operation
 * - o fsname.............: File system name (used for umount)
 * - o ro.................: Read only
 * - o default_permissions: Enable permission checking by kernel
 */
int zfuse_mount_dump(void)
{
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	char tmp_str[PATH_MAX];

	if (!dfi_feat_seek())
		ERR_EXIT("Mounting not possible for %s dumps", dfi_name());
	fuse_opt_add_arg(&args, "zgetdump");
	fuse_opt_add_arg(&args, "-s");
	snprintf(tmp_str, sizeof(tmp_str),
		 "-ofsname=%s,ro,default_permissions,nonempty",
		 g.opts.device);
	fuse_opt_add_arg(&args, tmp_str);
	fuse_opt_add_arg(&args, g.opts.mount_point);
	add_argv_fuse(&args);
	stat_root_init();
	stat_dump_init();
	snprintf(l.path, sizeof(l.path), "/dump.%s", dfo_name());
	return fuse_main(args.argc, args.argv, &zfuse_ops, NULL);
}

/*
 * Unmount dump
 */
void zfuse_umount(void)
{
	char umount_cmd[PATH_MAX];
	char *umount_tool;
	struct stat sbuf;
	int rc;

	if (stat("/usr/bin/fusermount", &sbuf) == 0)
		umount_tool = "/usr/bin/fusermount -u";
	else if (stat("/bin/fusermount", &sbuf) == 0)
		umount_tool = "/bin/fusermount -u";
	else
		umount_tool = "umount";

	snprintf(umount_cmd, sizeof(umount_cmd), "%s %s", umount_tool,
		 g.opts.mount_point);
	rc = system(umount_cmd);

	if (rc == -1)
		ERR_EXIT_ERRNO("\"%s\" failed", umount_cmd);
	if (rc > 0)
		ERR_EXIT("\"%s\" failed", umount_cmd);
	exit(0);
}
