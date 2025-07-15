/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * NGDump dump input format
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <sys/mount.h>

#include "lib/util_libc.h"

#include "zgetdump.h"
#include "zg.h"
#include "dfi.h"
#include "ngdump.h"

/*
 * File local static data
 */
static struct {
	char *device;
	char *mount_point;
	struct ngdump_meta meta;
} l;

static int open_dump_file(void)
{
	char *mount_point = NULL;
	char *filename = NULL;

	mount_point = util_strdup("/tmp/zdump-ngdump-XXXXXX");

	/* Create a mount point directory */
	if (mkdtemp(mount_point) == NULL) {
		warnx("Could not create directory \"%s\"", mount_point);
		goto fail_free;
	}

	if (mount(l.device, mount_point, NGDUMP_FSTYPE, MS_RDONLY, NULL)) {
		warnx("Could not mount \"%s\" (%s)", l.device, strerror(errno));
		goto fail_rmdir;
	}

	util_asprintf(&filename, "%s/%s", mount_point, l.meta.file);

	g.fh = zg_open(filename, O_RDONLY, ZG_CHECK);
	free(filename);
	if (!g.fh)
		goto fail_umount;

	l.mount_point = mount_point;

	return 0;

fail_umount:
	umount(mount_point);
fail_rmdir:
	rmdir(mount_point);
fail_free:
	free(mount_point);
	return -1;
}

static void cleanup(void)
{
	if (l.mount_point) {
		zg_close(g.fh);
		g.fh = NULL;
		umount(l.mount_point);
		rmdir(l.mount_point);
		free(l.mount_point);
		l.mount_point = NULL;
	}
	if (l.device) {
		g.fh = zg_open(l.device, O_RDONLY, ZG_CHECK);
		free(l.device);
		l.device = NULL;
	}
}

static int dfi_ngdump_init(void)
{
	/*
	 * Copy path to the dump partition and close its file descriptor
	 * because we don't read raw partitions with NGDump but use a
	 * file system instead.
	 */
	l.device = util_strdup(g.fh->path);
	zg_close(g.fh);
	g.fh = NULL;

	/*
	 * First, we need to read information contained in the meta-data
	 * file because it will tell us where a dump file on the file system
	 * is located.
	 */
	if (ngdump_read_meta_from_device(l.device, &l.meta)) {
		cleanup();
		return -1;
	}

	/* No dump made yet but partition is a valid NGDump partition. */
	if (!l.meta.file) {
		cleanup();
		return -1;
	}

	/*
	 * Now we open the dump file and initialize the ELF DFI.
	 * After that, the control is passed to the ELF DFI.
	 */
	if (open_dump_file()) {
		cleanup();
		return -1;
	}

	if (dfi_elf.init()) {
		cleanup();
		return -1;
	}

	return 0;
}

static void dfi_ngdump_exit(void)
{
	if (dfi_elf.exit)
		dfi_elf.exit();
	cleanup();
}

/*
 * NGDump DFI operations
 */
struct dfi dfi_ngdump = {
	.name		= "elf",
	.init		= dfi_ngdump_init,
	.exit		= dfi_ngdump_exit,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
