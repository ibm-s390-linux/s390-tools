/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions to map logical addresses to physical ones
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <linux/fs.h>
#include <linux/fiemap.h>

#include "disk.h"
#include "error.h"
#include "misc.h"

#ifndef REISERFS_SUPER_MAGIC
#define REISERFS_SUPER_MAGIC	0x52654973
#endif /* not REISERFS_SUPER_MAGIC */

#ifndef REISERFS_IOC_UNPACK
#define REISERFS_IOC_UNPACK	_IOW(0xCD, 1, long)
#endif /* not REISERFS_IOC_UNPACK */

/**
 * Filesystem-specific hook.
 * Do whatever needed before mapping logical address to physical one
 */
static int fs_premap_hook(int fd)
{
	struct statfs buf;

	/* Get file system type */
	if (fstatfs(fd, &buf)) {
		error_reason(strerror(errno));
		return -1;
	}
	switch (buf.f_type) {
	case REISERFS_SUPER_MAGIC:
		/* Files on ReiserFS need unpacking */
		if (ioctl(fd, REISERFS_IOC_UNPACK, 1)) {
			error_reason("Could not unpack ReiserFS file");
			return -1;
		}
		break;
	default:
		break;
	}
	return 0;
}

/**
 * Find a disk address for a file system block,
 * where a specified byte of the file body is located
 *
 * FD: file descriptor
 * OFFSET: offset of the byte in the file body
 * MAPPED: resulted disk address
 * FS_BLOCK_SIZE : file system block size in bytes
 */
int fs_map(int fd, uint64_t offset, blocknum_t *mapped,
	   int fs_block_size)
{
	struct fiemap *fiemap;
	int fiemap_size;
	int map_offset;
	int block;

	if (fs_premap_hook(fd))
		return -1;
	/*
	 * First try FIEMAP, more complicated to set up
	 */
	fiemap_size = sizeof(struct fiemap) + sizeof(struct fiemap_extent);

	fiemap = misc_malloc(fiemap_size);
	if (!fiemap)
		return -1;
	memset(fiemap, 0, fiemap_size);

	fiemap->fm_extent_count = 1;
	fiemap->fm_flags = FIEMAP_FLAG_SYNC;
	fiemap->fm_start = offset;
	fiemap->fm_length = fs_block_size;

	if (ioctl(fd, FS_IOC_FIEMAP, (unsigned long)fiemap)) {
		/* FIEMAP failed, fall back to FIBMAP */
		block = offset / fs_block_size;
		if (ioctl(fd, FIBMAP, &block)) {
			error_reason("Could not get file mapping");
			free(fiemap);
			return -1;
		}
		*mapped = block;
	} else {
		if (fiemap->fm_mapped_extents) {
			if (fiemap->fm_extents[0].fe_flags &
			    FIEMAP_EXTENT_ENCODED) {
				error_reason("File mapping is encoded");
				free(fiemap);
				return -1;
			}
			/*
			 * returned extent may start prior to our request
			 */
			map_offset = fiemap->fm_start -
				fiemap->fm_extents[0].fe_logical;
			*mapped = fiemap->fm_extents[0].fe_physical +
				map_offset;
			/* set mapped to fs block units */
			*mapped = *mapped / fs_block_size;
		} else {
			*mapped = 0;
		}
	}
	free(fiemap);
	return 0;
}
