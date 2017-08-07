/*
 * cmsfs-fuse - CMS EDF filesystem support for Linux
 *
 * Data structures
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _CMSFS_H
#define _CMSFS_H

#include <iconv.h>
#include <search.h>

#include "lib/util_list.h"

#define COMP "cmsfs-fuse: "
extern struct cmsfs cmsfs;

/* conversion between absolute and relative addresses */
#define ABS(x)			((off_t) (x - 1) * cmsfs.blksize)
#define REL(x)			((x / cmsfs.blksize) + 1)

struct fcache_entry {
	/* filename used as hash key */
	char		name[18];
	/* location of fst entry */
	off_t		fst_addr;
	/* filename string address */
	char		*str;
};

enum cmsfs_mode {
	BINARY_MODE,
	TEXT_MODE,
	TYPE_MODE,
};

/* the per device global struture */
struct cmsfs {
	/* name of the block device, e.g. /dev/dasde */
	const char	*device;
	/* global file descriptor of the underlying block device */
	int		fd;
	/* start of mmap of the whole block device */
	char		*map;
	/* size of the disk */
	off_t		size;
	/* formatted blocksize */
	int		blksize;
	/* number of 512 byte blocks per block */
	int		nr_blocks_512;
	/* device is read only */
	int		readonly;
	/* access permission for other users */
	int		allow_other;
	/* offset to label */
	off_t		label;
	/* offset to file directory root FST */
	off_t		fdir;
	/* offset to allocation map  */
	off_t		amap;
	/* depth of directories */
	int		dir_levels;
	/* depth of allocation maps */
	int		amap_levels;
	/* files count on the device */
	int		files;
	/* conversion mode */
	enum cmsfs_mode	mode;
	/* iconv codepage options */
	const char	*codepage_from;
	const char	*codepage_to;
	iconv_t		iconv_from;
	iconv_t		iconv_to;

	/* disk stats */
	int		total_blocks;
	int		used_blocks;
	/* blocks reserved for outstanding meta data */
	int		reserved_blocks;

	/* constants */
	int		fixed_ptrs_per_block;
	int		var_ptrs_per_block;
	int		bits_per_data_block;
	int		bits_per_ptr_block;
	int		data_block_mask;
	off_t		amap_bytes_per_block;

	/* file cache */
	struct		fcache_entry *fcache;
	int		fcache_used;
	int		fcache_max;
	struct hsearch_data htab;
};

#define MAX_TYPE_LEN		9

struct filetype {
	char		name[MAX_TYPE_LEN];
	struct util_list_node	list;
};

#define NULL_BLOCK		0
#define VAR_FILE_END		1

#define PTRS_PER_BLOCK		(cmsfs.fixed_ptrs_per_block)
#define VPTRS_PER_BLOCK		(cmsfs.var_ptrs_per_block)
#define DATA_BLOCK_MASK		(cmsfs.data_block_mask)
#define BITS_PER_DATA_BLOCK	(cmsfs.bits_per_data_block)
#define BYTES_PER_BLOCK		(cmsfs.amap_bytes_per_block)

extern int get_device_info(struct cmsfs *cmsfs);
extern int scan_conf_file(struct util_list *list);
extern int is_edf_char(int c);

#ifndef _CMSFS_FSCK
int _read(void *, size_t, off_t);
int _write(const void *, size_t, off_t);
int _zero(off_t, size_t);
off_t get_fixed_pointer(off_t);

off_t get_free_block(void);
off_t get_zero_block(void);
void free_block(off_t);
#endif

#endif
