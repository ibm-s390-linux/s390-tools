/*
 * s390-tools/zipl/include/disk.h
 *   Functions to handle disk layout specific operations.
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef DISK_H
#define DISK_H

#include <stdint.h>
#include <sys/types.h>

#include "misc.h"
#include "zipl.h"
#include "lib/vtoc.h"

#define FS_MAP_ERROR    "Could not get file mapping"


/* Type for representing disk block numbers */
typedef uint64_t blocknum_t;

/* Pointer to block on a disk with cyl/head/sec layout */
struct disk_blockptr_chs {
	unsigned int cyl;
	int head;
	int sec;
	int size;
	int blockct;
};

/* Pointer to a block on a disk with linear layout */
struct disk_blockptr_linear {
	blocknum_t block;
	int size;
	int blockct;
};

/* This represents in-memory pointer to a block on disk */
typedef union {
	struct disk_blockptr_chs chs;
	struct disk_blockptr_linear linear;
} disk_blockptr_t;

/* Disk type identifier */
typedef enum {
	disk_type_scsi,
	disk_type_fba,
	disk_type_diag,
	disk_type_eckd_ldl,
	disk_type_eckd_cdl,
} disk_type_t;

struct disk_ext_type {
	disk_type_t type;
	bool is_nvme;
};

/* targetbase definition */
typedef enum {
	defined_as_device,
	defined_as_name,
	undefined
} definition_t;

/* Physical disk information type */
struct disk_info {
	dev_t disk;
	disk_type_t type;
	dev_t partition;
	int devno;
	int partnum;
	int phy_block_size;
	uint64_t phy_blocks;
	struct hd_geometry geo;
	definition_t targetbase_def;
	int is_nvme;
};

/* Logical device information type */
struct device_info {
	dev_t device; /* logical device for bootmap creation */
	char *name; /* name of the logical device as retrieved
		     *  from "/proc/partitions"
		     */
	char *drv_name; /* name of the driver managing the logical device
			 * as retrieved from "/proc/devices", or evaluated
			 */
	int fs_block_size;
	struct disk_info base[MAX_TARGETS]; /* array of physical disks for
					     * bootstrap blocks recording
					     */
};

struct file_range {
	off_t offset;
	size_t len;
};

struct job_target_data;

int device_get_info(const char *device, struct job_target_data *target,
		    struct device_info **info);
int disk_get_ext_type(const char *device, struct disk_ext_type *ext_type,
		      int disk_id);
int disk_is_tape(const char *device);
int disk_type_is_scsi(struct disk_ext_type *ext_type);
int disk_type_is_eckd_ldl(struct disk_ext_type *ext_type);
int disk_type_is_nvme(struct disk_ext_type *ext_type);
int disk_type_is_eckd(disk_type_t type);

int device_info_set_fs_block(const char *filename, struct device_info *info);
int device_get_info_from_file(const char *filename,
			      struct job_target_data *target,
			      struct device_info **info);
void device_free_info(struct device_info *info);
char *disk_get_type_name(disk_type_t type);
char *disk_get_ipl_type(disk_type_t type, int is_dump);
int disk_is_large_volume(struct disk_info* info);
int disk_cyl_from_blocknum(blocknum_t blocknum, struct disk_info* info);
int disk_head_from_blocknum(blocknum_t blocknum, struct disk_info* info);
int disk_sec_from_blocknum(blocknum_t blocknum, struct disk_info* info);
void disk_blockptr_from_blocknum(disk_blockptr_t* ptr, blocknum_t blocknum,
				 struct disk_info *info);
int disk_write_block_aligned(struct misc_fd *mfd, const void *data,
			     size_t bytecount, disk_blockptr_t *block,
			     int fs_block_size, struct disk_info *info);
blocknum_t disk_write_block_buffer(struct misc_fd *fd, int fd_is_basedisk,
				   const void* buffer, size_t bytecount,
				   disk_blockptr_t** blocklist,
				   int fs_block_size, struct disk_info *info);
blocknum_t disk_write_block_buffer_align(struct misc_fd *mfd, int fd_is_basedisk,
					 const void *buffer, size_t bytecount,
					 disk_blockptr_t **blocklist,
					 int fs_block_size,
					 struct disk_info *info, int align,
					 off_t *offset);
void disk_print_devt(dev_t d);
void disk_print_devname(dev_t d);
void prepare_footnote_ptr(int source, char *ptr);
void print_footnote_ref(int source, const char *prefix);
void device_print_info(struct device_info *info, struct job_target_data *td);
int disk_is_zero_block(disk_blockptr_t *block, struct disk_info *info);
blocknum_t disk_compact_blocklist(disk_blockptr_t* list, blocknum_t count,
				  struct disk_info *info);
blocknum_t disk_get_blocklist_from_file(const char* filename,
					struct file_range *reg,
					disk_blockptr_t **blocklist,
					int fs_block_size,
					struct disk_info *info);
int disk_check_subchannel_set(int devno, dev_t device, char* dev_name);
int fs_map(int fd, uint64_t offset, blocknum_t *mapped, int fs_block_size);

#endif /* not DISK_H */
