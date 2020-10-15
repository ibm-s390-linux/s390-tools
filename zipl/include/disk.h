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

#include "zipl.h"


/* Type for representing disk block numbers */
typedef uint64_t blocknum_t;

/* Pointer to block on a disk with cyl/head/sec layout */
struct disk_blockptr_chs {
	int cyl;
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

/* Pointer to a block on disk */
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

/* from linux/hdregs.h */
struct hd_geometry {
	unsigned char heads;
	unsigned char sectors;
	unsigned short cylinders;
	unsigned long start;
};

/* Disk information source */
typedef enum {
	source_auto,
	source_user,
	source_script
} source_t;

/* targetbase definition */
typedef enum {
	defined_as_device,
	defined_as_name
} definition_t;

/* Disk information type */
struct disk_info {
	disk_type_t type;
	dev_t device;
	dev_t partition;
	int devno;
	int partnum;
	int phy_block_size;
	int fs_block_size;
	uint64_t phy_blocks;
	struct hd_geometry geo;
	char* name;
	char* drv_name;
	source_t source;
	definition_t targetbase;
};

struct file_range {
	off_t offset;
	size_t len;
};

struct job_target_data;

int disk_get_info(const char* device, struct job_target_data* target,
		  struct disk_info** info);
int disk_is_tape(const char* device);
int disk_is_scsi(const char* device, struct job_target_data* target);
int disk_get_info_from_file(const char* filename,
			    struct job_target_data* target,
			    struct disk_info** info);
void disk_free_info(struct disk_info* info);
char* disk_get_type_name(disk_type_t type);
int disk_is_large_volume(struct disk_info* info);
int disk_cyl_from_blocknum(blocknum_t blocknum, struct disk_info* info);
int disk_head_from_blocknum(blocknum_t blocknum, struct disk_info* info);
int disk_sec_from_blocknum(blocknum_t blocknum, struct disk_info* info);
void disk_blockptr_from_blocknum(disk_blockptr_t* ptr, blocknum_t blocknum,
				 struct disk_info* info);
int disk_write_block_aligned(int fd, const void* data, size_t bytecount,
	  		     disk_blockptr_t* block, struct disk_info* info);
blocknum_t disk_write_block_buffer(int fd, int fd_is_basedisk,
				   const void* buffer, size_t bytecount,
				   disk_blockptr_t** blocklist,
				   struct disk_info *info);
blocknum_t disk_write_block_buffer_align(int fd, int fd_is_basedisk,
					 const void *buffer, size_t bytecount,
					 disk_blockptr_t **blocklist,
					 struct disk_info *info, int align,
					 off_t *offset);
void disk_print_devt(dev_t d);
void disk_print_info(struct disk_info* info);
int disk_is_zero_block(disk_blockptr_t* block, struct disk_info* info);
blocknum_t disk_compact_blocklist(disk_blockptr_t* list, blocknum_t count,
				  struct disk_info* info);
blocknum_t disk_get_blocklist_from_file(const char* filename,
					struct file_range *reg,
					disk_blockptr_t** blocklist,
					struct disk_info* pinfo);
int disk_check_subchannel_set(int devno, dev_t device, char* dev_name);
void disk_print_geo(struct disk_info *data);

#endif /* not DISK_H */
