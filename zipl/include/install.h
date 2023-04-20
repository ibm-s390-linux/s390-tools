/*
 * s390-tools/zipl/include/install.h
 *   Functions handling the installation of the boot loader code onto disk.
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef INSTALL_H
#define INSTALL_H

#include "disk.h"
#include "job.h"
#include "zipl.h"
#include "boot/boot_defs.h"

#define NR_PROGRAM_TABLES NR_BLKPTR_FORMATS

enum program_component_id {
	COMPONENT_ID_HEAP_AREA,
	COMPONENT_ID_STACK_AREA,
	COMPONENT_ID_LOADER_SIGNATURE,
	COMPONENT_ID_LOADER,
	COMPONENT_ID_PARAMETERS,
	COMPONENT_ID_IMAGE_SIGNATURE,
	COMPONENT_ID_KERNEL_IMAGE,
	COMPONENT_ID_PARMLINE,
	COMPONENT_ID_RAMDISK_SIGNATURE,
	COMPONENT_ID_RAMDISK,
	COMPONENT_ID_ENVBLK,
	COMPONENT_ID_SEGMENT_FILE,
	NR_PROGRAM_COMPONENTS
};

struct component_loc {
	address_t addr;
	size_t size;
};

struct component_footer {
	component_type type;
	const char *desc;
};

struct program_component {
	struct component_loc loc;
	disk_blockptr_t *list;
	blocknum_t count;
};

struct program_table {
	disk_blockptr_t table;
	disk_blockptr_t *stage1b_list;
	blocknum_t stage1b_count;
};

/* Bootloader Installation Set */
struct install_set {
	struct program_table tables[NR_PROGRAM_TABLES];
	struct program_component *components[NR_PROGRAM_COMPONENTS];
	int nr_tables; /* number of "similar" program tables to be installed */
	int nr_menu_entries;
	int fd;
	char *device;
	char *filename;
	char *dump_mount_point;
	unsigned int dump_tmp_dir_created:1;
	unsigned int dump_mounted:1;
	struct disk_info *info;
	disk_blockptr_t scsi_dump_sb_blockptr;
};

extern struct component_footer component_footers[NR_PROGRAM_COMPONENTS];

static inline component_type component_type_by_id(enum program_component_id id)
{
	return component_footers[id].type;
}

static inline const char *component_desc_by_id(enum program_component_id id)
{
	return component_footers[id].desc;
}

static inline struct program_component *get_component(struct install_set *bis,
						      int i, int j)
{
	return bis->components[i] + j;
}

int prepare_bootloader(struct job_data *job, struct install_set *bis);
int install_bootloader(struct job_data *job, struct install_set *bis);
void free_bootloader(struct install_set *bis);
int install_tapeloader(const char* device, const char* image,
		       const char* parmline, const char* ramdisk,
		       address_t image_addr, address_t parm_addr,
		       address_t initrd_addr);
int install_dump(const char* device, struct job_target_data* target,
		 uint64_t mem);
int install_mvdump(char* const device[], struct job_target_data* target,
		   int device_count, uint64_t mem, uint8_t force);

int install_fba_stage1b(int fd, disk_blockptr_t **stage1b_list,
			blocknum_t *stage1b_count, disk_blockptr_t *stage2_list,
			blocknum_t stage2_count, struct disk_info *info);
int install_eckd_stage1b(int fd, disk_blockptr_t **stage1b_list,
			 blocknum_t *stage1b_count,
			 disk_blockptr_t *stage2_list,
			 blocknum_t stage2_count, struct disk_info *info);
int rewind_tape(int fd);

#endif /* INSTALL_H */
