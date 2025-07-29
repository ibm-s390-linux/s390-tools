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
#include "misc.h"
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

/* Types of SCSI disk layouts */
enum scsi_layout {
	scsi_layout_pcbios,
	scsi_layout_sun,
	scsi_layout_sgi,
	scsi_layout_unknown
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

/* A part of Bootloader Installation Set specific for an individual mirror */
struct install_set_mirror {
	struct program_table tables[NR_PROGRAM_TABLES];
	struct program_component *components[NR_PROGRAM_COMPONENTS];
	char *basetmp;
	unsigned int print_details:1;
	unsigned int skip_prepare_blocklist:1;
};

/* Bootloader Installation Set */
struct install_set {
	int nr_menu_entries;
	struct misc_fd mfd;
	struct install_set_mirror mirrors[MAX_TARGETS];
	char *filename;
	unsigned int skip_prepare_device:1;
	unsigned int tmp_filename_created:1;
	struct device_info *info;
	disk_blockptr_t scsi_dump_sb_blockptr;
};

extern struct component_footer component_footers[NR_PROGRAM_COMPONENTS];

/* Determine SCSI disk layout from the specified BOOTBLOCK. */
static inline enum scsi_layout get_scsi_layout(unsigned char *bootblock)
{
	if ((bootblock[510] == 0x55) && (bootblock[511] == 0xaa))
		return scsi_layout_pcbios;
	else if ((bootblock[508] == 0xda) && (bootblock[509] == 0xbe))
		return scsi_layout_sun;
	else if ((bootblock[0] == 0x0b) && (bootblock[1] == 0xe5) &&
		 (bootblock[2] == 0xa9) && (bootblock[3] == 0x41))
		return scsi_layout_sgi;
	return scsi_layout_unknown;
}

static inline component_type component_type_by_id(enum program_component_id id)
{
	return component_footers[id].type;
}

static inline const char *component_desc_by_id(enum program_component_id id)
{
	return component_footers[id].desc;
}

static inline struct program_component *get_component(struct install_set *bis,
						      int mirror_id,
						      int i, int j)
{
	return bis->mirrors[mirror_id].components[i] + j;
}

int prepare_bootloader(struct job_data *job, struct install_set *bis);
int install_bootloader(struct job_data *job, struct install_set *bis);
int post_install_bootloader(struct job_data *job, struct install_set *bis);
void free_bootloader(struct install_set *bis, struct job_data *job);
int install_tapeloader(const char* device, const char* image,
		       const char* parmline, const char* ramdisk,
		       address_t image_addr, address_t parm_addr,
		       address_t initrd_addr);
int install_dump(const char *device, struct job_target_data *target,
		 uint64_t mem, bool no_compress);
int install_mvdump(char* const device[], struct job_target_data* target,
		   int device_count, uint64_t mem, uint8_t force);

int install_fba_stage1b(struct misc_fd *mfd, disk_blockptr_t **stage1b_list,
			blocknum_t *stage1b_count, disk_blockptr_t *stage2_list,
			blocknum_t stage2_count, int fs_block_size,
			struct disk_info *info);
int install_eckd_stage1b(struct misc_fd *mfd, disk_blockptr_t **stage1b_list,
			 blocknum_t *stage1b_count,
			 disk_blockptr_t *stage2_list,
			 blocknum_t stage2_count, int fs_block_size,
			 struct disk_info *info);
int rewind_tape(int fd);

#endif /* INSTALL_H */
