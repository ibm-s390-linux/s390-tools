/*
 * s390-tools/zipl/include/boot.h
 *   Functions to handle the boot loader data.
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef BOOT_H
#define BOOT_H

#include <sys/types.h>

#include "boot/boot_defs.h"
#include "lib/zt_common.h"
#include "dump/s390_dump.h"

#include "disk.h"
#include "job.h"
#include "zipl.h"

#define STAGE2_BLK_CNT_MAX	24 /* Stage 1b can load up to 24 blocks */
#define STAGE1B_BLK_CNT_MAX	2  /* Stage 1 can load up to 2 blocks */

struct boot_ccw0 {
	uint8_t cmd;
	uint8_t address_hi;
	uint16_t address_lo;
	uint8_t flags;
	uint8_t pad;
	uint16_t count;
} __packed;

/* Boot data structures for FBA disks */

struct boot_fba_locread {
	struct boot_ccw0 locate;
	struct boot_ccw0 read;
} __packed;

struct boot_fba_locdata {
	uint8_t command;
	uint8_t dummy;
	uint16_t blockct;
	uint32_t blocknr;
} __packed;

struct boot_fba_stage0 {
	uint64_t psw;
	uint64_t read_ipl;
	uint64_t tic1;
	struct boot_fba_locread locread[2];
	uint64_t tic1b;
	struct boot_fba_locdata locdata[2];
	uint64_t reserved[4];
	struct boot_info boot_info;
} __packed;

struct boot_fba_stage1b {
	struct boot_fba_locread locread[STAGE2_BLK_CNT_MAX];
	struct boot_fba_locdata locdata[STAGE2_BLK_CNT_MAX];
	uint8_t unused[448];
} __packed;

/* Boot data structures for ECKD disks */

struct boot_eckd_ccw1 {
	uint8_t cmd;
	uint8_t flags;
	uint16_t count;
	uint32_t address;
} __packed;

struct boot_eckd_ssrt {
	struct boot_ccw0 seek;
	struct boot_ccw0 search;
	struct boot_ccw0 tic;
	struct boot_ccw0 read;
} __packed;

struct boot_eckd_seekarg {
	uint16_t pad;
	uint16_t cyl;
	uint16_t head;
	uint8_t sec;
	uint8_t pad2;
} __packed;

struct boot_eckd_cdl_stage0 {
	uint64_t psw;
	struct boot_ccw0 read;
	struct boot_ccw0 tic;
} __packed;

struct boot_eckd_ldl_stage0 {
	uint64_t psw;
	struct boot_ccw0 read_r0;
	struct boot_ccw0 read_r1;
} __packed;

struct boot_eckd_stage1 {
	struct boot_eckd_ssrt ssrt[2];
	struct boot_ccw0 tic1b;
	struct boot_eckd_seekarg seek[2];
	struct boot_info boot_info;
} __packed;

struct boot_eckd_stage1b {
	struct boot_eckd_ssrt ssrt[STAGE2_BLK_CNT_MAX];
	struct boot_eckd_seekarg seek[STAGE2_BLK_CNT_MAX];
	uint8_t unused[64];
} __packed;

/* Stage 2 boot menu parameter structure */

#define BOOT_MENU_ENTRIES		62

struct boot_stage2_params {
	uint16_t flag;
	uint16_t timeout;
	uint16_t banner;
	uint16_t config[BOOT_MENU_ENTRIES + 1];
	uint64_t config_kdump;
} __packed;


/* Tape IPL bootloader parameter structure */

#define BOOT_TAPE_IPL_PARAMS_OFFSET	0x200

struct boot_tape_ipl_params {
	uint64_t parm_addr;
	uint64_t initrd_addr;
	uint64_t load_psw;
};

/* Partition parameter table for multi-volume dump */

struct mvdump_param {
	uint16_t	devno;
	uint32_t	start_blk;
	uint32_t	end_blk;
	uint8_t		blocksize;
	uint8_t		bpt;
	uint8_t		num_heads;
} __packed;

struct mvdump_parm_table {
	uint64_t	timestamp;
	uint16_t	num_param;
	struct mvdump_param param[MAX_DUMP_VOLUMES];
	uint8_t		ssid[MAX_DUMP_VOLUMES];
	unsigned char	reserved[512 - sizeof(uint64_t) - sizeof(uint16_t) -
		(MAX_DUMP_VOLUMES * (sizeof(struct mvdump_param) + 1))];
} __packed;

void boot_get_dump_info(struct boot_info *boot_info, uint8_t dev_type,
			void *param);
void boot_get_ipl_info_ccw(struct boot_info *boot_info, uint8_t dev_type,
			   disk_blockptr_t *bm_ptr, struct disk_info *info);

int boot_check_data(void);
int boot_init_fba_stage0(struct boot_fba_stage0* stage0,
			 disk_blockptr_t* stage2_list,
			 blocknum_t stage2_count);
int boot_get_fba_stage2(void** data, size_t* size, struct job_data* job);
void boot_init_eckd_ldl_stage0(struct boot_eckd_ldl_stage0 *stage0);
void boot_init_eckd_cdl_stage0(struct boot_eckd_cdl_stage0 *stage0);
int boot_init_eckd_stage1(struct boot_eckd_stage1 *stage1,
			  disk_blockptr_t *stage1b_list,
			  blocknum_t stage1b_count);
int boot_init_eckd_stage1b(struct boot_eckd_stage1b *stage1b,
			   disk_blockptr_t *stage2_list,
			   blocknum_t stage2_count);
int boot_init_fba_stage1b(struct boot_fba_stage1b *stage1b,
			  disk_blockptr_t *stage2_list,
			  blocknum_t stage2_count);
int boot_get_eckd_stage2(void** data, size_t* size, struct job_data* job);
int boot_get_stage3_parms(void **buffer, size_t *bytecount, address_t parm_addr,
			  address_t initrd_addr, size_t initrd_len,
			  address_t entry, int extra_parm, uint64_t flags,
			  address_t image_addr, size_t image_len,
			  address_t envblk_addr, size_t envblk_len);
int boot_get_tape_ipl(void** data, size_t* size, address_t parm_addr,
		      address_t initrd_addr, address_t image_addr);
int boot_get_tape_dump(void **data, size_t *size,
		       const struct stage2dump_parm_tail *stage2dump_parms);
int boot_get_eckd_dump_stage2(void **data, size_t *size,
			      const struct stage2dump_parm_tail *stage2dump_parms);
int boot_get_eckd_ld_ipl_br(void **br_ptr, size_t *size_ptr,
			    disk_blockptr_t *table, struct disk_info *info);
int boot_get_eckd_mvdump_stage2(void **data, size_t *size,
				const struct stage2dump_parm_tail *stage2dump_parms,
				const struct mvdump_parm_table *mv_parm_table);
int boot_get_fba_dump_stage2(void **data, size_t *size,
			     const struct stage2dump_parm_tail *stage2dump_parms);

#endif /* BOOT_H */
