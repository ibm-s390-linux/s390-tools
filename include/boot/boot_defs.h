/*
 * Boot and dump related definitions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef BOOT_DEFS_H
#define BOOT_DEFS_H

#include <stdint.h>

#include "lib/zt_common.h"

#define ZIPL_MAGIC			"zIPL"
#define ZIPL_MAGIC_SIZE			4

/*
 * ECKD dump parameter
 */
struct eckd_dump_param {
	uint32_t blk_start;
	uint32_t blk_end;
	uint16_t blk_size;
	uint8_t num_heads;
	uint8_t bpt;
	char reserved[4];
} __packed;

/*
 * FBA dump parameter
 */
struct fba_dump_param {
	uint32_t	res1;
	uint32_t	blk_start;
	uint32_t	res2;
	uint32_t	blk_end;
} __packed;

/*
 * SCSI dump parameter
 */
struct scsi_dump_param {
	uint64_t block;
	uint64_t reserved;
} __packed;

/*
 * Layout of block pointer for linear devices
 * e.g. SCSI
 */
struct linear_blockptr {
	uint64_t blockno;
	uint16_t size;
	uint16_t blockct;
	uint8_t reserved[4];
} __packed;

/*
 * Format of a boot record on ECKD DASD for List-Directed IPL
 */
struct eckd_boot_record {
	uint8_t magic[4];
	uint32_t version_id;
	uint8_t unused[8];
	uint8_t program_table_pointer[16];
	uint8_t reserved[478];
	uint16_t os_id;
} __packed;

/*
 * Layout of block pointer for cylinder/head/sector devices
 * e.g. ECKD
 */

enum blkptr_format_id {
	/*
	 * this is the old format which serves only CCW-type IPL,
	 * and doesn't fit List-Directed IPL. Still supported for
	 * compatibility reasons.
	 */
	LEGACY_BLKPTR_FORMAT_ID,
	/*
	 * this is the "new" format which serves only List-Directed IPL,
	 * but is also suitable for CCW-type IPL.
	 */
	BLKPTR_FORMAT_ID,
	NR_BLKPTR_FORMATS
};

/*
 * Block pointers format identified as LEGACY_BLKPTR_FORMAT_ID.
 */
struct eckd_blockptr_legacy {
	uint16_t cyl;
	uint16_t head;
	uint8_t sec;
	uint16_t size;
	uint8_t blockct;
	uint8_t reserved[8];
} __packed;

/*
 * Block pointers format identified as BLKPTR_FORMAT_ID.
 */
struct eckd_blockptr {
	uint32_t cyl;
	uint8_t head;
	uint8_t sec;
	uint8_t reserved1[4];
	uint16_t blockct;
	uint8_t reserved2[4];
} __packed;

typedef enum {
	COMPONENT_TYPE_EXECUTE = 0x01,
	COMPONENT_TYPE_LOAD = 0x02,
	COMPONENT_TYPE_SIGNATURE = 0x03
} component_type;

typedef enum {
	COMPONENT_HEADER_IPL = 0x00,
	COMPONENT_HEADER_DUMP = 0x01
} component_header_type;

struct component_header {
	uint8_t magic[4];
	uint8_t type;
	uint8_t reserved[27];
} __packed;

struct signature_header {
	uint8_t format;
	uint8_t reserved[3];
	uint32_t length;
} __packed;

typedef union {
	uint64_t load_address;
	uint64_t load_psw;
	struct signature_header sig_head;
} component_data;

struct component_entry {
	uint8_t data[23];
	uint8_t type;
	component_data compdat;
} __packed;

/* SCSI dump super block */

struct scsi_dump_sb {
	uint64_t        magic;
	uint64_t        version;
	uint64_t        part_start;
	uint64_t        part_size;
	uint64_t        dump_offset;
	uint64_t        dump_size;
	uint64_t        csum_offset;
	uint64_t        csum_size;
	uint64_t        csum;
};
STATIC_ASSERT(sizeof(struct scsi_dump_sb) == 72);

#define SCSI_DUMP_SB_MAGIC	0x5a46435044554d50ULL /* ZFCPDUMP */
/* To avoid a csum entry of 0 a seed is used */
#define SCSI_DUMP_SB_SEED	0x12345678
#define SCSI_DUMP_SB_CSUM_SIZE  4096

/* Boot info */

#define BOOT_INFO_VERSION		1
#define BOOT_INFO_MAGIC			"zIPL"

#define BOOT_INFO_DEV_TYPE_ECKD		0x00
#define BOOT_INFO_DEV_TYPE_FBA		0x01
#define BOOT_INFO_DEV_TYPE_SCSI         0x02

#define BOOT_INFO_BP_TYPE_IPL		0x00
#define BOOT_INFO_BP_TYPE_DUMP		0x01

#ifdef __s390x__
#define BOOT_INFO_FLAGS_ARCH		0x01
#else
#define BOOT_INFO_FLAGS_ARCH		0x00
#endif

struct boot_info_bp_dump {
	union {
		struct eckd_dump_param eckd;
		struct fba_dump_param fba;
		struct scsi_dump_param scsi;
	} param;
	uint8_t		unused[16];
} __packed;

struct boot_info_bp_ipl {
	union {
		struct eckd_blockptr_legacy eckd_legacy;
		struct eckd_blockptr eckd;
		struct linear_blockptr lin;
	} bm_ptr;
	uint8_t		unused[16];
} __packed;

struct boot_info {
	char		magic[4];
	uint8_t		version;
	uint8_t		bp_type;
	uint8_t		dev_type;
	uint8_t		flags;
	union {
		struct boot_info_bp_dump dump;
		struct boot_info_bp_ipl ipl;
	} bp;
} __packed;

#define DISK_LAYOUT_ID 0x00000001

struct scsi_mbr {
	uint8_t			magic[4];
	uint32_t		version_id;
	uint8_t			reserved[8];
	struct linear_blockptr	program_table_pointer;
	uint8_t			reserved2[0x50];
	struct boot_info 	boot_info;
}  __packed;

#endif /* BOOT_DEFS_H */
