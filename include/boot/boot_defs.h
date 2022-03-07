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
 * Layout of block pointer for cylinder/head/sector devices
 * e.g. ECKD
 */
struct eckd_blockptr {
	uint16_t cyl;
	uint16_t head;
	uint8_t sec;
	uint16_t size;
	uint8_t blockct;
	uint8_t reserved[8];
} __packed;

#endif /* BOOT_DEFS_H */
