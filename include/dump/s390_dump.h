/*
 * s390 related definitions and functions.
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef S390_DUMP_H
#define S390_DUMP_H

#include <stdint.h>

#include "lib/zt_common.h"

/*
 * S390 dump format defines
 */
#define DF_S390_MAGIC		0xa8190173618f23fdULL
#define DF_S390_MAGIC_EXT	0xa8190173618f23feULL
#define DF_S390_HDR_SIZE	0x1000
#define DF_S390_EM_SIZE		16
#define DF_S390_EM_MAGIC	0x44554d505f454e44ULL
#define DF_S390_CPU_MAX		512
#define DF_S390_MAGIC_BLK_ECKD	3

/*
 * Architecture of dumped system
 */
enum df_s390_arch {
	DF_S390_ARCH_32	= 1,
	DF_S390_ARCH_64	= 2,
};

/*
 * s390 dump header format
 */
struct df_s390_hdr {
	uint64_t	magic;				/* 0x000 */
	uint32_t	version;			/* 0x008 */
	uint32_t	hdr_size;			/* 0x00c */
	uint32_t	dump_level;			/* 0x010 */
	uint32_t	page_size;			/* 0x014 */
	uint64_t	mem_size;			/* 0x018 */
	uint64_t	mem_start;			/* 0x020 */
	uint64_t	mem_end;			/* 0x028 */
	uint32_t	num_pages;			/* 0x030 */
	uint32_t	pad;				/* 0x034 */
	uint64_t	tod;				/* 0x038 */
	uint64_t	cpu_id;				/* 0x040 */
	uint32_t	arch;				/* 0x048 */
	uint32_t	volnr;				/* 0x04c */
	uint32_t	build_arch;			/* 0x050 */
	uint64_t	mem_size_real;			/* 0x054 */
	uint8_t		mvdump;				/* 0x05c */
	uint16_t	cpu_cnt;			/* 0x05d */
	uint16_t	real_cpu_cnt;			/* 0x05f */
	uint8_t		end_pad1[0x200 - 0x061];	/* 0x061 */
	uint64_t	mvdump_sign;			/* 0x200 */
	uint64_t	mvdump_zipl_time;		/* 0x208 */
	uint8_t		end_pad2[0x800 - 0x210];	/* 0x210 */
	uint32_t	lc_vec[DF_S390_CPU_MAX];	/* 0x800 */
} __packed __aligned(16);

/*
 *  End marker: Should be at the end of every valid s390 crash dump
 */
struct df_s390_em {
	uint64_t	magic;
	uint64_t	tod;
} __packed __aligned(16);

/*
 * Dump segment header
 */
struct df_s390_dump_segm_hdr {
	uint64_t start;
	uint64_t len;
	uint64_t stop_marker;
};

#endif /* S390_DUMP_H */
