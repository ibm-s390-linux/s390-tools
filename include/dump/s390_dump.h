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

#include "boot/page.h"
#include "lib/zt_common.h"

/*
 * S390 dump format defines
 */
#define DF_S390_MAGIC		0xa8190173618f23fdULL
#define DF_S390_MAGIC_EXT	0xa8190173618f23feULL
#define DF_S390_HDR_SIZE	0x1000
#define DF_S390_EM_SIZE		16
#define DF_S390_EM_MAGIC	0x44554d505f454e44ULL
#define DF_S390_EM_STR		"DUMP_END"
#define DF_S390_CPU_MAX		512
#define DF_S390_MAGIC_BLK_ECKD	3
#define DF_S390_DUMPER_MAGIC_SIZE	7
#define DF_S390_DUMPER_MAGIC_EXT	"XECKD64"
#define DF_S390_DUMPER_MAGIC_FBA_EXT	"XDFBA64"
#define DF_S390_DUMPER_MAGIC_MV_EXT	"XMULT64"

/*
 * Architecture of dumped system
 */
enum df_s390_arch {
	DF_S390_ARCH_32	= 1,
	DF_S390_ARCH_64	= 2,
};

/*
 * zipl parameters passed at tail of dump tools
 */
struct stage2dump_parm_tail {
	char		reserved[6];
	uint8_t		no_compress;
	uint8_t		mvdump_force;
	uint64_t	mem_upper_limit;
} __packed;

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
	uint8_t		zlib_version_s390;		/* 0x061 */
	uint32_t	zlib_entry_size;		/* 0x062 */
	uint8_t		end_pad1[0x200 - 0x066];	/* 0x066 */
	uint64_t	mvdump_sign;			/* 0x200 */
	uint64_t	mvdump_zipl_time;		/* 0x208 */
	uint8_t		end_pad2[0x800 - 0x210];	/* 0x210 */
	uint32_t	lc_vec[DF_S390_CPU_MAX];	/* 0x800 */
} __packed __aligned(16);

/*
 *  End marker: Should be at the end of every valid s390 crash dump
 */
struct df_s390_em {
	union {
		uint64_t magic;
		char str[8];
	};
	uint64_t tod;
} __packed __aligned(16);

/*
 * Dump segment header
 */
struct df_s390_dump_segm_hdr {
	union {
		struct {
			uint64_t start;				/* 0x000 */
			uint64_t len;				/* 0x008 */
			uint64_t stop_marker;			/* 0x010 */
			/* Size in blocks of compressed dump segment written to disk */
			uint32_t size_on_disk;			/* 0x018 */
			uint8_t  reserved_pad[0x30 - 0x1c];	/* 0x01c */
			/*
			 * Number of compressed entries in this dump segment (up to
			 * 1011 entries)
			 */
			uint32_t entry_count;			/* 0x030 */
			/*
			 * Offsets in blocks to compressed entries written to disk
			 * from the start of the dump segment.
			 * High-order bit is set if the entry has been written
			 * uncompressed.
			 */
			uint32_t entry_offset[];		/* 0x034 */
		} __packed;
		uint8_t padding[PAGE_SIZE];
	};
};

/* Data compression granularity (size of input data chunk for zlib deflate) */
#define DUMP_SEGM_ZLIB_ENTSIZE   (1 * MIB)
/* Maximum number of compressed entries in one dump segment */
#define DUMP_SEGM_ZLIB_MAXENTS   ((sizeof(struct df_s390_dump_segm_hdr) \
				   - offsetof(struct df_s390_dump_segm_hdr, entry_offset)) \
				   / sizeof(uint32_t))
/*
 * Maximum length of compressed dump segment considering the size of
 * a single input chunk
 */
#define DUMP_SEGM_ZLIB_MAXLEN    (DUMP_SEGM_ZLIB_MAXENTS * DUMP_SEGM_ZLIB_ENTSIZE)
/* Bitmask to mark uncompressed chunks */
#define DUMP_SEGM_ENTRY_UNCOMPRESSED    0x80000000

#endif /* S390_DUMP_H */
