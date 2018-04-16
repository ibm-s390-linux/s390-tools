/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 dump format common functions
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DF_S390_H
#define DF_S390_H

#include "dt.h"
#include "zg.h"

#define DF_S390_MAGIC		0xa8190173618f23fdULL
#define DF_S390_MAGIC_EXT	0xa8190173618f23feULL
#define DF_S390_HDR_SIZE	0x1000
#define DF_S390_EM_SIZE		16
#define DF_S390_EM_STR		"DUMP_END"
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
	u64	magic;				/* 0x000 */
	u32	version;			/* 0x008 */
	u32	hdr_size;			/* 0x00c */
	u32	dump_level;			/* 0x010 */
	u32	page_size;			/* 0x014 */
	u64	mem_size;			/* 0x018 */
	u64	mem_start;			/* 0x020 */
	u64	mem_end;			/* 0x028 */
	u32	num_pages;			/* 0x030 */
	u32	pad;				/* 0x034 */
	u64	tod;				/* 0x038 */
	u64	cpu_id;				/* 0x040 */
	u32	arch;				/* 0x048 */
	u32	volnr;				/* 0x04c */
	u32	build_arch;			/* 0x050 */
	u64	mem_size_real;			/* 0x054 */
	u8	mvdump;				/* 0x05c */
	u16	cpu_cnt;			/* 0x05d */
	u16	real_cpu_cnt;			/* 0x05f */
	u8	end_pad1[0x200-0x061];		/* 0x061 */
	u64	mvdump_sign;			/* 0x200 */
	u64	mvdump_zipl_time;		/* 0x208 */
	u8	end_pad2[0x800-0x210];		/* 0x210 */
	u32	lc_vec[DF_S390_CPU_MAX];	/* 0x800 */
} __attribute__((packed));

/*
 *  End marker: Should be at the end of every valid s390 crash dump.
 */
struct df_s390_em {
	char	str[8];
	u64	tod;
} __attribute__((packed));

/*
 * Segment header for s390 extended dump format
 */
struct df_s390_dump_segm_hdr {
	u64	start;
	u64	len;
	u64	stop_marker;
	u8	reserved[0x1000 - 24];
} __attribute__((packed));

/*
 * Convert DFI arch to s390 arch
 */
static inline enum df_s390_arch df_s390_from_dfi_arch(enum dfi_arch dfi_arch)
{
	return dfi_arch == DFI_ARCH_64 ? DF_S390_ARCH_64 : DF_S390_ARCH_32;
}

/*
 * Convert s390 arch to DFI arch
 */
static inline enum dfi_arch df_s390_to_dfi_arch(enum df_s390_arch df_s390_arch)
{
	return df_s390_arch == DF_S390_ARCH_64 ? DFI_ARCH_64 : DFI_ARCH_32;
}

#define DF_S390_DUMPER_SIZE_V1		0x1000
#define DF_S390_DUMPER_SIZE_V2		0x2000
#define DF_S390_DUMPER_SIZE_V3		0x3000
#define DF_S390_DUMPER_MAGIC32		"ZECKD31"
#define DF_S390_DUMPER_MAGIC64		"ZECKD64"
#define DF_S390_DUMPER_MAGIC_EXT	"XECKD64"
#define DF_S390_DUMPER_MAGIC32_FBA	"ZDFBA31"
#define DF_S390_DUMPER_MAGIC64_FBA	"ZDFBA64"
#define DF_S390_DUMPER_MAGIC_FBA_EXT	"XDFBA64"
#define DF_S390_DUMPER_MAGIC_MV		"ZMULT64"
#define DF_S390_DUMPER_MAGIC_MV_EXT	"XMULT64"
#define OLD_DUMPER_HEX_INSTR1 "\x0d\x10\x47\xf0" /* BASR + 1st halfword of BC */
#define OLD_DUMPER_HEX_INSTR2 "\x0d\xd0" /* BASR 13,0 */

/*
 * Dump tool structure
 */
struct df_s390_dumper {
	char	magic[7];
	u8	version;
	u32	size;
	u8	force;
	u64	mem;
} __attribute__ ((packed));

/*
 * s390 dump helpers
 */
extern void df_s390_hdr_add(struct df_s390_hdr *hdr);
extern void df_s390_em_add(struct df_s390_em *em);
extern void df_s390_cpu_info_add(struct df_s390_hdr *hdr, u64 addr_max);
extern int df_s390_em_verify(struct df_s390_em *em, struct df_s390_hdr *hdr);
extern void df_s390_dumper_read(struct zg_fh *fh, int32_t blk_size,
				struct df_s390_dumper *dumper);

/*
 * DASD multi-volume dumper functions
 */
extern int dt_s390mv_init(void);
extern void dt_s390mv_info(void);

#endif /* DF_S390_H */
