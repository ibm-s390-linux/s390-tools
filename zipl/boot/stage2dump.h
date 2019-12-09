/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Common dump functions
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef STAGE2DUMP_H
#define STAGE2DUMP_H

#include "libc.h"
#include "boot/s390.h"

#define IPL_SC	*((struct subchannel_id *) &S390_lowcore.subchannel_id)
#define ROUND_DOWN(x, a)		((x) & ~((typeof(x))(a) - 1))
#define IS_ALIGNED(x, a)		~((x) & ((typeof(x))(a) - 1))

/*
 * zipl parameters passed at tail of dump tools
 */
struct stage2dump_parm_tail {
	char		reserved[6];
	uint16_t	mvdump_force;
	uint64_t	mem_upper_limit;
} __packed;

extern struct stage2dump_parm_tail __section(.stage2dump.tail) parm_tail;

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
	uint8_t		end_pad1[0x200-0x061];		/* 0x061 */
	uint64_t	mvdump_sign;			/* 0x200 */
	uint64_t	mvdump_zipl_time;		/* 0x208 */
	uint8_t		end_pad2[0x800-0x210];		/* 0x210 */
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

/*
 * Linker script defined symbols
 */
extern char __eckd2mvdump_parm_start[];
extern char __stage2_desc[];

/*
 * Dump common globals
 */
extern struct df_s390_hdr *dump_hdr;
extern unsigned long total_dump_size;

/*
 * Common functions
 */
void create_ida_list(unsigned long *list, int len, unsigned long addr,
		     unsigned long zero_page);
void init_progress_print(void);
void progress_print(unsigned long addr);
void df_s390_em_page_init(unsigned long page);
void pgm_check_handler(void);
int is_zero_mb(unsigned long addr);
unsigned long find_dump_segment(unsigned long start, unsigned long end,
				unsigned long max_len,
				struct df_s390_dump_segm_hdr *dump_segm);

/*
 * Dump tool backend functions
 */
void dt_device_parm_setup(void);
void dt_device_enable(void);
void dt_dump_mem(void);

#endif /* STAGE2DUMP_H */
