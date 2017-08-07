/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * LKCD dump format definitions
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DF_LKCD_H
#define DF_LKCD_H

#define DF_LKCD_MAGIC		0xa8190173618f23edULL
#define DF_LKCD_MAGIC_ASM	0x733339302d64756dULL
#define DF_LKCD_VERSION		0x8	/* dump version number */
#define DF_LKCD_PANIC_LEN	0x100	/* dump panic string length */
#define DF_LKCD_HDR_SIZE	0x10000	/* Max space for the dump header */

#define DF_LKCD_COMPRESS_NONE	0x0	/* don't compress this dump */
#define DF_LKCD_COMPRESS_GZIP	0x2	/* use GZIP compression */

#define DF_LKCD_DH_RAW		0x1	/* raw pg (no compression) */
#define DF_LKCD_DH_COMPRESSED	0x2	/* pg is compressed */
#define DF_LKCD_DH_END		0x4	/* end marker on a full dump */

#define DF_LKCD_UCP_SIZE	(PAGE_SIZE + sizeof(struct df_lkcd_pg_hdr))

/*
 * LKCD standard header
 */
struct df_lkcd_hdr {
	u64	magic;
	u32	version;
	u32	hdr_size;
	u32	dump_level;
	u32	page_size;
	u64	mem_size;
	u64	mem_start;
	u64	mem_end;
	u32	num_dump_pgs;
	char	panic_string[0x100];
	u64	time_tv_sec;
	u64	time_tv_usec;
	char	utsname_sysname[65];
	char	utsname_nodename[65];
	char	utsname_release[65];
	char	utsname_version[65];
	char	utsname_machine[65];
	char	utsname_domainname[65];
	u64	current_task;
	u32	dump_compress;
	u32	dump_flags;
	u32	dump_device;
} __attribute__((packed));

/*
 * s390 LKCD asm header
 */
struct df_lkcd_hdr_asm {
	u64	magic;
	u32	version;
	u32	hdr_size;
	u16	cpu_cnt;
	u16	real_cpu_cnt;
	u32	lc_vec[512];
} __attribute__((packed));

/*
 * Page header
 */
struct df_lkcd_pg_hdr {
	u64	addr;	/* Address of dump page */
	u32	size;	/* Size of dump page */
	u32	flags;	/* flags (DF_LKCD_COMPRESSED, DF_LKCD_RAW,...) */
} __attribute__((packed));

#endif /* DF_LKCD_H */
