/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Generic input dump format functions (DFI - Dump Format Input)
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DFI_H
#define DFI_H

#include <linux/utsname.h>

#include "lib/zt_common.h"
#include "lib/util_list.h"

#include "dfi_mem_chunk.h"

/*
 * CPU info functions and definitions
 */

enum dfi_arch {
	DFI_ARCH_32		= 0,
	DFI_ARCH_64		= 1,
	DFI_ARCH_UNKNOWN	= 2,
};

struct dfi_lowcore_32 {
	u8	pad_0x0000[0x0084 - 0x0000];	/* 0x0000 */
	u16	cpu_addr;			/* 0x0084 */
	u8	pad_0x0086[0x00d4 - 0x0086];	/* 0x0086 */
	u32	extended_save_area_addr;	/* 0x00d4 */
	u32	timer_save_area[2];		/* 0x00d8 */
	u32	clock_comp_save_area[2];	/* 0x00e0 */
	u32	mcck_interruption_code[2];	/* 0x00e8 */
	u8	pad_0x00f0[0x00f4-0x00f0];	/* 0x00f0 */
	u32	external_damage_code;		/* 0x00f4 */
	u32	failing_storage_address;	/* 0x00f8 */
	u8	pad_0x00fc[0x0100-0x00fc];	/* 0x00fc */
	u32	st_status_fixed_logout[2];	/* 0x0100 */
	u32	prefixreg_save_area;		/* 0x0108 */
	u8	pad_0x0110[0x0120-0x010c];	/* 0x010c */
	u32	access_regs_save_area[16];	/* 0x0120 */
	u32	floating_pt_save_area[8];	/* 0x0160 */
	u32	gpregs_save_area[16];		/* 0x0180 */
	u32	cregs_save_area[16];		/* 0x01c0 */
	u8	pad_0x0200[0x1000 - 0x0200];	/* 0x0200 */
};

struct dfi_lowcore_64 {
	u8	pad_0x0000[0x0084 - 0x0000];	/* 0x0000 */
	u16	cpu_addr;			/* 0x0084 */
	u8	pad_0x0086[0x11b0 - 0x0086];	/* 0x0086 */
	u64	vector_save_area_addr;		/* 0x11b0 */
	u8	pad_0x11b8[0x1200 - 0x11b8];	/* 0x11b8 */
	u64	floating_pt_save_area[16];	/* 0x1200 */
	u64	gpregs_save_area[16];		/* 0x1280 */
	u32	st_status_fixed_logout[4];	/* 0x1300 */
	u8	pad_0x1310[0x1318-0x1310];	/* 0x1310 */
	u32	prefixreg_save_area;		/* 0x1318 */
	u32	fpt_creg_save_area;		/* 0x131c */
	u8	pad_0x1320[0x1324-0x1320];	/* 0x1320 */
	u32	tod_progreg_save_area;		/* 0x1324 */
	u32	timer_save_area[2];		/* 0x1328 */
	u32	clock_comp_save_area[2];	/* 0x1330 */
	u8	pad_0x1338[0x1340-0x1338];	/* 0x1338 */
	u32	access_regs_save_area[16];	/* 0x1340 */
	u64	cregs_save_area[16];		/* 0x1380 */
	u8	pad_0x1400[0x2000-0x1400];	/* 0x1400 */
} __packed;

static inline u64 dfi_lc_size(enum dfi_arch arch)
{
	if (arch == DFI_ARCH_64)
		return 0x2000;
	else
		return 0x1000;
}

struct dfi_vxrs {
	u64 low;
	u64 high;
};

struct dfi_cpu {
	struct util_list_node	list;
	u64		gprs[16];
	u64		ctrs[16];
	u32		acrs[16];
	u64		fprs[16];
	u32		fpc;
	u64		psw[2];
	u32		prefix;
	u64		timer;
	u64		todcmp;
	u32		todpreg;
	u64		vxrs_low[16];
	struct dfi_vxrs	vxrs_high[16];
	u16		cpu_id;
};

struct dfi_cpu_32 {
	u32		gprs[16];
	u32		ctrs[16];
	u32		acrs[16];
	u64		fprs[4];
	u32		psw[2];
	u32		prefix;
	u64		timer;
	u64		todcmp;
	u64		vxrs_low[16];
	struct dfi_vxrs	vxrs_high[16];
};

void dfi_cpu_64_to_32(struct dfi_cpu_32 *cpu_32, struct dfi_cpu *cpu_64);

enum dfi_arch dfi_arch(void);
void dfi_arch_set(enum dfi_arch arch);
const char *dfi_arch_str(enum dfi_arch arch);

enum dfi_cpu_content {
	DFI_CPU_CONTENT_NONE,	/* No register information available */
	DFI_CPU_CONTENT_LC,	/* Only lowcore information available */
	DFI_CPU_CONTENT_ALL,	/* Complete register information available */
};

#define DFI_CPU_CONTENT_FAC_VX	0x00000001
int dfi_cpu_content_fac_check(int flags);
void dfi_cpu_content_fac_add(int flags);

#define dfi_cpu_iterate(cpu) \
	util_list_iterate(dfi_cpu_list(), cpu)

struct util_list *dfi_cpu_list(void);
void dfi_cpu_info_init(enum dfi_cpu_content content);
struct dfi_cpu *dfi_cpu_alloc(void);
struct dfi_cpu *dfi_cpu(unsigned int cpu_nr);
void dfi_cpu_add(struct dfi_cpu *cpu);
unsigned int dfi_cpu_cnt(void);
enum dfi_cpu_content dfi_cpu_content(void);
int dfi_cpu_add_from_lc(u32 lc_addr);

#define DFI_VX_SA_SIZE		(32 * 16)
int dfi_cpu_lc_has_vx_sa(void *lc);
void dfi_cpu_vx_copy(void *buf, struct dfi_cpu *cpu);

/*
 * Dump header attribute set/get functions
 */
void dfi_attr_time_set(struct timeval *time);
struct timeval *dfi_attr_time(void);

void dfi_attr_time_end_set(struct timeval *time_end);
struct timeval *dfi_attr_time_end(void);

void dfi_attr_cpu_id_set(u64 cpu_id);
u64 *dfi_attr_cpu_id(void);

void dfi_attr_utsname_set(struct new_utsname *utsname);
struct new_utsname *dfi_attr_utsname(void);

void dfi_attr_dump_method_set(char *dump_method);
char *dfi_attr_dump_method(void);

void dfi_attr_mem_size_real_set(u64 mem_size_real);
u64 *dfi_attr_mem_size_real(void);

void dfi_attr_file_size_set(u64 dump_size);
u64 *dfi_attr_file_size(void);

void dfi_attr_vol_nr_set(unsigned int vol_nr);
unsigned int *dfi_attr_vol_nr(void);

void dfi_attr_version_set(unsigned int dfi_version);
unsigned int *dfi_attr_dfi_version(void);

void dfi_attr_build_arch_set(enum dfi_arch build_arch);
enum dfi_arch *dfi_attr_build_arch(void);

void dfi_attr_real_cpu_cnt_set(u32 real_cpu_cnt);
u32 *dfi_attr_real_cpu_cnt(void);

void dfi_info_print(void);

/*
 * DFI feature bits
 */
#define DFI_FEAT_SEEK	0x1 /* Necessary for fuse mount */
#define DFI_FEAT_COPY	0x2 /* Necessary for stdout */

int dfi_feat_seek(void);
int dfi_feat_copy(void);

/*
 * DFI kdump functions
 */
unsigned long dfi_kdump_base(void);

/*
 * DFI operations
 */
struct dfi {
	const char	*name;
	int		(*init)(void);
	void		(*exit)(void);
	void		(*info_dump)(void);
	int		feat_bits;
};

const char *dfi_name(void);
int dfi_init(void);
void dfi_exit(void);

/*
 * Dump access
 */
struct zg_fh *dfi_dump_open(const char *path);

/*
 * Live dump memory magic
 */
extern u64 dfi_live_dump_magic;

/*
 * Dump methods
 */
#define DFI_DUMP_METHOD_LIVE	"live"

#endif /* DFI_H */
