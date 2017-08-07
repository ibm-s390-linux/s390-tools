/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Generic input dump format functions (DFI - Dump Format Input)
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DFI_H
#define DFI_H

#include <linux/utsname.h>
#include "lib/util_list.h"
#include "zg.h"

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
} __attribute__((packed));

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

extern void dfi_cpu_64_to_32(struct dfi_cpu_32 *cpu_32, struct dfi_cpu *cpu_64);

extern enum dfi_arch dfi_arch(void);
extern void dfi_arch_set(enum dfi_arch arch);
extern const char *dfi_arch_str(enum dfi_arch arch);

enum dfi_cpu_content {
	DFI_CPU_CONTENT_NONE,	/* No register information available */
	DFI_CPU_CONTENT_LC,	/* Only lowcore information available */
	DFI_CPU_CONTENT_ALL,	/* Complete register information available */
};

#define DFI_CPU_CONTENT_FAC_VX	0x00000001
extern int dfi_cpu_content_fac_check(int falgs);
extern void dfi_cpu_content_fac_add(int flags);

#define dfi_cpu_iterate(cpu) \
	util_list_iterate(dfi_cpu_list(), cpu)

extern struct util_list *dfi_cpu_list(void);
extern void dfi_cpu_info_init(enum dfi_cpu_content content);
extern struct dfi_cpu *dfi_cpu_alloc(void);
extern struct dfi_cpu *dfi_cpu(unsigned int cpu_nr);
extern void dfi_cpu_add(struct dfi_cpu *cpu);
extern unsigned int dfi_cpu_cnt(void);
extern enum dfi_cpu_content dfi_cpu_content(void);
extern void dfi_cpu_add_from_lc(u32 lc_addr);

#define DFI_VX_SA_SIZE		(32 * 16)
extern int dfi_cpu_lc_has_vx_sa(void *lc);
extern void dfi_cpu_vx_copy(void *buf, struct dfi_cpu *cpu);

/*
 * Mem chunk functions and definitions
 */
struct dfi_mem_chunk;

typedef void (*dfi_mem_chunk_read_fn)(struct dfi_mem_chunk *mem_chunk,
				      u64 off, void *buf, u64 cnt);
typedef void (*dfi_mem_chunk_free_fn)(void *data);

struct dfi_mem_chunk {
	struct util_list_node	list;		/* List */
	u64			start;		/* Start address in memory */
	u64			end;		/* End address in memory */
	u64			size;		/* Size of chunk in dump file */
	u64			out_start;	/* Start offset in dump file */
	u64			out_end;	/* End offset in dump file */
	dfi_mem_chunk_read_fn	read_fn;	/* Chunk read callback */
	dfi_mem_chunk_free_fn	free_fn;	/* Free data callback */
	void			*data;		/* Data for callback */
};

extern void dfi_mem_chunk_add(u64 start, u64 size, void *data,
			      dfi_mem_chunk_read_fn read_fn,
			      dfi_mem_chunk_free_fn free_fn);
extern void dfi_mem_chunk_virt_add(u64 start, u64 size, void *data,
				   dfi_mem_chunk_read_fn read_fn,
				   dfi_mem_chunk_free_fn free_fn);
extern u64 dfi_mem_range(void);
extern int dfi_mem_range_valid(u64 addr, u64 len);
extern unsigned int dfi_mem_chunk_cnt(void);
extern struct dfi_mem_chunk *dfi_mem_chunk_first(void);
extern struct dfi_mem_chunk *dfi_mem_chunk_next(struct dfi_mem_chunk *chunk);
extern struct dfi_mem_chunk *dfi_mem_chunk_prev(struct dfi_mem_chunk *chunk);
extern struct dfi_mem_chunk *dfi_mem_chunk_find(u64 addr);

extern struct util_list *dfi_mem_chunk_list(void);
#define dfi_mem_chunk_iterate(mem_chunk) \
	util_list_iterate(dfi_mem_chunk_list(), mem_chunk)

/*
 * Dump header attribute set/get functions
 */
extern void dfi_attr_time_set(struct timeval *time);
extern struct timeval *dfi_attr_time(void);

extern void dfi_attr_time_end_set(struct timeval *time_end);
extern struct timeval *dfi_attr_time_end(void);

extern void dfi_attr_cpu_id_set(u64 cpu_id);
extern u64 *dfi_attr_cpu_id(void);

extern void dfi_attr_utsname_set(struct new_utsname *utsname);
extern struct new_utsname *dfi_attr_utsname(void);

extern void dfi_attr_dump_method_set(char *dump_method);
extern char *dfi_attr_dump_method(void);

extern void dfi_attr_mem_size_real_set(u64 mem_size_real);
extern u64 *dfi_attr_mem_size_real();

extern void dfi_attr_vol_nr_set(unsigned int vol_nr);
extern unsigned int *dfi_attr_vol_nr(void);

extern void dfi_attr_version_set(unsigned int dfi_version);
extern unsigned int *dfi_attr_dfi_version(void);

extern void dfi_attr_build_arch_set(enum dfi_arch build_arch);
extern enum dfi_arch *dfi_attr_build_arch(void);

extern void dfi_attr_real_cpu_cnt_set(u32 real_cpu_cnt);
extern u32 *dfi_attr_real_cpu_cnt(void);

/*
 * DFI external functions
 */
extern void dfi_mem_read(u64 addr, void *buf, size_t cnt);
extern int dfi_mem_read_rc(u64 addr, void *buf, size_t cnt);
extern void dfi_mem_phys_read(u64 addr, void *buf, size_t cnt);
extern void dfi_info_print(void);

/*
 * DFI feature bits
 */
#define DFI_FEAT_SEEK	0x1 /* Necessary for fuse mount */
#define DFI_FEAT_COPY	0x2 /* Necessary for stdout */

extern int dfi_feat_seek(void);
extern int dfi_feat_copy(void);

/*
 * DFI kdump functions
 */
extern unsigned long dfi_kdump_base(void);

/*
 * DFI vmcoreinfo functions
 */
extern void dfi_vmcoreinfo_init(void);
extern char *dfi_vmcoreinfo_get(void);
extern int dfi_vmcoreinfo_tag(char *str, int len, const char *sym);
extern int dfi_vmcoreinfo_symbol(unsigned long *val, const char *sym);
extern int dfi_vmcoreinfo_offset(unsigned long *offs, const char *sym);
extern int dfi_vmcoreinfo_size(unsigned long *size, const char *sym);
extern int dfi_vmcoreinfo_length(unsigned long *len, const char *sym);
extern int dfi_vmcoreinfo_val(unsigned long *val, const char *sym);

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

extern const char *dfi_name(void);
extern int dfi_init(void);
extern void dfi_exit(void);

/*
 * Dump access
 */
extern struct zg_fh *dfi_dump_open(const char *path);

/*
 * Live dump memory magic
 */
extern u64 dfi_live_dump_magic;

/*
 * Dump methods
 */
#define DFI_DUMP_METHOD_LIVE	"live"

#endif /* DFI_H */
