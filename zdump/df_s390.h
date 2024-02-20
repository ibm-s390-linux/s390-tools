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

#include "lib/zt_common.h"
#include "dump/s390_dump.h"
#include "boot/loaders_layout.h"

#include "dt.h"
#include "zg.h"

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

/*
 * Dump tool structure
 */
struct df_s390_dumper {
	char	magic[7];
	u8	version;
	u32	size;
	u8	force;
	u64	mem;
} __packed;

/*
 * s390 dump helpers
 */
extern void df_s390_hdr_add(struct df_s390_hdr *hdr);
extern void df_s390_em_add(struct df_s390_em *em);
extern int df_s390_cpu_info_add(struct df_s390_hdr *hdr, u64 addr_max);
extern int df_s390_em_verify(struct df_s390_em *em, struct df_s390_hdr *hdr);
extern void df_s390_dumper_read(struct zg_fh *fh, int32_t blk_size,
				struct df_s390_dumper *dumper);

/*
 * DASD dt and dfi functions
 */
extern int dt_s390sv_init_gen(bool extended);
extern int dt_s390mv_init_gen(bool extended);
extern void dt_s390mv_info(void);

extern int dfi_s390_init_gen(bool extended);
extern int dfi_s390mv_init_gen(bool extended);
extern void dfi_s390mv_info(void);

#endif /* DF_S390_H */
