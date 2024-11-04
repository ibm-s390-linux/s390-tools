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
extern int df_s390_dumper_read(struct zg_fh *fh, int32_t blk_size,
			       struct df_s390_dumper *dumper);

/*
 * DASD dt and dfi functions
 */
extern int dt_s390mv_ext_init(void);
extern void dt_s390mv_info(void);

extern int dfi_s390_init_gen(bool extended);

#endif /* DF_S390_H */
