/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Main program for stage2 bootloader.
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef COMMON_H
#define COMMON_H

#include "lib/zt_common.h"

#define DESCR_PER_BLOCK         _AC(16, U)


#ifndef __ASSEMBLER__

#include "boot/boot_defs.h"

#include "libc.h"
#include "boot/s390.h"
#include "cio.h"
#include "error.h"

struct stage2_descr {
	uint8_t reserved[16];
} __packed __aligned(8);

void *load_direct(union disk_blockptr *data, struct subchannel_id sid,
		  void *load_addr);
int extract_length(void *);
int is_zero_block(void *);
void kdump_stage2(unsigned long);

#endif /* __ASSEMBLER__ */

#endif /* COMMON_H */
