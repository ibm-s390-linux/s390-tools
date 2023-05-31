/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Common dump functions
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef STAGE2DUMP_H
#define STAGE2DUMP_H

#include "boot/s390.h"
#include "dump/s390_dump.h"

#define IPL_SC				S390_lowcore.tpi_info.schid
#define ROUND_DOWN(x, a)		((x) & ~((typeof(x))(a) - 1))
#define ROUND_UP(x, a)			ROUND_DOWN((x) + (typeof(x))(a) - 1, a)
#define IS_ALIGNED(x, a)		~((x) & ((typeof(x))(a) - 1))

extern struct stage2dump_parm_tail __section(.stage2dump.tail) parm_tail;

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
