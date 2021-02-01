/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Common ECKD dump I/O functions
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef ECKD2DUMP_H
#define ECKD2DUMP_H

#include "cio.h"
#include "stage2dump.h"

struct eckd_device {
	uint32_t blk_start;
	uint32_t blk_end;
	uint16_t blk_size;
	uint8_t num_heads;
	uint8_t bpt;
	struct subchannel_id sid;
	uint16_t devno;
};

extern struct eckd_device device;
extern unsigned long eckd_blk_max;

/*
 * Convert memory size to number of blocks
 */
static inline unsigned long m2b(unsigned long mem)
{
	return mem / device.blk_size;
}

/*
 * Convert number of blocks to memory size
 */
static inline unsigned long b2m(unsigned long blk)
{
	return blk * device.blk_size;
}

void stage2dump_eckd_init();
void writeblock(unsigned long blk, unsigned long addr, unsigned long blk_count,
		unsigned long zero_page);
void readblock(unsigned long blk, unsigned long addr, unsigned long blk_count);
unsigned long write_dump_segment(unsigned long blk,
				 struct df_s390_dump_segm_hdr *segm);

#endif /* ECKD2DUMP_H */
