/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Single-volume ECKD DASD dump tool
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "eckd2dump.h"
#include "error.h"
#include "stage2dump.h"

/*
 * Magic number at start of dump record
 */
uint64_t magic __attribute__((section(".stage2.head"))) =
	0x5a45434b44363404ULL; /* "ZECKD64", version 4 */

/*
 * ECKD parameter block passed by zipl
 */
struct eckd_dump_param {
	uint32_t blk_start;
	uint32_t blk_end;
	uint16_t blk_size;
	uint8_t num_heads;
	uint8_t bpt;
	char reserved[4];
} __packed;

/*
 * Get device characteristics from zipl parameter block
 */
void dt_device_parm_setup(void)
{
	struct eckd_dump_param *parm = (void *) __stage2_desc;

	device.blk_start = parm->blk_start;
	device.blk_end = parm->blk_end;
	device.blk_size = parm->blk_size;
	device.num_heads = parm->num_heads;
	device.bpt = parm->bpt;
	device.sid = IPL_SC;
}

/*
 * Enable DASD device
 */
void dt_device_enable(void)
{
	io_irq_enable();
	set_device(device.sid, ENABLED);
	stage2dump_eckd_init();
}

/*
 * Dump all memory to DASD partition
 */
void dt_dump_mem(void)
{
	unsigned long blk, addr, page;

	blk = device.blk_start;
	page = get_zeroed_page();

	/* Write dump header */
	writeblock(blk, __pa(dump_hdr), m2b(DF_S390_HDR_SIZE), 0);
	blk += m2b(DF_S390_HDR_SIZE);

	/* Write memory */
	for (addr = 0; addr < dump_hdr->mem_size; addr += b2m(eckd_blk_max)) {
		writeblock(blk, addr, eckd_blk_max, page);
		progress_print(addr);
		blk += eckd_blk_max;
	}
	progress_print(addr);

	/* Write end marker */
	df_s390_em_page_init(page);
	writeblock(blk, page, 1, 0);
	free_page(page);
}
