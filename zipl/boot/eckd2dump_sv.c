/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Single-volume ECKD DASD dump tool
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/zt_common.h"

#include "eckd2dump.h"
#include "error.h"
#include "stage2dump.h"

/*
 * Magic number at start of dump record
 */
uint64_t __section(.stage2.head) magic = 0x5845434b44363401ULL; /* "XECKD64", version 1 */

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
	unsigned long blk, addr, end, page;
	struct df_s390_dump_segm_hdr *dump_segm;

	blk = device.blk_start;
	dump_segm = (void *)get_zeroed_page();

	/* Write dump header */
	writeblock(blk, __pa(dump_hdr), m2b(DF_S390_HDR_SIZE), 0);
	blk += m2b(DF_S390_HDR_SIZE);

	/* Write memory */
	addr = 0;
	total_dump_size = 0;
	end = dump_hdr->mem_size;
	while (addr < end) {
		addr = find_dump_segment(addr, end, 0, dump_segm);
		blk = write_dump_segment(blk, dump_segm);
		total_dump_size += dump_segm->len;
		if (dump_segm->stop_marker) {
			addr = end;
			break;
		}
	}
	free_page(__pa(dump_segm));
	progress_print(addr);

	/* Write end marker */
	page = get_zeroed_page();
	df_s390_em_page_init(page);
	writeblock(blk, page, 1, 0);
	free_page(page);
}
