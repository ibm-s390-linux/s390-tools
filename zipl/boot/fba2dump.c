/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Single-volume FBA DASD dump tool
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/zt_common.h"
#include "error.h"
#include "fba.h"
#include "stage2dump.h"

#define BLK_PWRT	64U			/* Blocks per write */
#define BLK_SIZE	0x200			/* FBA block size */
#define BLK_PER_PAGE	(PAGE_SIZE / BLK_SIZE)	/* FBA blocks per page */

/*
 * Magic number at start of dump record
 */
uint64_t __section(.stage2.head) magic = 0x5844464241363401ULL; /* XDFBA64, version 1 */

/*
 * FBA dump device partition specification
 */
static struct {
	unsigned int blk_start;
	unsigned int blk_end;
} device;

/*
 * ORB / IRB
 */
static struct orb orb = {
	.intparm	= 0x0049504c,	/* Interruption Parameter */
	.fmt		= 0x1,		/* Use format 1 CCWs */
	.c64		= 0x1,		/* Use IDAs */
	.lpm		= 0xff,		/* Logical path mask */
};

static struct irb irb;

/*
 * Data for Locate Record CCW
 */
static struct LO_fba_data lodata = {
	.operation = {
		.cmd = 0x1,
	},
};

/*
 * Data for Define Extend CCW
 */
static struct DE_fba_data dedata = {
	.mask = {
		.perm	= 0x3,
	},
	.blk_size	= 0x200,
};

/*
 * CCW program and IDA list
 */
static struct {
	struct ccw1 deccw;
	struct ccw1 loccw;
	struct ccw1 wrccw;
	unsigned long ida_list[BLK_PWRT * BLK_SIZE / 4096];
} ccw_program __aligned(8);

/*
 * FBA parameter block passed by zipl
 */
struct fba_dump_param {
	uint32_t	res1;
	uint32_t	blk_start;
	uint32_t	res2;
	uint32_t	blk_end;
} __packed;

/*
 * Convert memory size to number of blocks
 */
static inline unsigned long m2b(unsigned long mem)
{
	return mem / BLK_SIZE;
}

/*
 * Convert number of blocks to memory size
 */
static inline unsigned long b2m(unsigned long blk)
{
	return blk * BLK_SIZE;
}

/*
 * Get device characteristics from zipl parameter block
 */
void dt_device_parm_setup(void)
{
	struct fba_dump_param *param = (void *) __stage2_desc;

	device.blk_start = param->blk_start;
	device.blk_end = param->blk_end;
}

/*
 * Enable DASD device
 */
void dt_device_enable(void)
{
	io_irq_enable();
	set_device(IPL_SC, ENABLED);
}

/*
 * Write memory with number of blocks to start block
 */
static void writeblock_fba(unsigned long blk, unsigned long addr,
			   unsigned long blk_count, unsigned long zero_page)
{
	unsigned long blk_end;

	blk_end = blk + blk_count;
	if (blk_end >= device.blk_end)
		panic(EMEM, "Device too small");
	ccw_program.wrccw.count = b2m(blk_count);
	lodata.blk_ct = blk_count;
	lodata.blk_nr = blk;
	create_ida_list(ccw_program.ida_list, b2m(blk_count), addr, zero_page);
	start_io(IPL_SC, &irb, &orb, 1);
}

/*
 * Write dump segment with the header to FBA and return the next free
 * block number
 */
unsigned long write_dump_segment_fba(unsigned long blk,
				     struct df_s390_dump_segm_hdr *dump_segm)
{
	unsigned long addr, start_blk, blk_count, zero_page;

	/* Write the dump segment header itself (1 page) */
	zero_page = get_zeroed_page();
	writeblock_fba(blk, __pa(dump_segm), BLK_PER_PAGE, zero_page);
	free_page(zero_page);
	blk += BLK_PER_PAGE;
	/* Write the dump segment */
	addr = dump_segm->start;
	start_blk = blk;
	while (addr < dump_segm->start + dump_segm->len) {
		/* Remaining blocks to write */
		blk_count = m2b(dump_segm->len) - (blk - start_blk);
		blk_count = MIN(blk_count, BLK_PWRT);
		zero_page = get_zeroed_page();
		writeblock_fba(blk, addr, blk_count, zero_page);
		free_page(zero_page);
		progress_print(addr);
		blk += blk_count;
		addr += b2m(blk_count);
	}
	return blk;
}


/*
 * Initialize the CCW program
 */
static void ccw_program_init(void)
{
	ccw_program.deccw.cmd_code = DASD_FBA_CCW_DE;
	ccw_program.deccw.flags = CCW_FLAG_CC;
	ccw_program.deccw.count = 0x0010;
	ccw_program.deccw.cda = __pa32(&dedata);

	ccw_program.loccw.cmd_code = DASD_FBA_CCW_LOCATE;
	ccw_program.loccw.flags = CCW_FLAG_CC;
	ccw_program.loccw.count = 0x0008;
	ccw_program.loccw.cda = __pa32(&lodata);

	ccw_program.wrccw.cmd_code = DASD_FBA_CCW_WRITE;
	ccw_program.wrccw.flags = CCW_FLAG_IDA | CCW_FLAG_SLI;
	ccw_program.wrccw.cda = __pa32(ccw_program.ida_list);

	orb.cpa = __pa32(&ccw_program);
	dedata.ext_end = device.blk_end;
}

/*
 * Dump all memory to DASD partition
 */
void dt_dump_mem(void)
{
	struct df_s390_dump_segm_hdr *dump_segm;
	unsigned long blk, addr, end, page;

	ccw_program_init();
	blk = device.blk_start;
	dump_segm = (void *)get_zeroed_page();

	/* Write dump header */
	writeblock_fba(blk, __pa(dump_hdr), m2b(DF_S390_HDR_SIZE), 0);
	blk += m2b(DF_S390_HDR_SIZE);

	/* Write memory */
	addr = 0;
	total_dump_size = 0;
	end = dump_hdr->mem_size;
	while (addr < end) {
		addr = find_dump_segment(addr, end, 0, dump_segm);
		blk = write_dump_segment_fba(blk, dump_segm);
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
	writeblock_fba(blk, page, 1, 0);
	free_page(page);
}
