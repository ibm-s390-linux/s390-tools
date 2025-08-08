/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Single-volume ECKD DASD dump tool
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/zt_common.h"
#include "boot/boot_defs.h"
#include "boot/error.h"
#include "dump/s390_dump.h"

#include "eckd2dump.h"
#include "eckd2dump_zlib.h"
#include "stage2dump.h"

/*
 * Magic number at start of dump record
 */
const uint64_t __used __section(.stage2.head) magic = 0x5845434b44363402ULL; /* "XECKD64", version 2 */

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

static unsigned long dt_dump_mem_non_compressed(unsigned long addr,
						unsigned long blk)
{
	struct df_s390_dump_segm_hdr *dump_segm;
	unsigned long end;

	dump_segm = (void *)get_zeroed_page();
	/* Write memory uncompressed */
	end = dump_hdr->mem_size;
	while (addr < end) {
		addr = find_dump_segment(addr, end, 0, dump_segm);
		blk = write_dump_segment(blk, dump_segm);
		if (dump_segm->stop_marker) {
			addr = end;
			if (dump_segm->start + dump_segm->len < end)
				progress_print(addr);
			break;
		}
	}
	free_page(__pa(dump_segm));
	return blk;
}

static unsigned long dt_dump_mem_compressed(unsigned long addr,
					    unsigned long blk)
{
	struct df_s390_dump_segm_hdr *dump_segm;
	unsigned long end;
	z_stream strm;

	/* Write memory compressed with zlib deflate */
	dump_segm = (void *)get_zeroed_page();
	end = dump_hdr->mem_size;
	/*
	 * Always write first megabyte of memory uncompressed in
	 * order to use it as zlib workarea
	 */
	dump_segm->start = addr;
	dump_segm->len = ZLIB_WORKSPACE_LIMIT;
	blk = write_dump_segment(blk, dump_segm);
	addr += dump_segm->len;
	/* Initialize zlib workarea, return value 0 is expected */
	if (zlib_workarea_init(dump_segm->start, &strm)) {
		printf("Zlib workarea initialization failed! Dumping without compression");
		free_page(__pa(dump_segm));
		return dt_dump_mem_non_compressed(addr, blk);
	}
	/*
	 * Compress on level 1 (hardware only) using default zlib
	 * wrapped stream.
	 */
	if (zlib_deflateInit2(&strm, 1, Z_DEFLATED, MAX_WBITS,
			      DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK) {
		/*
		 * Could not allocate or initialize a workarea for zlib deflate,
		 * continue dumping without compression.
		 */
		printf("Deflate initialization failed! Dumping without compression");
		free_page(__pa(dump_segm));
		return dt_dump_mem_non_compressed(addr, blk);
	}
	while (addr < end) {
		/*
		 * Limit the max size of compressed dump segment in order to
		 * fit all the compressed chunk entries in the segment header.
		 */
		addr = find_dump_segment(addr, end, DUMP_SEGM_ZLIB_MAXLEN,
					 dump_segm);
		blk = write_compressed_dump_segment(blk, dump_segm, &strm);
		if (dump_segm->stop_marker) {
			addr = end;
			if (dump_segm->start + dump_segm->len < end)
				progress_print(addr);
			break;
		}
	}
	zlib_deflateEnd(&strm);
	free_page(__pa(dump_segm));
	return blk;
}

/*
 * Dump all memory to DASD partition.
 * Use zlib compression if DFLTCC facility is available.
 */
void dt_dump_mem(void)
{
	unsigned long blk, start, page;

	total_dump_size = 0;
	/* Write dump header */
	blk = device.blk_start;
	writeblock(blk, __pa(dump_hdr), m2b(DF_S390_HDR_SIZE), 0);
	blk += m2b(DF_S390_HDR_SIZE);
	/* Write memory starting from zero address */
	start = 0;
	/* Check for zlib flag in the dump header */
	if (dump_hdr->zlib_version_s390) {
		printf("DFLTCC facility available, using zlib compression");
		blk = dt_dump_mem_compressed(start, blk);
	} else {
		blk = dt_dump_mem_non_compressed(start, blk);
	}
	/* Write end marker */
	page = get_zeroed_page();
	df_s390_em_page_init(page);
	writeblock(blk, page, 1, 0);
	blk++;
	free_page(page);
}
