/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 tape dump input format
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mtio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "zgetdump.h"
#include "df_s390.h"
#include "dfi.h"
#include "dfi_mem_chunk.h"

#define TAPE_BLK_SIZE	32768	/* Defined by zipl tape dumper */

/*
 * File local static data
 *
 * blk_buf_addr: Memory address of last read memory block
 * blk_buf:      Content of the last read memory block
 * blk:          The next block number that will be read relative to blk_start
 * blk_start:    The absolute block number on the tape where the dump starts
 */
static struct {
	char	blk_buf[TAPE_BLK_SIZE];
	u64	blk_buf_addr;
	u64	blk;
	int	blk_start;
} l;

/*
 * MT ioctls
 */
struct mtioctl {
	int		op;
	const char	*desc;
};

static struct mtioctl mt_fsfm	= {MTFSFM, "forward space file"};
static struct mtioctl mt_bsr	= {MTBSR,  "backward space record"};
static struct mtioctl mt_tell	= {MTTELL, "tell"};
static struct mtioctl mt_seek	= {MTSEEK, "seek"};

/*
 * Do MT ioctl with count argument
 */
static int mtioctl(struct mtioctl *op, int cnt, enum zg_check check)
{
	struct mtop mtop;

	mtop.mt_count = cnt;
	mtop.mt_op = op->op;
	return zg_ioctl(g.fh, MTIOCTOP, &mtop, op->desc, check);
}

/*
 * Verify end marker
 */
static int em_verify(struct df_s390_em *em)
{
	if ((memcmp(em->str, "DUMP_END", 8) == 0)) {
		df_s390_em_add(em);
		return 0;
	} else {
		return -EINVAL;
	}
}

/*
 * Verify dump header
 */
static void hdr_verify(struct df_s390_hdr *hdr)
{
	if (hdr->magic != DF_S390_MAGIC)
		ERR_EXIT("No valid dump found on tape");
	if (hdr->volnr != 0) {
		STDERR_PR("Found volume number: %d\n", hdr->volnr);
		ERR_EXIT("Multi-volume dumps are no longer supported");
	}
}

/*
 * Seek to relative block number in dump (block 0 is the dump header)
 */
static void seek_blk(u64 blk)
{
	if (l.blk == blk)
		return;
	mtioctl(&mt_seek, l.blk_start + blk, ZG_CHECK);
	l.blk = blk;
}

/*
 * Read memory from cartridge
 */
static void df_s390tape_mem_read(struct dfi_mem_chunk *mem_chunk, u64 addr,
				 void *buf, u64 cnt)
{
	unsigned int copied = 0, size;
	(void) mem_chunk;
	u64 blk, off;

	do {
		blk = addr / TAPE_BLK_SIZE + 1;
		if (addr >= l.blk_buf_addr + TAPE_BLK_SIZE ||
		    addr < l.blk_buf_addr) {
			seek_blk(blk);
			zg_read(g.fh, l.blk_buf, sizeof(l.blk_buf),
				ZG_CHECK);
			l.blk_buf_addr = (l.blk - 1) * TAPE_BLK_SIZE;
			l.blk++;
		}
		off = addr - l.blk_buf_addr;
		size = MIN(cnt - copied, TAPE_BLK_SIZE - off);
		memcpy(buf + copied, &l.blk_buf[off], size);
		addr += size;
		copied += size;
	} while (copied != cnt);
}

/*
 * Initialize cache for memory read (block 0 is the dump header)
 */
static void mem_read_init(void)
{
	mtioctl(&mt_seek, l.blk_start + 1, ZG_CHECK);
	zg_read(g.fh, l.blk_buf, sizeof(l.blk_buf), ZG_CHECK);
	l.blk_buf_addr = 0;
	l.blk = 2;
}

/*
 * Init a new tape volume
 */
static int vol_init(void)
{
	struct df_s390_hdr hdr;
	struct df_s390_em em;
	int rc;

	STDERR("Checking tape, this can take a while...\n");
	/* Init dump header */
	l.blk_start = mtioctl(&mt_tell, 1, ZG_CHECK);
	zg_read(g.fh, &hdr, sizeof(hdr), ZG_CHECK);
	hdr_verify(&hdr);
	df_s390_hdr_add(&hdr);
	dfi_mem_chunk_add(0, hdr.mem_size, NULL, df_s390tape_mem_read, NULL);

	/* Init end marker */
	mtioctl(&mt_fsfm, 1, ZG_CHECK_NONE);
	mtioctl(&mt_bsr, 1, ZG_CHECK);
	rc = zg_read(g.fh, &em, sizeof(em), ZG_CHECK_ERR);
	if (rc != 8 && rc != 16)
		return -EINVAL;
	if (em_verify(&em) != 0)
		return -EINVAL;

	/* Init memory read & CPU info */
	mem_read_init();
	rc = df_s390_cpu_info_add(&hdr, hdr.mem_size - 1);
	if (rc)
		return rc;
	return 0;
}

/*
 * Exit function: Seek to block 0
 */
static void  dfi_s390tape_exit(void)
{
	seek_blk(0);
}

/*
 * Initialize s390 tape DFI
 */
static int dfi_s390tape_init(void)
{
	if (zg_type(g.fh) != ZG_TYPE_TAPE)
		return -ENODEV;
	if (vol_init() != 0)
		return -EINVAL;
	zg_atexit(dfi_s390tape_exit);
	return 0;
}

/*
 * S390 tape DFI operations
 */
struct dfi dfi_s390tape = {
	.name		= "s390tape",
	.init		= dfi_s390tape_init,
	.feat_bits	= DFI_FEAT_SEEK | DFI_FEAT_COPY,
};
