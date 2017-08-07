/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 dump input format
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "zgetdump.h"

/*
 * File local static data
 */
static struct {
	struct df_s390_hdr	hdr;	/* s390 dump header */
	struct df_s390_em	em;	/* s390 end marker */
} l;

/*
 * S390 mem chunk read callback
 */
static void dfi_s390_mem_chunk_read(struct dfi_mem_chunk *mem_chunk, u64 off,
				    void *buf, u64 cnt)
{
	(void) mem_chunk;

	zg_seek(g.fh, off + DF_S390_HDR_SIZE, ZG_CHECK);
	zg_read(g.fh, buf, cnt, ZG_CHECK);
}

/*
 * Read s390 dump header
 */
static int read_s390_hdr(void)
{
	if ((zg_type(g.fh) == ZG_TYPE_FILE) && (zg_size(g.fh) < sizeof(l.hdr)))
		return -ENODEV;
	if (zg_read(g.fh, &l.hdr, sizeof(l.hdr), ZG_CHECK_ERR) != sizeof(l.hdr))
		return -ENODEV;
	if (l.hdr.magic != DF_S390_MAGIC)
		return -ENODEV;
	df_s390_hdr_add(&l.hdr);
	return 0;
}

/*
 * Init end marker
 */
static int read_s390_em(void)
{
	u64 rc;

	rc = zg_seek(g.fh, l.hdr.mem_size + DF_S390_HDR_SIZE, ZG_CHECK_NONE);
	if (rc != l.hdr.mem_size + DF_S390_HDR_SIZE)
		return -EINVAL;
	rc = zg_read(g.fh, &l.em, sizeof(l.em), ZG_CHECK_ERR);
	if (rc != sizeof(l.em))
		return -EINVAL;
	if (df_s390_em_verify(&l.em, &l.hdr) != 0)
		return -EINVAL;
	df_s390_em_add(&l.em);
	return 0;
}

/*
 * Initialize s390 DFI
 */
static int dfi_s390_init(void)
{
	if (read_s390_hdr() != 0)
		return -ENODEV;
	dfi_mem_chunk_add(0, l.hdr.mem_size, NULL, dfi_s390_mem_chunk_read,
			  NULL);
	if (read_s390_em() != 0)
		return -EINVAL;
	df_s390_cpu_info_add(&l.hdr, l.hdr.mem_size);
	zg_seek(g.fh, sizeof(l.hdr), ZG_CHECK);
	return 0;
}

/*
 * S390 DFI operations
 */
struct dfi dfi_s390 = {
	.name		= "s390",
	.init		= dfi_s390_init,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
