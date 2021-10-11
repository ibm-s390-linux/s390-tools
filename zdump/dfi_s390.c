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
#include <errno.h>

#include "lib/util_log.h"

#include "zgetdump.h"
#include "zg.h"
#include "dfi.h"
#include "dfi_mem_chunk.h"
#include "df_elf.h"
#include "df_s390.h"

/*
 * File local static data
 */
static struct {
	struct df_s390_hdr	hdr;	/* s390 dump header */
	struct df_s390_em	em;	/* s390 end marker */
	bool extended;			/* Extended input dump format */
} l;

/*
 * s390 mem chunk read callback
 */
static void dfi_s390_mem_chunk_read(struct dfi_mem_chunk *mem_chunk, u64 off,
				    void *buf, u64 cnt)
{
	(void) mem_chunk;

	zg_seek(g.fh, off + DF_S390_HDR_SIZE, ZG_CHECK);
	zg_read(g.fh, buf, cnt, ZG_CHECK);
}

/*
 * s390_ext mem chunk read callback
 */
static void dfi_s390_ext_mem_chunk_read(struct dfi_mem_chunk *mem_chunk,
					u64 off, void *buf, u64 cnt)
{
	u64 *mem_chunk_off = mem_chunk->data;

	zg_seek(g.fh, *mem_chunk_off + off, ZG_CHECK);
	zg_read(g.fh, buf, cnt, ZG_CHECK);
}


/*
 * Read s390 dump header
 */
static int read_s390_hdr(void)
{
	u64 magic_number;

	magic_number = l.extended ? DF_S390_MAGIC_EXT : DF_S390_MAGIC;
	if ((zg_type(g.fh) == ZG_TYPE_FILE) && (zg_size(g.fh) < sizeof(l.hdr)))
		return -ENODEV;
	if (zg_read(g.fh, &l.hdr, sizeof(l.hdr), ZG_CHECK_ERR) != sizeof(l.hdr))
		return -ENODEV;
	if (l.hdr.magic != magic_number)
		return -ENODEV;
	if (l.hdr.cpu_cnt > DF_S390_CPU_MAX)
		return -ENODEV;
	util_log_print(UTIL_LOG_INFO, "DFI S390 version %u\n", l.hdr.version);
	df_s390_hdr_add(&l.hdr);
	return 0;
}

/*
 * Init end marker
 */
static int read_s390_em(void)
{
	u64 rc;

	rc = zg_read(g.fh, &l.em, sizeof(l.em), ZG_CHECK_ERR);
	if (rc != sizeof(l.em))
		return -EINVAL;
	if (df_s390_em_verify(&l.em, &l.hdr) != 0)
		return -EINVAL;
	df_s390_em_add(&l.em);
	return 0;
}

/*
 * Register memory chunks and verify the end marker
 */
static int mem_chunks_add(void)
{
	u64 rc;

	util_log_print(UTIL_LOG_DEBUG, "DFI S390 mem_size 0x%016lx\n",
		       l.hdr.mem_size);

	/* Single memory chunk for non-extended dump format */
	dfi_mem_chunk_add(0, l.hdr.mem_size, NULL,
			  dfi_s390_mem_chunk_read,
			  NULL);
	rc = zg_seek(g.fh, DF_S390_HDR_SIZE + l.hdr.mem_size,
		     ZG_CHECK_NONE);
	if (rc != DF_S390_HDR_SIZE + l.hdr.mem_size)
		return -EINVAL;
	/* Read and verify the end marker */
	return read_s390_em();
}

/*
 * Register memory chunks (extended dump format) and verify the end marker
 */
static int mem_chunks_add_ext(void)
{
	struct df_s390_dump_segm_hdr dump_segm = { 0 };
	u64 rc, off, old = 0, dump_size = 0;

	off = zg_seek(g.fh, DF_S390_HDR_SIZE, ZG_CHECK_NONE);
	if (off != DF_S390_HDR_SIZE)
		return -EINVAL;
	while (off < DF_S390_HDR_SIZE + l.hdr.mem_size - PAGE_SIZE) {
		rc = zg_read(g.fh, &dump_segm, PAGE_SIZE, ZG_CHECK_ERR);
		if (rc != PAGE_SIZE)
			return -EINVAL;
		util_log_print(UTIL_LOG_DEBUG,
			       "DFI S390 dump segment start 0x%016lx size 0x%016lx stop marker %d\n",
			       dump_segm.start, dump_segm.len, dump_segm.stop_marker);
		off += PAGE_SIZE;
		/* Add zero memory chunk */
		dfi_mem_chunk_add(old, dump_segm.start - old, NULL,
				  dfi_mem_chunk_read_zero, NULL);
		/* Add memory chunk for a dump segment */
		u64 *off_ptr = zg_alloc(sizeof(*off_ptr));
		*off_ptr = off;
		dfi_mem_chunk_add(dump_segm.start, dump_segm.len, off_ptr,
				  dfi_s390_ext_mem_chunk_read, zg_free);
		off_ptr = NULL;
		old = dump_segm.start + dump_segm.len;
		dump_size += dump_segm.len;
		off = zg_seek_cur(g.fh, dump_segm.len, ZG_CHECK_NONE);
		if (dump_segm.stop_marker)
			break;
	}
	/* Check if the last dump segment found */
	if (!dump_segm.stop_marker)
		return -EINVAL;
	/* Add zero memory chunk at the end */
	dfi_mem_chunk_add(old, l.hdr.mem_size - old, NULL,
			  dfi_mem_chunk_read_zero, NULL);
	/* Set the actual size of the dump file */
	dfi_attr_file_size_set(dump_size);
	/* Read and verify the end marker */
	return read_s390_em();
}

/*
 * Initialize s390 single-volume DFI general function
 */
int dfi_s390_init_gen(bool extended)
{
	int rc;

	util_log_print(UTIL_LOG_DEBUG, "DFI S390 %sinitialization\n",
		       extended ? "extended " : "");

	l.extended = extended;
	if (read_s390_hdr() != 0)
		return -ENODEV;
	if (!extended)
		rc = mem_chunks_add();
	else
		rc = mem_chunks_add_ext();
	if (rc)
		return rc;
	rc = df_s390_cpu_info_add(&l.hdr, l.hdr.mem_size);
	if (rc)
		return rc;
	zg_seek(g.fh, sizeof(l.hdr), ZG_CHECK);
	return 0;
}

/*
 * Initialize s390 single-volume DFI (non-extended)
 */
static int dfi_s390_init(void)
{
	return dfi_s390_init_gen(DUMP_NON_EXTENDED);
}

/*
 * s390 single-volume DFI (non-extended) operations
 */
struct dfi dfi_s390 = {
	.name		= "s390",
	.init		= dfi_s390_init,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
