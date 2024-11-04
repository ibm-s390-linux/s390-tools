/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * LKCD dump input format
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>
#include <errno.h>
#include <zlib.h>

#include "zgetdump.h"
#include "zg.h"
#include "df_lkcd.h"
#include "dfi.h"
#include "dfi_mem_chunk.h"

#define MEM_HOLE_SIZE_MIN	(1024 * 1024)
#define IDX_KIB		64	/* One index entry per IDX_KIB */
#define IDX_TO_ADDR(idx) (idx * IDX_KIB * 1024)
#define ADDR_TO_IDX(addr) (addr / (1024 * IDX_KIB))

/*
 * File local static data
 */
static struct {
	u64			*pg_hdr_idx;
	u64			page_last;
	struct df_lkcd_hdr	hdr;
	struct df_lkcd_hdr_asm	hdr_asm;
	int			dump_full;
} l;

/*
 * Read LKCD page buffer, either compressed or uncompressed
 */
static void read_page_buf(struct df_lkcd_pg_hdr *pg_hdr, void *buf)
{
	unsigned long size = PAGE_SIZE;
	unsigned char cbuf[PAGE_SIZE];

	switch (pg_hdr->flags) {
	case DF_LKCD_DH_RAW:
		zg_read(g.fh, buf, pg_hdr->size, ZG_CHECK);
		break;
	case DF_LKCD_DH_COMPRESSED:
		zg_read(g.fh, cbuf, pg_hdr->size, ZG_CHECK);
		uncompress(buf, &size, cbuf, pg_hdr->size);
		if (size != PAGE_SIZE)
			ABORT("Invalid page size: %ld", size);
		break;
	default:
		ERR_EXIT("Unsupported page flags: %x at addr %Lx",
			 pg_hdr->flags, pg_hdr->addr);
	}
}

/*
 * Read next LKCD page from current file position
 *
 * If we find the page, we copy the page content. If the page is not present
 * we copy zeroes and skip it. If the page address is not yet reached, we just
 * skip it.
 */
static int read_next_page(u64 addr, void *buf)
{
	struct df_lkcd_pg_hdr pg_hdr;

	zg_read(g.fh, &pg_hdr, sizeof(pg_hdr), ZG_CHECK);
	l.page_last = pg_hdr.addr / PAGE_SIZE;
	if (pg_hdr.addr == addr) {
		read_page_buf(&pg_hdr, buf);
		return 0;
	}
	if (pg_hdr.addr > addr) {
		memset(buf, 0, PAGE_SIZE);
		zg_seek_cur(g.fh, pg_hdr.size, ZG_CHECK);
		return 0;
	}
	zg_seek_cur(g.fh, pg_hdr.size, ZG_CHECK);
	return -ENODEV;
}

/*
 * Read LKCD dump page for flex dump
 *
 * If the page after the last read page should be read, we just read
 * the next one. Otherwise we seek to the beginning of the page cluster
 * of the page index and search the page there.
 */
static void read_page_flex(u64 pg_num, void *buf)
{
	u64 addr = pg_num * PAGE_SIZE;

	if (l.pg_hdr_idx[ADDR_TO_IDX(addr)] == 0)
		ABORT("Dump page index broken");

	if (l.page_last == pg_num - 1) {
		read_next_page(addr, buf);
		return;
	}

	zg_seek(g.fh, l.pg_hdr_idx[ADDR_TO_IDX(addr)], ZG_CHECK);
	do {
		if (read_next_page(addr, buf) == 0)
			break;
	} while (1);
}

/*
 * Read lkcd page for full dump
 */
static void read_page_full(u64 pg_num, void *buf)
{
	zg_seek(g.fh, DF_LKCD_HDR_SIZE + pg_num * DF_LKCD_UCP_SIZE +
		sizeof(struct df_lkcd_pg_hdr), ZG_CHECK);
	zg_read(g.fh, buf, PAGE_SIZE, ZG_CHECK);
}

/*
 * Read lkcd page
 */
static void read_page(u64 pg_num, void *buf)
{
	if (l.dump_full)
		read_page_full(pg_num, buf);
	else
		read_page_flex(pg_num, buf);
}

/*
 * LKCD mem chunk read callback
 */
static void dfi_lkcd_mem_chunk_read_fn(struct dfi_mem_chunk *mem_chunk, u64 off,
				       void *buf, u64 cnt)
{
	u64 copied = 0, size, pg_nr, addr = off + mem_chunk->start;
	char pg_buf[PAGE_SIZE];
	unsigned int pg_off;

	while (copied != cnt) {
		pg_nr = (addr + copied) / PAGE_SIZE;
		pg_off = (addr + copied) % PAGE_SIZE;
		size = MIN(cnt - copied, PAGE_SIZE - pg_off);
		read_page(pg_nr, pg_buf);
		memcpy(buf + copied, &pg_buf[pg_off], size);
		copied += size;
	}
}

/*
 * Did we find the end of the LCKD dump?
 */
static int dump_end(u64 addr, struct df_lkcd_pg_hdr *pg_hdr)
{
	if (addr == pg_hdr->addr) {
		/*
		 * This is a workaroud for a bug in vmconvert,
		 * where instaed of the end marker the last
		 * page was written twice. Sorry for that...
		 */
		return 1;
	}
	if (pg_hdr->addr == 0 && pg_hdr->size == 4 && pg_hdr->flags == 0) {
		/*
		 * zfcpdump bug (wrong end marker)
		 */
		return 1;
	}
	if (pg_hdr->flags == DF_LKCD_DH_END)
		return 1;
	return 0;
}

/*
 * Init memory chunks for full dump
 *
 * Full dump: It is not compressed and it does not have any memory holes.
 */
static int mem_init_full(void)
{
	dfi_mem_chunk_add(0, l.hdr.mem_end, NULL, dfi_lkcd_mem_chunk_read_fn,
			  NULL);
	l.dump_full = 1;
	return 0;
}

/*
 * Init memory chunks for flex dump
 *
 * Flex dump: It is compressed and/or it has memory holes.
 */
static int mem_init_flex(void)
{
	u64 addr = U64_MAX, idx = 0, mem_chunk_start = 0, rc;
	struct df_lkcd_pg_hdr pg_hdr;
	int dump_incomplete = 0;

	l.pg_hdr_idx = zg_alloc(sizeof(u64) * (ADDR_TO_IDX(l.hdr.mem_end) + 1));
	zg_seek(g.fh, DF_LKCD_HDR_SIZE, ZG_CHECK_NONE);
	zg_progress_init("Analyzing dump", l.hdr.mem_end);
	do {
		rc = zg_read(g.fh, &pg_hdr, sizeof(pg_hdr), ZG_CHECK_ERR);
		if (rc != sizeof(pg_hdr)) {
			dump_incomplete = 1;
			break;
		}
		if (dump_end(addr, &pg_hdr))
			break;
		if (pg_hdr.addr - addr > MEM_HOLE_SIZE_MIN) {
			dfi_mem_chunk_add(mem_chunk_start,
					  addr + PAGE_SIZE - mem_chunk_start,
					  NULL, dfi_lkcd_mem_chunk_read_fn,
					  NULL);
			mem_chunk_start = pg_hdr.addr;
		}
		addr = pg_hdr.addr;
		zg_progress(addr);
		if (addr >= IDX_TO_ADDR(idx)) {
			idx = ADDR_TO_IDX(addr);
			l.pg_hdr_idx[idx] = zg_tell(g.fh, ZG_CHECK) -
				sizeof(pg_hdr);
			idx++;
		}
		zg_seek_cur(g.fh, pg_hdr.size, ZG_CHECK);
	} while (1);

	if (addr != mem_chunk_start) {
		dfi_mem_chunk_add(mem_chunk_start,
				  l.hdr.mem_end - mem_chunk_start,
				  NULL, dfi_lkcd_mem_chunk_read_fn, NULL);
	}
	zg_progress(l.hdr.mem_end);
	if (g.opts.action != ZG_ACTION_MOUNT)
		fprintf(stderr, "\n");
	if (dump_incomplete)
		return -EINVAL;
	return 0;
}

/*
 * Do we have a full dump?
 */
static int is_full_dump(void)
{
	u64 full_size;
	int pages;

	if (l.hdr.dump_compress != DF_LKCD_COMPRESS_NONE)
		return 0;
	pages = l.hdr.mem_end / PAGE_SIZE;
	full_size = DF_LKCD_HDR_SIZE + pages * DF_LKCD_UCP_SIZE +
		sizeof(struct df_lkcd_pg_hdr);
	if (zg_size(g.fh) != full_size)
		return 0;
	return 1;
}

/*
 * Init memory chunks
 */
static int mem_init(void)
{
	if (is_full_dump())
		return mem_init_full();
	else
		return mem_init_flex();
}

/*
 * Initialize CPU information
 */
static int cpu_init(void)
{
	unsigned int i;
	int rc;

	if (l.hdr_asm.magic != DF_LKCD_MAGIC_ASM) {
		/* Old LKCD dump without asm header */
		dfi_cpu_info_init(DFI_CPU_CONTENT_NONE);
		return 0;
	}

	dfi_cpu_info_init(DFI_CPU_CONTENT_ALL);
	for (i = 0; i < l.hdr_asm.cpu_cnt; i++) {
		rc = dfi_cpu_add_from_lc(l.hdr_asm.lc_vec[i]);
		if (rc)
			return rc;
	}

	return 0;
}

/*
 * Read LKCD dump header and dump asm header
 */
static int read_lkcd_hdr(void)
{
	if (zg_size(g.fh) < DF_LKCD_HDR_SIZE)
		return -ENODEV;

	/* Read dump header */
	zg_read(g.fh, &l.hdr, sizeof(l.hdr), ZG_CHECK);

	if (l.hdr.magic != DF_LKCD_MAGIC)
		return -ENODEV;

	/* Read asm header */
	zg_seek(g.fh, l.hdr.hdr_size, ZG_CHECK);
	zg_read(g.fh, &l.hdr_asm, sizeof(l.hdr_asm), ZG_CHECK);
	if (strncmp(l.hdr.utsname_machine, "s390x", sizeof("s390x")) != 0)
		ERR_EXIT("Dump architecture \"%s\" is not supported",
			 l.hdr.utsname_machine);
	if (l.hdr_asm.magic == DF_LKCD_MAGIC_ASM)
		dfi_attr_real_cpu_cnt_set(l.hdr_asm.real_cpu_cnt);
	dfi_attr_version_set(l.hdr.version);
	return 0;
}

/*
 * Initialize LKCD DFI
 */
static int dfi_lkcd_init(void)
{
	if (read_lkcd_hdr() != 0)
		return -ENODEV;
	if (mem_init() != 0)
		return -EINVAL;
	if (cpu_init() != 0)
		return -EINVAL;
	return 0;
}

/*
 * LKCD DFI operations
 */
struct dfi dfi_lkcd = {
	.name		= "lkcd",
	.init		= dfi_lkcd_init,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
