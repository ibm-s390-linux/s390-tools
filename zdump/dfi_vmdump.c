/*
 * zgetdump - Tool for copying and converting IBM zSystem dumps
 *
 * VMDUMP input format - Convert a vmdump 64big format to internal format.
 *
 * Copyright IBM Corp. 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <iconv.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mtio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "zgetdump.h"
#include "df_vmdump.h"
#include "dfi.h"
#include "dfi_mem_chunk.h"
#include "lib/util_log.h"
#include "lib/util_libc.h"

static struct {
	struct vmd_adsr adsr;		/* Dump file symptom record */
	struct vmd_fmbk fmbk;		/* Dump file map record */
	struct vmd_fir_basic fir_basic; /* Dump file info record */
	struct vmd_albk albk;		/* Dump access list record */

	struct vmd_asibk_64_new asibk_new;
	struct vmd_fir_64 fir;
	struct vmd_fir_other_64 *fir_other;

	u64 memory_start_record;
	u8 *bitmap;
} l;

/* Convert EBCDIC to ASCII. Used for very few selective fields. */
static void ebc_2_asc(u8 *in, u8 *out, const size_t size)
{
	iconv_t etoa = iconv_open("ISO-8859-1", "EBCDIC-US");
	size_t size_out = size;
	size_t size_in = size;
	size_t rc;

	rc = iconv(etoa, (char **)&in, &size_in, (char **)&out, &size_out);
	if (rc == (size_t)-1)
		errx(EXIT_FAILURE, "Code page translation EBCDIC-ASCII failed");
	iconv_close(etoa);
}

static void vmdump_tod_to_timeval(u64 todval, struct timeval *xtime)
{
	/* adjust todclock to 1970 */
	todval -= 0x8126d60e46000000LL - (0x3c26700LL * 1000000 * 4096);

	todval >>= 12;
	xtime->tv_sec = todval / 1000000;
	xtime->tv_usec = todval % 1000000;
}

static void vmdump64big_debug(void)
{
	u8 fmbk_id[sizeof(FMBK_MAGIC)];
	u8 albk_id[sizeof(ALBK_MAGIC)];
	struct timeval time;

	util_log_print(UTIL_LOG_DEBUG, "Memory Offset: %#lx\n", l.memory_start_record);
	util_log_print(UTIL_LOG_DEBUG, "Dumped Pages: %d\n",
		       l.asibk_new.storage_size_def_store / PAGE_SIZE);

	/* adsr */
	vmdump_tod_to_timeval(l.adsr.tod, &time);
	util_log_print(UTIL_LOG_DEBUG, "Time: %s", ctime(&time.tv_sec));
	util_log_print(UTIL_LOG_DEBUG, "Statusflag 1: %#x\n", l.adsr.record_status_flag1);
	util_log_print(UTIL_LOG_DEBUG, "Statusflag 2: %#x\n", l.adsr.record_status_flag2);
	util_log_print(UTIL_LOG_DEBUG, "Section 2 len: %i\n", l.adsr.sec2_len);
	util_log_print(UTIL_LOG_DEBUG, "Section 2.1 len: %i/%i\n", l.adsr.sec2_1_len,
		       l.adsr.sec2_1_offset);
	util_log_print(UTIL_LOG_DEBUG, "Section 3 len: %i/%i\n", l.adsr.sec3_len,
		       l.adsr.sec3_offset);
	util_log_print(UTIL_LOG_DEBUG, "Section 4 len: %i/%i\n", l.adsr.sec4_len,
		       l.adsr.sec4_offset);
	util_log_print(UTIL_LOG_DEBUG, "Section 5 len: %i/%i\n", l.adsr.sec5_len,
		       l.adsr.sec5_offset);
	util_log_print(UTIL_LOG_DEBUG, "Section 6 len: %i/%i\n", l.adsr.sec6_len,
		       l.adsr.sec6_offset);

	/* fmbk */
	ebc_2_asc(l.fmbk.id, fmbk_id, sizeof(l.fmbk.id));
	fmbk_id[sizeof(fmbk_id) - 1] = 0;
	util_log_print(UTIL_LOG_DEBUG, "Fmbk id: %8.8s\n", fmbk_id);
	util_log_print(UTIL_LOG_DEBUG, "Fir rec nr: %i\n", l.fmbk.rec_nr_fir);
	util_log_print(UTIL_LOG_DEBUG, "Vec rec nr: %i\n", l.fmbk.rec_nr_vector);
	util_log_print(UTIL_LOG_DEBUG, "Access rec nr: %i\n", l.fmbk.rec_nr_access);

	/* albk */
	ebc_2_asc(l.albk.id, albk_id, sizeof(l.albk.id));
	albk_id[sizeof(albk_id) - 1] = 0;
	util_log_print(UTIL_LOG_DEBUG, "Albk id: %8.8s\n", albk_id);

	/* fir */
	util_log_print(UTIL_LOG_DEBUG, "Cpus: %d\n", l.fir.online_cpus + 1);
	util_log_print(UTIL_LOG_DEBUG, "PSW: %#016lx %#016lx\n", l.fir.psw[0], l.fir.psw[1]);
	util_log_print(UTIL_LOG_DEBUG, "Prefix (CPU 0): %#010x\n", l.fir.prefix);
	for (unsigned int i = 0; i < l.fir.online_cpus; i++)
		util_log_print(UTIL_LOG_DEBUG, "Prefix (CPU %i): %#010x\n", i + 1,
			       l.fir_other[i].prefix);
}

static bool test_bitmap_key_page(u8 *page, const u64 bit)
{
	return page[bit] & 0x01;
}

static bool test_page_bit(u8 *bitmap, const u64 bit)
{
	return bitmap[bit / 8] & (1 << (7 - (bit % 8)));
}

static void set_page_bit(u8 *bitmap, const u64 bit)
{
	bitmap[bit / 8] |= (1 << (7 - (bit % 8)));
}

/*
 * Read VMDUMP headers, page index bit maps and page bit maps to
 * construct a list of non-zero pages with memory locations. Zeroed pages
 * are not bitmapped and are detected by memory location without bitmap
 * entry.
 */
static void vmdump64big_init(void)
{
	u64 page_num = 0, nr_dumped_pages;
	size_t bitmap_sz;
	unsigned int i;

	/* Record 1: adsr */
	zg_seek(g.fh, 0, ZG_CHECK);
	zg_read(g.fh, &l.adsr, sizeof(l.adsr), ZG_CHECK);

	if (g.opts.verbose) {
		u8 buf_asc[1024], buf[1024];

		zg_seek(g.fh, l.adsr.sec5_offset, ZG_CHECK);
		zg_read(g.fh, buf, l.adsr.sec5_len, ZG_CHECK);
		ebc_2_asc(buf, buf_asc, l.adsr.sec5_len);
		for (i = 0; i < l.adsr.sec5_len; i++) {
			if (buf_asc[i] == 0 || iscntrl(buf_asc[i]))
				buf_asc[i] = ' ';
		}
		buf_asc[l.adsr.sec5_len] = 0;
		util_log_print(UTIL_LOG_DEBUG, "Symptom string: %s\n", buf_asc);
	}

	/* Record 2: fmbk */
	zg_seek(g.fh, PAGE_SIZE, ZG_CHECK);
	zg_read(g.fh, &l.fmbk, sizeof(l.fmbk), ZG_CHECK);

	/* Record 3-7: fir records */
	zg_seek(g.fh, (l.fmbk.rec_nr_fir - 1) * PAGE_SIZE, ZG_CHECK);
	zg_read(g.fh, &l.fir, sizeof(l.fir), ZG_CHECK);

	bitmap_sz = sizeof(struct vmd_fir_other_64) * l.fir.online_cpus;
	l.fir_other = util_zalloc(bitmap_sz);
	for (i = 0; i < l.fir.online_cpus; i++)
		zg_read(g.fh, &l.fir_other[i], sizeof(l.fir_other[0]), ZG_CHECK);

	/* Record 8: albk */
	zg_seek(g.fh, (l.fmbk.rec_nr_access - 1) * PAGE_SIZE, SEEK_SET);
	zg_read(g.fh, &l.albk, sizeof(l.albk), SEEK_SET);

	/* Record 9: asibk */
	zg_seek(g.fh, l.fmbk.rec_nr_access * PAGE_SIZE, ZG_CHECK);
	zg_read(g.fh, &l.asibk_new, sizeof(l.asibk_new), ZG_CHECK);

	l.memory_start_record = (l.fmbk.rec_nr_access + 1) * PAGE_SIZE;

	/*
	 * Record 10: bitmaps:
	 * Read all bitmap pages and setup bitmap array
	 */
	nr_dumped_pages = l.asibk_new.storage_size_def_store / PAGE_SIZE;
	bitmap_sz = l.asibk_new.storage_size_def_store / (PAGE_SIZE * 8);
	if (!bitmap_sz)
		ERR_EXIT("Dump file inconsistent, no bitmap detected");
	l.bitmap = util_zalloc(bitmap_sz);
	zg_seek(g.fh, (l.fmbk.rec_nr_access + 1) * PAGE_SIZE, ZG_CHECK);

	do {
		u8 bm_index_page[PAGE_SIZE];

		zg_read(g.fh, bm_index_page, sizeof(bm_index_page), ZG_CHECK);
		l.memory_start_record += PAGE_SIZE;
		for (i = 0; i < 8 * PAGE_SIZE; i++) {
			if (test_page_bit(bm_index_page, i)) {
				u8 bm_page[PAGE_SIZE];

				zg_read(g.fh, bm_page, sizeof(bm_page), ZG_CHECK);
				l.memory_start_record += PAGE_SIZE;
				for (unsigned int j = 0; j < PAGE_SIZE; j++) {
					if (page_num / 8 >= bitmap_sz)
						ERR_EXIT("Dump file inconsistent,"
							 " corrupted bitmap detected");
					if (test_bitmap_key_page(bm_page, j))
						set_page_bit(l.bitmap, page_num);
					page_num++;
					if (page_num == nr_dumped_pages)
						goto out;
				}
			} else {
				page_num += PAGE_SIZE; /* Empty page */
			}
		}
	} while (page_num < nr_dumped_pages);

out:
	vmdump64big_debug();
}

static void display_register(const struct dfi_cpu *cpu)
{
	unsigned int i;

	util_log_print(UTIL_LOG_TRACE, "CPU %d\n", cpu->cpu_id);
	for (i = 0; i < ARRAY_SIZE(cpu->gprs); i += 2)
		util_log_print(UTIL_LOG_TRACE, "gpr%02d: %016lx\t gpr%02d: %016lx\n", i,
			       cpu->gprs[i], i + 1, cpu->gprs[i + 1]);
	for (i = 0; i < ARRAY_SIZE(cpu->ctrs); i += 2)
		util_log_print(UTIL_LOG_TRACE, "ctr%02d: %016lx\t ctr%02d: %016lx\n", i,
			       cpu->ctrs[i], i + 1, cpu->ctrs[i + 1]);
	for (i = 0; i < ARRAY_SIZE(cpu->acrs); i += 2)
		util_log_print(UTIL_LOG_TRACE, "acr%02d: %016lx\t acr%02d: %016lx\n", i,
			       cpu->acrs[i], i + 1, cpu->acrs[i + 1]);
	for (i = 0; i < ARRAY_SIZE(cpu->fprs); i += 2)
		util_log_print(UTIL_LOG_TRACE, "fpr%02d: %016lx\t fpr%02d: %016lx\n", i,
			       cpu->fprs[i], i + 1, cpu->fprs[i + 1]);
}

/*
 * Read out register setting for each CPU.
 */
static void vmdump_read_register(int cpu_nr)
{
	struct dfi_cpu *cpu;

	if (cpu_nr >= l.fir.online_cpus + 1)
		return;

	cpu = dfi_cpu_alloc();
	cpu->cpu_id = dfi_cpu_cnt();
	if (!cpu_nr) { /* First CPU in fir */
		memcpy(cpu->gprs, l.fir.gprs, sizeof(cpu->gprs));
		memcpy(cpu->ctrs, &l.fir.crs, sizeof(cpu->ctrs));
		memcpy(cpu->acrs, &l.fir.acrs, sizeof(cpu->acrs));
		memcpy(cpu->fprs, &l.fir.fprs, sizeof(cpu->fprs));
		memcpy(cpu->psw, &l.fir.psw, sizeof(cpu->psw));
		memcpy(&cpu->prefix, &l.fir.prefix, sizeof(cpu->prefix));
		memcpy(&cpu->timer, &l.fir.cpu_timer, sizeof(cpu->timer));
		memcpy(&cpu->todcmp, &l.fir.clock_cmp, sizeof(cpu->todcmp));
		memcpy(&cpu->fpc, &l.fir.fp_cntrl_reg, sizeof(cpu->fpc));
	} else {
		cpu_nr -= 1; /* Other CPUs start at offset 0 in fir_other */
		memcpy(cpu->gprs, l.fir_other[cpu_nr].gprs, sizeof(cpu->gprs));
		memcpy(cpu->ctrs, &l.fir_other[cpu_nr].crs, sizeof(cpu->ctrs));
		memcpy(cpu->acrs, &l.fir_other[cpu_nr].acrs, sizeof(cpu->acrs));
		memcpy(cpu->fprs, &l.fir_other[cpu_nr].fprs, sizeof(cpu->fprs));
		memcpy(cpu->psw, &l.fir_other[cpu_nr].psw, sizeof(cpu->psw));
		memcpy(&cpu->prefix, &l.fir_other[cpu_nr].prefix, sizeof(cpu->prefix));
		memcpy(&cpu->timer, &l.fir_other[cpu_nr].cpu_timer, sizeof(cpu->timer));
		memcpy(&cpu->todcmp, &l.fir_other[cpu_nr].clock_cmp, sizeof(cpu->todcmp));
		memcpy(&cpu->fpc, &l.fir_other[cpu_nr].fp_cntrl_reg, sizeof(cpu->fpc));
	}
	display_register(cpu);
	dfi_cpu_add(cpu);
}

/*
 * Initialize z/VM VMDUMP file DFI. Check if the input file is vmdump file
 * with format 64big. Other formats are not supported.
 */
static int read_vmdump_hdr(void)
{
	if (zg_type(g.fh) != ZG_TYPE_FILE)
		return -EBADF;
	if (zg_size(g.fh) < DF_VMDUMP_HDR_SIZE)
		return -ENODEV;
	zg_read(g.fh, &l.adsr, sizeof(l.adsr), ZG_CHECK);
	if (memcmp(l.adsr.sr, ADSR_MAGIC, sizeof(l.adsr.sr)))
		return -EBADF; /* Not an ADSR record */
	if (memcmp(l.adsr.dump_type, VMDUMP_MAGIC, sizeof(l.adsr.dump_type)))
		return -EBADF; /* Not a vmdump */
	zg_seek(g.fh, PAGE_SIZE, ZG_CHECK);
	zg_read(g.fh, &l.fmbk, sizeof(l.fmbk), ZG_CHECK);
	if (memcmp(l.fmbk.id, FMBK_MAGIC, sizeof(l.fmbk.id)))
		return -EBADF; /* Not a FMBK record */

	/* Record 3-7: fir */
	zg_seek(g.fh, (l.fmbk.rec_nr_fir - 1) * PAGE_SIZE, ZG_CHECK);
	zg_read(g.fh, &l.fir, sizeof(l.fir), ZG_CHECK);
	switch (l.fir.fir_format) {
	case 0x0:
	case 0x82:
		util_log_print(UTIL_LOG_DEBUG, "Vmdump %d bit format not supported anymore\n",
			       l.fir.fir_format ? 64 : 32);
		return -EBADF;
	case 0x2:
		util_log_print(UTIL_LOG_DEBUG, "%s: Vmdump 64big format\n", g.opts.device);
		break;
	default:
		util_log_print(UTIL_LOG_DEBUG, "Vmdump unknown format\n");
		return -EBADF;
	}

	return 0;
}

/*
 * Read vmdump page. Need to check if page was dumped or is located in a
 * hole. Holes are ranges of pages full of zeroes.
 * The vmdump file format has a 64KB header followed by some bitmaps for
 * valid non-zero pages and the 4KB memory pages itself. Only non-zero pages
 * are stored. The memory pages start at vmdump file location stored in
 * member named memory_start_record.
 *
 * Bit map organization:
 * Page 0: bitmap byte 0 bit 0 (most signification bit)
 * Page 1: bitmap byte 0 bit 1 (seconds most signification bit)
 * ...
 * Page 15: bitmap byte 1 bit 7 (least signification bit)
 *
 * If a bit for a page is set, this page is stored in the vmdump file.
 * The location in the file depends on the number of previous non-zero pages.
 * If bitmap byte zero has value 1 and bitmap byte one has value 5, three
 * bits are set and page 15 is located at file offset:
 * memory_start_record + 2 * PAGE_SIZE.
 *
 * Calculate the number of bits set to determine the file location of a
 * given page in the vmdump file.
 */
static unsigned int count_bits(u8 x)
{
	unsigned int bits_set = 0;

	while (x) {
		bits_set += x & 1;
		x >>= 1;
	}
	return bits_set;
}

/*
 * Return byte offset into vmdump file for a given page number.
 */
static u64 bitmap_2_fileoffset(const u64 pg_num)
{
	unsigned int bytes_to_check = pg_num / 8;
	unsigned int bits_to_check = pg_num % 8;
	unsigned int bits_set = 0;

	/* Count bits set in first to second last byte */
	for (unsigned int i = 0; i < bytes_to_check; i++)
		bits_set += count_bits(l.bitmap[i]);

	/* Count bits set in last byte */
	bits_set += count_bits(l.bitmap[bytes_to_check] >> (8 - bits_to_check));
	return bits_set * PAGE_SIZE;
}

static void read_page(const u64 pg_num, void *buf)
{
	if (test_page_bit(l.bitmap, pg_num)) {
		u64 file_off = bitmap_2_fileoffset(pg_num);

		zg_seek(g.fh, l.memory_start_record + file_off, ZG_CHECK);
		zg_read(g.fh, buf, PAGE_SIZE, ZG_CHECK);
	} else {
		memset(buf, 0, PAGE_SIZE);
	}
}

/*
 * VMDUMP mem chunk read callback
 */
static void dfi_vmdump_mem_chunk_read_fn(struct dfi_mem_chunk *mem_chunk, u64 off, void *buf,
					 u64 cnt)
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

static void cpu_init(void)
{
	dfi_cpu_info_init(DFI_CPU_CONTENT_ALL);
	for (unsigned int i = 0; i <= l.fir.online_cpus; i++)
		vmdump_read_register(i);
}

/*
 * Walk bitmap and find consecutive bitstring consisting of '1' or '0'.
 * Return its length.
 */
static u64 find_bitrange(u8 *bitmap, const u64 bit, const u64 max, const bool isset)
{
	u64 pos;

	for (pos = bit + 1; pos < max && test_page_bit(bitmap, pos) == isset; pos++)
		;
	return pos - bit;
}

static void mem_init(void)
{
	u64 nr_dumped_pages = l.asibk_new.storage_size_def_store / PAGE_SIZE;
	u64 pos, more;

	for (pos = 0; pos < nr_dumped_pages;) {
		bool isset = test_page_bit(l.bitmap, pos);

		more = find_bitrange(l.bitmap, pos, nr_dumped_pages, isset);
		dfi_mem_chunk_add(pos * PAGE_SIZE, more * PAGE_SIZE, NULL,
				  isset ? dfi_vmdump_mem_chunk_read_fn : dfi_mem_chunk_read_zero,
				  NULL);
		pos += more;
	}
}

static int dfi_vmdump_init(void)
{
	if (read_vmdump_hdr())
		return -ENODEV;

	vmdump64big_init();
	dfi_attr_version_set(l.fir.fir_format);
	dfi_arch_set(DFI_ARCH_64);
	dfi_attr_real_cpu_cnt_set(l.fir.online_cpus + 1);
	mem_init();
	cpu_init();
	return 0;
}

/*
 * z/VM VMDUMP DFI operations
 */
struct dfi dfi_vmdump = {
	.name = "vmdump",
	.init = dfi_vmdump_init,
	.feat_bits = DFI_FEAT_SEEK | DFI_FEAT_COPY,
};
