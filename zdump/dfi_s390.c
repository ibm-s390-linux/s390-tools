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
#include <zlib.h>

#include "lib/util_log.h"
#include "dump/s390_dump.h"

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
	int blk_size;			/* Dump device block size */
} l;

struct mem_chunk_compressed_data {
	/* Offset of the dump segment data on disk in bytes */
	u64 offset_on_disk;
	/* Number of compressed entries */
	u32 entry_count;
	/*
	 * Offsets to compressed entries from
	 * the start of mem_chunk in blocks
	 */
	u32 entry_offset[];
};

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
	util_log_print(UTIL_LOG_DEBUG,
		       "DFI S390 mem_chunk_read: start=0x%016lx, off=0x%016lx, cnt=0x%08lx\n",
		       mem_chunk->start, off, cnt);

	zg_seek(g.fh, *mem_chunk_off + off, ZG_CHECK);
	zg_read(g.fh, buf, cnt, ZG_CHECK);
}

static inline unsigned long b2m(unsigned long blk)
{
	return blk * l.blk_size;
}

/*
 * Read compressed data entry using global file handle and decompress up to
 * count bytes to the output buffer. The size of the output buffer considered
 * to be enough to fit the decompressed data.
 */
static unsigned long read_decompress_entry(void *buf_out, u64 count)
{
	unsigned char buf_in[8 * PAGE_SIZE];
	z_stream strm = { 0 };
	u64 total_out;
	int rc;

	/* Initialize inflate stream */
	strm.next_in = NULL;
	strm.avail_in = 0;
	rc = inflateInit2(&strm, MAX_WBITS);
	if (rc != Z_OK)
		ERR_EXIT("Decompression failed, inflateInit RC = %d", rc);
	strm.next_out = buf_out;
	strm.avail_out = count;
	/* Decompress data entry to the output buffer */
	while (rc != Z_STREAM_END) {
		/* Read in more compressed data */
		if (strm.avail_in == 0) {
			strm.next_in = buf_in;
			rc = zg_read(g.fh, buf_in, sizeof(buf_in), ZG_CHECK_NONE);
			if (rc < 0)
				ERR_EXIT("Decompression failed, read error encountered");
			strm.avail_in = rc;
		}
		rc = inflate(&strm, Z_SYNC_FLUSH);
		if (rc != Z_OK && rc != Z_STREAM_END)
			ERR_EXIT("Decompression failed, inflate RC = %d", rc);
		/* No need to decompress more data */
		if (strm.avail_out == 0)
			break;
	}
	total_out = strm.total_out;
	inflateEnd(&strm);
	return total_out;
}

/*
 * s390_ext compressed mem chunk read callback
 */
static void dfi_s390_ext_mem_chunk_read_decompress(struct dfi_mem_chunk *mem_chunk,
						   u64 off, void *buf, u64 cnt)
{
	u64 bytes_to_copy, start_offset, compressed_data_addr, copied, decompressed_out;
	struct mem_chunk_compressed_data *data = mem_chunk->data;
	u32 uncompressed, entry_size, entry_index;
	void *buf_out;

	util_log_print(UTIL_LOG_DEBUG,
		       "DFI S390 mem_chunk_read_decomp: start=0x%016lx, offset_on_disk=0x%016lx, off=0x%016lx, cnt=0x%08lx\n",
		       mem_chunk->start, data->offset_on_disk, off, cnt);
	/*
	 * The dump is compressed in data pieces of equal size (stored in the dump header).
	 * Identify the first compressed entry of interest within a memory chunk.
	 */
	entry_size = l.hdr.zlib_entry_size;
	entry_index = off / entry_size;
	/* Offset within the decompressed data of the first entry */
	start_offset = off % entry_size;
	buf_out = zg_alloc(entry_size);
	copied = 0;
	while (copied < cnt) {
		if (entry_index >= data->entry_count)
			ERR_EXIT("Decompression failed, compressed entry index out of bounds");
		/* Check if the entry is actually compressed */
		uncompressed = data->entry_offset[entry_index] & DUMP_SEGM_ENTRY_UNCOMPRESSED;
		/* Calculate entry location on disk */
		compressed_data_addr = data->offset_on_disk +
			b2m(~DUMP_SEGM_ENTRY_UNCOMPRESSED & data->entry_offset[entry_index]);
		if (uncompressed) {
			/* Read entire uncompressed entry from disk */
			zg_seek(g.fh, compressed_data_addr + start_offset, ZG_CHECK);
			bytes_to_copy = MIN(cnt - copied, entry_size - start_offset);
			zg_read(g.fh, buf + copied, bytes_to_copy, ZG_CHECK);
		} else {
			/*
			 * Decompress entry to the output buffer. Limit the size of the
			 * output data if needed.
			 */
			zg_seek(g.fh, compressed_data_addr, ZG_CHECK);
			decompressed_out = MIN(start_offset + cnt - copied, entry_size);
			decompressed_out = read_decompress_entry(buf_out, decompressed_out);
			/* Copy the decompressed output produced so far */
			bytes_to_copy = MIN(decompressed_out - start_offset, cnt - copied);
			memcpy(buf + copied, buf_out + start_offset, bytes_to_copy);
		}
		copied += bytes_to_copy;
		entry_index++;
		/* For further entries, copy from the start of the decompressed data */
		start_offset = 0;
	}
	zg_free(buf_out);
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
	if (l.hdr.arch != DF_S390_ARCH_64)
		ERR_EXIT("Dump architecture is not supported!");
	if (l.hdr.build_arch && l.hdr.build_arch != DF_S390_ARCH_64)
		ERR_EXIT("Dump-tool build architecture is not supported!");
	if (l.hdr.cpu_cnt > DF_S390_CPU_MAX)
		return -ENODEV;
	if (l.hdr.zlib_version_s390 && l.hdr.version != 2)
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
 * Add memory chunk for a compressed dump segment. Set file handle position
 * and return the offset to the next dump segment.
 */
static void create_compressed_mem_chunk(const struct df_s390_dump_segm_hdr *dump_segm,
					u64 offset)
{
	/*
	 * Need to preserve entry_offset array from the header of a
	 * compressed segment along with the segment offset on disk
	 * for the read callback function.
	 */
	struct mem_chunk_compressed_data *data = zg_alloc(sizeof(*data) +
			dump_segm->entry_count * sizeof(u32));
	data->offset_on_disk = offset;
	data->entry_count = dump_segm->entry_count;
	memcpy(&data->entry_offset, &dump_segm->entry_offset,
	       data->entry_count * sizeof(u32));
	dfi_mem_chunk_add(dump_segm->start, dump_segm->len, data,
			  dfi_s390_ext_mem_chunk_read_decompress, zg_free);
	data = NULL;
}

/*
 * Add memory chunk for a non-compressed dump segment. Set file handle position
 * and return the offset to the next dump segment.
 */
static void create_uncompressed_mem_chunk(const struct df_s390_dump_segm_hdr *dump_segm,
					  u64 offset)
{
	/* For non-compressed segment just an offset is needed for a callback */
	u64 *off_ptr = zg_alloc(sizeof(*off_ptr));
	*off_ptr = offset;
	dfi_mem_chunk_add(dump_segm->start, dump_segm->len, off_ptr,
			  dfi_s390_ext_mem_chunk_read, zg_free);
	off_ptr = NULL;
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
	while (off < DF_S390_HDR_SIZE + l.hdr.mem_size) {
		rc = zg_read(g.fh, &dump_segm, sizeof(dump_segm), ZG_CHECK_ERR);
		if (rc != sizeof(dump_segm))
			return -EINVAL;
		util_log_print(UTIL_LOG_DEBUG,
			       "DFI S390 dump segment start 0x%016lx size 0x%016lx compr_size 0x%08lx stop marker %d\n",
			       dump_segm.start, dump_segm.len, b2m(dump_segm.size_on_disk),
			       dump_segm.stop_marker ? 1 : 0);
		off += sizeof(dump_segm);
		/* Add zero memory chunk */
		dfi_mem_chunk_add(old, dump_segm.start - old, NULL,
				  dfi_mem_chunk_read_zero, NULL);
		/* Add memory chunk for a dump segment */
		if (dump_segm.size_on_disk) {
			/* Compressed dump segment detected */
			create_compressed_mem_chunk(&dump_segm, off);
			off = zg_seek_cur(g.fh, b2m(dump_segm.size_on_disk), ZG_CHECK_NONE);
			dump_size += b2m(dump_segm.size_on_disk);
		} else {
			create_uncompressed_mem_chunk(&dump_segm, off);
			off = zg_seek_cur(g.fh, dump_segm.len, ZG_CHECK_NONE);
			dump_size += dump_segm.len;
		}
		old = dump_segm.start + dump_segm.len;
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
	if (!extended) {
		rc = mem_chunks_add();
	} else {
		/*
		 * A device block size is required for a decompression of
		 * s390_ext dump with compressed dump segments.
		 * Since dumps in s390_ext format can reside on DASD partition
		 * only, bail out upon ioctl error on BLKSSZGET.
		 */
		if (zg_ioctl(g.fh, BLKSSZGET, &l.blk_size, "BLKSSZGET", ZG_CHECK_NONE))
			return -ENODEV;
		rc = mem_chunks_add_ext();
	}
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
