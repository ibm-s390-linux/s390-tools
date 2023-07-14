/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Common ECKD dump I/O functions
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "cio.h"
#include "eckd2dump.h"
#include "eckd2dump_zlib.h"
#include "boot/linux_layout.h"
#include "boot/s390.h"
#include "stage2dump.h"
#include "dump/s390_dump.h"

/*
 * The first megabyte of memory is used for zlib workspace and
 * the output buffer for compressed data.
 */
static void *zlib_out_buf;		// zlib output buffer
static unsigned long zlib_buf_size;	// zlib output buffer size

/* Zlib workspace memory offset (skipping first 64K for the dumper itself) */
#define ZLIB_WORKSPACE_OFFSET		IMAGE_ENTRY

/*
 * Zlib workspace initialization.
 * Return -1 if zlib deflate workspace requires more than half of the
 * reserved memory area. Otherwise return 0.
 */
int zlib_workarea_init(unsigned long addr, z_stream *strm)
{
	strm->workspace = (void *)MAX(addr, ZLIB_WORKSPACE_OFFSET);
	zlib_out_buf = (void *)ROUND_UP((unsigned long)strm->workspace +
					zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL),
					PAGE_SIZE);
	/* Make sure there is enough space left for zlib output buffer (at least half) */
	if ((unsigned long)(zlib_out_buf - strm->workspace) > ZLIB_WORKSPACE_LIMIT / 2)
		return -1;
	/* Memory left for zlib output buffer (currently 692K) */
	zlib_buf_size = addr + ZLIB_WORKSPACE_LIMIT - (unsigned long)zlib_out_buf;
	return 0;
}

#define COMPRESSED		0
#define UNCOMPRESSED		1
#define COMPRESSION_ERROR	-1

/*
 * Compress chunk of data of given length at the given address using zlib
 * deflate compression and write it starting from the given block number.
 * Variable *blk is updated to the next free block number.
 * Return 0 if memory chunk is successfully compressed and written.
 * Return 1 if compression is ineffective and the entire chunk is written
 * uncompressed.
 * In case of deflate error, write the chunk uncompressed and return -1
 */
static int compress_write_next_chunk(unsigned long addr, unsigned long len,
				     unsigned long *blk, z_stream *strm)
{
	unsigned long start_blk;
	int rc;

	/* Reset the stream for each new chunk */
	zlib_deflateReset(strm);
	strm->next_in = (void *)addr;
	strm->avail_in = len;
	strm->next_out = zlib_out_buf;
	strm->avail_out = zlib_buf_size;
	start_blk = *blk;
	while (strm->avail_in != 0) {
		rc = zlib_deflate(strm, Z_NO_FLUSH);
		/*
		 * Compression error. Write this data chunk uncompressed and
		 * notify the caller.
		 */
		if (rc != Z_OK) {
			*blk = write_addr_range(start_blk, addr, len, NO_PROGRESS);
			return COMPRESSION_ERROR;
		}
		if (strm->avail_out == 0) {
			/*
			 * If compressed output is larger than the input, write this chunk of
			 * data uncompressed and notify the caller with the return code.
			 * Do it only if no compressed output has been written yet.
			 */
			if (strm->total_out >= strm->total_in &&
			    *blk == start_blk) {
				*blk = write_addr_range(start_blk, addr, len, NO_PROGRESS);
				return UNCOMPRESSED;
			}
			*blk = write_addr_range(*blk, (unsigned long)zlib_out_buf,
						zlib_buf_size, NO_PROGRESS);
			strm->next_out = (void *)zlib_out_buf;
			strm->avail_out = zlib_buf_size;
		}
	}
	while (rc == Z_OK) {
		strm->next_in = NULL;
		strm->avail_in = 0;
		rc = zlib_deflate(strm, Z_FINISH);
		len = ROUND_UP(zlib_buf_size - strm->avail_out, PAGE_SIZE);
		*blk = write_addr_range(*blk, (unsigned long)zlib_out_buf, len, NO_PROGRESS);
		if (strm->avail_out == 0) {
			strm->next_out = zlib_out_buf;
			strm->avail_out = zlib_buf_size;
			rc = Z_OK;
		} else {
			break;
		}
	}
	return COMPRESSED;
}

/*
 * Compress and write memory dump segment with the uncompressed header to DASD
 * and return the next free block number.
 * The compression takes place in chunks of data of equal size (currently 1MB)
 * and the offset of each compressed chunk is stored in the dump segment
 * header. Due to limited size of header, the maximum size of compressed dump
 * segment is limited to  DUMP_SEGM_ZLIB_MAXLEN.
 * If compression of a memory chunk leads to the data expansion (due to
 * incompressible input), the chunk of data is written uncompressed.
 * Thus every chunk of data is compressed separately and can be
 * decompressed independently. The main reason is to enable zgetdump to make
 * fast read seeks. Otherwise, zgetdump would need to uncompress a big dump
 * segment in the worst case to extract a single piece of data.
 */
unsigned long write_compressed_dump_segment(unsigned long blk,
					    struct df_s390_dump_segm_hdr *segm,
					    z_stream *strm)
{
	unsigned long head_blk, start_blk, zero_page, len, offset = 0;
	unsigned long chunk_size;
	int rc;

	head_blk = blk;
	/* Skip one block for the header (written later on) */
	blk += m2b(sizeof(struct df_s390_dump_segm_hdr));
	/* Compress each data chunk of the dump segment separately */
	chunk_size = dump_hdr->zlib_entry_size;
	for (unsigned int i = 0; i <= segm->len / chunk_size; i++) {
		/* Save starting block number */
		start_blk = blk;
		len = i < segm->len / chunk_size ?
			chunk_size : segm->len % chunk_size;
		if (len == 0)
			break;
		rc = compress_write_next_chunk(segm->start + i * chunk_size,
					       len, &blk, strm);
		/*
		 * Store the offset to the compressed chunk of data written
		 * to disk in blocks.
		 */
		segm->entry_count++;
		segm->entry_offset[i] = (uint32_t)offset;
		/*
		 * Compression was ineffective or compression error ocurred,
		 * data chunk has benn written uncompressed.
		 */
		if (rc == UNCOMPRESSED || rc == COMPRESSION_ERROR)
			segm->entry_offset[i] |= DUMP_SEGM_ENTRY_UNCOMPRESSED;
		offset += blk - start_blk;
		/* Print progress after each compressed chunk written */
		progress_print(segm->start + i * chunk_size + len);
	}
	/* Compression successful, store compressed size in the segment header */
	segm->size_on_disk = (uint32_t)offset;
	/*
	 * Write the dump segment header itself (1 page, uncompressed) to
	 * the predefined location.
	 */
	zero_page = get_zeroed_page();
	writeblock(head_blk, (unsigned long)segm,
		   m2b(sizeof(struct df_s390_dump_segm_hdr)), zero_page);
	free_page(zero_page);

	return blk;
}
