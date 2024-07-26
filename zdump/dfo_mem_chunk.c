/*
 * Copyright IBM Corp. 2001, 2017, 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>
#include "lib/util_log.h"

#include "zg.h"
#include "dfi_mem_chunk.h"
#include "dfo_mem_chunk.h"

/*
 * File local static data
 */
static struct {
	u64			size;		/* Size of dump in bytes */
	unsigned int		chunk_cnt;	/* Number of dump chunks */
	struct util_list	chunk_list;	/* DFO chunk list */
} l;

/*
 * Add dump chunk
 */
void dfo_chunk_add(u64 start, u64 size, void *data, dfo_chunk_read_fn read_fn)
{
	struct dfo_chunk *dfo_chunk;

	util_log_print(UTIL_LOG_DEBUG, "DFO add chunk start=0x%lx, size=0x%lx\n", start, size);

	if (size == 0)
		return;
	dfo_chunk = zg_alloc(sizeof(*dfo_chunk));
	dfo_chunk->start = start;
	dfo_chunk->end = start + size - 1;
	dfo_chunk->data = data;
	dfo_chunk->read_fn = read_fn;
	util_list_add_head(&l.chunk_list, dfo_chunk);
	l.chunk_cnt++;
	l.size = MAX(l.size, dfo_chunk->end + 1);
}

/*
 * Dump chunk function: Copy zero pages for chunk
 */
void dfo_chunk_zero_fn(struct dfo_chunk *dfo_chunk, u64 off, void *buf, u64 cnt)
{
	(void) dfo_chunk;
	(void) off;

	memset(buf, 0, cnt);
}

/*
 * Dump chunk function: Copy given buffer for chunk
 */
void dfo_chunk_buf_fn(struct dfo_chunk *dfo_chunk, u64 off, void *buf, u64 cnt)
{
	memcpy(buf, dfo_chunk->data + off, cnt);
}

/*
 * Dump chunk function: Copy given memory range for chunk
 */
void dfo_chunk_mem_fn(struct dfo_chunk *dfo_chunk, u64 off, void *buf, u64 cnt)
{
	struct dfi_mem_chunk *mem_chunk = dfo_chunk->data;

	mem_chunk->read_fn(mem_chunk, off, buf, cnt);
}

/*
 * Find dump chunk for offset "off"
 *
 * This function is a bit hacky. DFO chunks can overlap. If two DFO chunks
 * overlap, the last registered chunk wins. The dfo_chunk_find() function
 * reflects that by returning the first memory chunk that is found in
 * the dfo chunk list.
 *
 * In addition to that it calculates the "virtual end" of that chunk. An
 * overlapping chunk can limit the "virtual end" of an underlying chunk so
 * that the "virtual end" of that chunk is lower than the "real end".
 *
 * Example:
 *
 * chunk 1.:      |------|
 * chunk 2.: |---------------------|
 * off.....: ^
 * virt end:      ^
 * real end:                       ^
 *
 * In this case chunk 2 will be returned and "end" is set to the start of
 * chunk 1.
 */
struct dfo_chunk *dfo_chunk_find(u64 off, u64 *end)
{
	struct dfo_chunk *dfo_chunk;

	*end = U64_MAX;
	dfo_chunk_iterate(dfo_chunk) {
		if (dfo_chunk->start <= off && dfo_chunk->end >= off) {
			*end = MIN(*end, dfo_chunk->end);
			return dfo_chunk;
		} else if (dfo_chunk->start > off) {
			*end = MIN(*end, dfo_chunk->start - 1);
		}
	}
	return NULL;
}

struct util_list *dfo_chunk_list(void)
{
	return &l.chunk_list;
}

u64 dfo_chunk_dump_size(void)
{
	return l.size;
}

int dfo_chunk_init(void)
{
	util_list_init(&l.chunk_list, struct dfo_chunk, list);

	return 0;
}

void dfo_chunk_deinit(void)
{
	memset(&l, 0, sizeof(l));
}
