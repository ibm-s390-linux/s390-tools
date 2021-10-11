/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Generic output dump format functions (DFO - Dump Format Output)
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <time.h>

#include "lib/util_list.h"

#include "dfi_mem_chunk.h"
#include "dfo.h"

#define dfo_chunk_iterate(dfo_chunk) \
	util_list_iterate(&l.dump.chunk_list, dfo_chunk)

/*
 * DFO vector
 */
static struct dfo *dfo_vec[] = {
	&dfo_s390,
	&dfo_elf,
	NULL,
};

/*
 * Dump (output) information
 */
struct dump {
	u64		off;		/* Current file offset in dump */
	u64		size;		/* Size of dump in bytes */
	unsigned int	chunk_cnt;	/* Number of dump chunks */
	struct util_list	chunk_list;	/* DFO chunk list */
};

/*
 * File local static data
 */
static struct {
	struct dump	dump;
	struct dfo	*dfo;
} l;

/*
 * Add dump chunk
 */
void dfo_chunk_add(u64 start, u64 size, void *data, dfo_chunk_read_fn read_fn)
{
	struct dfo_chunk *dfo_chunk;

	dfo_chunk = zg_alloc(sizeof(*dfo_chunk));
	dfo_chunk->start = start;
	dfo_chunk->end = start + size - 1;
	dfo_chunk->data = data;
	dfo_chunk->read_fn = read_fn;
	util_list_add_head(&l.dump.chunk_list, dfo_chunk);
	l.dump.chunk_cnt++;
	l.dump.size = MAX(l.dump.size, dfo_chunk->end + 1);
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
 * Get DFO name
 */
const char *dfo_name(void)
{
	return l.dfo->name;
}

/*
 * Set DFO by name
 */
int dfo_set(const char *dfo_name)
{
	struct dfo *dfo;
	int i = 0;

	while ((dfo = dfo_vec[i])) {
		if (strcmp(dfo->name, dfo_name) == 0) {
			l.dfo = dfo;
			return 0;
		}
		i++;
	}
	return -ENODEV;
}

/*
 * Initialize output dump format
 */
void dfo_init(void)
{
	if (!l.dfo)
		ABORT("DFO not set");
	util_list_init(&l.dump.chunk_list, struct dfo_chunk, list);
	l.dfo->init();
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
static struct dfo_chunk *dfo_chunk_find(u64 off, u64 *end)
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

/*
 * Seek to output dump offset "off"
 */
void dfo_seek(u64 off)
{
	l.dump.off = off;
}

/*
 * Read "cnt" bytes of output dump at current offest
 */
u64 dfo_read(void *buf, u64 cnt)
{
	struct dfo_chunk *dfo_chunk;
	u64 copied = 0, end, size;
	u64 off = l.dump.off;

	while (copied != cnt) {
		dfo_chunk = dfo_chunk_find(off, &end);
		if (!dfo_chunk)
			goto out;
		size = MIN(cnt - copied, end - off + 1);
		dfo_chunk->read_fn(dfo_chunk, off - dfo_chunk->start,
				    buf + copied, size);
		copied += size;
		off += size;
	}
out:
	l.dump.off = off;
	return copied;
}

/*
 * Return output dump size
 */
u64 dfo_size(void)
{
	return l.dump.size;
}
