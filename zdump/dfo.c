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

#include <string.h>
#include <errno.h>

#include "zg.h"
#include "dfo_mem_chunk.h"
#include "dfo.h"

/*
 * DFO vector
 */
static struct dfo *dfo_vec[] = {
	&dfo_s390,
	&dfo_elf,
	NULL,
};

/*
 * File local static data
 */
static struct {
	u64		off;		/* Current file offset in dump */
	struct dfo	*dfo;
} l;

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
	if (dfo_chunk_init())
		ABORT("DFO memory chunk init failed");
	l.dfo->init();
}

/*
 * Seek to output dump offset "off"
 */
void dfo_seek(u64 off)
{
	l.off = off;
}

/*
 * Read "cnt" bytes of output dump at current offest
 */
u64 dfo_read(void *buf, u64 cnt)
{
	struct dfo_chunk *dfo_chunk;
	u64 copied = 0, end, size;
	u64 off = l.off;

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
	l.off = off;
	return copied;
}

/*
 * Return output dump size
 */
u64 dfo_size(void)
{
	return dfo_chunk_dump_size();
}
