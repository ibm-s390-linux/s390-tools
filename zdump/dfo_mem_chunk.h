/*
 * Copyright IBM Corp. 2001, 2017, 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DFO_MEM_CHUNK_H
#define DFO_MEM_CHUNK_H

#include "lib/zt_common.h"
#include "lib/util_list.h"

struct dfo_chunk;

typedef void (*dfo_chunk_read_fn)(struct dfo_chunk *chunk, u64 off,
				  void *buf, u64 cnt);

struct dfo_chunk {
	struct util_list_node	list;
	u64			start;
	u64			end;
	dfo_chunk_read_fn	read_fn;
	void			*data;
};

void dfo_chunk_zero_fn(struct dfo_chunk *chunk, u64 off, void *buf, u64 cnt);
void dfo_chunk_buf_fn(struct dfo_chunk *chunk, u64 off, void *buf, u64 cnt);
void dfo_chunk_mem_fn(struct dfo_chunk *chunk, u64 off, void *buf, u64 cnt);
void dfo_chunk_add(u64 start, u64 size, void *data, dfo_chunk_read_fn read_fn);
struct dfo_chunk *dfo_chunk_find(u64 off, u64 *end);

struct util_list *dfo_chunk_list(void);
#define dfo_chunk_iterate(dfo_chunk) \
	util_list_iterate(dfo_chunk_list(), dfo_chunk)

u64 dfo_chunk_dump_size(void);

int dfo_chunk_init(void);
void dfo_chunk_deinit(void);

#endif /* DFO_MEM_CHUNK_H */
