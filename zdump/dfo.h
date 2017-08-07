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

#ifndef DFO_H
#define DFO_H

#include "lib/util_list.h"
#include "zg.h"

struct dfo_chunk;

typedef void (*dfo_chunk_read_fn)(struct dfo_chunk *chunk, u64 off,
				    void *buf, u64 cnt);

struct dfo_chunk {
	struct util_list_node	list;
	u64			start;
	u64			end;
	u64			size;
	dfo_chunk_read_fn	read_fn;
	void			*data;
};

extern void dfo_chunk_zero_fn(struct dfo_chunk *chunk, u64 off, void *buf,
			      u64 cnt);
extern void dfo_chunk_buf_fn(struct dfo_chunk *chunk, u64 off, void *buf,
			     u64 cnt);
extern void dfo_chunk_mem_fn(struct dfo_chunk *chunk, u64 off, void *buf,
			     u64 cnt);
extern void dfo_chunk_add(u64 start, u64 size, void *data,
			  dfo_chunk_read_fn read_fn);

extern u64 dfo_read(void *buf, u64 cnt);
extern void dfo_seek(u64 addr);
extern u64 dfo_size(void);
extern const char *dfo_name(void);
extern void dfo_init(void);
extern int dfo_set(const char *dfo_name);

/*
 * DFO operations
 */
struct dfo {
	const char	*name;
	void		(*init)(void);
};

#endif /* DFO_H */
