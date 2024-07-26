/*
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DFI_MEM_CHUNK_H
#define DFI_MEM_CHUNK_H

#include <stdbool.h>

#include "lib/zt_common.h"
#include "lib/util_list.h"

/*
 * Mem chunk functions and definitions
 */
struct dfi_mem_chunk;

typedef void (*dfi_mem_chunk_read_fn)(struct dfi_mem_chunk *mem_chunk,
				      u64 off, void *buf, u64 cnt);
typedef void (*dfi_mem_chunk_free_fn)(void *data);

struct dfi_mem_chunk {
	struct util_list_node	list;		/* List */
	u64			start;		/* Start address in memory */
	u64			end;		/* End address in memory */
	u64			size;		/* Size of chunk in dump file */
	dfi_mem_chunk_read_fn	read_fn;	/* Chunk read callback */
	dfi_mem_chunk_free_fn	free_fn;	/* Free data callback */
	void			*data;		/* Data for callback */
	u32			volnr;		/* Volume id where chunk resides */
};

void dfi_mem_chunk_read_zero(struct dfi_mem_chunk *UNUSED(mem_chunk),
			     u64 UNUSED(off), void *buf, u64 cnt);
void dfi_mem_chunk_add_vol(u64 start, u64 size, void *data,
			   dfi_mem_chunk_read_fn read_fn,
			   dfi_mem_chunk_free_fn free_fn,
			   u32 volnr);
void dfi_mem_chunk_add(u64 start, u64 size, void *data,
		       dfi_mem_chunk_read_fn read_fn,
		       dfi_mem_chunk_free_fn free_fn);
u64 dfi_mem_range(void);
u64 dfi_mem_end(void);
int dfi_mem_range_valid(u64 addr, u64 len);
unsigned int dfi_mem_chunk_cnt(void);
struct dfi_mem_chunk *dfi_mem_chunk_first(void);
struct dfi_mem_chunk *dfi_mem_chunk_last(void);
struct dfi_mem_chunk *dfi_mem_chunk_next(struct dfi_mem_chunk *chunk);
struct dfi_mem_chunk *dfi_mem_chunk_prev(struct dfi_mem_chunk *chunk);
struct dfi_mem_chunk *dfi_mem_chunk_find(u64 addr);

struct util_list *dfi_mem_chunk_list(void);
#define dfi_mem_chunk_iterate(mem_chunk) \
	util_list_iterate(dfi_mem_chunk_list(), mem_chunk)
void dfi_mem_chunk_sort(void);

int dfi_mem_virt_read(u64 addr, void *buf, size_t cnt);
int dfi_mem_phys_read(u64 addr, void *buf, size_t cnt);

void dfi_mem_map_print(bool verbose);

void dfi_mem_unmap(u64 start, u64 size);
void dfi_mem_map(u64 start, u64 size, u64 start_phys);

int dfi_mem_chunk_init(void);
void dfi_mem_chunk_deinit(void);

#endif /* DFI_MEM_CHUNK_H */
