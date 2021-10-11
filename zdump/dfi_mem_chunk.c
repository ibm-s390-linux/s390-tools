/*
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "lib/util_libc.h"
#include "lib/util_log.h"

#include "zg.h"
#include "dfi_mem_chunk.h"

/*
 * Memory information
 */
struct mem {
	struct dfi_mem_chunk	*chunk_cache;
	u64			start_addr;
	u64			end_addr;
	unsigned int		chunk_cnt;
	struct util_list	chunk_list;
};

/*
 * File local static data
 */
static struct {
	struct mem	mem_phys;
	struct mem	mem_virt;
} l;

/*
 * Initialize DFI memory chunks
 */
static void mem_init(struct mem *mem)
{
	mem->start_addr = U64_MAX;
	mem->end_addr = 0;
	util_list_init(&mem->chunk_list, struct dfi_mem_chunk, list);
}

/*
 * Memory chunk compare function for list sorting
 */
static int mem_chunk_cmp_fn(void *a, void *b, void *UNUSED(data))
{
	struct dfi_mem_chunk *mem_chunk1 = a;
	struct dfi_mem_chunk *mem_chunk2 = b;

	return mem_chunk1->start < mem_chunk2->start ? -1 : 1;
}

/*
 * Update DFI memory chunks
 */
static void mem_update(struct mem *mem)
{
	struct dfi_mem_chunk *mem_chunk;

	util_list_sort(&mem->chunk_list, mem_chunk_cmp_fn, NULL);
	mem->start_addr = U64_MAX;
	mem->end_addr = 0;
	util_list_iterate(&mem->chunk_list, mem_chunk) {
		mem->start_addr = MIN(mem->start_addr, mem_chunk->start);
		mem->end_addr = MAX(mem->end_addr, mem_chunk->end);
	}
}

/*
 * Print memory map
 */
void dfi_mem_map_print(bool verbose)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 print_start = 0, print_end = 0;
	const char *zero_str;
	u32 volnr = 0;

	STDERR("\nMemory map:\n");
	/*
	 * Print each memory chunk if verbose specified
	 */
	if (verbose) {
		dfi_mem_chunk_iterate(mem_chunk) {
			zero_str = "";
			if (mem_chunk->read_fn == dfi_mem_chunk_read_zero)
				zero_str = " zeroes";
			STDERR("  %016llx - %016llx (%llu MB%s)\n",
			       mem_chunk->start, mem_chunk->end,
			       TO_MIB(mem_chunk->size), zero_str);
		}
		return;
	}
	/*
	 * Merge adjacent memory chunks from the same volume
	 */
	dfi_mem_chunk_iterate(mem_chunk) {
		if (print_end == 0) {
			print_start = mem_chunk->start;
			print_end = mem_chunk->end;
			volnr = mem_chunk->volnr;
			continue;
		}
		if (mem_chunk->start != print_end + 1 ||
		    mem_chunk->volnr != volnr) {
			STDERR("  %016llx - %016llx (%llu MB)\n", print_start,
			       print_end, TO_MIB(print_end - print_start + 1));
			print_start = mem_chunk->start;
			volnr = mem_chunk->volnr;
		}
		print_end = mem_chunk->end;
	}
	STDERR("  %016llx - %016llx (%llu MB)\n", print_start,
	       print_end, TO_MIB(print_end - print_start + 1));
}

/*
 * Check if memory chunk contains address
 */
static int mem_chunk_has_addr(struct dfi_mem_chunk *mem_chunk, u64 addr)
{
	return (addr >= mem_chunk->start && addr <= mem_chunk->end);
}

/*
 * Find memory chunk that contains address
 */
static struct dfi_mem_chunk *mem_chunk_find(struct mem *mem, u64 addr)
{
	struct dfi_mem_chunk *mem_chunk;

	if (mem->chunk_cache && mem_chunk_has_addr(mem->chunk_cache, addr))
		return mem->chunk_cache;
	util_list_iterate(&mem->chunk_list, mem_chunk) {
		if (mem_chunk_has_addr(mem_chunk, addr)) {
			mem->chunk_cache = mem_chunk;
			return mem_chunk;
		}
	}
	return NULL;
}

/*
 * Is memory range valid?
 */
static int mem_range_valid(struct mem *mem, u64 addr, u64 len)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 addr_end = addr + len;

	/* check for unsigned wrap */
	if (addr_end < addr)
		return 0;

	do {
		mem_chunk = mem_chunk_find(mem, addr);
		if (!mem_chunk)
			return 0;
		addr += MIN(len, mem_chunk->end - addr + 1);
	} while (addr < addr_end);
	return 1;
}

/*
 * Is memory already mapped at range?
 */
static int mem_range_mapped(u64 start, u64 size)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 end = start + size - 1;

	dfi_mem_chunk_iterate(mem_chunk) {
		if (mem_chunk->start > end)
			continue;
		if (mem_chunk->end < start)
			continue;
		return 1;
	}
	return 0;
}

/*
 * Add memory chunk to memory
 */
static void mem_chunk_create(struct mem *mem, u64 start, u64 size, void *data,
			     dfi_mem_chunk_read_fn read_fn,
			     dfi_mem_chunk_free_fn free_fn)
{
	struct dfi_mem_chunk *mem_chunk;

	mem_chunk = util_malloc(sizeof(*mem_chunk));
	mem_chunk->start = start;
	mem_chunk->end = start + size - 1;
	mem_chunk->size = size;
	mem_chunk->read_fn = read_fn;
	mem_chunk->free_fn = free_fn;
	mem_chunk->data = data;

	util_list_add_tail(&mem->chunk_list, mem_chunk);
	mem->start_addr = MIN(mem->start_addr, mem_chunk->start);
	mem->end_addr = MAX(mem->end_addr, mem_chunk->end);
	mem->chunk_cache = mem_chunk;
	mem->chunk_cnt++;
}

/*
 * Read memory at given address
 */
static void mem_read(struct mem *mem, u64 addr, void *buf, size_t cnt)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 size, off, copied = 0;

	while (copied != cnt) {
		mem_chunk = mem_chunk_find(mem, addr);
		size = MIN(cnt - copied, mem_chunk->end - addr + 1);
		off = addr - mem_chunk->start;
		mem_chunk->read_fn(mem_chunk, off, buf + copied, size);
		copied += size;
		addr += size;
	}
}

/*
 * Read memory for virtual map memory chunk
 */
static void mem_chunk_map_read_fn(struct dfi_mem_chunk *mem_chunk, u64 off,
				  void *buf, u64 cnt)
{
	u64 *start = mem_chunk->data;

	dfi_mem_phys_read(*start + off, buf, cnt);
}

/*
 * Check if memory chunk is a virtual mapping
 */
static int mem_chunk_is_map(struct dfi_mem_chunk *mem_chunk)
{
	return mem_chunk->read_fn == mem_chunk_map_read_fn;
}

/*
 * Return physical start address for memory chunk
 */
static u64 mem_chunk_start_phys(struct dfi_mem_chunk *mem_chunk)
{
	if (mem_chunk_is_map(mem_chunk))
		return *((u64 *) mem_chunk->data);
	else
		return mem_chunk->start;
}

/*
 * Add virtual memory chunk
 */
static void mem_chunk_virt_add(u64 start, u64 size, void *data,
			       dfi_mem_chunk_read_fn read_fn,
			       dfi_mem_chunk_free_fn free_fn)
{
	util_log_print(UTIL_LOG_DEBUG,
		       "DFI add %svirt mem chunk start 0x%016lx size 0x%016lx\n",
		       read_fn == dfi_mem_chunk_read_zero ? "zero " : "",
		       start, size);

	if (size == 0)
		return;
	mem_chunk_create(&l.mem_virt, start, size, data, read_fn, free_fn);
}

/*
 * Add virtual memory chunk with simple virtual mapping
 */
static void mem_chunk_map_add(u64 start, u64 size, u64 start_p)
{
	u64 *data = util_malloc(sizeof(*data));

	*data = start_p;
	mem_chunk_virt_add(start, size, data, mem_chunk_map_read_fn, free);
}

/*
 * Add memory chunk with volume index
 */
void dfi_mem_chunk_add_vol(u64 start, u64 size, void *data,
			   dfi_mem_chunk_read_fn read_fn,
			   dfi_mem_chunk_free_fn free_fn,
			   u32 volnr)
{
	util_log_print(UTIL_LOG_DEBUG,
		       "DFI add %svol mem chunk start 0x%016lx size 0x%016lx volnr %u\n",
		       read_fn == dfi_mem_chunk_read_zero ? "zero " : "",
		       start, size, volnr);

	if (size == 0)
		return;
	mem_chunk_create(&l.mem_phys, start, size, data, read_fn, free_fn);
	mem_chunk_create(&l.mem_virt, start, size, data, read_fn, NULL);
	l.mem_virt.chunk_cache->volnr = volnr;

}

/*
 * Add memory chunk
 */
void dfi_mem_chunk_add(u64 start, u64 size, void *data,
		       dfi_mem_chunk_read_fn read_fn,
		       dfi_mem_chunk_free_fn free_fn)
{
	dfi_mem_chunk_add_vol(start, size, data, read_fn, free_fn, 0);
}

/*
 * Read zero pages
 */
void dfi_mem_chunk_read_zero(struct dfi_mem_chunk *UNUSED(mem_chunk),
			     u64 UNUSED(off), void *buf, u64 cnt)
{
	memset(buf, 0, cnt);
}

/*
 * Return mem_chunk list head
 */
struct util_list *dfi_mem_chunk_list(void)
{
	return &l.mem_virt.chunk_list;
}

/*
 * Return number of memory chunks in input dump
 */
unsigned int dfi_mem_chunk_cnt(void)
{
	return l.mem_virt.chunk_cnt;
}

/*
 * Return maximum memory range
 */
u64 dfi_mem_range(void)
{
	if (l.mem_virt.start_addr == U64_MAX)
		return 0;
	return l.mem_virt.end_addr - l.mem_virt.start_addr + 1;
}

/*
 * Is memory range valid?
 */
int dfi_mem_range_valid(u64 addr, u64 len)
{
	return mem_range_valid(&l.mem_virt, addr, len);
}

/*
 * Return first memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_first(void)
{
	if (util_list_is_empty(&l.mem_virt.chunk_list))
		return NULL;
	return util_list_start(&l.mem_virt.chunk_list);
}

/*
 * Return last memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_last(void)
{
	if (util_list_is_empty(&l.mem_virt.chunk_list))
		return NULL;
	return util_list_end(&l.mem_virt.chunk_list);
}

/*
 * Return next memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_next(struct dfi_mem_chunk *mem_chunk)
{
	return util_list_next(&l.mem_virt.chunk_list, mem_chunk);
}

/*
 * Return previous memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_prev(struct dfi_mem_chunk *mem_chunk)
{
	return util_list_prev(&l.mem_virt.chunk_list, mem_chunk);
}

/*
 * Find memory chunk for given address
 */
struct dfi_mem_chunk *dfi_mem_chunk_find(u64 addr)
{
	return mem_chunk_find(&l.mem_virt, addr);
}

/*
 * Read physical memory at given address
 */
int dfi_mem_phys_read(u64 addr, void *buf, size_t cnt)
{
	util_log_print(UTIL_LOG_TRACE,
		       "DFI phys mem read addr 0x%016lx size 0x%016lx\n",
		       addr, cnt);
	if (!mem_range_valid(&l.mem_phys, addr, cnt))
		return -EINVAL;
	mem_read(&l.mem_phys, addr, buf, cnt);
	return 0;
}

/*
 * Read virtual memory at given address
 */
int dfi_mem_virt_read(u64 addr, void *buf, size_t cnt)
{
	util_log_print(UTIL_LOG_TRACE,
		       "DFI virt mem read addr 0x%016lx size 0x%016lx\n",
		       addr, cnt);
	if (!mem_range_valid(&l.mem_virt, addr, cnt))
		return -EINVAL;
	mem_read(&l.mem_virt, addr, buf, cnt);
	return 0;
}

/*
 * Unmap memory region
 */
void dfi_mem_unmap(u64 start, u64 size)
{
	u64 start_phys, end_phys, addr_phys, addr_virt, size_virt;
	struct dfi_mem_chunk *mem_chunk, *tmp;
	u64 end = start + size - 1;

	util_list_iterate_safe(&l.mem_virt.chunk_list, mem_chunk, tmp) {
		/*
		 * Chunk not hit?
		 */
		if (mem_chunk->start >= start + size)
			continue;
		if (mem_chunk->end < start)
			continue;
		/*
		 * Chunk completely unmapped
		 *
		 * UNMAP: UUUUUUUUU || UUUUUU
		 * CHUNK:   CCCC    || CCCCCC
		 * TO:
		 */
		if (mem_chunk->start >= start && mem_chunk->end <= end)
			goto free;

		/*
		 * Get real start and end addresses
		 */
		start_phys = mem_chunk_start_phys(mem_chunk);
		end_phys = start_phys + mem_chunk->size - 1;

		/*
		 * Chunk hit at start or in the middle?
		 *
		 * UNMAP: UUUUUU   ||   UU    || UUU
		 * CHUNK:    CCCCC || CCCCCC  ||   CCCC
		 * TO:          NN ||     NN  ||    NNN
		 */
		if (mem_chunk->end > end) {
			addr_virt = end + 1;
			size_virt = mem_chunk->end - end;
			addr_phys = end_phys - size_virt + 1;
			mem_chunk_map_add(addr_virt, size_virt, addr_phys);
		}
		/*
		 * Chunk hit at end or in the middle?
		 *
		 * UNMAP:   UUUUUU   ||   UU    ||   UUU
		 * CHUNK: CCCCC      || CCCCCC  || CCC
		 * TO:    NN         || NN      || NN
		 */
		if (mem_chunk->start < start) {
			addr_virt = mem_chunk->start;
			size_virt = start - addr_virt;
			addr_phys = start_phys;
			mem_chunk_map_add(addr_virt, size_virt, addr_phys);
		}
	free:
		util_list_remove(&l.mem_virt.chunk_list, mem_chunk);
		l.mem_virt.chunk_cnt--;
		if (mem_chunk->data && mem_chunk->free_fn)
			mem_chunk->free_fn(mem_chunk->data);
		free(mem_chunk);
	}
	mem_update(&l.mem_virt);
}

/*
 * Map memory region
 */
void dfi_mem_map(u64 start, u64 size, u64 start_phys)
{
	if (mem_range_mapped(start, size)) {
		dfi_mem_map_print(false);
		ABORT("Map request for already mapped region (%llx/%llx/%llx)",
		      start, size, start_phys);
	}
	mem_chunk_map_add(start, size, start_phys);
	mem_update(&l.mem_virt);
}

int dfi_mem_chunk_init(void)
{
	mem_init(&l.mem_virt);
	mem_init(&l.mem_phys);

	return 0;
}

void dfi_mem_chunk_deinit(void)
{
	memset(&l, 0, sizeof(l));
}
