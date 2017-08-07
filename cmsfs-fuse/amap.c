/*
 * cmsfs-fuse - CMS EDF filesystem support for Linux
 *
 * Allocation map functions
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/zt_common.h"

#include "cmsfs-fuse.h"
#include "edf.h"
#include "helper.h"

/*
 * Hint where to look for the next free block (level 0 only).
 * Updated if a free block is found. If the level 0 amap bitmap
 * block is exhausted we still scan all amap blocks.
 */
struct amap_alloction_hint {
	/* addr of amap bitmap block to check */
	off_t amap_addr;
	/* disk addr of the last allocated or freed block */
	off_t addr;
	/* offset to start of the amap data block */
	off_t offset;
};

static struct amap_alloction_hint amap_hint;

static void update_amap_hint(off_t amap_addr, off_t addr)
{
	amap_hint.amap_addr = amap_addr;
	amap_hint.addr = addr;
}

/*
 * Get L1 block number from address.
 */
static int amap_blocknumber(off_t addr)
{
	return addr / BYTES_PER_BLOCK;
}

/*
 * Get the block number for a specific level.
 */
static int amap_blocknumber_level(int level, off_t addr)
{
	int entry = amap_blocknumber(addr);

	while (level-- > 1)
		entry /= PTRS_PER_BLOCK;
	return entry;
}

/*
 * Return address of to the allocation map for a block number > 0.
 */
static off_t get_amap_addr(int level, off_t addr, off_t ptr)
{
	int block = amap_blocknumber_level(level, addr) % PTRS_PER_BLOCK;

	if (cmsfs.amap_levels == 0)
		return cmsfs.amap;

	if (level--) {
		ptr = get_fixed_pointer(ptr + (off_t) block * PTR_SIZE);
		if (!ptr)
			DIE("amap invalid ptr at addr: %llx\n",
				(unsigned long long) ptr +
				(off_t) block * PTR_SIZE);
		return get_amap_addr(level, addr, ptr);
	}
	return ptr;
}

/*
 * Mark disk address as allocated in alloc map.
 */
static void amap_block_set(off_t amap, int bit)
{
	u8 entry;
	int rc;

	rc = _read(&entry, sizeof(entry), amap);
	BUG(rc < 0);

	/* already used */
	BUG(entry & (1 << (7 - bit)));

	entry |= (1 << (7 - bit));
	rc = _write(&entry, sizeof(entry), amap);
	BUG(rc < 0);
}

/*
 * Mark disk address as free in alloc map. Unaligned addr is tolerated.
 */
static void amap_block_clear(off_t addr)
{
	off_t amap = get_amap_addr(cmsfs.amap_levels, addr, cmsfs.amap);
	int rc, block = amap_blocknumber(addr);
	off_t disk_addr = addr;
	unsigned int byte, bit;
	u8 entry;

	if (block > 0)
		addr -= (off_t) block * BYTES_PER_BLOCK;

	addr >>= BITS_PER_DATA_BLOCK;
	byte = addr / 8;
	bit = addr % 8;

	rc = _read(&entry, sizeof(entry), amap + byte);
	BUG(rc < 0);

	/* already cleared */
	BUG(!(entry & (1 << (7 - bit))));

	entry &= ~(1 << (7 - bit));
	rc = _write(&entry, sizeof(entry), amap + byte);
	BUG(rc < 0);

	/*
	 * If the freed addr is lower set the hint to it to ensure
	 * the amap bitmap is packed from the start. That way we do not
	 * need an extra check if the bitmap entry is above disk end, the
	 * check if we overflow the total block limit is sufficient.
	 */
	if (disk_addr < amap_hint.addr)
		update_amap_hint(amap + byte, disk_addr);
}

/*
 * Return the first free bit in one byte.
 */
static inline int find_first_empty_bit(u8 entry)
{
	u8 i;

	for (i = 0; i < 8; i++)
		if (!(entry & 1 << (7 - i)))
			return i;
	/* unreachable */
	return -1;
}

/*
 * Return the number of bytes addressed by one pointer entry for the
 * specified level.
 */
static off_t bytes_per_level(int level)
{
	off_t mult = BYTES_PER_BLOCK;

	if (!level)
		return 0;
	level--;
	while (level--)
		mult *= PTRS_PER_BLOCK;
	return mult;
}

static inline int get_amap_entry_bit(off_t amap)
{
	u8 entry;
	int rc;

	rc = _read(&entry, sizeof(entry), amap);
	BUG(rc < 0);

	if (entry == 0xff)
		return -1;
	return find_first_empty_bit(entry);
}

static off_t __get_free_block_fast(void)
{
	off_t addr, amap = amap_hint.amap_addr & ~DATA_BLOCK_MASK;
	int bit, i = amap_hint.amap_addr & DATA_BLOCK_MASK;

	for (; i < cmsfs.blksize; i++) {
		bit = get_amap_entry_bit(amap + i);
		if (bit == -1)
			continue;

		/* Calculate the addr for the free block we've found. */
		addr = (off_t) amap_blocknumber(amap_hint.addr) * BYTES_PER_BLOCK;
		addr += i * 8 * cmsfs.blksize;
		addr += bit * cmsfs.blksize;

		amap_block_set(amap + i, bit);
		update_amap_hint(amap + i, addr);
		return addr;
	}
	return 0;
}

/*
 * Look for the first unallocated block and return addr of allocated block.
 */
static off_t __get_free_block(int level, off_t amap, off_t addr)
{
	off_t ptr;
	int bit, i;

	if (level > 0) {
		for (i = 0; i < PTRS_PER_BLOCK; i++) {
			ptr = get_fixed_pointer(amap);
			if (!ptr)
				return 0;
			ptr = __get_free_block(level - 1, ptr,
				addr + i * bytes_per_level(level));
			if (ptr)
				return ptr;
			amap += PTR_SIZE;
		}
		return 0;
	}

	for (i = 0; i < cmsfs.blksize; i++) {
		bit = get_amap_entry_bit(amap + i);
		if (bit == -1)
			continue;
		amap_block_set(amap + i, bit);
		/* add byte offset */
		addr += i * 8 * cmsfs.blksize;
		/* add bit offset */
		addr += bit * cmsfs.blksize;
		update_amap_hint(amap + i, addr);
		return addr;
	}
	return 0;
}

/*
 * Allocate a free block and increment label block counter.
 */
off_t get_free_block(void)
{
	off_t addr = 0;

	if (cmsfs.used_blocks + cmsfs.reserved_blocks >= cmsfs.total_blocks)
		return -ENOSPC;
	if (amap_hint.amap_addr)
		addr = __get_free_block_fast();
	if (!addr)
		addr = __get_free_block(cmsfs.amap_levels, cmsfs.amap, 0);
	BUG(!addr);

	cmsfs.used_blocks++;
	return addr;
}

/*
 * Allocate a zero-filled block and increment label block counter.
 */
off_t get_zero_block(void)
{
	off_t addr = get_free_block();
	int rc;

	if (addr < 0)
		return -ENOSPC;

	rc = _zero(addr, cmsfs.blksize);
	if (rc < 0)
		return rc;
	return addr;
}

/*
 * Free a block and decrement label block counter.
 */
void free_block(off_t addr)
{
	if (addr) {
		amap_block_clear(addr);
		cmsfs.used_blocks--;
	}
}
