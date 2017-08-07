/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * /dev/mem and /dev/crash dump input format
 *
 * Copyright IBM Corp. 2012, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include "zgetdump.h"

/*
 * Add live dump magic to buffer
 */
static void add_live_magic(void *buf, u64 off, u64 cnt)
{
	if (off >= sizeof(dfi_live_dump_magic))
		return;
	memcpy(buf, &dfi_live_dump_magic,
	       MIN(cnt, sizeof(dfi_live_dump_magic)));
}

/*
 * "devmem" mem chunk read callback
 *
 * This functions reads page wise in order to detect unreadable pages
 */
static void dfi_devmem_mem_chunk_read(struct dfi_mem_chunk *mem_chunk, u64 off,
				      void *buf, u64 cnt)
{
	u64 copied = 0, len = PAGE_SIZE;
	(void) mem_chunk;

	if (off % PAGE_SIZE)
		len = MIN(len, PAGE_SIZE - off % PAGE_SIZE);
	len = MIN(len, cnt);
	do {
		zg_seek(g.fh, mem_chunk->start + off + copied, ZG_CHECK);
		if (zg_read(g.fh, buf + copied, len, ZG_CHECK_NONE) < 0) {
			if (errno == EFAULT) {
				/* This can happen when using CMM */
				memset(buf + copied, 0, len);
			} else {
				ERR_EXIT_ERRNO("Could not read %s",
					       g.opts.device);
			}
		}
		copied += len;
		len = MIN(PAGE_SIZE, cnt - copied);
	} while (len);
	add_live_magic(buf, mem_chunk->start + off, cnt);
}

/*
 * Detect memory chunks via /proc/iomem
 *
 * check = 0: Initialize memory map
 * check = 1: Verifiy that current system memory map is same as DFI memory map
 */
static int detect_mem_chunks(int check)
{
	char line[4096], type1[4096], type2[4096];
	unsigned long start, end, cnt = 0;
	struct dfi_mem_chunk *mem_chunk;
	struct zg_fh *fh;
	ssize_t rc;

	fh = zg_open("/proc/iomem", O_RDONLY, ZG_CHECK);
	do {
		rc = zg_gets(fh, line, sizeof(line), ZG_CHECK);
		if (rc == 0)
			break;
		sscanf(line, "%lx-%lx : %s %s", &start, &end, type1, type2);
		if (strcmp(type1, "System") != 0)
			continue;
		if (strcmp(type2, "RAM") != 0 && strcmp(type2, "ROM") != 0)
			continue;
		if (check) {
			mem_chunk = dfi_mem_chunk_find(start);
			if (!mem_chunk)
				return -EINVAL;
			if (mem_chunk->start != start)
				return -EINVAL;
			if (mem_chunk->end != end)
				return -EINVAL;
			cnt++;
		} else {
			dfi_mem_chunk_add(start, end - start + 1, NULL,
					  dfi_devmem_mem_chunk_read, NULL);
		}
	} while (1);
	if (check && cnt != dfi_mem_chunk_cnt())
		return -EINVAL;
	return 0;
}

/*
 * Return architecture of running system
 */
static enum dfi_arch system_arch(void)
{
	struct utsname utsname;

	uname(&utsname);
	if (memcmp(utsname.machine, "s390x", 5) == 0)
		return DFI_ARCH_64;
	if (memcmp(utsname.machine, "s390", 4) == 0)
		return DFI_ARCH_32;
	return DFI_ARCH_UNKNOWN;
}

/*
 * Initialize devmem DFI
 */
static int dfi_devmem_init(void)
{
	if (strcmp(g.fh->path, "/dev/mem") != 0 &&
	    strcmp(g.fh->path, "/dev/crash") != 0)
		return -ENODEV;
	dfi_arch_set(system_arch());
	dfi_cpu_info_init(DFI_CPU_CONTENT_NONE);
	detect_mem_chunks(0);
	dfi_attr_dump_method_set(DFI_DUMP_METHOD_LIVE);
	zg_seek(g.fh, 0, ZG_CHECK);
	return 0;
}

/*
 * Cleanup devmem DFI
 */
static void dfi_devmem_exit(void)
{
	if (detect_mem_chunks(1))
		STDERR("Warning: memory map has changed\n");
}

/*
 * devmem DFI operations
 */
struct dfi dfi_devmem = {
	.name		= "devmem",
	.init		= dfi_devmem_init,
	.exit		= dfi_devmem_exit,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
