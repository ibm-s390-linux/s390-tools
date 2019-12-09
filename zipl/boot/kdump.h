/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Stand-alone kdump definitions
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */


#ifndef KDUMP_H
#define KDUMP_H

#include "libc.h"
#include "boot/s390.h"

#define OS_INFO_VERSION_MAJOR_SUPPORTED	1
#define OS_INFO_MAGIC			0x4f53494e464f535aULL /* OSINFOSZ */
#define OS_INF0_CSUM_SIZE		4084

#define OS_INFO_VMCOREINFO		0
#define OS_INFO_REIPL_BLOCK		1

struct os_info_entry {
	uint64_t addr;
	uint64_t size;
	uint32_t csum;
} __packed;

struct os_info {
	uint64_t magic;
	uint32_t csum;
	uint16_t version_major;
	uint16_t version_minor;
	uint64_t crashkernel_addr;
	uint64_t crashkernel_size;
	struct os_info_entry entry[2];
	uint8_t reserved[4024];
} __packed;

void os_info_check(struct os_info *os_info);
void kdump_failed(unsigned long reason);

#endif /* KDUMP_H */
