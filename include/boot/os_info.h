/*
 * zipl - zSeries Initial Program Loader tool
 *
 * os-info definitions
 *
 * Copyright IBM Corp. 2013, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef OS_INFO_H
#define OS_INFO_H

#include "lib/zt_common.h"
#include <stdint.h>

#define OS_INFO_MAGIC			0x4f53494e464f535aULL /* OSINFOSZ */
#define OS_INFO_CSUM_SIZE		(sizeof(struct os_info) - offsetof(struct os_info, version_major))

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

#endif /* OS_INFO_H */
