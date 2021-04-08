/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_HSA_MEM_H
#define _HSAVMCORE_HSA_MEM_H

#include <stdbool.h>

#include "hsa.h"

/*
 * This concrete HSA memory reader reads the whole HSA memory from /proc/vmcore
 * and caches it all in an internal memory buffer.
 * In order for it to work, the system must provide enough memory or swap space.
 */
struct hsa_reader *make_hsa_mem_reader(const char *zcore_hsa_path,
				       const char *vmcore_path, long hsa_size,
				       bool release_hsa_flag);

#endif
