/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Common ELF core dump input format definitions
 *
 * Copyright IBM Corp. 2001, 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DFI_ELF_COMMON_H
#define DFI_ELF_COMMON_H

#include <elf.h>

#include "dfi_mem_chunk.h"
#include "zg.h"

/**
 * pt_load_add:
 * @fh: (not nullable): open input file
 * @phdr: (not nullable): program ELF header of the load segment to add
 * @data: (not nullable): arbitrary pointer passed to the read callback @read_fn
 * @read_fn: (not nullable): callback used for reading the data of a memory chunk
 * @free_fn: (not nullable): function called to cleanup @data
 *
 * Add load (memory chunk) to DFI dump. After a successful call, @data belongs
 * to the mem_chunk structure created and the @data pointer is set to %NULL.
 *
 * Returns: %0 on success, returns < 0 in case of an error
 */
int pt_load_add(const struct zg_fh *fh, const Elf64_Phdr *phdr, void **data,
		dfi_mem_chunk_read_fn read_fn, dfi_mem_chunk_free_fn free_fn);

#endif /* DFI_ELF_COMMON_H */
