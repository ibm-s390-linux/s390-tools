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

#include "dfi_elf_common.h"

#include <assert.h>

#include "lib/util_log.h"

int pt_load_add(const struct zg_fh *fh, const Elf64_Phdr *phdr, void **data,
		dfi_mem_chunk_read_fn read_fn, dfi_mem_chunk_free_fn free_fn)
{
	assert(fh);
	assert(phdr);
	assert(data);
	assert(read_fn);
	assert(free_fn);

	util_log_print(
		UTIL_LOG_DEBUG,
		"%s p_paddr 0x%016lx p_vaddr 0x%016lx p_offset 0x%016lx p_filesz 0x%016lx p_memsz 0x%016lx\n",
		__func__, phdr->p_paddr, phdr->p_vaddr, phdr->p_offset, phdr->p_filesz,
		phdr->p_memsz);

	if (phdr->p_paddr != phdr->p_vaddr) {
		STDERR("Dump file \"%s\" is a user space core dump\n", fh->path);
		return -EINVAL;
	}
	if (phdr->p_memsz == 0)
		return -EINVAL;
	if (phdr->p_offset + phdr->p_filesz > zg_size(fh))
		return -EINVAL;
	if (phdr->p_filesz > phdr->p_memsz)
		return -EINVAL;
	/* check for wrap-around */
	if (phdr->p_paddr + phdr->p_filesz < phdr->p_paddr)
		return -EINVAL;

	if (phdr->p_filesz > 0) {
		dfi_mem_chunk_add(phdr->p_paddr, phdr->p_filesz, *data, read_fn, free_fn);
		*data = NULL;
	} else {
		/* Free @data directly as it's not used */
		free_fn(*data);
		*data = NULL;
	}
	if (phdr->p_memsz - phdr->p_filesz > 0) {
		/* Add zero memory chunk */
		dfi_mem_chunk_add(phdr->p_paddr + phdr->p_filesz, phdr->p_memsz - phdr->p_filesz,
				  NULL, dfi_mem_chunk_read_zero, NULL);
	}
	return 0;
}
