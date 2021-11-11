/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * ELF core dump output format
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "df_elf.h"
#include "dfi.h"
#include "dfi_mem_chunk.h"
#include "dfo_mem_chunk.h"
#include "dfi_vmcoreinfo.h"
#include "dfo.h"

#define HDR_PER_CPU_SIZE	0x4a0
#define HDR_PER_MEMC_SIZE	0x100
#define HDR_BASE_SIZE		0x2000

/*
 * Initialize ELF loads program headers
 */
static u64 load_phdrs_init(Elf64_Phdr *phdr, u64 elf_offset)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 mem_size = 0;

	dfi_mem_chunk_iterate(mem_chunk) {
		phdr->p_type = PT_LOAD;
		phdr->p_offset = elf_offset;
		phdr->p_vaddr = mem_chunk->start;
		phdr->p_paddr = phdr->p_vaddr;
		phdr->p_memsz = mem_chunk->size;
		if (mem_chunk->read_fn == dfi_mem_chunk_read_zero)
			/* Zero memory chunk */
			phdr->p_filesz = 0;
		else
			phdr->p_filesz = phdr->p_memsz;
		phdr->p_flags = PF_R | PF_W | PF_X;
		phdr->p_align = PAGE_SIZE;
		elf_offset += phdr->p_filesz;
		mem_size += phdr->p_memsz;
		phdr++;
	}
	return mem_size;
}

/*
 * Initialize the program header entries for the notes and the related segment
 * data.
 */
static void *notes_init(Elf64_Phdr *phdr, void *segment_start, u64 elf_offset)
{
	void *ptr = segment_start;
	struct dfi_cpu *cpu;

	ptr = nt_prpsinfo(ptr);

	if (dfi_cpu_content() != DFI_CPU_CONTENT_ALL)
		goto out;

	dfi_cpu_iterate(cpu) {
		ptr = nt_prstatus(ptr, cpu);
		ptr = nt_fpregset(ptr, cpu);
		ptr = nt_s390_timer(ptr, cpu);
		ptr = nt_s390_tod_cmp(ptr, cpu);
		ptr = nt_s390_tod_preg(ptr, cpu);
		ptr = nt_s390_ctrs(ptr, cpu);
		ptr = nt_s390_prefix(ptr, cpu);
		if (dfi_cpu_content_fac_check(DFI_CPU_CONTENT_FAC_VX)) {
			ptr = nt_s390_vxrs_low(ptr, cpu);
			ptr = nt_s390_vxrs_high(ptr, cpu);
		}
	}
out:
	ptr = nt_vmcoreinfo(ptr, dfi_vmcoreinfo_get());
	memset(phdr, 0, sizeof(*phdr));
	phdr->p_type = PT_NOTE;
	phdr->p_offset = elf_offset;
	phdr->p_filesz = PTR_DIFF(ptr, segment_start);
	return ptr;
}

/*
 * Setup dump chunks
 */
static void dump_chunks_init(void *hdr, u64 hdr_size)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 off = 0;

	dfo_chunk_add(off, hdr_size, hdr, dfo_chunk_buf_fn);
	off += hdr_size;
	dfi_mem_chunk_iterate(mem_chunk) {
		if (mem_chunk->read_fn == dfi_mem_chunk_read_zero)
			/* Zero memory chunk */
			continue;
		dfo_chunk_add(off, mem_chunk->size, mem_chunk,
				   dfo_chunk_mem_fn);
		off += mem_chunk->size;
	}
}

/*
 * ELF DFO is only supported for 64 bit (s390x)
 */
static void ensure_s390x(void)
{
	if (dfi_arch() != DFI_ARCH_64)
		ERR_EXIT("Error: The ELF dump format is only supported for "
			 "s390x source dumps");
	df_elf_ensure_s390x();
}

/*
 * Initialize ELF output dump format
 */
static void dfo_elf_init(void)
{
	Elf64_Phdr *phdr_notes, *phdr_loads;
	u32 alloc_size;
	void *buf, *ptr;
	u64 hdr_off;

	ensure_s390x();
	alloc_size = HDR_BASE_SIZE +
		dfi_cpu_cnt() * HDR_PER_CPU_SIZE +
		dfi_mem_chunk_cnt() * HDR_PER_MEMC_SIZE;
	buf = zg_alloc(alloc_size);
	/* Init elf header */
	ptr = ehdr_init(buf, dfi_mem_chunk_cnt() + 1);
	/* Init program headers */
	phdr_notes = ptr;
	ptr = PTR_ADD(ptr, sizeof(Elf64_Phdr));
	phdr_loads = ptr;
	ptr = PTR_ADD(ptr, sizeof(Elf64_Phdr) * dfi_mem_chunk_cnt());
	/* Init notes */
	hdr_off = PTR_DIFF(ptr, buf);
	ptr = notes_init(phdr_notes, ptr, hdr_off);
	hdr_off = PTR_DIFF(ptr, buf);
	load_phdrs_init(phdr_loads, hdr_off);
	if (hdr_off > alloc_size)
		ABORT("hdr_size=%llu alloc_size=%u", hdr_off, alloc_size);
	dump_chunks_init(buf, hdr_off);
}

/*
 * ELF DFO operations
 */
struct dfo dfo_elf = {
	.name		= "elf",
	.init		= dfo_elf_init,
};
