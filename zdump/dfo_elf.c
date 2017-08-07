/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * ELF core dump output format
 *
 * Copyright IBM Corp. 2001, 2017
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

#include "zgetdump.h"

#define HDR_PER_CPU_SIZE	0x4a0
#define HDR_PER_MEMC_SIZE	0x100
#define HDR_BASE_SIZE		0x2000

/*
 * File local static data
 */
static struct {
	void	*hdr;
	u32	hdr_size;
} l;

/*
 * Initialize ELF header
 */
static void *ehdr_init(Elf64_Ehdr *ehdr)
{
	memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2MSB;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr->e_ident[EI_ABIVERSION] = 0;
	memset(ehdr->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);
	ehdr->e_type = ET_CORE;
	ehdr->e_machine = EM_S390;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_entry = 0;
	ehdr->e_phoff = sizeof(Elf64_Ehdr);
	ehdr->e_shoff = 0;
	ehdr->e_flags = 0;
	ehdr->e_ehsize = sizeof(Elf64_Ehdr);
	ehdr->e_phentsize = sizeof(Elf64_Phdr);
	ehdr->e_phnum = dfi_mem_chunk_cnt() + 1;
	ehdr->e_shentsize = 0;
	ehdr->e_shnum = 0;
	ehdr->e_shstrndx = 0;
	return ehdr + 1;
}

/*
 * Initialize ELF loads
 */
static u64 loads_init(Elf64_Phdr *phdr, u64 loads_offset)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 mem_size = 0;

	dfi_mem_chunk_iterate(mem_chunk) {
		phdr->p_type = PT_LOAD;
		phdr->p_offset = loads_offset;
		phdr->p_vaddr = mem_chunk->start;
		phdr->p_paddr = mem_chunk->start;
		phdr->p_filesz = mem_chunk->end - mem_chunk->start + 1;
		phdr->p_memsz = phdr->p_filesz;
		phdr->p_flags = PF_R | PF_W | PF_X;
		phdr->p_align = PAGE_SIZE;
		loads_offset += phdr->p_filesz;
		mem_size += phdr->p_memsz;
		phdr++;
	}
	return mem_size;
}

/*
 * Initialize ELF note
 */
static void *nt_init(void *buf, Elf64_Word type, void *desc, int d_len,
		     const char *name)
{
	Elf64_Nhdr *note;
	u64 len;

	note = (Elf64_Nhdr *)buf;
	note->n_namesz = strlen(name) + 1;
	note->n_descsz = d_len;
	note->n_type = type;
	len = sizeof(Elf64_Nhdr);

	memcpy(buf + len, name, note->n_namesz);
	len = ROUNDUP(len + note->n_namesz, 4);

	memcpy(buf + len, desc, note->n_descsz);
	len = ROUNDUP(len + note->n_descsz, 4);

	return PTR_ADD(buf, len);
}

/*
 * Initialize prstatus note
 */
static void *nt_prstatus(void *ptr, struct dfi_cpu *cpu)
{
	struct nt_prstatus_64 nt_prstatus;
	static int cpu_nr = 1;

	memset(&nt_prstatus, 0, sizeof(nt_prstatus));
	memcpy(&nt_prstatus.gprs, cpu->gprs, sizeof(cpu->gprs));
	memcpy(&nt_prstatus.psw, cpu->psw, sizeof(cpu->psw));
	memcpy(&nt_prstatus.acrs, cpu->acrs, sizeof(cpu->acrs));
	nt_prstatus.pr_pid = cpu_nr;
	cpu_nr++;

	return nt_init(ptr, NT_PRSTATUS, &nt_prstatus, sizeof(nt_prstatus),
			 "CORE");
}

/*
 * Initialize fpregset (floating point) note
 */
static void *nt_fpregset(void *ptr, struct dfi_cpu *cpu)
{
	struct nt_fpregset_64 nt_fpregset;

	memset(&nt_fpregset, 0, sizeof(nt_fpregset));
	memcpy(&nt_fpregset.fpc, &cpu->fpc, sizeof(cpu->fpc));
	memcpy(&nt_fpregset.fprs, &cpu->fprs, sizeof(cpu->fprs));

	return nt_init(ptr, NT_FPREGSET, &nt_fpregset, sizeof(nt_fpregset),
			 "CORE");
}

/*
 * Initialize timer note
 */
static void *nt_s390_timer(void *ptr, struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_TIMER, &cpu->timer, sizeof(cpu->timer),
			 "LINUX");
}

/*
 * Initialize TOD clock comparator note
 */
static void *nt_s390_tod_cmp(void *ptr, struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_TODCMP, &cpu->todcmp,
		       sizeof(cpu->todcmp), "LINUX");
}

/*
 * Initialize TOD programmable register note
 */
static void *nt_s390_tod_preg(void *ptr, struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_TODPREG, &cpu->todpreg,
		       sizeof(cpu->todpreg), "LINUX");
}

/*
 * Initialize control register note
 */
static void *nt_s390_ctrs(void *ptr, struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_CTRS, &cpu->ctrs, sizeof(cpu->ctrs),
		       "LINUX");
}

/*
 * Initialize prefix register note
 */
static void *nt_s390_prefix(void *ptr, struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_PREFIX, &cpu->prefix,
			 sizeof(cpu->prefix), "LINUX");
}

/*
 * Initialize vxrs_low register note
 */
static void *nt_s390_vxrs_low(void *ptr, struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_VXRS_LOW, &cpu->vxrs_low,
			 sizeof(cpu->vxrs_low), "LINUX");
}

/*
 * Initialize vxrs_high register note
 */
static void *nt_s390_vxrs_high(void *ptr, struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_VXRS_HIGH, &cpu->vxrs_high,
			 sizeof(cpu->vxrs_high), "LINUX");
}

/*
 * Initialize prpsinfo note
 */
static void *nt_prpsinfo(void *ptr)
{
	struct nt_prpsinfo_64 prpsinfo;

	memset(&prpsinfo, 0, sizeof(prpsinfo));
	prpsinfo.pr_state = 0;
	prpsinfo.pr_sname = 'R';
	prpsinfo.pr_zomb = 0;
	strcpy(prpsinfo.pr_fname, "vmlinux");

	return nt_init(ptr, NT_PRPSINFO, &prpsinfo, sizeof(prpsinfo), "CORE");
}

/*
 * Initialize vmcoreinfo note
 */
static void *nt_vmcoreinfo(void *ptr)
{
	char *vmcoreinfo = dfi_vmcoreinfo_get();

	if (!vmcoreinfo)
		return ptr;
	return nt_init(ptr, 0, vmcoreinfo, strlen(vmcoreinfo), "VMCOREINFO");
}

/*
 * Initialize notes
 */
static void *notes_init(Elf64_Phdr *phdr, void *ptr, u64 notes_offset)
{
	void *ptr_start = ptr;
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
	ptr = nt_vmcoreinfo(ptr);
	memset(phdr, 0, sizeof(*phdr));
	phdr->p_type = PT_NOTE;
	phdr->p_offset = notes_offset;
	phdr->p_filesz = (unsigned long) PTR_SUB(ptr, ptr_start);
	return ptr;
}

/*
 * Setup dump chunks
 */
static void dump_chunks_init(void)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 off = 0;

	dfo_chunk_add(0, l.hdr_size, l.hdr, dfo_chunk_buf_fn);
	off = l.hdr_size;
	dfi_mem_chunk_iterate(mem_chunk) {
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
	u64 hdr_off;
	void *ptr;

	ensure_s390x();
	alloc_size = HDR_BASE_SIZE +
		dfi_cpu_cnt() * HDR_PER_CPU_SIZE +
		dfi_mem_chunk_cnt() * HDR_PER_MEMC_SIZE;
	l.hdr = zg_alloc(alloc_size);
	/* Init elf header */
	ptr = ehdr_init(l.hdr);
	/* Init program headers */
	phdr_notes = ptr;
	ptr = PTR_ADD(ptr, sizeof(Elf64_Phdr));
	phdr_loads = ptr;
	ptr = PTR_ADD(ptr, sizeof(Elf64_Phdr) * dfi_mem_chunk_cnt());
	/* Init notes */
	hdr_off = PTR_DIFF(ptr, l.hdr);
	ptr = notes_init(phdr_notes, ptr, hdr_off);
	/* Init loads */
	hdr_off = PTR_DIFF(ptr, l.hdr);
	loads_init(phdr_loads, hdr_off);
	l.hdr_size = hdr_off;
	if (l.hdr_size > alloc_size)
		ABORT("hdr_size=%u alloc_size=%u", l.hdr_size, alloc_size);
	dump_chunks_init();
}

/*
 * ELF DFO operations
 */
struct dfo dfo_elf = {
	.name		= "elf",
	.init		= dfo_elf_init,
};
