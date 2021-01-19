/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * ELF core dump input format
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

#include "zgetdump.h"

/*
 * Read memory for given memory chunk
 */
static void dfi_elf_mem_chunk_read_fn(struct dfi_mem_chunk *mem_chunk, u64 off,
				      void *buf, u64 cnt)
{
	u64 elf_load_off = *((u64 *) mem_chunk->data);

	zg_seek(g.fh, elf_load_off + off, ZG_CHECK);
	zg_read(g.fh, buf, cnt, ZG_CHECK);
}

/*
 * Add load (memory chunk) to DFI dump
 */
static int pt_load_add(Elf64_Phdr *phdr)
{
	u64 *off_ptr;

	if (phdr->p_paddr != phdr->p_vaddr) {
		phdr->p_paddr = phdr->p_vaddr;
		STDERR("Dump file \"%s\" is a user space core dump\n",
		      g.opts.device);
	}
	if (phdr->p_offset + phdr->p_filesz > zg_size(g.fh))
		return -EINVAL;
	if (phdr->p_filesz == 0) {
		/* Add zero memory chunk */
		dfi_mem_chunk_add(phdr->p_paddr, phdr->p_memsz, NULL,
				  dfi_mem_chunk_read_zero, NULL);
	} else {
		off_ptr = zg_alloc(sizeof(*off_ptr));
		*off_ptr = phdr->p_offset;
		dfi_mem_chunk_add(phdr->p_paddr, phdr->p_memsz, off_ptr,
				  dfi_elf_mem_chunk_read_fn, zg_free);
	}
	return 0;
}

/*
 * Skip name of note
 */
static void nt_name_skip(Elf64_Nhdr *note)
{
	zg_seek_cur(g.fh, ROUNDUP(note->n_namesz, 4), ZG_CHECK);
}

/*
 * Read note
 */
static int nt_read(Elf64_Nhdr *note, void *buf)
{
	off_t buf_len = ROUNDUP(note->n_descsz, 4);
	char tmp_buf[buf_len];

	nt_name_skip(note);
	if (zg_read(g.fh, tmp_buf, buf_len, ZG_CHECK_ERR) != buf_len)
		return -EINVAL;
	if (buf)
		memcpy(buf, tmp_buf, note->n_descsz);
	return 0;
}

/*
 * Skip note
 */
static int nt_skip(Elf64_Nhdr *note)
{
	return nt_read(note, NULL);
}

/*
 * Ensure that CPU is already defined by prstatus note
 */
static void check_cpu(struct dfi_cpu *cpu, const char *note_str)
{
	if (cpu)
		return;
	ERR_EXIT("Invalid ELF dump (%s before prstatus found)", note_str);
}

/*
 * Read prstatus note and return new DFI CPU
 */
static struct dfi_cpu *nt_prstatus_read(Elf64_Nhdr *note)
{
	struct dfi_cpu *cpu = dfi_cpu_alloc();
	struct nt_prstatus_64 nt_prstatus;

	if (nt_read(note, &nt_prstatus))
		return NULL;

	memcpy(cpu->gprs, &nt_prstatus.gprs, sizeof(cpu->gprs));
	memcpy(cpu->psw, &nt_prstatus.psw, sizeof(cpu->psw));
	memcpy(cpu->acrs, &nt_prstatus.acrs, sizeof(cpu->acrs));

	dfi_cpu_add(cpu);
	return cpu;
}

/*
 * Read fpregset note
 */
static int nt_fpregset_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	struct nt_fpregset_64 nt_fpregset;

	check_cpu(cpu, "FPREGSET");
	if (nt_read(note, &nt_fpregset))
		return -EINVAL;

	memcpy(&cpu->fpc, &nt_fpregset.fpc, sizeof(cpu->fpc));
	memcpy(cpu->fprs, &nt_fpregset.fprs, sizeof(cpu->fprs));
	return 0;
}

/*
 * Read s390 timer note
 */
static int nt_s390_timer_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_TIMER");
	return nt_read(note, &cpu->timer);
}

/*
 * Read s390 todcmp note
 */
static int nt_s390_todcmp_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_TODCMP");
	return nt_read(note, &cpu->todcmp);
}

/*
 * Read s390 todpreg note
 */
static int nt_s390_todpreg_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_TODPREG");
	return nt_read(note, &cpu->todpreg);
}

/*
 * Read s390 ctrs note
 */
static int nt_s390_ctrs_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_CTRS");
	return nt_read(note, &cpu->ctrs);
}

/*
 * Read s390 prefix note
 */
static int nt_s390_prefix_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_PREFIX");
	return nt_read(note, &cpu->prefix);
}

/*
 * Read s390 vxrs_low note
 */
static int nt_s390_vxrs_low_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_VXRS_LOW");
	return nt_read(note, &cpu->vxrs_low);
}

/*
 * Read s390 vxrs_high note
 */
static int nt_s390_vxrs_high_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_VXRS_HIGH");
	return nt_read(note, &cpu->vxrs_high);
}

/*
 * Add all notes for notes phdr
 */
static int pt_notes_add(Elf64_Phdr *phdr)
{
	u64 start_off = zg_tell(g.fh, ZG_CHECK);
	struct dfi_cpu *cpu_current = NULL;
	u64 notes_start_off;
	Elf64_Nhdr note;
	int rc;

	zg_seek(g.fh, phdr->p_offset, ZG_CHECK);
	notes_start_off = zg_tell(g.fh, ZG_CHECK);
	while (zg_tell(g.fh, ZG_CHECK) - notes_start_off < phdr->p_filesz) {
		rc = zg_read(g.fh, &note, sizeof(note), ZG_CHECK_ERR);
		if (rc != sizeof(note))
			return -EINVAL;
		switch (note.n_type) {
		case NT_PRSTATUS:
			cpu_current = nt_prstatus_read(&note);
			if (!cpu_current)
				return -EINVAL;
			break;
		case NT_FPREGSET:
			if (nt_fpregset_read(cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_TIMER:
			if (nt_s390_timer_read(cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_TODCMP:
			if (nt_s390_todcmp_read(cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_TODPREG:
			if (nt_s390_todpreg_read(cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_CTRS:
			if (nt_s390_ctrs_read(cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_PREFIX:
			if (nt_s390_prefix_read(cpu_current, &note))
				return -EINVAL;
			break;
		case NT_S390_VXRS_LOW:
			if (nt_s390_vxrs_low_read(cpu_current, &note))
				return -EINVAL;
			dfi_cpu_content_fac_add(DFI_CPU_CONTENT_FAC_VX);
			break;
		case NT_S390_VXRS_HIGH:
			if (nt_s390_vxrs_high_read(cpu_current, &note))
				return -EINVAL;
			dfi_cpu_content_fac_add(DFI_CPU_CONTENT_FAC_VX);
			break;
		default:
			if (nt_skip(&note))
				return -EINVAL;
			break;
		}
	}
	zg_seek(g.fh, start_off, ZG_CHECK);
	return 0;
}

/*
 * Read ELF header
 */
static int read_elf_hdr(Elf64_Ehdr *ehdr)
{
	if (zg_size(g.fh) < sizeof(*ehdr))
		return -ENODEV;
	zg_read(g.fh, ehdr, sizeof(*ehdr), ZG_CHECK);
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		return -ENODEV;
	if (ehdr->e_type != ET_CORE)
		return -ENODEV;
	if (ehdr->e_machine != EM_S390 || ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		ERR_EXIT("Only s390x (64 bit) core dump files are supported");
	return 0;
}

/*
 * Initialize ELF input dump format
 */
static int dfi_elf_init(void)
{
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;
	int i;

	if (read_elf_hdr(&ehdr) != 0)
		return -ENODEV;

	df_elf_ensure_s390x();
	dfi_arch_set(DFI_ARCH_64);
	dfi_cpu_info_init(DFI_CPU_CONTENT_ALL);

	for (i = 0; i < ehdr.e_phnum; i++) {
		zg_read(g.fh, &phdr, sizeof(phdr), ZG_CHECK);
		switch (phdr.p_type) {
		case PT_LOAD:
			if (pt_load_add(&phdr))
				return -EINVAL;
			break;
		case PT_NOTE:
			if (pt_notes_add(&phdr))
				return -EINVAL;
			break;
		default:
			break;
		}
	}
	dfi_attr_version_set(ehdr.e_ident[EI_VERSION]);
	return 0;
}

/*
 * ELF DFI operations
 */
struct dfi dfi_elf = {
	.name		= "elf",
	.init		= dfi_elf_init,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
