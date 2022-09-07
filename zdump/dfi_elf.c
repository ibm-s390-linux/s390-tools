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

#include "lib/util_libc.h"
#include "lib/util_log.h"

#include "zgetdump.h"
#include "zg.h"
#include "df_elf.h"
#include "dfi.h"
#include "dfi_mem_chunk.h"

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

	util_log_print(UTIL_LOG_DEBUG,
		       "DFI ELF p_paddr 0x%016lx p_vaddr 0x%016lx p_offset 0x%016lx p_filesz 0x%016lx p_memsz 0x%016lx\n",
		       phdr->p_paddr, phdr->p_vaddr, phdr->p_offset,
		       phdr->p_filesz, phdr->p_memsz);

	if (phdr->p_paddr != phdr->p_vaddr) {
		phdr->p_paddr = phdr->p_vaddr;
		STDERR("Dump file \"%s\" is a user space core dump\n",
		      g.opts.device);
		return -EINVAL;
	}
	if (phdr->p_memsz == 0)
		return -EINVAL;
	if (phdr->p_offset + phdr->p_filesz > zg_size(g.fh))
		return -EINVAL;
	if (phdr->p_filesz > phdr->p_memsz)
		return -EINVAL;
	if (phdr->p_filesz > 0) {
		off_ptr = zg_alloc(sizeof(*off_ptr));
		*off_ptr = phdr->p_offset;
		dfi_mem_chunk_add(phdr->p_paddr, phdr->p_filesz, off_ptr,
				  dfi_elf_mem_chunk_read_fn, zg_free);
	}
	if (phdr->p_memsz - phdr->p_filesz > 0) {
		/* Add zero memory chunk */
		dfi_mem_chunk_add(phdr->p_paddr + phdr->p_filesz,
				  phdr->p_memsz - phdr->p_filesz, NULL,
				  dfi_mem_chunk_read_zero, NULL);
	}
	return 0;
}

/*
 * Read note
 */
static int nt_read(const Elf64_Nhdr *note, void *buf, size_t buf_len)
{
	ssize_t nread;

	/* We cannot read more than the current note provides */
	if (note->n_descsz < buf_len)
		return -EINVAL;
	/* Skip note's name and position file at note's descriptor */
	zg_seek_cur(g.fh, ELF_NOTE_ROUNDUP(note->n_namesz), ZG_CHECK);
	/* Read note's descriptor */
	nread = zg_read(g.fh, buf, buf_len, ZG_CHECK_ERR);
	if (nread < 0 || (size_t)nread != buf_len)
		return -EINVAL;
	/* Skip the rest of note's descriptor until the next note */
	zg_seek_cur(g.fh, ELF_NOTE_ROUNDUP(note->n_descsz) - buf_len, ZG_CHECK);
	return 0;
}

/*
 * Skip note
 */
static void nt_skip(const Elf64_Nhdr *note)
{
	/* Skip note's name + descriptor and position file at the next note */
	zg_seek_cur(g.fh, ELF_NOTE_ROUNDUP(note->n_namesz) + ELF_NOTE_ROUNDUP(note->n_descsz),
		    ZG_CHECK);
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

	if (nt_read(note, &nt_prstatus, sizeof(nt_prstatus)))
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
	if (nt_read(note, &nt_fpregset, sizeof(nt_fpregset)))
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
	return nt_read(note, &cpu->timer, sizeof(cpu->timer));
}

/*
 * Read s390 todcmp note
 */
static int nt_s390_todcmp_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_TODCMP");
	return nt_read(note, &cpu->todcmp, sizeof(cpu->todcmp));
}

/*
 * Read s390 todpreg note
 */
static int nt_s390_todpreg_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_TODPREG");
	return nt_read(note, &cpu->todpreg, sizeof(cpu->todpreg));
}

/*
 * Read s390 ctrs note
 */
static int nt_s390_ctrs_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_CTRS");
	return nt_read(note, &cpu->ctrs, sizeof(cpu->ctrs));
}

/*
 * Read s390 prefix note
 */
static int nt_s390_prefix_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_PREFIX");
	return nt_read(note, &cpu->prefix, sizeof(cpu->prefix));
}

/*
 * Read s390 vxrs_low note
 */
static int nt_s390_vxrs_low_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_VXRS_LOW");
	return nt_read(note, &cpu->vxrs_low, sizeof(cpu->vxrs_low));
}

/*
 * Read s390 vxrs_high note
 */
static int nt_s390_vxrs_high_read(struct dfi_cpu *cpu, Elf64_Nhdr *note)
{
	check_cpu(cpu, "S390_VXRS_HIGH");
	return nt_read(note, &cpu->vxrs_high, sizeof(cpu->vxrs_high));
}

/*
 * Add all notes for notes phdr
 */
static int pt_notes_add(Elf64_Phdr *phdr)
{
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
		util_log_print(UTIL_LOG_DEBUG, "DFI ELF n_type 0x%x\n",
			       note.n_type);
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
			nt_skip(&note);
			break;
		}
	}
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
	Elf64_Phdr *phdr;
	int i;

	util_log_print(UTIL_LOG_DEBUG, "DFI ELF initialization\n");

	if (read_elf_hdr(&ehdr) != 0)
		return -ENODEV;

	df_elf_ensure_s390x();
	dfi_arch_set(DFI_ARCH_64);
	dfi_cpu_info_init(DFI_CPU_CONTENT_ALL);

	phdr = util_malloc(sizeof(*phdr) * ehdr.e_phnum);
	zg_seek(g.fh, ehdr.e_phoff, ZG_CHECK);
	zg_read(g.fh, phdr, sizeof(*phdr) * ehdr.e_phnum, ZG_CHECK);
	util_log_print(UTIL_LOG_DEBUG, "DFI ELF e_phnum %u\n", ehdr.e_phnum);
	for (i = 0; i < ehdr.e_phnum; i++) {
		util_log_print(UTIL_LOG_DEBUG, "DFI ELF p_type[%d] 0x%lx\n",
			       i, phdr[i].p_type);
		switch (phdr[i].p_type) {
		case PT_LOAD:
			if (pt_load_add(&phdr[i])) {
				free(phdr);
				return -EINVAL;
			}
			break;
		case PT_NOTE:
			if (pt_notes_add(&phdr[i])) {
				free(phdr);
				return -EINVAL;
			}
			break;
		default:
			break;
		}
	}
	free(phdr);

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
