/*
 * Copyright IBM Corp. 2001, 2018, 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>

#include "lib/util_libc.h"

#include "df_elf.h"

void *ehdr_init(Elf64_Ehdr *ehdr, Elf64_Half phnum)
{
	memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2MSB;
	ehdr->e_ident[EI_VERSION] = ELF_VERSION_1;
	ehdr->e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr->e_ident[EI_ABIVERSION] = 0;
	memset(ehdr->e_ident+EI_PAD, 0, EI_NIDENT-EI_PAD);
	ehdr->e_type = ET_CORE;
	ehdr->e_machine = EM_S390;
	ehdr->e_version = ELF_VERSION_1;
	ehdr->e_entry = 0;
	ehdr->e_phoff = sizeof(Elf64_Ehdr);
	ehdr->e_shoff = 0;
	ehdr->e_flags = 0;
	ehdr->e_ehsize = sizeof(Elf64_Ehdr);
	ehdr->e_phentsize = sizeof(Elf64_Phdr);
	ehdr->e_phnum = phnum;
	ehdr->e_shentsize = 0;
	ehdr->e_shnum = 0;
	ehdr->e_shstrndx = 0;
	return ehdr + 1;
}

bool ehdr_is_elf_object(const Elf64_Ehdr *ehdr)
{
	return (ehdr->e_version == ELF_VERSION_1) && (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0);
}

bool ehdr_is_vmcore(const Elf64_Ehdr *ehdr)
{
	return ehdr->e_type == ET_CORE;
}

bool ehdr_is_s390x(const Elf64_Ehdr *ehdr)
{
	return ehdr->e_machine == EM_S390 && ehdr->e_ident[EI_DATA] == ELFDATA2MSB &&
	       ehdr->e_ident[EI_CLASS] == ELFCLASS64;
}

int ehdr_check_s390x(const Elf64_Ehdr *ehdr)
{
	if (!ehdr_is_elf_object(ehdr) || !ehdr_is_vmcore(ehdr))
		return -ENODEV;
	if (!ehdr_is_s390x(ehdr))
		ERR_EXIT("Only s390x (64 bit) core dump files are supported");
	return 0;
}

Elf64_Ehdr *read_elf_hdr(const struct zg_fh *fh)
{
	Elf64_Ehdr *ehdr;
	const size_t ehdr_size = sizeof(*ehdr);

	if (zg_size(fh) < ehdr_size)
		return NULL;

	ehdr = util_malloc(ehdr_size);
	zg_read(fh, ehdr, ehdr_size, ZG_CHECK);
	return ehdr;
}

Elf64_Phdr *read_elf_phdrs(const struct zg_fh *fh, const Elf64_Ehdr *ehdr, unsigned int *phdr_count)
{
	const Elf64_Half phnum = ehdr->e_phnum;
	size_t phdrs_size;
	Elf64_Phdr *phdrs;

	if (!phnum) {
		*phdr_count = phnum;
		return NULL;
	}

	if (ehdr->e_phoff > OFF_T_MAX)
		ERR_EXIT("Unsupported offset");

	/* Cannot wraparound since `Elf64_Half`` is `uint16_t` */
	phdrs_size = sizeof(*phdrs) * phnum;
	phdrs = util_malloc(phdrs_size);
	zg_seek(fh, (off_t)ehdr->e_phoff, ZG_CHECK);
	zg_read(fh, phdrs, phdrs_size, ZG_CHECK);
	*phdr_count = phnum;
	return phdrs;
}

int nt_read(const struct zg_fh *fh, const Elf64_Nhdr *note, void *buf, size_t buf_len)
{
	ssize_t nread;

	/* We cannot read more than the current note provides */
	if (note->n_descsz < buf_len)
		return -EINVAL;
	/* Skip note's name and position file at note's descriptor */
	zg_seek_cur(fh, ELF_NOTE_ROUNDUP(note->n_namesz), ZG_CHECK);
	/* Read note's descriptor */
	nread = zg_read(fh, buf, buf_len, ZG_CHECK_ERR);
	if (nread < 0 || (size_t)nread != buf_len)
		return -EINVAL;
	/* Skip the rest of note's descriptor until the next note */
	zg_seek_cur(fh, ELF_NOTE_ROUNDUP(note->n_descsz) - buf_len, ZG_CHECK);
	return 0;
}

void nt_skip(const struct zg_fh *fh, const Elf64_Nhdr *note)
{
	/* Skip note's name + descriptor and position file at the next note */
	zg_seek_cur(fh, ELF_NOTE_ROUNDUP(note->n_namesz) + ELF_NOTE_ROUNDUP(note->n_descsz),
		    ZG_CHECK);
}

void *nt_init(void *buf, Elf64_Word type, const void *desc, int d_len,
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
	len = ELF_NOTE_ROUNDUP(len + note->n_namesz);

	memcpy(buf + len, desc, note->n_descsz);
	len = ELF_NOTE_ROUNDUP(len + note->n_descsz);

	return PTR_ADD(buf, len);
}

void *nt_prstatus(void *ptr, const struct dfi_cpu *cpu)
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
		       NOTE_NAME_CORE);
}

void *nt_fpregset(void *ptr, const struct dfi_cpu *cpu)
{
	struct nt_fpregset_64 nt_fpregset;

	memset(&nt_fpregset, 0, sizeof(nt_fpregset));
	memcpy(&nt_fpregset.fpc, &cpu->fpc, sizeof(cpu->fpc));
	memcpy(&nt_fpregset.fprs, &cpu->fprs, sizeof(cpu->fprs));

	return nt_init(ptr, NT_FPREGSET, &nt_fpregset, sizeof(nt_fpregset),
		       NOTE_NAME_CORE);
}

void *nt_s390_timer(void *ptr, const struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_TIMER, &cpu->timer, sizeof(cpu->timer),
		       NOTE_NAME_LINUX);
}

void *nt_s390_tod_cmp(void *ptr, const struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_TODCMP, &cpu->todcmp,
		       sizeof(cpu->todcmp), NOTE_NAME_LINUX);
}

void *nt_s390_tod_preg(void *ptr, const struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_TODPREG, &cpu->todpreg,
		       sizeof(cpu->todpreg), NOTE_NAME_LINUX);
}

void *nt_s390_ctrs(void *ptr, const struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_CTRS, &cpu->ctrs, sizeof(cpu->ctrs),
		       NOTE_NAME_LINUX);
}

void *nt_s390_prefix(void *ptr, const struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_PREFIX, &cpu->prefix,
		       sizeof(cpu->prefix), NOTE_NAME_LINUX);
}

void *nt_s390_vxrs_low(void *ptr, const struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_VXRS_LOW, &cpu->vxrs_low,
		       sizeof(cpu->vxrs_low), NOTE_NAME_LINUX);
}

void *nt_s390_vxrs_high(void *ptr, const struct dfi_cpu *cpu)
{
	return nt_init(ptr, NT_S390_VXRS_HIGH, &cpu->vxrs_high,
		       sizeof(cpu->vxrs_high), NOTE_NAME_LINUX);
}

void *nt_prpsinfo(void *ptr)
{
	struct nt_prpsinfo_64 prpsinfo;

	memset(&prpsinfo, 0, sizeof(prpsinfo));
	prpsinfo.pr_state = 0;
	prpsinfo.pr_sname = 'R';
	prpsinfo.pr_zomb = 0;
	strcpy(prpsinfo.pr_fname, "vmlinux");

	return nt_init(ptr, NT_PRPSINFO, &prpsinfo, sizeof(prpsinfo),
		       NOTE_NAME_CORE);
}

void *nt_vmcoreinfo(void *ptr, const char *vmcoreinfo)
{
	if (!vmcoreinfo)
		return ptr;
	return nt_init(ptr, 0, vmcoreinfo, strlen(vmcoreinfo),
		       NOTE_NAME_VMCOREINFO);
}
