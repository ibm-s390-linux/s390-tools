/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * ELF core dump format definitions
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DF_ELF_H
#define DF_ELF_H

#include <elf.h>
#include <linux/types.h>
#include <stdbool.h>

#include "lib/zt_common.h"

#include "zg.h"
#include "dfi.h"

#ifndef ELF_VERSION_1
#define ELF_VERSION_1 0x1
#endif

/*
 * S390 CPU timer note (u64)
 */
#ifndef NT_S390_TIMER
#define NT_S390_TIMER 0x301
#endif

/*
 * S390 TOD clock comparator note (u64)
 */
#ifndef NT_S390_TODCMP
#define NT_S390_TODCMP 0x302
#endif

/*
 * S390 TOD programmable register note (u32)
 */
#ifndef NT_S390_TODPREG
#define NT_S390_TODPREG 0x303
#endif

/*
 * S390 control registers note (16 * u32)
 */
#ifndef NT_S390_CTRS
#define NT_S390_CTRS 0x304
#endif

/*
 * S390 prefix note (u32)
 */
#ifndef NT_S390_PREFIX
#define NT_S390_PREFIX 0x305
#endif

/*
 * S390 vector registers 0-15 upper half note (16 * u64)
 */
#ifndef NT_S390_VXRS_LOW
#define NT_S390_VXRS_LOW 0x309
#endif

/*
 * S390 vector registers 16-31 note (16 * u128)
 */
#ifndef NT_S390_VXRS_HIGH
#define NT_S390_VXRS_HIGH 0x30a
#endif

#define NOTE_NAME_CORE	     "CORE"
#define NOTE_NAME_LINUX	     "LINUX"
#define NOTE_NAME_VMCOREINFO "VMCOREINFO"

#define ELF_NOTE_ROUNDUP(size) ROUNDUP(size, 4)
#define ELF_NOTE_NAME_SIZE(name) ELF_NOTE_ROUNDUP(name ? strlen(name) + 1 : 0)
#define ELF64_NOTE_SIZE(name, desc_size) \
	(sizeof(Elf64_Nhdr) + ELF_NOTE_NAME_SIZE(name) + ELF_NOTE_ROUNDUP(desc_size))

/*
 * prstatus ELF Note
 */
struct nt_prstatus_64 {
	u8	pad1[32];
	u32	pr_pid;
	u8	pad2[76];
	u64	psw[2];
	u64	gprs[16];
	u32	acrs[16];
	u64	orig_gpr2;
	u32	pr_fpvalid;
	u8	pad3[4];
} __packed;

/*
 * fpregset ELF Note
 */
struct nt_fpregset_64 {
	u32	fpc;
	u32	pad;
	u64	fprs[16];
} __packed;

/*
 * prpsinfo ELF Note
 */
struct nt_prpsinfo_64 {
	char	pr_state;
	char	pr_sname;
	char	pr_zomb;
	char	pr_nice;
	u64	pr_flag;
	u32	pr_uid;
	u32	pr_gid;
	u32	pr_pid, pr_ppid, pr_pgrp, pr_sid;
	char	pr_fname[16];
	char	pr_psargs[80];
};

static inline void df_elf_ensure_s390x(void)
{
#ifndef __s390x__
	ERR_EXIT("The ELF dump format is only supported on s390x (64 bit)");
#endif
}

/*
 * Initialize ELF header
 */
void *ehdr_init(Elf64_Ehdr *ehdr, Elf64_Half phnum);

/*
 * Checks whether @ehdr is a ELF object
 */
bool ehdr_is_elf_object(const Elf64_Ehdr *ehdr);

/*
 * Checks whether @ehdr is a vmcore
 */
bool ehdr_is_vmcore(const Elf64_Ehdr *ehdr);

/*
 * Checks whether @ehdr is a s390x header
 */
bool ehdr_is_s390x(const Elf64_Ehdr *ehdr);

/*
 * Verify that given header is a s390x ELF header
 */
int ehdr_check_s390x(const Elf64_Ehdr *ehdr);

/*
 * Read ELF header at current offset
 */
Elf64_Ehdr *read_elf_hdr(const struct zg_fh *fh);

/*
 * Read ELF program headers
 *
 * To read the program headers the offset of @fh is changed.
 */
Elf64_Phdr *read_elf_phdrs(const struct zg_fh *fh, const Elf64_Ehdr *ehdr,
			   unsigned int *phdr_count);

/*
 * Read ELF section headers
 *
 * To read the section headers the offset of @fh is changed.
 */
Elf64_Shdr *read_elf_shdrs(const struct zg_fh *fh, const Elf64_Ehdr *ehdr,
			   unsigned int *shdr_count);

/*
 * Read ELF section content
 *
 * To read the section content the offset of @fh is changed.
 */
unsigned char *read_elf_section_data(const struct zg_fh *fh, const Elf64_Shdr *shdr, size_t *size);

/*
 * Read ELF section header string table
 *
 * To read the section header string table the offset of @fh is changed.
 */
char *read_elf_shstrtab(const struct zg_fh *fh, const Elf64_Ehdr *ehdr, const Elf64_Shdr *shdrs,
			const unsigned int shnum, size_t *shstrtab_size);

/*
 * Find ELF section header by section name
 */
const Elf64_Shdr *find_elf_shdr_by_name(const Elf64_Shdr *shdrs, const unsigned int shnum,
					const char *shstrtab, const size_t shstrtab_size,
					const char *name);

/*
 * Read note and store the note description in @buf
 */
int nt_read(const struct zg_fh *fh, const Elf64_Nhdr *note, void *buf, size_t buf_len);

/*
 * Skip note
 */
void nt_skip(const struct zg_fh *fh, const Elf64_Nhdr *note);

/*
 * Initialize ELF note
 */
void *nt_init(void *buf, Elf64_Word type, const void *desc, int d_len,
	      const char *name);

/*
 * Initialize prstatus note
 */
void *nt_prstatus(void *ptr, const struct dfi_cpu *cpu);

/*
 * Initialize fpregset (floating point) note
 */
void *nt_fpregset(void *ptr, const struct dfi_cpu *cpu);

/*
 * Initialize timer note
 */
void *nt_s390_timer(void *ptr, const struct dfi_cpu *cpu);

/*
 * Initialize TOD clock comparator note
 */
void *nt_s390_tod_cmp(void *ptr, const struct dfi_cpu *cpu);

/*
 * Initialize TOD programmable register note
 */
void *nt_s390_tod_preg(void *ptr, const struct dfi_cpu *cpu);

/*
 * Initialize control register note
 */
void *nt_s390_ctrs(void *ptr, const struct dfi_cpu *cpu);

/*
 * Initialize prefix register note
 */
void *nt_s390_prefix(void *ptr, const struct dfi_cpu *cpu);

/*
 * Initialize vxrs_low register note
 */
void *nt_s390_vxrs_low(void *ptr, const struct dfi_cpu *cpu);

/*
 * Initialize vxrs_high register note
 */
void *nt_s390_vxrs_high(void *ptr, const struct dfi_cpu *cpu);

/*
 * Initialize prpsinfo note
 */
void *nt_prpsinfo(void *ptr);

/*
 * Initialize vmcoreinfo note
 */
void *nt_vmcoreinfo(void *ptr, const char *vmcoreinfo);

size_t get_max_note_size_per_cpu(void);

#endif /* DF_ELF_H */
