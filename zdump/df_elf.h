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

#include "lib/zt_common.h"

#include "zg.h"
#include "dfi.h"

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

#define ELF_NOTE_ROUNDUP(size) ROUNDUP(size, 4)

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

void *ehdr_init(Elf64_Ehdr *ehdr, Elf64_Half phnum);

void *nt_init(void *buf, Elf64_Word type, const void *desc, int d_len,
	      const char *name);
void *nt_prstatus(void *ptr, const struct dfi_cpu *cpu);
void *nt_fpregset(void *ptr, const struct dfi_cpu *cpu);
void *nt_s390_timer(void *ptr, const struct dfi_cpu *cpu);
void *nt_s390_tod_cmp(void *ptr, const struct dfi_cpu *cpu);
void *nt_s390_tod_preg(void *ptr, const struct dfi_cpu *cpu);
void *nt_s390_ctrs(void *ptr, const struct dfi_cpu *cpu);
void *nt_s390_prefix(void *ptr, const struct dfi_cpu *cpu);
void *nt_s390_vxrs_low(void *ptr, const struct dfi_cpu *cpu);
void *nt_s390_vxrs_high(void *ptr, const struct dfi_cpu *cpu);
void *nt_prpsinfo(void *ptr);
void *nt_vmcoreinfo(void *ptr, const char *vmcoreinfo);

#endif /* DF_ELF_H */
