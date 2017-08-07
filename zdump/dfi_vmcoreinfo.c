/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * vmcoreinfo access functions
 *
 * Copyright IBM Corp. 2011, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <elf.h>
#include "zgetdump.h"

#ifdef __s390x__
#define LC_VMCORE_INFO		0xe0c
#else
#define LC_VMCORE_INFO		0xe08
#endif

#define LC_OS_INFO		0xe18
#define OS_INFO_MAGIC  0x4f53494e464f535aULL /* OSINFOSZ */

struct os_info {
	u64	magic;
	u32	csum;
	u16	version_major;
	u16	version_minor;
	u64	crashkernel_addr;
	u64	crashkernel_size;
	u64	vmcoreinfo_addr;
	u64	vmcoreinfo_size;
	u32	vmcoreinfo_csum;
	u64	reipl_block_addr;
	u64	reipl_block_size;
	u32	reipl_block_csum;
	u64	init_fn_addr;
	u64	init_fn_size;
	u32	init_fn_csum;
	u8	reserved[4004];
} __attribute__ ((packed));

/*
 * File local static data
 */
static struct {
	char		*vmcoreinfo;
	struct os_info	*os_info;
} l;

static u32 os_info_csum(struct os_info *os_info)
{
	int size = sizeof(*os_info) - offsetof(struct os_info, version_major);
	return zg_csum_partial(&os_info->version_major, size, 0);
}

static struct os_info *os_info_get(void)
{
	static struct os_info os_info;
	unsigned long addr;

	dfi_mem_read(LC_OS_INFO, &addr, sizeof(addr));
	if (addr % 0x1000)
		return NULL;
	if (dfi_mem_read_rc(addr, &os_info, sizeof(os_info)))
		return NULL;
	if (os_info.magic != OS_INFO_MAGIC)
		return NULL;
	if (os_info.csum != os_info_csum(&os_info))
		return NULL;
	return &os_info;
}

/*
 * Initialize vmcoreinfo
 */
void dfi_vmcoreinfo_init(void)
{
	unsigned long addr, size;
	Elf64_Nhdr note;
	char str[128];

	l.os_info = os_info_get();

	if (l.os_info && l.os_info->vmcoreinfo_size) {
		addr = l.os_info->vmcoreinfo_addr;
		size = l.os_info->vmcoreinfo_size;
	} else {
		dfi_mem_read(LC_VMCORE_INFO, &addr, sizeof(addr));
		if (addr == 0)
			return;
		if (dfi_mem_read_rc(addr, &note, sizeof(note)))
			return;
		memset(str, 0, sizeof(str));
		if (dfi_mem_read_rc(addr + sizeof(note), str, note.n_namesz))
			return;
		if (memcmp(str, "VMCOREINFO", sizeof("VMCOREINFO")) != 0)
			return;
		size = note.n_descsz;
		addr += 24;
	}
	l.vmcoreinfo = zg_alloc(size + 1);
	if (dfi_mem_read_rc(addr, l.vmcoreinfo, size)) {
		zg_free(l.vmcoreinfo);
		l.vmcoreinfo = NULL;
		return;
	}
	l.vmcoreinfo[size] = 0;
}

/*
 * Return vmcoreinfo data
 */
char *dfi_vmcoreinfo_get(void)
{
	return l.vmcoreinfo;
}

/*
 * Generic function: Return vmcoreinfo item (-1 on failure)
 */
static int vmcoreinfo_item(char *buf, int UNUSED(len), const char *fmt,
			   const char *sym)
{

	char str[1024], *sym_str, *sym_str_end;

	if (!l.vmcoreinfo)
		return -1;
	if (fmt)
		snprintf(str, sizeof(str), "%s(%s)=", fmt, sym);
	else
		snprintf(str, sizeof(str), "%s=", sym);
	sym_str = strstr(l.vmcoreinfo, str);
	if (!sym_str)
		return -1;
	sym_str += strlen(str);
	sym_str_end = strchr(sym_str, '\n');
	if (!sym_str_end)
		sym_str_end = strchr(sym_str, '\0');
	memset(str, 0, sizeof(str));
	memcpy(str, sym_str, (unsigned long) (sym_str_end - sym_str));
	strcpy(buf, str);
	return 0;
}

/*
 * Generic function: Return vmcoreinfo ulong item (-1 on failure)
 */
static int vmcoreinfo_item_ulong(unsigned long *val, const char *fmt,
				 const char *sym, unsigned long base)
{
	char str[1024];
	int rc;

	rc = vmcoreinfo_item(str, sizeof(str), fmt, sym);
	if (rc)
		return rc;
	*val = strtoul(str, NULL, base);
	return 0;
}

/*
 * Return vmcoreinfo tag (-1 on failure)
 */
int dfi_vmcoreinfo_tag(char *str, int len, const char *sym)
{
	return vmcoreinfo_item(str, len, NULL, sym);
}

/*
 * Return vmcoreinfo symbol address (-1 on failure)
 */
int dfi_vmcoreinfo_symbol(unsigned long *addr, const char *sym)
{
	return vmcoreinfo_item_ulong(addr, "SYMBOL", sym, 16);
}

/*
 * Return vmcoreinfo offset of a member of a datastructure (-1 on failure)
 */
int dfi_vmcoreinfo_offset(unsigned long *off, const char *sym)
{
	return vmcoreinfo_item_ulong(off, "OFFSET", sym, 10);
}

/*
 * Return vmcoreinfo datatype size (-1 on failure)
 */
int dfi_vmcoreinfo_size(unsigned long *size, const char *sym)
{
	return vmcoreinfo_item_ulong(size, "SIZE", sym, 10);
}

/*
 * Return vmcoreinfo symbol length (-1 on failure)
 */
int dfi_vmcoreinfo_length(unsigned long *len, const char *sym)
{
	return vmcoreinfo_item_ulong(len, "LENGTH", sym, 10);
}

/*
 * Return vmcoreinfo number (-1 on failure)
 */
int dfi_vmcoreinfo_val(unsigned long *val, const char *sym)
{
	return vmcoreinfo_item_ulong(val, NULL, sym, 10);
}
