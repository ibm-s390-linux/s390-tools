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

#include <stdio.h>
#include <string.h>
#include <elf.h>

#include "lib/zt_common.h"
#include "lib/util_log.h"

#include "zg.h"
#include "dfi_mem_chunk.h"
#include "dfi_vmcoreinfo.h"

#include "boot/os_info.h"

#ifdef __s390x__
#define LC_VMCORE_INFO		0xe0c
#else
#define LC_VMCORE_INFO		0xe08
#endif

#define LC_OS_INFO		0xe18

struct vm_info {
	u64	identity_base;
	u64	kaslr_offset;
	u64	kaslr_offset_phys;
	u64	amode31_start;
	u64	amode31_end;
};

/*
 * File local static data
 */
static struct {
	char		*vmcoreinfo;
	struct os_info	*os_info;
	struct vm_info  *vm_info;
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

	util_log_print(UTIL_LOG_TRACE, "DFI get osinfo\n");

	if (dfi_mem_virt_read(LC_OS_INFO, &addr, sizeof(addr)))
		return NULL;
	util_log_print(UTIL_LOG_DEBUG, "DFI osinfo addr: 0x%016lx\n", addr);
	if (addr % 0x1000)
		return NULL;
	if (dfi_mem_virt_read(addr, &os_info, sizeof(os_info)))
		return NULL;
	if (os_info.magic != OS_INFO_MAGIC)
		return NULL;
	if (os_info.csum != os_info_csum(&os_info))
		return NULL;

	util_log_print(UTIL_LOG_DEBUG, "DFI found valid osinfo!\n");
	return &os_info;
}

static struct vm_info *vm_info_get(void)
{
	static struct vm_info vm_info = { 0 };

	util_log_print(UTIL_LOG_TRACE, "DFI read vm_info\n");

	vm_info.kaslr_offset = l.os_info->entry[OS_INFO_KASLR_OFFSET].val;
	if (vm_info.kaslr_offset == 0)
		return NULL;
	vm_info.kaslr_offset_phys = l.os_info->entry[OS_INFO_KASLR_OFF_PHYS].val;
	vm_info.identity_base = l.os_info->entry[OS_INFO_IDENTITY_BASE].val;
	vm_info.amode31_start = l.os_info->entry[OS_INFO_AMODE31_START].val;
	vm_info.amode31_end = l.os_info->entry[OS_INFO_AMODE31_END].val;

	return &vm_info;
}

/*
 * Convert virual address in the dump to the physical address using
 * vm_info data derived from os_info
 */
u64 dfi_vm_vtop(u64 vaddr)
{
	if (!l.vm_info)
		return vaddr;
	if (vaddr < LOWCORE_SIZE)
		return vaddr;
	if ((vaddr < l.vm_info->amode31_end) &&
	    (vaddr >= l.vm_info->amode31_start))
		return vaddr;
	if (vaddr < l.vm_info->kaslr_offset)
		return vaddr - l.vm_info->identity_base;
	return vaddr - l.vm_info->kaslr_offset + l.vm_info->kaslr_offset_phys;
}

/*
 * Initialize vmcoreinfo
 */
void dfi_vmcoreinfo_init(void)
{
	unsigned long addr, size;
	Elf64_Nhdr note;
	char str[128];

	util_log_print(UTIL_LOG_TRACE, "DFI vmcoreinfo initialization\n");

	l.os_info = os_info_get();
	if (l.os_info)
		l.vm_info = vm_info_get();

	if (l.os_info && l.os_info->entry[OS_INFO_VMCOREINFO].size) {
		util_log_print(UTIL_LOG_DEBUG, "DFI found valid osinfo\n");
		addr = l.os_info->entry[OS_INFO_VMCOREINFO].addr;
		size = l.os_info->entry[OS_INFO_VMCOREINFO].size;
	} else {
		if (dfi_mem_virt_read(LC_VMCORE_INFO, &addr, sizeof(addr)))
			return;
		if (addr == 0)
			return;
		if (dfi_mem_virt_read(addr, &note, sizeof(note)))
			return;
		if (note.n_namesz == 0 || note.n_namesz > sizeof(str))
			return;
		memset(str, 0, sizeof(str));
		if (dfi_mem_virt_read(addr + sizeof(note), str, note.n_namesz))
			return;
		if (memcmp(str, "VMCOREINFO", sizeof("VMCOREINFO")) != 0)
			return;
		size = note.n_descsz;
		addr += 24;
	}
	util_log_print(UTIL_LOG_DEBUG,
		       "DFI vmcoreinfo addr 0x%016lx size 0x%016lx\n",
		       addr, size);
	l.vmcoreinfo = zg_alloc(size + 1);
	if (dfi_mem_virt_read(addr, l.vmcoreinfo, size)) {
		zg_free(l.vmcoreinfo);
		l.vmcoreinfo = NULL;
		return;
	}
	l.vmcoreinfo[size] = 0;
	util_log_print(UTIL_LOG_INFO, "DFI found valid vmcoreinfo\n");
}

/*
 * Return vmcoreinfo data
 */
const char *dfi_vmcoreinfo_get(void)
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
	util_log_print(UTIL_LOG_DEBUG, "DFI vmcoreinfo symbol %s : %s\n", sym, str);
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
