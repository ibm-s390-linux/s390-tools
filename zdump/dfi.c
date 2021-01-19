/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Generic input dump format functions (DFI - Dump Format Input)
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <time.h>
#include "zgetdump.h"

#define TIME_FMT_STR "%a, %d %b %Y %H:%M:%S %z"
#define PROGRESS_HASH_CNT 50

/*
 * DFI vector - ensure that tape is the first in the list and devmem the second!
 */
static struct dfi *dfi_vec[] = {
	&dfi_s390tape,
	&dfi_devmem,
	&dfi_s390mv_ext,
	&dfi_s390mv,
	&dfi_s390_ext,
	&dfi_s390,
	&dfi_lkcd,
	&dfi_elf,
	&dfi_kdump,
	&dfi_kdump_flat,
	NULL,
};

/*
 * Live dump magic
 */
u64 dfi_live_dump_magic = 0x4c49564544554d50ULL; /* LIVEDUMP */

/*
 * CPU information
 */
struct cpus {
	struct util_list	list;
	enum dfi_cpu_content	content;
	int			fac;
	unsigned int		cnt;
};

/*
 * Memory information
 */
struct mem {
	struct dfi_mem_chunk	*chunk_cache;
	u64			start_addr;
	u64			end_addr;
	unsigned int		chunk_cnt;
	struct util_list	chunk_list;
};

/*
 * Dump header attribute information
 */
struct attr {
	unsigned int		*dfi_version;
	struct timeval		*time;
	struct timeval		*time_end;
	u64			*cpu_id;
	u64			*mem_size_real;
	enum dfi_arch		*build_arch;
	unsigned int		*vol_nr;
	u32			*real_cpu_cnt;
	struct new_utsname	*utsname;
	char			*dump_method;
	u64			*file_size;
};

/*
 * File local static data
 */
static struct {
	enum dfi_arch	arch;
	struct attr	attr;
	struct mem	mem_phys;
	struct mem	mem_virt;
	struct cpus	cpus;
	struct dfi	*dfi;
	unsigned long	kdump_base;
	unsigned long	kdump_size;
} l;

/*
 * Print Dump date
 */
static void date_print(void)
{
	char time_str[80];
	struct tm *tmp;

	if (l.attr.time) {
		tmp = localtime(&l.attr.time->tv_sec);
		strftime(time_str, sizeof(time_str), TIME_FMT_STR, tmp);
		STDERR("  Dump created.......: %s\n", time_str);
	}
	if (l.attr.time_end) {
		tmp = localtime(&l.attr.time_end->tv_sec);
		strftime(time_str, sizeof(time_str), TIME_FMT_STR, tmp);
		STDERR("  Dump ended.........: %s\n", time_str);
	}
}

/*
 * Initialize DFI memory chunks
 */
static void mem_init(struct mem *mem)
{
	mem->start_addr = U64_MAX;
	mem->end_addr = 0;
	util_list_init(&mem->chunk_list, struct dfi_mem_chunk, list);
}

/*
 * Memory chunk compare function for list sorting
 */
static int mem_chunk_cmp_fn(void *a, void *b, void *UNUSED(data))
{
	struct dfi_mem_chunk *mem_chunk1 = a;
	struct dfi_mem_chunk *mem_chunk2 = b;

	return mem_chunk1->start < mem_chunk2->start ? -1 : 1;
}

/*
 * Update DFI memory chunks
 */
static void mem_update(struct mem *mem)
{
	struct dfi_mem_chunk *mem_chunk;

	util_list_sort(&mem->chunk_list, mem_chunk_cmp_fn, NULL);
	mem->start_addr = U64_MAX;
	mem->end_addr = 0;
	util_list_iterate(&mem->chunk_list, mem_chunk) {
		mem->start_addr = MIN(mem->start_addr, mem_chunk->start);
		mem->end_addr = MAX(mem->end_addr, mem_chunk->end);
	}
}

/*
 * Print memory map
 */
static void mem_map_print(void)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 print_start = 0, print_end = 0;
	const char *zero_str;
	u32 volnr = 0;

	STDERR("\nMemory map:\n");
	/*
	 * Print each memory chunk if verbose specified
	 */
	if (g.opts.verbose_specified) {
		dfi_mem_chunk_iterate(mem_chunk) {
			zero_str = "";
			if (mem_chunk->read_fn == dfi_mem_chunk_read_zero)
				zero_str = " zeroes";
			STDERR("  %016llx - %016llx (%llu MB%s)\n",
			       mem_chunk->start, mem_chunk->end,
			       TO_MIB(mem_chunk->size), zero_str);
		}
		return;
	}
	/*
	 * Merge adjacent memory chunks from the same volume
	 */
	dfi_mem_chunk_iterate(mem_chunk) {
		if (print_end == 0) {
			print_start = mem_chunk->start;
			print_end = mem_chunk->end;
			volnr = mem_chunk->volnr;
			continue;
		}
		if (mem_chunk->start != print_end + 1 ||
		    mem_chunk->volnr != volnr) {
			STDERR("  %016llx - %016llx (%llu MB)\n", print_start,
			       print_end, TO_MIB(print_end - print_start + 1));
			print_start = mem_chunk->start;
			volnr = mem_chunk->volnr;
		}
		print_end = mem_chunk->end;
	}
	STDERR("  %016llx - %016llx (%llu MB)\n", print_start,
	       print_end, TO_MIB(print_end - print_start + 1));
}

/*
 * Is memory range valid?
 */
int dfi_mem_range_valid(u64 addr, u64 len)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 addr_end = addr + len;

	do {
		mem_chunk = dfi_mem_chunk_find(addr);
		if (!mem_chunk)
			return 0;
		addr += MIN(len, mem_chunk->end - addr + 1);
	} while (addr < addr_end);
	return 1;
}

/*
 * Is memory already mapped at range?
 */
static int mem_range_mapped(u64 start, u64 size)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 end = start + size - 1;

	dfi_mem_chunk_iterate(mem_chunk) {
		if (mem_chunk->start > end)
			continue;
		if (mem_chunk->end < start)
			continue;
		return 1;
	}
	return 0;
}
/*
 * Print dump information (--info option)
 */
void dfi_info_print(void)
{
	STDERR("General dump info:\n");
	STDERR("  Dump format........: %s\n", l.dfi->name);
	if (l.attr.dfi_version)
		STDERR("  Version............: %d\n", *l.attr.dfi_version);
	date_print();
	if (l.attr.dump_method)
		STDERR("  Dump method........: %s\n", l.attr.dump_method);
	if (l.attr.cpu_id)
		STDERR("  Dump CPU ID........: %llx\n", *l.attr.cpu_id);
	if (l.attr.utsname) {
		STDERR("  UTS node name......: %s\n", l.attr.utsname->nodename);
		STDERR("  UTS kernel release.: %s\n", l.attr.utsname->release);
		STDERR("  UTS kernel version.: %s\n", l.attr.utsname->version);
	}
	if (l.attr.vol_nr)
		STDERR("  Volume number......: %d\n", *l.attr.vol_nr);
	if (l.attr.build_arch)
		STDERR("  Build arch.........: %s\n",
		      dfi_arch_str(*l.attr.build_arch));
	STDERR("  System arch........: %s\n", dfi_arch_str(l.arch));
	if (l.cpus.cnt)
		STDERR("  CPU count (online).: %d\n", l.cpus.cnt);
	if (l.attr.real_cpu_cnt)
		STDERR("  CPU count (real)...: %d\n", *l.attr.real_cpu_cnt);
	if (dfi_mem_range())
		STDERR("  Dump memory range..: %lld MB\n",
		       TO_MIB(dfi_mem_range()));
	if (l.attr.mem_size_real)
		STDERR("  Real memory range..: %lld MB\n",
		      TO_MIB(*l.attr.mem_size_real));
	if (l.attr.file_size)
		STDERR("  Dump file size.....: %lld MB\n",
		      TO_MIB(*l.attr.file_size));
	if (dfi_mem_range())
		mem_map_print();
	if (l.dfi->info_dump) {
		STDERR("\nDump device info:\n");
		l.dfi->info_dump();
	}
}

/*
 * Add memory chunk to memory
 */
static void mem_chunk_create(struct mem *mem, u64 start, u64 size, void *data,
			     dfi_mem_chunk_read_fn read_fn,
			     dfi_mem_chunk_free_fn free_fn)
{
	struct dfi_mem_chunk *mem_chunk;

	mem_chunk = zg_alloc(sizeof(*mem_chunk));
	mem_chunk->start = start;
	mem_chunk->end = start + size - 1;
	mem_chunk->size = size;
	mem_chunk->read_fn = read_fn;
	mem_chunk->free_fn = free_fn;
	mem_chunk->data = data;

	util_list_add_tail(&mem->chunk_list, mem_chunk);
	mem->start_addr = MIN(mem->start_addr, mem_chunk->start);
	mem->end_addr = MAX(mem->end_addr, mem_chunk->end);
	mem->chunk_cache = mem_chunk;
	mem->chunk_cnt++;
}

/*
 * Check if memory chunk contains address
 */
static int mem_chunk_has_addr(struct dfi_mem_chunk *mem_chunk, u64 addr)
{
	return (addr >= mem_chunk->start && addr <= mem_chunk->end);
}

/*
 * Find memory chunk that contains address
 */
static struct dfi_mem_chunk *mem_chunk_find(struct mem *mem, u64 addr)
{
	struct dfi_mem_chunk *mem_chunk;

	if (mem_chunk_has_addr(mem->chunk_cache, addr))
		return mem->chunk_cache;
	util_list_iterate(&mem->chunk_list, mem_chunk) {
		if (mem_chunk_has_addr(mem_chunk, addr)) {
			mem->chunk_cache = mem_chunk;
			return mem_chunk;
		}
	}
	return NULL;
}

/*
 * Read memory at given address
 */
static void mem_read(struct mem *mem, u64 addr, void *buf, size_t cnt)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 size, off, copied = 0;

	while (copied != cnt) {
		mem_chunk = mem_chunk_find(mem, addr);
		size = MIN(cnt - copied, mem_chunk->end - addr + 1);
		off = addr - mem_chunk->start;
		mem_chunk->read_fn(mem_chunk, off, buf + copied, size);
		copied += size;
		addr += size;
	}
}

/*
 * Read memory for virtual map memory chunk
 */
static void mem_chunk_map_read_fn(struct dfi_mem_chunk *mem_chunk, u64 off,
				  void *buf, u64 cnt)
{
	u64 *start = mem_chunk->data;

	dfi_mem_phys_read(*start + off, buf, cnt);
}

/*
 * Check if memory chunk is a virtual mapping
 */
static int mem_chunk_is_map(struct dfi_mem_chunk *mem_chunk)
{
	return mem_chunk->read_fn == mem_chunk_map_read_fn;
}

/*
 * Return physical start address for memory chunk
 */
static u64 mem_chunk_start_phys(struct dfi_mem_chunk *mem_chunk)
{
	if (mem_chunk_is_map(mem_chunk))
		return *((u64 *) mem_chunk->data);
	else
		return mem_chunk->start;
}

/*
 * Add virtual memory chunk with simple virtual mapping
 */
static void mem_chunk_map_add(u64 start, u64 size, u64 start_p)
{
	u64 *data = zg_alloc(sizeof(*data));

	*data = start_p;
	dfi_mem_chunk_virt_add(start, size, data, mem_chunk_map_read_fn,
			       zg_free);
}

/*
 * Add virtual memory chunk
 */
void dfi_mem_chunk_virt_add(u64 start, u64 size, void *data,
			    dfi_mem_chunk_read_fn read_fn,
			    dfi_mem_chunk_free_fn free_fn)
{
	if (size == 0)
		return;
	mem_chunk_create(&l.mem_virt, start, size, data, read_fn, free_fn);
}

/*
 * Add memory chunk with volume index
 */
void dfi_mem_chunk_add_vol(u64 start, u64 size, void *data,
			   dfi_mem_chunk_read_fn read_fn,
			   dfi_mem_chunk_free_fn free_fn,
			   u32 volnr)
{
	if (size == 0)
		return;
	mem_chunk_create(&l.mem_phys, start, size, data, read_fn, free_fn);
	mem_chunk_create(&l.mem_virt, start, size, data, read_fn, NULL);
	l.mem_virt.chunk_cache->volnr = volnr;

}

/*
 * Add memory chunk
 */
void dfi_mem_chunk_add(u64 start, u64 size, void *data,
		       dfi_mem_chunk_read_fn read_fn,
		       dfi_mem_chunk_free_fn free_fn)
{
	dfi_mem_chunk_add_vol(start, size, data, read_fn, free_fn, 0);
}

/*
 * Read zero pages
 */
void dfi_mem_chunk_read_zero(struct dfi_mem_chunk *UNUSED(mem_chunk),
			     u64 UNUSED(off), void *buf, u64 cnt)
{
	memset(buf, 0, cnt);
}

/*
 * Return mem_chunk list head
 */
struct util_list *dfi_mem_chunk_list(void)
{
	return &l.mem_virt.chunk_list;
}

/*
 * Return number of memory chunks in input dump
 */
unsigned int dfi_mem_chunk_cnt(void)
{
	return l.mem_virt.chunk_cnt;
}

/*
 * Return maximum memory range
 */
u64 dfi_mem_range(void)
{
	if (l.mem_virt.start_addr == U64_MAX)
		return 0;
	return l.mem_virt.end_addr - l.mem_virt.start_addr + 1;
}

/*
 * Return first memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_first(void)
{
	if (util_list_is_empty(&l.mem_virt.chunk_list))
		return NULL;
	return util_list_start(&l.mem_virt.chunk_list);
}

/*
 * Return last memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_last(void)
{
	if (util_list_is_empty(&l.mem_virt.chunk_list))
		return NULL;
	return util_list_end(&l.mem_virt.chunk_list);
}

/*
 * Return next memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_next(struct dfi_mem_chunk *mem_chunk)
{
	return util_list_next(&l.mem_virt.chunk_list, mem_chunk);
}

/*
 * Return previous memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_prev(struct dfi_mem_chunk *mem_chunk)
{
	return util_list_prev(&l.mem_virt.chunk_list, mem_chunk);
}

/*
 * Find memory chunk for given address
 */
struct dfi_mem_chunk *dfi_mem_chunk_find(u64 addr)
{
	return mem_chunk_find(&l.mem_virt, addr);
}

/*
 * Initialize CPU info
 */
void dfi_cpu_info_init(enum dfi_cpu_content cpu_content)
{
	l.cpus.content = cpu_content;
	util_list_init(&l.cpus.list, struct dfi_cpu, list);
	l.cpus.cnt = 0;
}

/*
 * Allocate new DFI CPU
 */
struct dfi_cpu *dfi_cpu_alloc(void)
{
	return zg_alloc(sizeof(struct dfi_cpu));
}

/*
 * Add DFI CPU
 */
void dfi_cpu_add(struct dfi_cpu *cpu)
{
	util_list_add_tail(&l.cpus.list, cpu);
	l.cpus.cnt++;
}

/*
 * Return CPU with number cpu_nr
 */
struct dfi_cpu *dfi_cpu(unsigned int cpu_nr)
{
	struct dfi_cpu *cpu;
	unsigned int i = 0;

	dfi_cpu_iterate(cpu) {
		if (i == cpu_nr)
			return cpu;
		i++;
	}
	return NULL;
}

/*
 * Return CPU count
 */
unsigned int dfi_cpu_cnt(void)
{
	return l.cpus.cnt;
}

/*
 * Return CPU content
 */
enum dfi_cpu_content dfi_cpu_content(void)
{
	return l.cpus.content;
}

/*
 * Add CPU facility
 */
void dfi_cpu_content_fac_add(int flags)
{
	l.cpus.fac |= flags;
}

/*
 * Check CPU facility
 */
int dfi_cpu_content_fac_check(int flags)
{
	return l.cpus.fac & flags;
}

/*
 * Set DFI architecture
 */
void dfi_arch_set(enum dfi_arch arch)
{
	l.arch = arch;
}

/*
 * Return DFI architecture
 */
enum dfi_arch dfi_arch(void)
{
	return l.arch;
}

/*
 * Return DFI CPU list
 */
struct util_list *dfi_cpu_list(void)
{
	return &l.cpus.list;
}

/*
 * Read memory at given address and do kdump swap if necessary
 */
void dfi_mem_read(u64 addr, void *buf, size_t cnt)
{
	mem_read(&l.mem_virt, addr, buf, cnt);
}

/*
 * Read physical memory at given address
 */
void dfi_mem_phys_read(u64 addr, void *buf, size_t cnt)
{
	mem_read(&l.mem_phys, addr, buf, cnt);
}

/*
 * Read memory at given address with return code
 */
int dfi_mem_read_rc(u64 addr, void *buf, size_t cnt)
{
	if (!dfi_mem_range_valid(addr, cnt))
		return -EINVAL;
	dfi_mem_read(addr, buf, cnt);
	return 0;
}

/*
 * Get input dump format name
 */
const char *dfi_name(void)
{
	return l.dfi->name;
}

/*
 * Can input dump format seek?
 */
int dfi_feat_seek(void)
{
	return l.dfi->feat_bits & DFI_FEAT_SEEK;
};

/*
 * Can input dump format be used for copying?
 */
int dfi_feat_copy(void)
{
	return l.dfi->feat_bits & DFI_FEAT_COPY;
};

/*
 * Return DFI arch string
 */
const char *dfi_arch_str(enum dfi_arch arch)
{
	switch (arch) {
	case DFI_ARCH_32:
		return "s390 (32 bit)";
	case DFI_ARCH_64:
		return "s390x (64 bit)";
	case DFI_ARCH_UNKNOWN:
		return "unknown";
	}
	ABORT("dfi_arch_str: Invalid dfi arch: %d", arch);
}

/*
 * Initialize attributes
 */
static void attr_init(void)
{
	memset(&l.attr, 0, sizeof(l.attr));
}

/*
 * Attribute: Dump time
 */
void dfi_attr_time_set(struct timeval *time)
{
	if (time->tv_sec == 0)
		return;
	l.attr.time = zg_alloc(sizeof(*l.attr.time));
	*l.attr.time = *time;
}

struct timeval *dfi_attr_time(void)
{
	return l.attr.time;
}

/*
 * Attribute: Dump end time
 */
void dfi_attr_time_end_set(struct timeval *time_end)
{
	if (time_end->tv_sec == 0)
		return;
	l.attr.time_end = zg_alloc(sizeof(*l.attr.time_end));
	*l.attr.time_end = *time_end;
}

struct timeval *dfi_attr_time_end(void)
{
	return l.attr.time_end;
}

/*
 * Attribute: Volume number
 */
void dfi_attr_vol_nr_set(unsigned int vol_nr)
{
	l.attr.vol_nr = zg_alloc(sizeof(*l.attr.vol_nr));
	*l.attr.vol_nr = vol_nr;
}

/*
 * Attribute: DFI version
 */
void dfi_attr_version_set(unsigned int dfi_version)
{
	l.attr.dfi_version = zg_alloc(sizeof(*l.attr.dfi_version));
	*l.attr.dfi_version = dfi_version;
}

/*
 * Attribute: CPU ID
 */
void dfi_attr_cpu_id_set(u64 cpu_id)
{
	l.attr.cpu_id = zg_alloc(sizeof(*l.attr.cpu_id));
	*l.attr.cpu_id = cpu_id;
}

u64 *dfi_attr_cpu_id(void)
{
	return l.attr.cpu_id;
}

/*
 * Attribute: utsname
 */
void dfi_attr_utsname_set(struct new_utsname *utsname)
{
	l.attr.utsname = zg_alloc(sizeof(*utsname));
	memcpy(l.attr.utsname, utsname, sizeof(*utsname));
}

struct new_utsname *dfi_attr_utsname(void)
{
	return l.attr.utsname;
}

/*
 * Attribute: Dump method
 */
void dfi_attr_dump_method_set(char *dump_method)
{
	l.attr.dump_method = zg_strdup(dump_method);
}

char *dfi_attr_dump_method(void)
{
	return l.attr.dump_method;
}

/*
 * Attribute: Real memory size
 */
void dfi_attr_mem_size_real_set(u64 mem_size_real)
{
	l.attr.mem_size_real = zg_alloc(sizeof(*l.attr.mem_size_real));
	*l.attr.mem_size_real = mem_size_real;
}

u64 *dfi_attr_mem_size_real(void)
{
	return l.attr.mem_size_real;
}

/*
 * Attribute: Dump file size
 */
void dfi_attr_file_size_set(u64 file_size)
{
	l.attr.file_size = zg_alloc(sizeof(*l.attr.file_size));
	*l.attr.file_size = file_size;
}

u64 *dfi_attr_file_size(void)
{
	return l.attr.file_size;
}


/*
 * Attribute: Build architecture
 */
void dfi_attr_build_arch_set(enum dfi_arch build_arch)
{
	l.attr.build_arch = zg_alloc(sizeof(*l.attr.build_arch));
	*l.attr.build_arch = build_arch;
}

enum dfi_arch *dfi_attr_build_arch(void)
{
	return l.attr.build_arch;
}

/*
 * Attribute: Real CPU count
 */
void dfi_attr_real_cpu_cnt_set(unsigned int real_cnt_cnt)
{
	l.attr.real_cpu_cnt = zg_alloc(sizeof(*l.attr.real_cpu_cnt));
	*l.attr.real_cpu_cnt = real_cnt_cnt;
}

unsigned int *dfi_attr_real_cpu_cnt(void)
{
	return l.attr.real_cpu_cnt;
}

/*
 * Convert 32 bit CPU register set to 64 bit
 */
static void cpu_32_to_64(struct dfi_cpu *cpu_64, struct dfi_cpu_32 *cpu_32)
{
	int i;

	for (i = 0; i < 16; i++) {
		cpu_64->gprs[i] = cpu_32->gprs[i];
		cpu_64->ctrs[i] = cpu_32->ctrs[i];
		cpu_64->acrs[i] = cpu_32->acrs[i];
		if (i < 4)
			cpu_64->fprs[i] = cpu_32->fprs[i];
	}
	cpu_64->psw[0] = cpu_32->psw[0];
	cpu_64->psw[1] = cpu_32->psw[1];
	cpu_64->prefix = cpu_32->prefix;
	cpu_64->timer = cpu_32->timer;
	cpu_64->todcmp = cpu_32->todcmp;
}

/*
 * Convert 64 bit CPU register set to 32 bit
 */
void dfi_cpu_64_to_32(struct dfi_cpu_32 *cpu_32, struct dfi_cpu *cpu_64)
{
	int i;

	for (i = 0; i < 16; i++) {
		cpu_32->gprs[i] = (u32) cpu_64->gprs[i];
		cpu_32->ctrs[i] = (u32) cpu_64->ctrs[i];
		cpu_32->acrs[i] = (u32) cpu_64->acrs[i];
		if (i < 4)
			cpu_32->fprs[i] = (u32) cpu_64->fprs[i];
	}
	cpu_32->psw[0] = (u32) cpu_64->psw[0];
	cpu_32->psw[1] = (u32) cpu_64->psw[1];
	cpu_32->prefix = cpu_64->prefix;
	cpu_32->timer = cpu_64->timer;
	cpu_32->todcmp = cpu_64->todcmp;
}

/*
 * Copy 64 bit lowcore to internal register set
 */
static void lc2cpu_64(struct dfi_cpu *cpu, struct dfi_lowcore_64 *lc)
{
	char vx_sa[DFI_VX_SA_SIZE];
	int i;

	memcpy(&cpu->gprs, lc->gpregs_save_area, sizeof(cpu->gprs));
	memcpy(&cpu->ctrs, lc->cregs_save_area, sizeof(cpu->ctrs));
	memcpy(&cpu->acrs, lc->access_regs_save_area, sizeof(cpu->acrs));
	memcpy(&cpu->fprs, lc->floating_pt_save_area, sizeof(cpu->fprs));
	memcpy(&cpu->fpc, &lc->fpt_creg_save_area, sizeof(cpu->fpc));
	memcpy(&cpu->psw, lc->st_status_fixed_logout, sizeof(cpu->psw));
	memcpy(&cpu->prefix, &lc->prefixreg_save_area, sizeof(cpu->prefix));
	memcpy(&cpu->timer, lc->timer_save_area, sizeof(cpu->timer));
	memcpy(&cpu->todpreg, &lc->tod_progreg_save_area, sizeof(cpu->todpreg));
	memcpy(&cpu->todcmp, lc->clock_comp_save_area, sizeof(cpu->todcmp));
	/* Add VX registers if available */
	if (!dfi_cpu_lc_has_vx_sa(lc))
		return;
	if (dfi_mem_read_rc(lc->vector_save_area_addr, &vx_sa, sizeof(vx_sa))) {
		STDERR("zgetdump: Vector registers save area is beyond dump memory limit for CPU %d\n", cpu->cpu_id);
		return;
	}
	memcpy(cpu->vxrs_high, &vx_sa[16 * 16], sizeof(cpu->vxrs_high));
	for (i = 0; i < 16; i++)
		memcpy(&cpu->vxrs_low[i], &vx_sa[16 * i + 8], sizeof(u64));
	dfi_cpu_content_fac_add(DFI_CPU_CONTENT_FAC_VX);
}

/*
 * Copy 32 bit lowcore to internal 32 bit cpu
 */
static void lc2cpu_32(struct dfi_cpu_32 *cpu, struct dfi_lowcore_32 *lc)
{
	memcpy(&cpu->gprs, lc->gpregs_save_area, sizeof(cpu->gprs));
	memcpy(&cpu->ctrs, lc->cregs_save_area, sizeof(cpu->ctrs));
	memcpy(&cpu->acrs, lc->access_regs_save_area, sizeof(cpu->acrs));
	memcpy(&cpu->fprs, lc->floating_pt_save_area, sizeof(cpu->fprs));
	memcpy(&cpu->psw, lc->st_status_fixed_logout, sizeof(cpu->psw));
	memcpy(&cpu->prefix, &lc->prefixreg_save_area, sizeof(cpu->prefix));
	memcpy(&cpu->timer, lc->timer_save_area, sizeof(cpu->timer));
	memcpy(&cpu->todcmp, lc->clock_comp_save_area, sizeof(cpu->todcmp));
}

/*
 * Initialize and add a new CPU with given lowcore pointer
 *
 * Note: When this function is called, the memory chunks have to be already
 *       defined by the DFI dump specific code.
 */
void dfi_cpu_add_from_lc(u32 lc_addr)
{
	struct dfi_cpu *cpu = dfi_cpu_alloc();

	cpu->cpu_id = l.cpus.cnt;
	switch (l.cpus.content) {
	case DFI_CPU_CONTENT_LC:
		cpu->prefix = lc_addr;
		break;
	case DFI_CPU_CONTENT_ALL:
		if (l.arch == DFI_ARCH_32) {
			struct dfi_cpu_32 cpu_32;
			struct dfi_lowcore_32 lc;
			dfi_mem_read(lc_addr, &lc, sizeof(lc));
			lc2cpu_32(&cpu_32, &lc);
			cpu_32_to_64(cpu, &cpu_32);
		} else {
			struct dfi_lowcore_64 lc;
			dfi_mem_read(lc_addr, &lc, sizeof(lc));
			lc2cpu_64(cpu, &lc);
		}
		break;
	case DFI_CPU_CONTENT_NONE:
		ABORT("dfi_cpu_add_from_lc() called for CONTENT_NONE");
	}
	dfi_cpu_add(cpu);
}

/*
 * Check if lowcore has VX registers
 */
int dfi_cpu_lc_has_vx_sa(void *_lc)
{
	struct dfi_lowcore_64 *lc = _lc;

	if (l.arch == DFI_ARCH_32)
		return 0;
	if (lc->vector_save_area_addr == 0)
		return 0;
	if (lc->vector_save_area_addr % 1024 != 0)
		return 0;
	return 1;
}

/*
 * Copy VX registers out of save areas
 */
void dfi_cpu_vx_copy(void *buf, struct dfi_cpu *cpu)
{
	char *_buf = buf;
	int i;

	for (i = 0; i < 16; i++) {
		memcpy(&_buf[i * 16], &cpu->fprs[i], 8);
		memcpy(&_buf[i * 16 + 8], &cpu->vxrs_low[i], 8);
	}
	memcpy(&_buf[16 * 16], &cpu->vxrs_high[0], 16 * 16);
}

/*
 * Return kdump base
 */
unsigned long dfi_kdump_base(void)
{
	return l.kdump_base;
}

/*
 * Unmap memory region
 */
static void mem_unmap(u64 start, u64 size)
{
	u64 start_phys, end_phys, addr_phys, addr_virt, size_virt;
	struct dfi_mem_chunk *mem_chunk, *tmp;
	u64 end = start + size - 1;

	util_list_iterate_safe(&l.mem_virt.chunk_list, mem_chunk, tmp) {
		/*
		 * Chunk not hit?
		 */
		if (mem_chunk->start >= start + size)
			continue;
		if (mem_chunk->end < start)
			continue;
		/*
		 * Chunk completely unmapped
		 *
		 * UNMAP: UUUUUUUUU || UUUUUU
		 * CHUNK:   CCCC    || CCCCCC
		 * TO:
		 */
		if (mem_chunk->start >= start && mem_chunk->end <= end)
			goto free;

		/*
		 * Get real start and end addresses
		 */
		start_phys = mem_chunk_start_phys(mem_chunk);
		end_phys = start_phys + mem_chunk->size - 1;

		/*
		 * Chunk hit at start or in the middle?
		 *
		 * UNMAP: UUUUUU   ||   UU    || UUU
		 * CHUNK:    CCCCC || CCCCCC  ||   CCCC
		 * TO:          NN ||     NN  ||    NNN
		 */
		if (mem_chunk->end > end) {
			addr_virt = end + 1;
			size_virt = mem_chunk->end - end;
			addr_phys = end_phys - size_virt + 1;
			mem_chunk_map_add(addr_virt, size_virt, addr_phys);
		}
		/*
		 * Chunk hit at end or in the middle?
		 *
		 * UNMAP:   UUUUUU   ||   UU    ||   UUU
		 * CHUNK: CCCCC      || CCCCCC  || CCC
		 * TO:    NN         || NN      || NN
		 */
		if (mem_chunk->start < start) {
			addr_virt = mem_chunk->start;
			size_virt = start - addr_virt;
			addr_phys = start_phys;
			mem_chunk_map_add(addr_virt, size_virt, addr_phys);
		}
free:
		util_list_remove(&l.mem_virt.chunk_list, mem_chunk);
		l.mem_virt.chunk_cnt--;
		if (mem_chunk->data && mem_chunk->free_fn)
			mem_chunk->free_fn(mem_chunk->data);
		zg_free(mem_chunk);
	}
	mem_update(&l.mem_virt);
}

/*
 * Map memory region
 */
static void mem_map(u64 start, u64 size, u64 start_phys)
{
	if (mem_range_mapped(start, size)) {
		mem_map_print();
		ABORT("Map request for already mapped region (%llx/%llx/%llx)",
		      start, size, start_phys);
	}
	mem_chunk_map_add(start, size, start_phys);
	mem_update(&l.mem_virt);
}

/*
 * Check if dump contains a kdump dump and initialize kdump_base and kdump_size
 */
static void kdump_init(void)
{
	unsigned long base, size;

	dfi_mem_phys_read(0x10418, &base, sizeof(base));
	dfi_mem_phys_read(0x10420, &size, sizeof(size));
	if (base == 0 || size == 0)
		return;
	if (base % MIB || size % MIB)
		return;
	if (!dfi_mem_range_valid(base, size))
		return;
	l.kdump_base = base;
	l.kdump_size = size;
	/*
	 * For dumped kdump and user has selected "prod" we swap
	 * the crashkernel memory with old memory. If user selected "kdump",
	 * we only provide kdump memory. If user selected "all", we
	 * provide the complete dump.
	 */
	if (!g.opts.select_specified)
		return;
	if (g.opts.select == OPTS_SELECT_PROD) {
		mem_unmap(0, size);
		mem_unmap(base, size);
		mem_map(0, size, base);
	} else if (g.opts.select == OPTS_SELECT_KDUMP) {
		mem_unmap(l.kdump_size, U64_MAX - l.kdump_size);
	}
}

/*
 * If "--select prod" is set, modify DFI to show production system dump
 */
static void kdump_select_prod_init(void)
{
	unsigned long prefix, ptr, count, tv_sec, i;
	struct timeval timeval;

	if (g.opts.select_specified && !l.kdump_base)
		ERR_EXIT("The \"--select\" option is not possible with this "
			 "dump");
	attr_init();
	dfi_arch_set(DFI_ARCH_64);
	dfi_cpu_info_init(DFI_CPU_CONTENT_NONE);
	if (dfi_vmcoreinfo_symbol(&ptr, "lowcore_ptr"))
		return;
	if (dfi_vmcoreinfo_length(&count, "lowcore_ptr"))
		return;
	if (dfi_vmcoreinfo_val(&tv_sec, "CRASHTIME") == 0) {
		timeval.tv_sec = tv_sec;
		timeval.tv_usec = 0;
		dfi_attr_time_set(&timeval);
	}
	dfi_cpu_info_init(DFI_CPU_CONTENT_ALL);
	for (i = 0; i < count; i++) {
		if (dfi_mem_read_rc(ptr + i * sizeof(long), &prefix,
				   sizeof(prefix)))
			continue;
		if (prefix == 0)
			continue;
		if (prefix % 0x1000)
			continue;
		dfi_cpu_add_from_lc(prefix);
	}
}

/*
 * Try to get utsname info from dump
 */
static void utsname_init(void)
{
	struct new_utsname *utsname;
	unsigned long ptr;
	char buf[1024];

	if (dfi_vmcoreinfo_symbol(&ptr, "init_uts_ns"))
		return;
	if (dfi_mem_read_rc(ptr, buf, sizeof(buf)))
		return;
	utsname = memchr(buf, 'L', sizeof(buf) - sizeof(*utsname));
	if (!utsname)
		return;
	if (strncmp(utsname->sysname, "Linux", sizeof(utsname->version)) != 0)
		return;
	dfi_attr_utsname_set(utsname);
}

/*
 * Try to get livedump magic
 */
static void livedump_init(void)
{
	u64 magic;

	if (dfi_mem_read_rc(0, &magic, sizeof(magic)))
		return;
	if (magic == dfi_live_dump_magic)
		dfi_attr_dump_method_set(DFI_DUMP_METHOD_LIVE);
}

/*
 * Open the dump
 *
 * In case of --mount we first try O_EXCL in order to prevent other
 * tools like zipl or mkfs.xxx to use the disk.
 *
 * On Linux 2.6 and later, O_EXCL can be used without O_CREAT if pathname
 * refers to a block device. If the block device is in use by the system
 * (e.g., mounted), open() fails with the error EBUSY.
 */
struct zg_fh *dfi_dump_open(const char *path)
{
	struct zg_fh *zg_fh;

	if (g.opts.action == ZG_ACTION_MOUNT) {
		zg_fh = zg_open(path, O_RDONLY | O_EXCL, ZG_CHECK_NONE);
		if (zg_fh)
			return zg_fh;
	}
	return zg_open(path, O_RDONLY, ZG_CHECK);
}

/*
 * Initialize input dump format.
 */
int dfi_init(void)
{
	struct dfi *dfi;
	int i = 0, rc;

	l.arch = DFI_ARCH_UNKNOWN;
	mem_init(&l.mem_virt);
	mem_init(&l.mem_phys);
	attr_init();
	dfi_cpu_info_init(DFI_CPU_CONTENT_NONE);
	while ((dfi = dfi_vec[i])) {
		l.dfi = dfi;
		g.fh = dfi_dump_open(g.opts.device);
		rc = dfi->init();
		if (rc == 0 && dfi_feat_seek()) {
			kdump_init();
			dfi_vmcoreinfo_init();
			if (g.opts.select == OPTS_SELECT_PROD)
				kdump_select_prod_init();
			utsname_init();
			livedump_init();
		}
		if (rc == 0 || rc == -EINVAL)
			return rc;
		zg_close(g.fh);
		i++;
	}
	ERR_EXIT("No valid dump found on \"%s\"", g.opts.device);
}

/*
 * Cleanup input dump format.
 */
void dfi_exit(void)
{
	if (l.dfi && l.dfi->exit)
		l.dfi->exit();
}
