/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Generic input dump format functions (DFI - Dump Format Input)
 *
 * Copyright IBM Corp. 2001, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/util_log.h"

#include "zgetdump.h"
#include "dfi_mem_chunk.h"
#include "dfi_vmcoreinfo.h"
#include "dfi.h"

#define TIME_FMT_STR "%a, %d %b %Y %H:%M:%S %z"
#define PROGRESS_HASH_CNT 50

#define KDUMP_OLDMEM_BASE	0x10418
#define KDUMP_OLDMEM_SIZE	0x10420

/*
 * DFI vector - ensure that tape is the first in the list and devmem the second!
 */
static struct dfi *dfi_vec[] = {
	/* clang-format off */
	&dfi_s390tape,
	&dfi_devmem,
	&dfi_s390mv_ext,
	&dfi_s390mv,
	&dfi_s390_ext,
	&dfi_s390,
	&dfi_lkcd,
	&dfi_vmdump,
	&dfi_pv_elf,
	&dfi_elf,
	&dfi_kdump,
	&dfi_kdump_flat,
	&dfi_ngdump,
	NULL,
	/* clang-format on */
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
	u8			*zlib_version;
	u32			*zlib_entsize;
};

/*
 * File local static data
 */
static struct {
	enum dfi_arch	arch;
	struct attr	attr;
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
 * Print dump information (--info option)
 */
void dfi_info_print(void)
{
	STDERR("General dump info:\n");
	STDERR("  Dump format........: %s\n", l.dfi->name);
	if (l.attr.dfi_version)
		STDERR("  Version............: %u\n", *l.attr.dfi_version);
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
		STDERR("  Volume number......: %u\n", *l.attr.vol_nr);
	if (l.attr.build_arch)
		STDERR("  Build arch.........: %s\n",
		       dfi_arch_str(*l.attr.build_arch));
	STDERR("  System arch........: %s\n", dfi_arch_str(l.arch));
	if (l.cpus.cnt)
		STDERR("  CPU count (online).: %u\n", l.cpus.cnt);
	if (l.attr.real_cpu_cnt)
		STDERR("  CPU count (real)...: %u\n", *l.attr.real_cpu_cnt);
	if (dfi_mem_range())
		STDERR("  Dump memory range..: %lld MB\n",
		       TO_MIB(dfi_mem_range()));
	if (l.attr.mem_size_real)
		STDERR("  Real memory range..: %lld MB\n",
		       TO_MIB(*l.attr.mem_size_real));
	if (l.attr.file_size)
		STDERR("  Dump file size.....: %lld MB\n",
		       TO_MIB(*l.attr.file_size));
	if (g.opts.verbose && l.attr.zlib_version && l.attr.zlib_entsize) {
		STDERR("  Zlib version.......: %lld\n", *l.attr.zlib_version);
		STDERR("  Zlib compression unit: %lld MB\n",
		       TO_MIB(*l.attr.zlib_entsize));
	}
	if (dfi_mem_range())
		dfi_mem_map_print(g.opts.verbose);
	if (l.dfi->info_dump) {
		STDERR("\nDump device info:\n");
		l.dfi->info_dump();
	}
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

void dfi_cpu_free(struct dfi_cpu *cpu)
{
	zg_free(cpu);
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
	return NULL; /* UNREACHABLE */
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
 * Attribute: Zlib version and zlib entry size
 */
void dfi_attr_zlib_info_set(u8 version, u32 entry_size)
{
	l.attr.zlib_version = zg_alloc(sizeof(*l.attr.zlib_version));
	*l.attr.zlib_version = version;
	l.attr.zlib_entsize = zg_alloc(sizeof(*l.attr.zlib_entsize));
	*l.attr.zlib_entsize = entry_size;
}

u8 *dfi_attr_zlib_version(void)
{
	return l.attr.zlib_version;
}

u32 *dfi_attr_zlib_entsize(void)
{
	return l.attr.zlib_entsize;
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
	if (dfi_mem_virt_read(lc->vector_save_area_addr, &vx_sa, sizeof(vx_sa))) {
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
int dfi_cpu_add_from_lc(u32 lc_addr)
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
			if (dfi_mem_virt_read(lc_addr, &lc, sizeof(lc)))
				return -EINVAL;
			lc2cpu_32(&cpu_32, &lc);
			cpu_32_to_64(cpu, &cpu_32);
		} else {
			struct dfi_lowcore_64 lc;
			if (dfi_mem_virt_read(lc_addr, &lc, sizeof(lc)))
				return -EINVAL;
			lc2cpu_64(cpu, &lc);
		}
		break;
	case DFI_CPU_CONTENT_NONE:
		ABORT("dfi_cpu_add_from_lc() called for CONTENT_NONE");
	}
	dfi_cpu_add(cpu);
	return 0;
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
 * Check if dump contains a kdump dump and initialize kdump_base and kdump_size
 */
static void kdump_init(void)
{
	unsigned long base, size;

	util_log_print(UTIL_LOG_TRACE, "DFI kdump initialization\n");

	if (dfi_mem_phys_read(KDUMP_OLDMEM_BASE, &base, sizeof(base)))
		return;
	if (dfi_mem_phys_read(KDUMP_OLDMEM_SIZE, &size, sizeof(size)))
		return;
	if (base == 0 || size == 0)
		return;
	if (base % MIB || size % MIB)
		return;
	if (!dfi_mem_range_valid(base, size))
		return;
	l.kdump_base = base;
	l.kdump_size = size;
	util_log_print(UTIL_LOG_INFO,
		       "DFI found valid kdump base 0x%016lx size 0x%016lx\n",
		       l.kdump_base, l.kdump_size);
	/*
	 * For dumped kdump and user has selected "prod" we swap
	 * the crashkernel memory with old memory. If user selected "kdump",
	 * we only provide kdump memory. If user selected "all", we
	 * provide the complete dump.
	 */
	if (!g.opts.select_specified)
		return;
	if (g.opts.select == OPTS_SELECT_PROD) {
		dfi_mem_unmap(0, size);
		dfi_mem_unmap(base, size);
		dfi_mem_map(0, size, base);
	} else if (g.opts.select == OPTS_SELECT_KDUMP) {
		dfi_mem_unmap(l.kdump_size, U64_MAX - l.kdump_size);
	}
}

/*
 * If "--select prod" is set, modify DFI to show production system dump
 */
static void kdump_select_prod_init(void)
{
	unsigned long prefix, ptr, count, tv_sec, i;
	struct timeval timeval;

	util_log_print(UTIL_LOG_TRACE, "DFI kdump production system dump initialization\n");

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
		if (dfi_mem_virt_read(dfi_vm_vtop(ptr) + i * sizeof(long), &prefix,
				      sizeof(prefix)))
			continue;
		prefix = dfi_vm_vtop(prefix);
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

	util_log_print(UTIL_LOG_TRACE, "DFI utsname initialization\n");

	if (dfi_vmcoreinfo_symbol(&ptr, "init_uts_ns"))
		return;
	if (dfi_mem_virt_read(dfi_vm_vtop(ptr), buf, sizeof(buf)))
		return;
	utsname = memchr(buf, 'L', sizeof(buf) - sizeof(*utsname));
	if (!utsname)
		return;
	if (strncmp(utsname->sysname, "Linux", sizeof(utsname->version)) != 0)
		return;
	dfi_attr_utsname_set(utsname);
	util_log_print(UTIL_LOG_INFO, "DFI utsname release %s version %s\n",
		       utsname->release, utsname->version);
}

/*
 * Try to get livedump magic
 */
static void livedump_init(void)
{
	u64 magic;

	util_log_print(UTIL_LOG_TRACE, "DFI livedump initialization\n");

	if (dfi_mem_virt_read(0, &magic, sizeof(magic)))
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

	util_log_print(UTIL_LOG_TRACE, "DFI initialization\n");

	l.arch = DFI_ARCH_UNKNOWN;
	rc = dfi_mem_chunk_init();
	if (rc)
		return rc;
	attr_init();
	dfi_cpu_info_init(DFI_CPU_CONTENT_NONE);
	while ((dfi = dfi_vec[i])) {
		util_log_print(UTIL_LOG_DEBUG, "DFI trying %s\n", dfi->name);
		l.dfi = dfi;
		g.fh = dfi_dump_open(g.opts.device);
		rc = dfi->init();
		if (rc == 0)
			dfi_mem_chunk_sort();
		if (rc == 0 && dfi_feat_seek()) {
			kdump_init();
			dfi_vmcoreinfo_init();
			if (g.opts.select == OPTS_SELECT_PROD)
				kdump_select_prod_init();
			utsname_init();
			livedump_init();
		}
		util_log_print(UTIL_LOG_DEBUG, "DFI %s returned with rc %d\n",
			       dfi->name, rc);
		if (rc == 0 || rc == -EINVAL || rc == -ENOKEY)
			return rc;
		zg_close(g.fh);
		i++;
	}
	ERR_EXIT("No valid dump found on \"%s\"", g.opts.device);
	return -1; /* UNREACHABLE */
}

/*
 * Cleanup input dump format.
 */
void dfi_exit(void)
{
	util_log_print(UTIL_LOG_TRACE, "DFI exit\n");

	if (l.dfi && l.dfi->exit)
		l.dfi->exit();
}
