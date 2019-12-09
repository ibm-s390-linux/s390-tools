/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Common functions for stand-alone dump tools
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdarg.h>

#include "lib/zt_common.h"

#include "libc.h"
#include "error.h"
#include "sclp.h"
#include "stage2dump.h"

#define CPU_ADDRESS_MAX	1000
#define MACHINE_HAS_VX	machine_has_vx

/*
 * Static globals
 */
static uint8_t machine_has_vx;

/*
 * IPL info in lowcore
 */
struct ipib_info {
	unsigned long	ipib;
	uint32_t	ipib_csum;
};

/*
 * Tail parameters
 */
struct stage2dump_parm_tail parm_tail = {
	.mem_upper_limit = 0xffffffffffffffffULL,
};

/*
 * Globals
 */
struct df_s390_hdr *dump_hdr;
unsigned long total_dump_size;

/*
 * Init dumper: Allocate standard pages, set timers
 */
static void init_early(void)
{
	/* Allocate dump header */
	dump_hdr = (void *) get_zeroed_page();

	/* Set clock comparator and CPU timer to future */
	set_clock_comparator(0xffffffffffffffffULL);
	set_cpu_timer(0x7fffffffffffffffULL);
	if (test_facility(129))
		machine_has_vx = 1;
}

/*
 * Print progress message
 */
void progress_print(unsigned long addr)
{
	/* Print a message approximately every 5 sec */
	static unsigned long delta = 5 * (1UL << 32);
	static unsigned long next;
	unsigned long time = get_tod_clock();

	if (next == 0) {
		next = time + delta;
		return;
	}
	if (time < next && addr != dump_hdr->mem_size)
		return;

	printf("%08lu / %08lu MB (Dump file size %08lu MB)", addr >> 20,
	       dump_hdr->mem_size >> 20, total_dump_size >> 20);
	next = time + delta;
}

/*
 * Check if one MB memory after addr is zero
 */
static int __is_zero_mb(unsigned long addr)
{
	register unsigned long _addr1 asm("2") = (unsigned long) addr;
	register unsigned long _len1  asm("3") = (unsigned long) MIB;
	register unsigned long _addr2 asm("4") = (unsigned long) addr;
	register unsigned long _len2  asm("5") = (unsigned long) 0;
	unsigned int ipm;

	asm volatile(
		"0:     clcle   %1,%3,0(0)\n"
		"       jo      0b\n"
		"       ipm     %0\n"
		"       srl     %0,28\n"
		: "=d" (ipm), "+d" (_addr1), "+d" (_len1), "+d" (_addr2), "+d" (_len2)
		:
		: "cc");
	return !ipm;
}

/*
 * Check if the megabyte contains all zeroes.
 */
int is_zero_mb(unsigned long addr)
{
	if (!page_is_valid(addr))
		return 1;
	if (__is_zero_mb(addr))
		return 1;
	return 0;
}

/*
 * Find next non-zero megabyte in the address range
 */
static unsigned long find_next_non_zero(unsigned long start, unsigned long end)
{
	while (start < end) {
		if (!is_zero_mb(start))
			break;
		start += MIB;
	}
	if (start > end)
		start = end;
	return start;
}

/*
 * Find next zero megabyte in the address range
 */
static unsigned long find_next_zero(unsigned long start, unsigned long end)
{
	while (start < end) {
		if (is_zero_mb(start))
			break;
		start += MIB;
	}
	if (start > end)
		start = end;
	return start;
}

/*
 * Find first continuous set of non-zero megabytes in the specified
 * address range and update *dump_segm structure accordingly. The segment's
 * length is truncated to max_len if required. Afterwards, look for the next
 * non-zero megabyte. Return the address of the next non-zero megabyte or zero
 * if no more follow.
 */
unsigned long find_dump_segment(unsigned long start, unsigned long end,
				unsigned long max_len,
				struct df_s390_dump_segm_hdr *dump_segm)
{
	unsigned long addr, limit;

	memset(dump_segm, 0, sizeof(*dump_segm));
	/* Check the input values for MB alingment */
	if (!IS_ALIGNED(start, MIB) || !IS_ALIGNED(max_len, MIB))
		panic(EINTERNAL, "start or max_len not MB aligned");
	/* Search for dump segment start */
	addr = find_next_non_zero(start, end);
	if (addr == end)
		goto out;
	dump_segm->start = addr;
	/* Search for dump segment end */
	limit = end;
	if (max_len)
		limit = MIN(addr + max_len, end);
	addr = find_next_zero(dump_segm->start, limit);
	dump_segm->len = addr - dump_segm->start;
	/* Search for next dump segment start */
	addr = find_next_non_zero(addr, end);
	/* Return the start address of the next segment */
	if (addr < end)
		return addr;
out:
	/*
	 * Set the stop-marker indicating no more non-zero
	 * segments in the address range
	 */
	dump_segm->stop_marker = -1UL;
	return 0;
}

/*
 * Create IDA list starting at "addr" with "len" bytes
 */
void create_ida_list(unsigned long *list, int len, unsigned long addr,
		     unsigned long zero_page)
{
	unsigned long ida_addr;

	while (len > 0) {
		if (zero_page)
			ida_addr = page_is_valid(addr) ? addr : zero_page;
		else
			ida_addr = addr;
		*list = ida_addr;
		list++;
		addr += PAGE_SIZE;
		len -= PAGE_SIZE;
	}
}

/*
 * Initialize s390 dump header
 */
static void df_s390_dump_init(void)
{
	struct df_s390_hdr *dh = dump_hdr;

	dh->magic = DF_S390_MAGIC_EXT;
	dh->hdr_size = DF_S390_HDR_SIZE;
	dh->page_size = PAGE_SIZE;
	dh->dump_level = 4;
	dh->version = 1;
	dh->mem_start = 0;
	dh->arch = DF_S390_ARCH_64;
	dh->build_arch = DF_S390_ARCH_64;
	get_cpu_id((struct cpuid *) &dh->cpu_id);
	dh->tod = get_tod_clock();
	dh->volnr = 0;
}

/*
 * Initialize page with end marker
 */
void df_s390_em_page_init(unsigned long addr)
{
	struct df_s390_em *em = (void *) addr;

	em->magic = DF_S390_EM_MAGIC;
	em->tod = get_tod_clock();
}

/*
 * Find out memory size
 */
static void mem_and_cpu_init(void)
{
	unsigned long mem_size_max, mem_size, addr, rnmax, rzm;
	struct read_info_sccb *sccb;
	unsigned int mtid_prev;

	sccb = (void *) get_zeroed_page();
	/* Get memory max */
	if (sclp_read_info(sccb))
		panic(EMEMCOUNT, "Could not evaluate memory layout");
	rnmax = sccb->rnmax ? sccb->rnmax : sccb->rnmax2;
	rzm = sccb->rnsize ? sccb->rnsize : sccb->rnsize2;
	rzm <<= 20;
	mem_size_max = rnmax * rzm;
	mem_size = 0;
	/* Find out real memory end without standby memory */
	for (addr = 0; addr < mem_size_max; addr += rzm) {
		if (!page_is_valid(addr))
			continue;
		mem_size = addr + rzm;
	}
	/* Restore maximum thread ID of previous system */
	mtid_prev = (sccb->fac42 & 0x80) ? (sccb->fac66 & 31) : 0;
	sigp(0, SIGP_SET_MULTI_THREADING, mtid_prev, NULL);

	free_page((unsigned long) sccb);

	dump_hdr->mem_size_real = mem_size;
	/* Check if we have an upper limit */
	if (mem_size > parm_tail.mem_upper_limit) {
		printf("Using memory limit");
		mem_size = parm_tail.mem_upper_limit;
	}
	dump_hdr->mem_size = dump_hdr->mem_end = mem_size;
	dump_hdr->num_pages = dump_hdr->mem_size >> 12;
}

/*
 * Copy 64 bit lowcore after store status
 */
static void copy_lowcore_64(void)
{
	char *real_cpu_cnt_ptr = ((char *) &dump_hdr->mem_size_real) + 11;
	char *cpu_cnt_ptr = ((char *) &dump_hdr->mem_size_real) + 9;
	unsigned long prefix;
	uint16_t cpu_cnt = 0;

	prefix = S390_lowcore.prefixreg_save_area;

	/* Need memcpy because of aligment problem of members */
	memcpy(&cpu_cnt, real_cpu_cnt_ptr, sizeof(cpu_cnt));
	cpu_cnt++;
	memcpy(real_cpu_cnt_ptr, &cpu_cnt, sizeof(cpu_cnt));

	if (prefix < 0x10000) /* if < linux-start addr */
		return;
	if (prefix % 0x1000) /* check page alignment */
		return;

	/* Save lowcore pointer (32 bit) in dump header */
	memcpy(&cpu_cnt, cpu_cnt_ptr, sizeof(cpu_cnt));
	dump_hdr->lc_vec[cpu_cnt] = prefix;
	cpu_cnt++;
	memcpy(cpu_cnt_ptr, &cpu_cnt, sizeof(cpu_cnt));
	/*
	 *  |-----------------------------------------------------------|
	 *  | Decimal |  Length   | Data                                |
	 *  | Address |  in Bytes |                                     |
	 *  |_________|___________|_____________________________________|
	 *  | 163     | 1         | Architectural Mode ID               |
	 *  | 4608    | 128       | Fl-pt registers 0-15                |
	 *  | 4736    | 128       | General registers 0-15              |
	 *  | 4864    | 16        | Current PSW                         |
	 *  | 4888    | 4         | Prefix register                     |
	 *  | 4892    | 4         | Fl-pt control register              |
	 *  | 4900    | 4         | TOD programmable register           |
	 *  | 4904    | 8         | CPU timer                           |
	 *  | 4912    | 1         | Zeros                               |
	 *  | 4913    | 7         | Bits 0-55 of clock comparator       |
	 *  | 4928    | 64        | Access registers 0-15               |
	 *  | 4992    | 128       | Control registers 0-15              |
	 *  |_________|___________|_____________________________________|
	 */
	memcpy((void *) prefix + 4608, (void *) 4608, 272);
	memcpy((void *) prefix + 4888, (void *) 4888, 8);
	memcpy((void *) prefix + 4900, (void *) 4900, 20);
	memcpy((void *) prefix + 4928, (void *) 4928, 192);
}

/*
 * Has machine VX and has kernel prepared save area?
 */
static int should_dump_vx(struct _lowcore *lc)
{
	unsigned long vx_sa;

	if (!MACHINE_HAS_VX)
		return 0;
	vx_sa = lc->vector_save_area_addr;
	if (vx_sa == 0 || (vx_sa % 1024) != 0)
		return 0;
	if (!page_is_valid(vx_sa))
		return 0;
	return 1;
}

/*
 * Do store status
 */
static void store_status(void)
{
	unsigned short current_cpu;
	struct _lowcore *lc;
	unsigned long page;
	int addr, cc;

	/* Save absolute zero lowcore */
	page = get_zeroed_page();
	memcpy((void *) page, (void *) 0x1000, PAGE_SIZE);

	current_cpu = stap();

	lc = (void *)(unsigned long) S390_lowcore.prefixreg_save_area;
	if (should_dump_vx(lc))
		save_vx_regs_safe((__vector128 *) lc->vector_save_area_addr);
	copy_lowcore_64();
	for (addr = 0; addr < CPU_ADDRESS_MAX; addr++) {
		if (addr == current_cpu)
			continue;
		cc = sigp_busy(addr, SIGP_STOP_AND_STORE_STATUS, 0, NULL);
		if (cc != SIGP_CC_ORDER_CODE_ACCEPTED)
			continue;
		lc = (void *)(unsigned long) S390_lowcore.prefixreg_save_area;
		copy_lowcore_64();
		if (!should_dump_vx(lc))
			continue;
		sigp_busy(addr, SIGP_STORE_ASTATUS_AT_ADDRESS,
			  lc->vector_save_area_addr, NULL);
	}
	/* Restore absolute zero lowcore */
	memcpy((void *) 0x1000, (void *) page, PAGE_SIZE);
	free_page(page);
}

/*
 * Perform reipl: check lowcore for the address of an IPL Information
 * Block followed by a valid checksum (as defined in lowcore.h and set
 * by ipl.c). In case of match use diag308 to IPL.
 */
static void dump_exit(unsigned long code)
{
	struct ipib_info *ipib_info = (struct ipib_info *)&S390_lowcore.ipib;
	uint32_t ipib_len, csum;

	if (!ipib_info->ipib)
		libc_stop(code);
	ipib_len = *((uint32_t *) ipib_info->ipib);
	csum = csum_partial((void *) ipib_info->ipib, ipib_len, 0);
	if (ipib_info->ipib_csum != csum)
		libc_stop(code);
	diag308(DIAG308_SET, (void *) ipib_info->ipib);
	diag308(DIAG308_IPL, NULL);
}

/*
 * Print message and exit dumper
 */
void panic_notify(unsigned long code)
{
	printf("Dump failed");
	dump_exit(code);
}

/*
 * Create stand-alone dump
 */
void start(void)
{
	init_early();
	dt_device_parm_setup();
	sclp_setup(SCLP_INIT);
	dt_device_enable();
	df_s390_dump_init();
	printf("zIPL v%s dump tool (64 bit)", RELEASE_STRING);
	printf("Dumping 64 bit OS");
	mem_and_cpu_init();
	store_status();
	dt_dump_mem();
	printf("Dump successful");
	dump_exit(0);
}
