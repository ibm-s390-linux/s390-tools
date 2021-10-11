/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 dump output format
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "zgetdump.h"

/*
 * File local static data
 */
static struct {
	struct df_s390_hdr	hdr;
	struct df_s390_em	em;
} l;

/*
 * Copy internal register set to 64 bit lowcore
 */
static void cpu2lc_64(void *lc_64, struct dfi_cpu *cpu)
{
	struct dfi_lowcore_64 *lc = lc_64;
	memcpy(lc->gpregs_save_area, &cpu->gprs, sizeof(cpu->gprs));
	memcpy(lc->cregs_save_area, &cpu->ctrs, sizeof(cpu->ctrs));
	memcpy(lc->access_regs_save_area, &cpu->acrs, sizeof(cpu->acrs));
	memcpy(lc->floating_pt_save_area, &cpu->fprs, sizeof(cpu->fprs));
	memcpy(&lc->fpt_creg_save_area, &cpu->fpc, sizeof(cpu->fpc));
	memcpy(lc->st_status_fixed_logout, &cpu->psw, sizeof(cpu->psw));
	memcpy(&lc->prefixreg_save_area, &cpu->prefix, sizeof(cpu->prefix));
	memcpy(lc->timer_save_area, &cpu->timer, sizeof(cpu->timer));
	memcpy(lc->clock_comp_save_area, &cpu->todcmp, sizeof(cpu->todcmp));
}

/*
 * Copy internal register set to 32 bit lowcore
 */
static void cpu2lc_32(void *lc_32, struct dfi_cpu *cpu_64)
{
	struct dfi_lowcore_32 *lc = lc_32;
	struct dfi_cpu_32 cpu;

	dfi_cpu_64_to_32(&cpu, cpu_64);
	memcpy(lc->gpregs_save_area, &cpu.gprs, sizeof(cpu.gprs));
	memcpy(lc->cregs_save_area, &cpu.ctrs, sizeof(cpu.ctrs));
	memcpy(lc->access_regs_save_area, &cpu.acrs, sizeof(cpu.acrs));
	memcpy(lc->floating_pt_save_area, &cpu.fprs, sizeof(cpu.fprs));
	memcpy(lc->st_status_fixed_logout, &cpu.psw, sizeof(cpu.psw));
	memcpy(&lc->prefixreg_save_area, &cpu.prefix, sizeof(cpu.prefix));
	memcpy(lc->timer_save_area, &cpu.timer, sizeof(cpu.timer));
	memcpy(lc->clock_comp_save_area, &cpu.todcmp, sizeof(cpu.todcmp));
}

/*
 * Convert timeval to s390 TOD clock
 */
static void timeval2tod(u64 *tod, struct timeval *xtime)
{
	u64 us = xtime->tv_sec * 1000000 + xtime->tv_usec;
	*tod = (us << 12);
	*tod += 0x8126d60e46000000LL - (0x3c26700LL * 1000000 * 4096);
}

/*
 * Setup lowcore array in dump header
 */
static void lc_setup(struct df_s390_hdr *dh)
{
	struct dfi_cpu *cpu;
	unsigned int i = 0;

	dfi_cpu_iterate(cpu) {
		if (i >= DF_S390_CPU_MAX)
			ERR_EXIT("Too many CPUs in source dump (%i)", i);
		dh->lc_vec[i] = cpu->prefix;
		i++;
	}
}

/*
 * Copy register set to prefix page
 */
static void dfo_s390_dump_chunk_lc_fn(struct dfo_chunk *dump_chunk,
				      u64 off, void *buf, u64 cnt)
{
	struct dfi_cpu *cpu = dump_chunk->data;
	char lc[0x2000];

	if (dfi_mem_read_rc(cpu->prefix + off, &lc[off], cnt))
		return;
	if (dfi_arch() == DFI_ARCH_64)
		cpu2lc_64(lc, cpu);
	else
		cpu2lc_32(lc, cpu);
	memcpy(buf, &lc[off], cnt);
}

/*
 * Copy register set to prefix page
 */
static void dfo_s390_dump_chunk_vx_fn(struct dfo_chunk *dump_chunk,
				      u64 off, void *buf, u64 cnt)
{
	char *vx_regs = dump_chunk->data;

	memcpy(buf, &vx_regs[off], cnt);
}

/*
 * Add register set to dump layout. We copy the register sets to the
 * lowcore pages.
 */
static void add_cpu_to_dfo(struct dfi_cpu *cpu)
{
	struct dfi_lowcore_64 lc;
	void *vx_regs;

	if (dfi_cpu_content() != DFI_CPU_CONTENT_ALL)
		return;
	if (!dfi_mem_range_valid(cpu->prefix, dfi_lc_size(dfi_arch()))) {
		STDERR("Info: Could not read CPU prefix page: %x\n",
		       cpu->prefix);
		return;
	}
	/* Add lowcore to memory */
	dfo_chunk_add(cpu->prefix + DF_S390_HDR_SIZE,
		      dfi_lc_size(dfi_arch()), cpu,
		      dfo_s390_dump_chunk_lc_fn);
	/* Add VX save area to memory */
	if (dfi_arch() != DFI_ARCH_64)
		return;
	if (!dfi_cpu_content_fac_check(DFI_CPU_CONTENT_FAC_VX))
		return;
	if (dfi_mem_read_rc(cpu->prefix, &lc, sizeof(lc)))
		return;
	if (!dfi_cpu_lc_has_vx_sa(&lc))
		return;
	vx_regs = zg_alloc(DFI_VX_SA_SIZE);
	dfi_cpu_vx_copy(vx_regs, cpu);
	dfo_chunk_add(lc.vector_save_area_addr + DF_S390_HDR_SIZE,
		      DFI_VX_SA_SIZE, vx_regs, dfo_s390_dump_chunk_vx_fn);
}

/*
 * Add memory chunk to dump layout
 */
static void add_mem_chunk_to_dfo(struct dfi_mem_chunk *mem_chunk)
{
	struct dfi_mem_chunk *mem_chunk_prev = dfi_mem_chunk_prev(mem_chunk);

	if (mem_chunk_prev && (mem_chunk_prev->end + 1 != mem_chunk->start))
		dfo_chunk_add(mem_chunk_prev->end + 1 + DF_S390_HDR_SIZE,
			      mem_chunk->start - mem_chunk_prev->end - 1,
			      NULL, dfo_chunk_zero_fn);

	dfo_chunk_add(mem_chunk->start + DF_S390_HDR_SIZE, mem_chunk->size,
		      mem_chunk, dfo_chunk_mem_fn);
}

/*
 * Setup dump chunks
 */
static void dump_chunks_init(void)
{
	struct dfi_mem_chunk *mem_chunk;
	struct dfi_cpu *cpu;

	dfo_chunk_add(0, DF_S390_HDR_SIZE, &l.hdr, dfo_chunk_buf_fn);
	dfi_mem_chunk_iterate(mem_chunk)
		add_mem_chunk_to_dfo(mem_chunk);
	dfi_cpu_iterate(cpu)
		add_cpu_to_dfo(cpu);
	dfo_chunk_add(dfi_mem_range() + DF_S390_HDR_SIZE,
			   DF_S390_EM_SIZE,
			   &l.em, dfo_chunk_buf_fn);
}

/*
 * Initialize s390 output dump format
 */
static void df_s390_dump_init(void)
{
	struct df_s390_hdr *dh = &l.hdr;
	struct df_s390_em *em = &l.em;

	dh->magic = DF_S390_MAGIC;
	dh->hdr_size = DF_S390_HDR_SIZE;
	dh->page_size = PAGE_SIZE;
	dh->dump_level = 4;
	if (dfi_cpu_content() == DFI_CPU_CONTENT_NONE)
		dh->version = 4;
	else
		dh->version = 5;
	dh->mem_start = 0;
	dh->mem_size = dh->mem_end = dfi_mem_range();
	dh->num_pages = dh->mem_size / PAGE_SIZE;
	dh->arch = df_s390_from_dfi_arch(dfi_arch());
	if (dfi_attr_build_arch())
		dh->build_arch = df_s390_from_dfi_arch(*dfi_attr_build_arch());
	dh->cpu_cnt = dfi_cpu_cnt();
	if (dfi_attr_real_cpu_cnt())
		dh->real_cpu_cnt = *dfi_attr_real_cpu_cnt();
	if (dfi_attr_cpu_id())
		dh->cpu_id = *dfi_attr_cpu_id();
	if (dfi_attr_mem_size_real())
		dh->mem_size_real = *dfi_attr_mem_size_real();
	if (dfi_attr_time()) {
		timeval2tod(&dh->tod, dfi_attr_time());
		timeval2tod(&em->tod, dfi_attr_time());
	}
	if (dfi_attr_time_end())
		timeval2tod(&em->tod, dfi_attr_time_end());
	lc_setup(dh);
	memcpy(em->str, DF_S390_EM_STR, sizeof(em->str));
	dump_chunks_init();
}

/*
 * S390 DFO operations
 */
struct dfo dfo_s390 = {
	.name		= "s390",
	.init		= df_s390_dump_init,
};
