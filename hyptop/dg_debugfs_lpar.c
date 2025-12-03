/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Hyptop LPAR data gatherer that operates on debugfs
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <iconv.h>
#include <string.h>
#include <unistd.h>

#include "dg_debugfs.h"
#include "helper.h"
#include "hyptop.h"
#include "sd.h"

#define MTID_MASK	0x1f
#define LPAR_NAME_LEN	8
#define TMP_SIZE	64
#define LPAR_PHYS_FLG	0x80
#define CPU_TYPE_LEN	16
#define DEBUGFS_FILE	"diag_204"

static u64 l_update_time_us;
static long l_204_buf_size;

/*
 * Diag data structure definition
 */

struct l_x_info_blk_hdr {
	u8	npar;
	u8	flags;
	u8	reserved1[6];
	u64	curtod1;
	u64	curtod2;
	u8	reserved[40];
} __attribute__ ((packed));

struct l_x_sys_hdr {
	u8	reserved1;
	u8	cpus;
	u8	rcpus;
	u8	reserved2[5];
	char	sys_name[LPAR_NAME_LEN];
	u8	reserved3[33];
	u8	mtid;
	u8	reserved4[46];
} __attribute__ ((packed));

static inline void l_sys_hdr__sys_name(struct l_x_sys_hdr *hdr, char *name)
{
	ht_ebcdic_to_ascii(hdr->sys_name, name, LPAR_NAME_LEN);
	name[LPAR_NAME_LEN] = 0;
	ht_strstrip(name);
}

struct l_x_cpu_info {
	u16	cpu_addr;
	u8	reserved1[2];
	u8	ctidx;
	u8	reserved2[3];
	u64	acc_time;
	u64	lp_time;
	u8	reserved3[6];
	u8	reserved4[2];
	u64	online_time;
	u8	reserved5[24];
	u64	mt_idle_time;
	u8	reserved6[24];
} __attribute__ ((packed));

static int l_thread_cnt(struct l_x_sys_hdr *hdr)
{
	return (hdr->mtid & MTID_MASK) + 1;
}

static void l_idx2name(int index, char *name)
{
	switch (index) {
	case 0:
		strcpy(name, SD_CPU_TYPE_STR_CP);
		break;
	case 3:
		strcpy(name, SD_CPU_TYPE_STR_IFL);
		break;
	default:
		strcpy(name, SD_CPU_TYPE_STR_UN);
	}
}

struct l_x_phys_hdr {
	u8	reserved1[1];
	u8	cpus;
	u8	reserved2[94];
} __attribute__ ((packed));

struct l_x_phys_cpu {
	u16	cpu_addr;
	u8	reserved1[2];
	u8	ctidx;
	u8	reserved2[3];
	u64	mgm_time;
	u8	reserved3[80];
} __attribute__ ((packed));

/*
 * Fill CPU with data
 */
static void l_sd_cpu_fill(struct sd_cpu *cpu, struct l_x_cpu_info *cpu_info,
			  int threads)
{
	sd_cpu_cpu_time_us_set(cpu, cpu_info->lp_time);
	sd_cpu_threads_per_core_set(cpu, threads);
	if (threads > 1)
		sd_cpu_thread_time_us_set(cpu,
			cpu_info->lp_time * threads - cpu_info->mt_idle_time);
	else
		sd_cpu_thread_time_us_set(cpu, cpu_info->lp_time);
	sd_cpu_mgm_time_us_set(cpu, G0(cpu_info->acc_time - cpu_info->lp_time));
	sd_cpu_online_time_us_set(cpu, cpu_info->online_time);
	sd_cpu_state_set(cpu, SD_CPU_STATE_UNKNOWN);
}

/*
 * Fill system with data
 */
static void *l_sd_sys_fill(struct sd_sys *lpar, struct l_x_sys_hdr *sys_hdr)
{
	struct l_x_cpu_info *cpu_info;
	int i;

	cpu_info = (struct l_x_cpu_info *) (sys_hdr + 1);

	for (i = 0; i < sys_hdr->rcpus; i++) {
		char cpu_type[CPU_TYPE_LEN + 1];
		struct sd_cpu *cpu;
		char cpu_id[10];

		sprintf(cpu_id, "%i", cpu_info->cpu_addr);

		cpu = sd_cpu_get(lpar, cpu_id);
		if (!cpu) {
			l_idx2name(cpu_info->ctidx, cpu_type);
			cpu = sd_cpu_new(lpar, cpu_id, cpu_type, 1);
		}

		l_sd_cpu_fill(cpu, cpu_info, lpar->threads_per_core);

		sd_cpu_commit(cpu);
		cpu_info++;
	}
	return cpu_info;
}

/*
 * Fill one physical CPU with data
 */
static void l_sd_cpu_phys_fill(struct sd_sys *sys,
			       struct l_x_phys_cpu *cpu_info)
{
	char cpu_type[CPU_TYPE_LEN + 1];
	char cpu_id[TMP_SIZE];
	struct sd_cpu *cpu;

	snprintf(cpu_id, TMP_SIZE, "%i", cpu_info->cpu_addr);
	cpu = sd_cpu_get(sys, cpu_id);
	if (!cpu) {
		l_idx2name(cpu_info->ctidx, cpu_type);
		cpu = sd_cpu_new(sys, cpu_id, cpu_type, 1);
		sd_cpu_state_set(cpu, SD_CPU_STATE_UNKNOWN);
	}
	sd_cpu_mgm_time_us_set(cpu, cpu_info->mgm_time);
	sd_cpu_commit(cpu);
}

/*
 * Fill all physical CPUs with data
 */
static void l_sd_sys_root_cpu_phys_fill(struct sd_sys *sys,
					struct l_x_phys_hdr *phys_hdr)
{
	struct l_x_phys_cpu *cpu_info;
	int i;

	cpu_info = (struct l_x_phys_cpu *) (phys_hdr + 1);
	for (i = 0; i < phys_hdr->cpus; i++) {
		l_sd_cpu_phys_fill(sys, cpu_info);
		cpu_info++;
	}
}

/*
 * Header for debugfs file "diag_204"
 */
struct l_debugfs_d204_hdr {
	u64	len;
	u16	version;
	u8	reserved[54];
} __attribute__ ((packed));

struct l_debugfs_d204 {
	struct l_debugfs_d204_hdr	h;
	char				buf[];
} __attribute__ ((packed));

/*
 * Read debugfs file
 */
static void l_read_debugfs(struct l_debugfs_d204_hdr **hdr,
			   struct l_x_info_blk_hdr **data)
{
	long real_buf_size;
	ssize_t rc;
	void *buf;
	int fh;

	do {
		fh = dg_debugfs_open(DEBUGFS_FILE);
		*hdr = buf = ht_alloc(l_204_buf_size);
		rc = read(fh, buf, l_204_buf_size);
		if (rc == -1)
			ERR_EXIT_ERRNO("Reading hypervisor data failed");
		close(fh);
		real_buf_size = (*hdr)->len + sizeof(struct l_debugfs_d204_hdr);
		if (rc == real_buf_size)
			break;
		l_204_buf_size = real_buf_size;
		ht_free(buf);
	} while (1);
	*data = buf + sizeof(struct l_debugfs_d204_hdr);
}

/*
 * Fill System Data
 */
static void l_sd_sys_root_fill(struct sd_sys *sys)
{
	struct l_x_info_blk_hdr *time_hdr;
	struct l_debugfs_d204_hdr *hdr;
	struct l_x_sys_hdr *sys_hdr;
	struct sd_sys *lpar;
	char lpar_id[10];
	int i;

	do {
		l_read_debugfs(&hdr, &time_hdr);
		if (l_update_time_us != ht_ext_tod_2_us(&time_hdr->curtod1)) {
			l_update_time_us = ht_ext_tod_2_us(&time_hdr->curtod1);
			break;
		}
		/*
		 * Got old snapshot from kernel. Wait some time until
		 * new snapshot is available.
		 */
		ht_free(hdr);
		usleep(DBFS_WAIT_TIME_US);
	} while (1);
	sys_hdr = ((void *) time_hdr) + sizeof(struct l_x_info_blk_hdr);
	for (i = 0; i < time_hdr->npar; i++) {
		l_sys_hdr__sys_name(sys_hdr, lpar_id);
		lpar = sd_sys_get(sys, lpar_id);
		if (!lpar)
			lpar = sd_sys_new(sys, lpar_id);
		lpar->threads_per_core = l_thread_cnt(sys_hdr);
		sys_hdr = l_sd_sys_fill(lpar, sys_hdr);
		sd_sys_commit(lpar);
	}

	if (time_hdr->flags & LPAR_PHYS_FLG)
		l_sd_sys_root_cpu_phys_fill(sys, (void *) sys_hdr);
	ht_free(hdr);
	sd_sys_commit(sys);
}

/*
 * Update system data
 */
static void l_sd_update(void)
{
	struct sd_sys *root = sd_sys_root_get();

	sd_sys_update_start(root);
	l_sd_sys_root_fill(root);
	sd_sys_update_end(root, l_update_time_us);
}

/*
 * Supported system items
 */
static struct sd_sys_item *l_sys_item_vec[] = {
	&sd_sys_item_core_cnt,
	&sd_sys_item_thread_cnt,
	&sd_sys_item_core_diff,
	&sd_sys_item_thread_diff,
	&sd_sys_item_smt_diff,
	&sd_sys_item_mgm_diff,
	&sd_sys_item_core,
	&sd_sys_item_thread,
	&sd_sys_item_mgm,
	&sd_sys_item_online,
	NULL,
};

/*
 * Default system items
 */
static struct sd_sys_item *l_sys_item_enable_vec[] = {
	&sd_sys_item_core_cnt,
	&sd_sys_item_core_diff,
	&sd_sys_item_thread_diff,
	&sd_sys_item_mgm_diff,
	&sd_sys_item_core,
	&sd_sys_item_mgm,
	&sd_sys_item_online,
	NULL,
};

/*
 * Supported CPU items
 */
static struct sd_cpu_item *l_cpu_item_vec[] = {
	&sd_cpu_item_type,
	&sd_cpu_item_core_diff,
	&sd_cpu_item_thread_diff,
	&sd_cpu_item_smt_diff,
	&sd_cpu_item_mgm_diff,
	&sd_cpu_item_core,
	&sd_cpu_item_thread,
	&sd_cpu_item_mgm,
	&sd_cpu_item_online,
	NULL,
};

/*
 * Default CPU items
 */
static struct sd_cpu_item *l_cpu_item_enable_vec[] = {
	&sd_cpu_item_type,
	&sd_cpu_item_core_diff,
	&sd_cpu_item_thread_diff,
	&sd_cpu_item_mgm_diff,
	NULL,
};

/*
 * Supported CPU types
 */
static struct sd_cpu_type *l_cpu_type_vec[] = {
	&sd_cpu_type_ifl,
	&sd_cpu_type_cp,
	&sd_cpu_type_un,
	NULL,
};

/*
 * Define data gatherer structure
 */
static struct sd_dg l_sd_dg = {
	.update_sys		= l_sd_update,
	.cpu_type_vec		= l_cpu_type_vec,
	.sys_item_vec		= l_sys_item_vec,
	.sys_item_enable_vec	= l_sys_item_enable_vec,
	.cpu_item_vec		= l_cpu_item_vec,
	.cpu_item_enable_vec	= l_cpu_item_enable_vec,
};

/*
 * Initialize LPAR debugfs data gatherer
 */
int dg_debugfs_lpar_init(void)
{
	int fh;

	l_204_buf_size = sizeof(struct l_debugfs_d204_hdr);
	fh = dg_debugfs_open(DEBUGFS_FILE);
	if (fh < 0)
		return fh;
	else
		close(fh);
	sd_dg_register(&l_sd_dg, 1, 1);
	return 0;
}
