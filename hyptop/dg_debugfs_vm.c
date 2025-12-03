/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Hyptop z/VM data gatherer that operates on debugfs
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "dg_debugfs.h"
#include "helper.h"
#include "hyptop.h"
#include "sd.h"

#define VM_CPU_TYPE	"UN"
#define VM_CPU_ID	"ALL"
#define NAME_LEN	8
#define DEBUGFS_FILE	"diag_2fc"
#define VM_CPU_ID_OPERATING	"0"
#define VM_CPU_ID_STOPPED	"1"

static u64 l_update_time_us;
static long l_2fc_buf_size;
static int l_use_debugfs_vmd0c;
static char l_guest_name[64];

/*
 * Diag 2fc data structure definition
 */
struct l_diag2fc_data {
	u32	version;
	u32	flags;
	u64	used_cpu;
	u64	el_time;
	u64	mem_min_kb;
	u64	mem_max_kb;
	u64	mem_share_kb;
	u64	mem_used_kb;
	u32	pcpus;
	u32	lcpus;
	u32	vcpus;
	u32	ocpus;
	u32	cpu_max;
	u32	cpu_shares;
	u32	cpu_use_samp;
	u32	cpu_delay_samp;
	u32	page_wait_samp;
	u32	idle_samp;
	u32	other_samp;
	u32	total_samp;
	char	guest_name[NAME_LEN];
};

/*
 * Header for debugfs file "diag_2fc"
 */
struct l_debugfs_d2fc_hdr {
	u64	len;
	u16	version;
	char	tod_ext[16];
	u64	count;
	char	reserved[30];
} __attribute__ ((packed));

struct l_debugfs_d2fc {
	struct l_debugfs_d2fc_hdr	h;
	char			diag2fc_buf[];
} __attribute__ ((packed));

 /*
 * Get local guest name
 */
static void l_guest_name_init(void)
{
	int level, found = 0;
	char line[1024];
	FILE *fh;

	fh = fopen("/proc/sysinfo", "r");
	if (!fh)
		ERR_EXIT_ERRNO("Could not open '/proc/sysinfo'");
	while (fgets(line, sizeof(line), fh)) {
		if (sscanf(line, "VM%02d Name: %s", &level, l_guest_name) == 2)
			found = 1;
	}
	if (!found)
		ERR_EXIT("Could find guest name in '/proc/sysinfo'");
	fclose(fh);
}

/*
 * Get existing or create new CPU
 */
static struct sd_cpu *l_cpu_alloc(struct sd_sys *guest, const char *id, int cnt)
{
	struct sd_cpu *cpu = sd_cpu_get(guest, id);

	return cpu ? cpu : sd_cpu_new(guest, id, SD_CPU_TYPE_STR_UN, cnt);
}

/*
 * Get number of operating CPUs
 */
static int l_ocpus(struct l_diag2fc_data *data)
{
	/*
	 * For guests with ABSOLUTE or limit SHARE, ocpus and cpu_max is zero.
	 * In this case we return vcpus.
	 */
	return (data->cpu_max == 0) ? data->vcpus : data->ocpus;
}

/*
 * Fill operating CPUs with data
 */
static void l_cpu_oper_fill(struct sd_sys *guest, struct l_diag2fc_data *data)
{
	struct sd_cpu *cpu;

	cpu = l_cpu_alloc(guest, VM_CPU_ID_OPERATING, l_ocpus(data));
	sd_cpu_state_set(cpu, SD_CPU_STATE_OPERATING);
	sd_cpu_cpu_time_us_set(cpu, data->used_cpu);
	sd_cpu_online_time_us_set(cpu, data->el_time);
	sd_cpu_cnt(cpu) = l_ocpus(data);
	sd_cpu_commit(cpu);
}

/*
 * Fill stopped CPUs with data
 */
static void l_cpu_stop_fill(struct sd_sys *guest, struct l_diag2fc_data *data)
{
	int cnt = data->vcpus - l_ocpus(data);
	struct sd_cpu *cpu;

	cpu = l_cpu_alloc(guest, VM_CPU_ID_STOPPED, cnt);
	sd_cpu_state_set(cpu, SD_CPU_STATE_STOPPED);
	sd_cpu_cpu_time_us_set(cpu, 0);
	sd_cpu_online_time_us_set(cpu, 0);
	sd_cpu_cnt(cpu) = cnt;
	sd_cpu_commit(cpu);
}

/*
 * Fill CPUs will data
 */
static void l_cpu_fill(struct sd_sys *guest, struct l_diag2fc_data *data)
{
	if (l_ocpus(data) > 0)
		l_cpu_oper_fill(guest, data);
	if (data->vcpus - l_ocpus(data) > 0)
		l_cpu_stop_fill(guest, data);
}

/*
 * Fill "guest" with data
 */
static void l_sd_sys_fill(struct sd_sys *guest, struct l_diag2fc_data *data)
{
	if (l_use_debugfs_vmd0c && (strcmp(guest->id, l_guest_name) == 0))
		dg_debugfs_vmd0c_sys_cpu_fill(guest, data->el_time,
					      data->vcpus);
	else
		l_cpu_fill(guest, data);

	sd_sys_weight_cur_set(guest, data->cpu_shares);
	sd_sys_weight_max_set(guest, data->cpu_max);

	sd_sys_mem_min_kib_set(guest, data->mem_min_kb);
	sd_sys_mem_max_kib_set(guest, data->mem_max_kb);
	sd_sys_mem_use_kib_set(guest, data->mem_used_kb);

	sd_sys_update_time_us_set(guest, l_update_time_us);
	sd_sys_commit(guest);
}

/*
 * Read debugfs file
 */
static void l_read_debugfs(struct l_debugfs_d2fc_hdr **hdr,
			   struct l_diag2fc_data **data)
{
	long real_buf_size;
	ssize_t rc;
	void *buf;
	int fh;

	do {
		fh = dg_debugfs_open(DEBUGFS_FILE);
		*hdr = buf = ht_alloc(l_2fc_buf_size);
		rc = read(fh, buf, l_2fc_buf_size);
		if (rc == -1)
			ERR_EXIT_ERRNO("Reading hypervisor data failed");
		close(fh);
		real_buf_size = (*hdr)->len + sizeof(struct l_debugfs_d2fc_hdr);
		if (rc == real_buf_size)
			break;
		l_2fc_buf_size = real_buf_size;
		ht_free(buf);
	} while (1);
	*data = buf + sizeof(struct l_debugfs_d2fc_hdr);
}

/*
 * Fill System Data
 */
static void l_sd_sys_root_fill(struct sd_sys *sys)
{
	struct l_diag2fc_data *d2fc_data;
	struct l_debugfs_d2fc_hdr *hdr;
	struct sd_cpu *cpu;
	unsigned int i;

	do {
		l_read_debugfs(&hdr, &d2fc_data);
		if (l_update_time_us != ht_ext_tod_2_us(&hdr->tod_ext)) {
			l_update_time_us = ht_ext_tod_2_us(&hdr->tod_ext);
			break;
		}
		/*
		 * Got old snapshot from kernel. Wait some time until
		 * new snapshot is available.
		 */
		ht_free(hdr);
		usleep(DBFS_WAIT_TIME_US);
	} while (1);

	cpu = sd_cpu_get(sys, VM_CPU_ID);
	if (!cpu)
		cpu = sd_cpu_new(sys, VM_CPU_ID, SD_CPU_TYPE_STR_UN,
				 d2fc_data[0].lcpus);
	sd_cpu_state_set(cpu, SD_CPU_STATE_UNKNOWN);
	sd_cpu_cnt(cpu) = d2fc_data[0].lcpus;
	sd_cpu_commit(cpu);

	for (i = 0; i < hdr->count; i++) {
		struct l_diag2fc_data *data = &d2fc_data[i];
		char guest_name[NAME_LEN + 1];
		struct sd_sys *guest;

		guest_name[NAME_LEN] = 0;
		ht_ebcdic_to_ascii(data->guest_name, guest_name, NAME_LEN);
		ht_strstrip(guest_name);

		guest = sd_sys_get(sys, guest_name);
		if (!guest)
			guest = sd_sys_new(sys, guest_name);
		l_sd_sys_fill(guest, data);
	}
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
	&sd_sys_item_cpu_cnt,
	&sd_sys_item_cpu_oper_cnt,
	&sd_sys_item_cpu_diff,
	&sd_sys_item_mgm_diff,
	&sd_sys_item_cpu,
	&sd_sys_item_mgm,
	&sd_sys_item_online,
	&sd_sys_item_mem_use,
	&sd_sys_item_mem_max,
	&sd_sys_item_weight_cur,
	&sd_sys_item_weight_max,
	NULL,
};

/*
 * Default system items
 */
static struct sd_sys_item *l_sys_item_enable_vec[] = {
	&sd_sys_item_cpu_cnt,
	&sd_sys_item_cpu_diff,
	&sd_sys_item_cpu,
	&sd_sys_item_online,
	&sd_sys_item_mem_max,
	&sd_sys_item_mem_use,
	&sd_sys_item_weight_cur,
	NULL,
};

/*
 * Supported CPU items
 */
static struct sd_cpu_item *l_cpu_item_vec[] = {
	&sd_cpu_item_cpu_diff,
	&sd_cpu_item_mgm_diff,
	&sd_cpu_item_cpu,
	&sd_cpu_item_mgm,
	&sd_cpu_item_online,
	NULL,
};

/*
 * Default CPU items
 */
static struct sd_cpu_item *l_cpu_item_enable_vec[] = {
	&sd_cpu_item_cpu_diff,
	NULL,
};

/*
 * Supported CPU types
 */
static struct sd_cpu_type *l_cpu_type_vec[] = {
	&sd_cpu_type_un,
	NULL,
};

/*
 * Define data gatherer structure
 */
static struct sd_dg dg_debugfs_vm_dg = {
	.update_sys		= l_sd_update,
	.cpu_type_vec		= l_cpu_type_vec,
	.sys_item_vec		= l_sys_item_vec,
	.sys_item_enable_vec	= l_sys_item_enable_vec,
	.cpu_item_vec		= l_cpu_item_vec,
	.cpu_item_enable_vec	= l_cpu_item_enable_vec,
};

/*
 * Initialize z/VM debugfs data gatherer
 */
int dg_debugfs_vm_init(void)
{
	int fh;

	fh = dg_debugfs_vmd0c_init();
	if (fh == 0)
		l_use_debugfs_vmd0c = 1;
	fh = dg_debugfs_open(DEBUGFS_FILE);
	if (fh < 0)
		return fh;
	else
		close(fh);
	l_2fc_buf_size = sizeof(struct l_debugfs_d2fc_hdr);
	l_guest_name_init();
	sd_dg_register(&dg_debugfs_vm_dg, 0, 0);
	return 0;
}
