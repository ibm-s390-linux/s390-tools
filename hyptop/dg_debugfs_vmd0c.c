/*
 * hyptop - Show hypervisor performance data on System z
 *
 * Hyptop z/VM data gatherer for diag 0c that operates on debugfs
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <linux/types.h>
#include <stdlib.h>
#include <unistd.h>

#include "dg_debugfs.h"
#include "helper.h"
#include "hyptop.h"
#include "sd.h"

#define DEBUGFS_FILE	"diag_0c"

static long l_0c_buf_size;

/*
 * Diag 0c entry structure definition
 */
struct hypfs_diag0c_entry {
	char	date[8];	/* MM/DD/YY in EBCDIC */
	char	time[8];	/* HH:MM:SS in EBCDIC */
	__u64	virtcpu;	/* Virtual time consumed by the virt CPU (us) */
	__u64	totalproc;	/* Total of virtual and simulation time (us) */
	__u32	cpu;		/* Linux logical CPU number */
	__u32	reserved;	/* Align to 8 byte */
};

/*
 * Header for debugfs file "diag_0c"
 */
struct hypfs_diag0c_hdr {
	__u64	len;		/* Length of diag0c buffer without header */
	__u16	version;	/* Version of header */
	char	reserved1[6];	/* Reserved */
	char	tod_ext[16];	/* TOD clock for diag0c */
	__u64	count;		/* Number of entries (CPUs) in diag0c array */
	char	reserved2[24];	/* Reserved */
};

struct hypfs_diag0c_data {
	struct hypfs_diag0c_hdr		hdr;		/* 64 byte header */
	struct hypfs_diag0c_entry	entry[];	/* diag0c entry array */
};

/*
 * Fill one CPU with data
 */
static void l_sd_cpu_fill(struct sd_sys *sys, unsigned int cpu_nr,
			  u64 online_time, u64 cpu_time,
			  u64 mgm_time, enum sd_cpu_state state)
{
	struct sd_cpu *cpu;
	char cpu_id[16];

	sprintf(cpu_id, "%d", cpu_nr);
	cpu = sd_cpu_get(sys, cpu_id);
	if (!cpu)
		cpu = sd_cpu_new(sys, cpu_id, SD_CPU_TYPE_STR_UN, 1);
	sd_cpu_cpu_time_us_set(cpu, cpu_time);
	sd_cpu_mgm_time_us_set(cpu, mgm_time);
	sd_cpu_online_time_us_set(cpu, online_time);
	sd_cpu_state_set(cpu, state);
	sd_cpu_cnt(cpu) = 1;
	sd_cpu_commit(cpu);
}

/*
 * Read debugfs file
 */
static void l_read_debugfs(struct hypfs_diag0c_hdr **hdr,
			   struct hypfs_diag0c_entry **entry)
{
	long real_buf_size;
	ssize_t rc;
	void *buf;
	int fh;

	do {
		fh = dg_debugfs_open(DEBUGFS_FILE);
		if (fh < 0)
			ERR_EXIT_ERRNO("Could not open file: %s", DEBUGFS_FILE);
		*hdr = buf = ht_alloc(l_0c_buf_size);
		rc = read(fh, buf, l_0c_buf_size);
		if (rc == -1)
			ERR_EXIT_ERRNO("Reading hypervisor data failed");
		close(fh);
		real_buf_size = (*hdr)->len + sizeof(struct hypfs_diag0c_hdr);
		if (rc == real_buf_size)
			break;
		l_0c_buf_size = real_buf_size;
		ht_free(buf);
	} while (1);
	*entry = buf + sizeof(struct hypfs_diag0c_hdr);
}

/*
 * Fill System Data
 */
void dg_debugfs_vmd0c_sys_cpu_fill(struct sd_sys *sys, u64 online_time,
				   unsigned int cpu_cnt)
{
	unsigned int i, cpu_online_vec[cpu_cnt];
	struct hypfs_diag0c_entry *d0c_entry;
	struct hypfs_diag0c_hdr *hdr;
	u64 mgm_time;

	memset(cpu_online_vec, 0, sizeof(cpu_online_vec));
	l_read_debugfs(&hdr, &d0c_entry);

	/* First fill online CPUs */
	for (i = 0; i < hdr->count; i++) {
		mgm_time = G0(d0c_entry[i].totalproc - d0c_entry[i].virtcpu);
		l_sd_cpu_fill(sys, d0c_entry[i].cpu, online_time,
			      d0c_entry[i].virtcpu, mgm_time,
			      SD_CPU_STATE_OPERATING);
		cpu_online_vec[d0c_entry[i].cpu] = 1;
	}
	/* Then fill offline CPUs */
	for (i = 0; i < cpu_cnt; i++) {
		if (cpu_online_vec[i])
			continue;
		l_sd_cpu_fill(sys, i, 0, 0, 0, SD_CPU_STATE_STOPPED);
	}
}

/*
 * Initialize z/VM debugfs data gatherer
 */
int dg_debugfs_vmd0c_init(void)
{
	int fh;

	fh = dg_debugfs_open(DEBUGFS_FILE);
	if (fh < 0)
		return -1;
	else
		close(fh);
	l_0c_buf_size = sizeof(struct hypfs_diag0c_hdr);
	return 0;
}
