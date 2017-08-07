/*
 * mon_procd - Write process data to the z/VM monitor strea
 *
 * Definitions used by mon_procd
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef __mon_procd_h__
#define __mon_procd_h__

#include <linux/types.h>
#include "lib/zt_common.h"

/* mon_function values */
#define MONWRITE_START_INTERVAL 0x00	/* start interval recording */
#define MONWRITE_STOP_INTERVAL	0x01	/* stop interval or config recording */

#define SMALL_MON_RECORD_LEN 512
#define MAX_REC_LEN 1500

#define PROCD_APPLID 0x02

#define SUM_FLAG 0x00
#define TASK_FLAG 0x01
#define	BUF_SIZE 4096
#define MAX_NAME_LEN 64
#define MAX_CMD_LEN 1024
#define MAX_TASK_REC 100
#define Hertz 100

struct monwrite_hdr {
	unsigned char	mon_function;
	unsigned short	applid;
	unsigned char	record_num;
	unsigned short	version;
	unsigned short	release;
	unsigned short	mod_level;
	unsigned short	datalen;
	unsigned char	hdrlen;

} __attribute__((packed));

struct procd_hdr {
	__u64	time_stamp;
	__u16	data_len;
	__u16	data_offset;
} __attribute__((packed));

struct task_sum_t {
	__u32	total;
	__u32	running;
	__u32	sleeping;
	__u32	stopped;
	__u32	zombie;
};

struct cpu_t {
	__u32	num_cpus;
	__u16	puser;
	__u16	pnice;
	__u16	psystem;
	__u16	pidle;
	__u16	piowait;
	__u16	pirq;
	__u16	psoftirq;
	__u16	psteal;
};

struct mem_t {
	__u64	total;
	__u64	used;
	__u64	free;
	__u64	buffers;
	__u64	pgpgin;
	__u64	pgpgout;
};

struct swap_t {
	__u64	total;
	__u64	used;
	__u64	free;
	__u64	cached;
	__u64	pswpin;
	__u64	pswpout;
};

struct proc_sum_t {
	__u64	uptime;
	__u32	users;
	char	loadavg_1[6];
	char	loadavg_5[6];
	char	loadavg_15[6];
	struct task_sum_t	task;
	struct cpu_t		cpu;
	struct mem_t		mem;
	struct swap_t		swap;
} __attribute__((packed));

struct task_t {
	__u32	pid;
	__u32	ppid;
	__u32	euid;
	__u16	tty;
	__s16	priority;
	__s16	nice;
	__u32	processor;
	__u16	pcpu;
	__u16	pmem;
	__u64	total_time;
	__u64	ctotal_time;
	__u64	size;
	__u64	swap;
	__u64	resident;
	__u64	trs;
	__u64	drs;
	__u64	share;
	__u64	dt;
	__u64	maj_flt;
	char	state;
	__u32	flags;
} __attribute__((packed));

struct cpudata_t {
	__u32	id;
	__u64	usr;
	__u64	nice;
	__u64	sys;
	__u64	idle;
	__u64	iowt;
	__u64	irq;
	__u64	sirq;
	__u64	steal;
	__u64	usr_prev;
	__u64	nice_prev;
	__u64	sys_prev;
	__u64	idle_prev;
	__u64	iowt_prev;
	__u64	irq_prev;
	__u64	sirq_prev;
	__u64	steal_prev;
};

struct task_sort_t {
	__u32	pid;
	__u64	tics;
	__u16	cpu_mem_usage;
	char	state;
};

static struct option options[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"attach", no_argument, NULL, 'a'},
	{"interval", required_argument, NULL, 'i'},
	{NULL, 0, NULL, 0}
};

static const char opt_string[] = "+hvai:";

static const char help_text[] =
	"mon_procd: Daemon that writes process data information\n"
	"to the z/VM monitor stream.\n"
	"\n"
	"Usage: mon_procd [OPTIONS]\n"
	"\n"
	"Options:\n"
	"-h, --help               Print this help, then exit\n"
	"-v, --version            Print version information, then exit\n"
	"-a, --attach             Run in foreground\n"
	"-i, --interval=<seconds> Sample interval\n"
	"\n"
	"Please report bugs to: linux390@de.ibm.com\n";
#endif

