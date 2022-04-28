/*
 * pai - Extract CPU Processor Activity Instrumentation (PAI) facility data.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PAI_H
#define PAI_H

#define S390_EVT_PAI_CRYPTO	0x1000

enum {			/* Event attribute specifications */
	S390_EVTATTR_CTX_SWITCH = 1,
	S390_EVTATTR_COMM = 2,
	S390_EVTATTR_FORK = 4,
	S390_EVTATTR_USERSPACE = 8,
	S390_EVTATTR_KERNELSPACE = 16
};

struct pai_event {
	struct util_list_node node;	/* List node */
	struct perf_event_attr attr;	/* Perf_event_open(2) attr */
	int fd;				/* Perf event file descriptor */
	void *map_addr;			/* Sampling data mapping address */
	size_t map_size;		/* Sampling size mapping size */
	char file_name[16];		/* File name of sampled data */
	int file_fd;			/* Map data output file descriptor */
	int cpu;			/* Perf_event_open(2) CPU */
	unsigned long flags;		/* Perf_event_open(2) flags */
};

struct pai_event_out {		/* Output for CRYPTO_ALL event */
	__u32 type;		/* Header type, see PERF_RECORD_xxx */
	__u16 misc;		/* Header misc, value depends on type */
	__u64 time;		/* Time stamp valid for all entries */
	__u32 cpu;		/* CPU number valid for all entries */
	union {
		/* Fields from PERF_RECORD_FORK|EXIT */
		struct {
			__u32 pid, ppid;
			__u32 tid, ptid;
			__u64 time;
		} s_fork;
		/* Fields from PERF_RECORD_COMM */
		struct {
			__u32 pid, tid;
			__u8 cmd[16];
		} s_comm;
		/* Fields from PERF_RECORD_SWITCH_CPU_WIDE */
		struct {
			__u32 next_prev_pid, next_prev_tid;
		} s_cs;
		/* Fields from PERF_RECORD_LOST_SAMPLES */
		struct {
			__u64 lost;
		} s_lost;
		/* Relevant fields from PERF_RECORD_SAMPLE, time and cpu
		 * are stored above
		 */
		struct {
			__u64 ip;
			__u64 period;
			__u32 pid, tid;
		} s_sample;
		/* Fields from PERF_RECORD_[UN]THROTTLE */
		struct {
			__u64 time;
			__u64 id;
			__u64 stream_id;
		} s_throttle;
	} u;
	/* Information on last context switch out */
	struct cs_switch {
		unsigned char valid;
		__u32 topid, totid;
		__u32 frompid, fromtid;
	} cs_switch;
	void *raw;	/* Pointer to key/value array for crypto counters */
};

struct data_pos {			/* Perf event mapped ring buffer */
	__u64   data_head;		/* Head in the data section */
	__u64	data_tail;		/* User-space written tail */
	__u64	data_offset;		/* Where the buffer starts */
	__u64	data_size;		/* Data buffer size */
};

struct event_name {		/* Event list for number to name xlate */
	char *name;		/* Event name */
	__u64 config;		/* Event config value */
	__u64 total;		/* Total counter value */
};

struct pmu_events {		/* Event list for PMU number to name xlate */
	struct util_list_node node;	/* List node */
	char *name;		/* PMU name */
	int type;		/* PMU type */
	int lstlen;		/* # of entries in lst */
	unsigned long base;	/* Base event number */
	struct event_name *lst;	/* List of event names */
};
#endif /* PAI_H */
