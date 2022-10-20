/*
 * pai - Extract CPU Processor Activity Instrumentation (PAI) facility data.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/user.h>

#include <linux/perf_event.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_scandir.h"
#include "lib/libcpumf.h"
#include "pai.h"

#define S390_EVT_PAI_CRYPTO	0x1000
#define S390_EVT_PAI_NNPA	0x1800

/* Default values for select() timeout: 1 second */
static unsigned long read_interval = 1000;
/* Size of mapped perf event ring buffer in 4KB pages.
 * It must be power of two and >= 4 which is the
 * absolute minimum required for file descriptors returned by the
 * perf_event_open system call. Default to 512 pages.
 */
static unsigned long mapsize = 512;
static cpu_set_t cpu_online_mask;
static int verbose, humantime;
static struct util_list list_pai_event;
static struct util_list list_pmu_event;
static bool summary;

/* System call to perf_event_open(2) */
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu,
		       group_fd, flags);
}

static void ev_dealloc(void)
{
	struct pai_event *next, *p;

	util_list_iterate_safe(&list_pai_event, p, next) {
		util_list_remove(&list_pai_event, p);
		free(p);
	}
}

static void ev_merge(struct pai_event *new)
{
	struct pai_event *p;

	util_list_iterate(&list_pai_event, p) {
		if (p->cpu == new->cpu && p->attr.config == new->attr.config) {
			warnx("dropped duplicate event %#llx for cpu %d",
			      new->attr.config, new->cpu);
			free(new);
			return;
		}
	}
	util_list_add_head(&list_pai_event, new);
}

static void ev_alloc(int enr, int cpu, int flags)
{
	struct pai_event *event = calloc(1, sizeof(*event));
	unsigned short as = (S390_EVTATTR_USERSPACE |
			     S390_EVTATTR_KERNELSPACE);

	if (!event)
		errx(EXIT_FAILURE, "Not enough memory to allocate event");
	if (cpu > CPU_SETSIZE || !CPU_ISSET(cpu, &cpu_online_mask))
		errx(EXIT_FAILURE, "Invalid CPU %d specified", cpu);
	event->file_fd = -1;
	event->fd = -1;
	event->flags = flags;
	event->attr.size = sizeof(event->attr);
	event->attr.config = enr;
	switch (enr) {
	case S390_EVT_PAI_CRYPTO:
		event->attr.type = libcpumf_pmutype(S390_SYSFS_PAI_CRYPTO);
		break;
	case S390_EVT_PAI_NNPA:
		if ((flags & as)) {
			warnx("NNPA does not support kernel/user space selector");
			flags &= ~as;
		}
		event->attr.type = libcpumf_pmutype(S390_SYSFS_PAI_EXT);
		break;
	}
	event->attr.sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_CPU |
				  PERF_SAMPLE_TIME | PERF_SAMPLE_RAW;
	event->attr.disabled = 1;
	event->attr.sample_period = 1;
	event->attr.sample_id_all = 1;
	event->attr.watermark = 1;		/* Wakeup on every event */
	event->attr.wakeup_watermark = 1;
	if (flags & S390_EVTATTR_CTX_SWITCH)
		event->attr.context_switch = 1;
	if (flags & S390_EVTATTR_FORK)
		event->attr.task = 1;
	if (flags & S390_EVTATTR_COMM) {
		event->attr.comm = 1;
		event->attr.comm_exec = 1;
	}
	if ((flags & as) != as && enr == S390_EVT_PAI_CRYPTO) {
		/* User space or kernel space selector */
		if (flags & S390_EVTATTR_USERSPACE)
			event->attr.exclude_kernel = 1;
		if (flags & S390_EVTATTR_KERNELSPACE)
			event->attr.exclude_user = 1;
	}
	event->cpu = cpu;
	event->map_size = mapsize;
	snprintf(event->file_name, sizeof(event->file_name), "pai%s.%03d",
		 enr == S390_EVT_PAI_CRYPTO ? "crypto" : "nnpa", cpu);
	ev_merge(event);
}

static void ev_deinstall(void)
{
	struct pai_event *p;

	util_list_iterate(&list_pai_event, p) {
		if (p->map_addr)
			munmap(p->map_addr, PAGE_SIZE + p->map_size * PAGE_SIZE);
		p->map_addr = NULL;
		if (p->fd >= 0)
			close(p->fd);
		p->fd = -1;
		if (p->file_fd >= 0)
			close(p->file_fd);
		p->file_fd = -1;
	}
}

static void ev_enable(void)
{
	struct pai_event *p;
	int rc;

	util_list_iterate(&list_pai_event, p) {
		rc = ioctl(p->fd, PERF_EVENT_IOC_RESET, 0);
		rc |= ioctl(p->fd, PERF_EVENT_IOC_ENABLE, 0);
		if (rc)
			err(EXIT_FAILURE, "ioctl error for enable event %lld CPU %d",
			    p->attr.config, p->cpu);
	}
}

static void ev_disable(void)
{
	struct pai_event *p;
	int rc;

	util_list_iterate(&list_pai_event, p) {
		rc = ioctl(p->fd, PERF_EVENT_IOC_DISABLE, 0);
		if (rc)
			err(EXIT_FAILURE, "ioctl error for disable event %lld CPU %d",
			    p->attr.config, p->cpu);
	}
}

/* Map one event's ring buffer and create an output file for it. */
static void ev_mapevent(struct pai_event *p)
{
	p->map_addr = mmap(NULL, PAGE_SIZE + p->map_size * PAGE_SIZE,
			   PROT_READ | PROT_WRITE, MAP_SHARED, p->fd, 0);
	if (p->map_addr == MAP_FAILED)
		err(EXIT_FAILURE, "mmap error for event %lld CPU %d",
		    p->attr.config, p->cpu);

	p->file_fd = open(p->file_name,
			  O_WRONLY | O_APPEND | O_CREAT | O_TRUNC, 0600);
	if (p->file_fd < 0)
		err(EXIT_FAILURE, "file error for event %lld CPU %d",
		    p->attr.config, p->cpu);
	if (write(p->file_fd, &p->attr, sizeof(p->attr)) == -1)
		err(EXIT_FAILURE, "write error for event %lld CPU %d",
		    p->attr.config, p->cpu);
}

/* Install one event using perf_event_open system call. */
static void ev_install(int group)
{
	unsigned long flags = 0;
	int group_fd = -1, rc;
	struct pai_event *p;

	util_list_iterate(&list_pai_event, p) {
		if (group_fd == -1) {
			p->attr.watermark = 1;
			p->attr.wakeup_watermark = PAGE_SIZE *
						   p->map_size / 2;
		}

		rc = perf_event_open(&p->attr, -1, p->cpu, group_fd, flags);
		if (rc == -1)
			err(EXIT_FAILURE, "perf_event_open error for event %lld CPU %d",
			    p->attr.config, p->cpu);
		p->fd = rc;
		if (group && group_fd == -1) {
			flags = PERF_FLAG_FD_OUTPUT | PERF_FLAG_FD_NO_GROUP;
			group_fd = rc;
			ev_mapevent(p);
		} else if (!group) {
			ev_mapevent(p);
		}
	}
}

/* Return pointer to event for a given perf event file descriptor returned
 * by the perf_event_open system call.
 */
static struct pai_event *perffd_2_event(int fd)
{
	struct pai_event *p;

	util_list_iterate(&list_pai_event, p)
		if (p->fd == fd)
			return p;
	return NULL;
}

/* Read the perf event ring buffer and write output to a file.
 * The file contents is interpreted later after the data collection
 * phase.
 */
static int savemap(int fd, void *data, struct data_pos *dp)
{
	unsigned long d_head_old, d_head = dp->data_head;
	unsigned long d_prev = dp->data_tail;
	int diff = d_head - d_prev;
	int wrapped;

	d_head_old = d_head;
	if (verbose) {
		printf("Data head:%#llx tail:%#llx offset:%#llx size:%#llx\n",
		       dp->data_head, dp->data_tail, dp->data_offset,
		       dp->data_size);
	}
	if (!diff)
		return 0;
	wrapped = d_head / dp->data_size != d_prev / dp->data_size;
	d_head %= dp->data_size;
	if (!d_head) {		/* Head at buffer end is buffer end */
		d_head = dp->data_size;
		wrapped = 0;
	}

	d_prev %= dp->data_size;
	if (wrapped) {		/* Read from d_prev to buffer end */
		int part2 = dp->data_size - d_prev;

		diff -= part2;
		if (verbose) {
			printf("Write %d bytes [%ld,%lld)\n", part2, d_prev,
			       dp->data_size);
		}
		if (write(fd, data + d_prev, part2) == -1)
			err(EXIT_FAILURE, "write error for event file");
		d_prev = 0;		/* Start at position zero */
	}
	if (verbose)
		printf("Write %d bytes [%ld,%ld)\n", diff, d_prev, d_head);
	if (write(fd, data + d_prev, diff) == -1)
		err(EXIT_FAILURE, "write error for event file");

	dp->data_tail = d_head_old;	/* Write last read position */
	return 0;
}

static void readmap(int fd)
{
	struct pai_event *p = perffd_2_event(fd);
	struct perf_event_mmap_page *area;

	if (verbose) {
		printf("Ring buffer for fd %d %s(%d)\n", fd, p->file_name,
		       p->file_fd);
	}
	area = p->map_addr;
	savemap(p->file_fd, p->map_addr + area->data_offset,
		(struct data_pos *)&area->data_head);
	syncfs(p->file_fd);
}

/* Collect the data in the event ring buffers. Since there might be one
 * ring buffer per event, sleep some short time and always read all
 * ring buffer for new contents.
 */
static void collect(unsigned long cnt)
{
	fd_set r_fds, e_fds, a_fds;
	struct pai_event *p;
	struct timeval tv;
	int rc, max_fd;

	do {
		max_fd = -1;
		tv.tv_sec = read_interval / 1000;
		tv.tv_usec = (1000 * read_interval) % 1000000;
		FD_ZERO(&r_fds);
		FD_ZERO(&e_fds);
		FD_ZERO(&a_fds);
		util_list_iterate(&list_pai_event, p) {
			if (p->attr.watermark) {
				FD_SET(p->fd, &r_fds);
				FD_SET(p->fd, &e_fds);
				FD_SET(p->fd, &a_fds);
				if (p->fd > max_fd)
					max_fd = p->fd;
			}
		}

		if (max_fd == -1)
			break;
		rc = select(max_fd + 1, &r_fds, NULL, &e_fds, &tv);
		if (rc >= 0) {
			if (rc == 0)
				/* Termination, trigger final read */
				r_fds = a_fds;
			for (int i = 0; i < max_fd + 1; ++i) {
				if (FD_ISSET(i, &r_fds))
					readmap(i);
			}
		}
	} while (rc != -1 && --cnt > 0);
}

static void lookup_event(__u64 evtnum, __u16 ctr, __u64 value)
{
	struct pmu_events *p;

	util_list_iterate(&list_pmu_event, p) {
		if (p->base == evtnum) {
			struct event_name *n = p->lst;

			for (int i = 0; i < p->lstlen; ++n, ++i) {
				if (p->base + ctr == n->config) {
					n->total += value;
					return;
				}
			}
		}
	}
}

/* Display the raw data, which is a pair of counter number and values
 * in the form of counter-nr:value. The first 4 bytes are the length
 * of the raw-data area. Then follows a key/value pair of 2 bytes key
 * and 8 bytes value.
 */
static int evtraw_show(__u64 evtnum, unsigned char *p)
{
	size_t offset = 4, bytes = *(__u32 *)p;
	__u16 ctr;
	__u64 value;

	while (offset < bytes) {
		ctr = *(__u16 *)(p + offset);
		offset += sizeof(ctr);
		value = *(__u64 *)(p + offset);
		offset += sizeof(value);
		if (!summary) {
			printf("%c%hd:%#llx", offset > 14 ? ',' : ' ', ctr,
			       value);
		}
		lookup_event(evtnum, ctr, value);
		if (offset + sizeof(ctr) + sizeof(value) > bytes)
			break;
	}
	return 1;
}

#define NSEC_PER_SEC    1000000000L
static void timestamp(u64 timestamp)
{
	if (humantime)
		printf("%lld.%09lld ", timestamp / NSEC_PER_SEC,
		       timestamp % NSEC_PER_SEC);
	else
		printf("%#llx ", timestamp);
}

static const char *evt_selector(struct perf_event_attr *pa)
{
	if (pa->exclude_kernel)
		return ":u";
	if (pa->exclude_user)
		return ":k";
	return "";
}

static void evt_show(__u64 evtnum, const char *evtsel, struct pai_event_out *ev)
{
	if (summary) {
		if (ev->type == PERF_RECORD_SAMPLE && ev->raw)
			evtraw_show(evtnum, ev->raw);
		return;
	}

	timestamp(ev->time);
	printf("%d ", ev->cpu);

	switch (ev->type) {
	case PERF_RECORD_EXIT:
	case PERF_RECORD_FORK:
		printf("%s pid %u ppid %u",
		       ev->type == PERF_RECORD_FORK ? "fork" : "exit",
		       ev->u.s_fork.pid, ev->u.s_fork.ppid);
		break;

	case PERF_RECORD_COMM:
		printf("%s %s pid %u/%u",
		       ev->misc ? "exec" : "prctl",
		       ev->u.s_comm.cmd, ev->u.s_comm.pid,
		       ev->u.s_comm.tid);
		break;

	case PERF_RECORD_SWITCH_CPU_WIDE:
		if (ev->misc & PERF_RECORD_MISC_SWITCH_OUT) {
			short p = PERF_RECORD_MISC_SWITCH_OUT_PREEMPT;

			printf("cs-out %c nextpid %u/%u",
			       (ev->misc & p) ? 'P' : '-',
			       ev->u.s_cs.next_prev_pid,
			       ev->u.s_cs.next_prev_tid);
		} else {
			printf("cs-in prevpid %u/%u ",
			       ev->u.s_cs.next_prev_pid,
			       ev->u.s_cs.next_prev_tid);
			if (ev->cs_switch.valid)
				printf("SWITCH %u/%u->%u/%u",
				       ev->cs_switch.frompid,
				       ev->cs_switch.fromtid,
				       ev->cs_switch.topid,
				       ev->cs_switch.totid);
		}
		break;

	case PERF_RECORD_LOST_SAMPLES:
		printf("lost %lld\n", ev->u.s_lost.lost);
		break;

	case PERF_RECORD_THROTTLE:
	case PERF_RECORD_UNTHROTTLE:
		printf("%sthrottle id %lld stream_id %lld\n",
		       ev->type == PERF_RECORD_THROTTLE ? "" : "un",
		       ev->u.s_throttle.id, ev->u.s_throttle.stream_id);
		break;

	case PERF_RECORD_SAMPLE:
		printf("event %lld%s sample pid %u/%u", evtnum, evtsel,
		       ev->u.s_sample.pid, ev->u.s_sample.tid);
		if (ev->raw) {
			evtraw_show(evtnum, ev->raw);
			ev->raw = NULL;
		}
	}
	putchar('\n');
}

/* Collect the contents of the event ring buffer data which was saved in
 * a file during data collection phase.
 */
static int evt_scan(char *fn, unsigned char *buf, size_t len,
		    struct perf_event_attr *pa)
{
	const char *evtsel = evt_selector(pa);
	__u64 sample_type = pa->sample_type;
	int allcnt = 0, cnt = 0, rawok = 0;
	struct perf_event_header *hdr;
	size_t offset = sizeof(*pa);
	__u64 evtnum = pa->config;
	struct pai_event_out ev;
	size_t limit;
	__u32 *ptr32;
	__u64 *ptr;
	struct {
		__u32 pid, tid;
		unsigned char valid;
	} last_csout = { 0, 0, 0 };

	while (offset < len) {
		hdr = (struct perf_event_header *)(buf + offset);
		memset(&ev, 0, sizeof(ev));

		if (hdr->size < sizeof(*hdr))
			return 1;
		++allcnt;
		if (verbose)
			printf("[%#08zx] type %d misc %hd size %hx ", offset,
			       hdr->type, hdr->misc, hdr->size);
		limit = offset + hdr->size;
		offset += sizeof(*hdr);
		ev.type = hdr->type;
		ev.misc = hdr->misc;

		switch (hdr->type) {
		case PERF_RECORD_EXIT:
		case PERF_RECORD_FORK:
			memcpy(&ev.u, buf + offset, sizeof(ev.u.s_fork));
			offset += sizeof(ev.u.s_fork);
			ev.time = ev.u.s_fork.time;
			break;

		case PERF_RECORD_COMM:
			memcpy(&ev.u, buf + offset, sizeof(ev.u.s_comm));
			offset += sizeof(ev.u.s_comm);
			/* The command name saved by the kernel is either
			 * 8 or 16 bytes in size. If it fits in 8 bytes, the
			 * entry size is eight bytes smaller, and not filled
			 * with terminating null bytes. Adjust offset in this
			 * case.
			 */
			if (strlen((const char *)ev.u.s_comm.cmd) < sizeof(__u64))
				offset -= sizeof(__u64);
			break;

		case PERF_RECORD_SWITCH_CPU_WIDE:
			memcpy(&ev.u, buf + offset, sizeof(ev.u.s_cs));
			offset += sizeof(ev.u.s_cs);
			if (hdr->misc & PERF_RECORD_MISC_SWITCH_OUT) {
				last_csout.valid = 1;
				last_csout.pid = ev.u.s_cs.next_prev_pid;
				last_csout.tid = ev.u.s_cs.next_prev_tid;
			} else {
				ev.cs_switch.valid = last_csout.valid;
				ev.cs_switch.topid = last_csout.pid;
				ev.cs_switch.totid = last_csout.tid;
				ev.cs_switch.frompid = ev.u.s_cs.next_prev_pid;
				ev.cs_switch.fromtid = ev.u.s_cs.next_prev_tid;
				last_csout.valid = 0;
			}
			break;

		case PERF_RECORD_THROTTLE:
		case PERF_RECORD_UNTHROTTLE:
			memcpy(&ev.u, buf + offset, sizeof(ev.u.s_throttle));
			offset += sizeof(ev.u.s_throttle);
			ev.time = ev.u.s_throttle.time;
			break;

		case PERF_RECORD_LOST:
			memcpy(&ev.u, buf + offset, sizeof(ev.u.s_lost));
			offset += sizeof(ev.u.s_lost);
			break;

		case PERF_RECORD_SAMPLE:
			++cnt;		/* Do nothing and collect below */
			break;

		default:
			printf("unknown header-type %d ", hdr->type);
			offset += hdr->size - sizeof(*hdr);
			goto bypass;
		}

		/* Now handle the data returned by samples and the fields
		 * mentioned in sample_id_all members which are appended
		 * to all PERF_RECORDS_xxx
		 * Note: SEQUENCE IS IMPORTANT.
		 */

		/* The sample ip is __schedule() no benefit for output */
		if (sample_type & PERF_SAMPLE_IP) {
			ptr = (__u64 *)(buf + offset);
			offset += sizeof(*ptr);
			ev.u.s_sample.ip = *ptr;
		}

		if (sample_type & PERF_SAMPLE_TID) {
			ptr = (__u64 *)(buf + offset);
			offset += sizeof(*ptr);
			ptr32 = (__u32 *)ptr;
			ev.u.s_sample.pid = *ptr32;
			ev.u.s_sample.tid = *(ptr32 + 1);
		}

		if (sample_type & PERF_SAMPLE_TIME) {
			ptr = (__u64 *)(buf + offset);
			offset += sizeof(*ptr);
			ev.time = *ptr;
		}

		if (sample_type & PERF_SAMPLE_CPU) {
			ptr = (__u64 *)(buf + offset);
			offset += sizeof(*ptr);
			ptr32 = (__u32 *)ptr;
			ev.cpu = *ptr32;
		}

		/* The period is always one, no benefit for output */
		if (sample_type & PERF_SAMPLE_PERIOD) {
			ptr = (__u64 *)(buf + offset);
			offset += sizeof(*ptr);
			ev.u.s_sample.period = *ptr;
		}

		if (hdr->type == PERF_RECORD_SAMPLE &&
		    sample_type & PERF_SAMPLE_RAW) {
			ptr32 = (__u32 *)(buf + offset);
			offset += *ptr32 + sizeof(*ptr32);
			if (*ptr32 > sizeof(*ptr32)) {
				ev.raw = ptr32;
				++rawok;
			}
		}
		evt_show(evtnum, evtsel, &ev);
bypass:
		if (offset != limit) {
			warnx("%s error at offset:%#zx limit:%#zx",
			      fn, offset, limit);
			return 1;
		}
	}
	if (verbose)
		printf("%s records %d samples %d raw-data %d\n", fn, allcnt,
		       cnt, rawok);
	return 0;
}

/* Scan event directory and fill event list. */
static int scan_events(struct pmu_events *p)
{
	char *evtname, *evtdir, *path;
	struct dirent **de_vec;
	struct event_name *ep;
	int evtnr, count, rc;

	path = util_path_sysfs("devices");
	rc = util_asprintf(&evtdir, "%s/%s/events", path, p->name);
	free(path);
	if (rc == -1)
		return rc;

	count = util_scandir(&de_vec, alphasort, evtdir, ".*");
	p->lst = calloc(count, sizeof(*p->lst));
	if (!p->lst) {
		rc = -1;
		goto out;
	}

	p->lstlen = 0;
	ep = p->lst;
	for (int i = 0; i < count; i++) {
		if (de_vec[i]->d_type == DT_DIR)
			continue;
		ep->name = util_strdup(de_vec[i]->d_name);
		util_asprintf(&evtname, "%s/%s", evtdir, de_vec[i]->d_name);
		rc = util_file_read_va(evtname, "event=%x", &evtnr);
		free(evtname);
		if (rc != 1) {
			for (ep = p->lst, rc = 0; rc < p->lstlen; ++rc, ++ep)
				free(ep->name);
			free(p->lst);
			p->lst = NULL;
			rc = -1;
			goto out;
		}
		ep->config = evtnr;
		if (p->base > ep->config)
			p->base = ep->config;
		++p->lstlen;
		++ep;
	}
	rc = 0;

out:
	util_scandir_free(de_vec, count);
	free(evtdir);
	return rc;
}

/* Scan all event names of PMU type. */
static int add_events(int type)
{
	struct pmu_events *p;
	char *pmuname;
	int rc;

	rc = libcpumf_pmuname(type, &pmuname);
	if (rc) {
		warnx("PMU type %d not found", type);
		return rc;
	}

	p = malloc(sizeof(*p));
	if (p) {
		p->type = type;
		p->name = pmuname;
		p->base = ~0UL;
		p->lst = NULL;
		rc = scan_events(p);
		if (rc)
			free(p);
		else
			util_list_add_head(&list_pmu_event, p);
	} else {
		rc = -1;
	}

	if (rc) {
		free(pmuname);
		warnx("failed building event list for %s", pmuname);
	}
	return rc;
}

/* Check event list for events of PMU type. If it does not exist, build it
 * and add it to the list all of PMU names.
 */
static void build_events(int type)
{
	struct pmu_events *p;

	util_list_iterate(&list_pmu_event, p)
		if (p->type == type)	/* PMU already scanned */
			return;

	/* PMU list not yet scanned read event names */
	add_events(type);
}

/* Show all events with a total number of non-zero. */
static void show_events(void)
{
	struct pmu_events *p;
	bool header = false;

	util_list_iterate(&list_pmu_event, p) {
		int i = 0;

		for (struct event_name *n = p->lst; i < p->lstlen; ++i, ++n) {
			if (n->total) {
				if (!header) {
					printf("Summary\n");
					header = true;
				}
				printf("PMU %s event %s nr %lld total %lld\n",
				       p->name, n->name, n->config - p->base,
				       n->total);
			}
		}
	}
}

/* Free all memory allocated for event summary. */
static void remove_events(void)
{
	struct pmu_events *next, *p;

	util_list_iterate_safe(&list_pmu_event, p, next) {
		int i = 0;

		for (struct event_name *n = p->lst; i < p->lstlen; ++i, ++n)
			free(n->name);
		free(p->name);
		free(p->lst);
		free(p);
	}
}

/* Scan one file which contains event ring buffer output. Print out the
 * entries to stdout.
 */
static int map_check(char *fn, int (*fct)(char *, unsigned char *, size_t,
					  struct perf_event_attr *))
{
	struct perf_event_attr pa;
	unsigned char *p;
	struct stat sb;
	int rc = 1, fd;

	fd = open(fn, O_RDONLY);
	if (fd == -1) {
		warnx("open() failed for %s", fn);
		return rc;
	}

	if (fstat(fd, &sb) == -1) {
		warnx("stat() failed for %s", fn);
		close(fd);
		return rc;
	}

	if (verbose)
		printf("%s size:%zu\n", fn, sb.st_size);
	if (!S_ISREG(sb.st_mode)) {
		warn("%s is not a file", fn);
		close(fd);
		return rc;
	}

	if (sb.st_size < (long)sizeof(pa)) {
		/* Event grouped --> empty file */
		close(fd);
		unlink(fn);
		return 0;
	}

	p = mmap(0, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		warnx("%s cannot map file", fn);
		close(fd);
		return rc;
	}

	memcpy(&pa, p, sizeof(pa));
	if (close(fd) == -1) {
		warnx("close() failed for %s", fn);
		return rc;
	}
	build_events(pa.type);
	rc = fct(fn, p, sb.st_size, &pa);
	munmap(p, sb.st_size);

	return rc;
}

/* Parse event attribute specification */
static int parse_event_attr(char *cp)
{
	int x = 0;

	for (; *cp; ++cp) {
		switch (tolower(*cp)) {
		case 's':
			x |= S390_EVTATTR_CTX_SWITCH;
			break;
		case 'c':
			x |= S390_EVTATTR_COMM;
			break;
		case 'f':
			x |= S390_EVTATTR_FORK;
			break;
		case 'u':
			x |= S390_EVTATTR_USERSPACE;
			break;
		case 'k':
			x |= S390_EVTATTR_KERNELSPACE;
			break;
		default:
			errx(EXIT_FAILURE,
			     "Invalid event specification '%c'", *cp);
		}
	}
	return x;
}

/* Parse CPU list and event specifications */
static void parse_cpulist(int enr, const char *parm)
{
	unsigned int evt_attr = 0;
	cpu_set_t cmdlist, result;
	char *cp;
	int rc;

	CPU_ZERO(&cmdlist);
	if (parm) {
		/* CPU list with optional event attribute */
		cp = strchr(parm, ':');
		if (cp) {		/* Handle event specification */
			*cp = '\0';
			evt_attr = parse_event_attr(++cp);
		}

		if (strlen(parm) > 0) {
			CPU_ZERO(&result);
			rc = libcpumf_cpuset(parm, &cmdlist);
			if (rc)
				errx(EXIT_FAILURE, "Cannot use CPU list %s",
				     parm);
			CPU_AND(&result, &cmdlist, &cpu_online_mask);
		} else {
			CPU_OR(&result, &cmdlist, &cpu_online_mask);
		}
	} else {
		CPU_OR(&result, &cmdlist, &cpu_online_mask);
		evt_attr = S390_EVTATTR_CTX_SWITCH | S390_EVTATTR_COMM |
			   S390_EVTATTR_FORK;
	}

	for (rc = 0; rc < CPU_SETSIZE; ++rc) {
		if (CPU_ISSET(rc, &result))
			ev_alloc(enr, rc, evt_attr);
	}
	for (rc = 0; rc < CPU_SETSIZE; ++rc) {
		if (CPU_ISSET(rc, &cmdlist) && !CPU_ISSET(rc, &cpu_online_mask))
			warnx("CPU %d not online, event dropped", rc);
	}
}

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "crypto", optional_argument, NULL, 'c' },
		.argument = "CPULIST[:DATA]",
		.desc = "Collect PAI crypto counters"
	},
	{
		.option = { "nnpa", optional_argument, NULL, 'n' },
		.argument = "CPULIST[:DATA]",
		.desc = "Collect PAI nnpa counters"
	},
	{
		.option = { "mapsize", required_argument, NULL, 'm' },
		.argument = "SIZE",
		.desc = "Specifies number of 4KB pages for event ring buffer"
	},
	{
		.option = { "report", no_argument, NULL, 'r' },
		.desc = "Report file contents"
	},
	{
		.option = { "interval", required_argument, NULL, 'i' },
		.argument = "NUMBER",
		.desc = "Specifies interval between read operations in milliseconds"
	},
	{
		.option = { "verbose", no_argument, NULL, 'V' },
		.desc = "Verbose output"
	},
	{
		.option = { "humantime", no_argument, NULL, 'H' },
		.desc = "Human readable timestamp in seconds.nanoseconds"
	},
	{
		.option = { "summary", no_argument, NULL, 'S' },
		.desc = "Print summary of all non-zero counter values"
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static const struct util_prg prg = {
	.desc = "Record and report Processor Activity Instrumentation Facility Counters.",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2022,
			.pub_last = 2022,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static void record_cpus_crypto(const char *cp)
{
	if (!libcpumf_have_pai_crypto())
		errx(EXIT_FAILURE, "No support for PAI crypto counters");
	parse_cpulist(S390_EVT_PAI_CRYPTO, cp);
}

static void record_cpus_nnpa(const char *cp)
{
	if (!libcpumf_have_pai_nnpa())
		errx(EXIT_FAILURE, "No support for PAI nnpa counters");
	parse_cpulist(S390_EVT_PAI_NNPA, cp);
}

/* Mapsize must be power of 2 and larger than 4. Count bits in n and
 * return 0 if input is invalid and has a bit count larger than one.
 */
static unsigned long check_mapsize(unsigned long n)
{
	int bit, cnt = 0;

	if (n < 4)
		return 0;
	for (bit = 0; bit < __BITS_PER_LONG; ++bit)
		if (n & (1 << bit))
			++cnt;
	return cnt == 1 ? n : 0;
}

int main(int argc, char **argv)
{
	bool crypto_record = false, report = false;
	bool nnpa_record = false;
	unsigned long loop_count = 1;
	int ch, group = 0;
	char *slash;

	util_list_init(&list_pai_event, struct pai_event, node);
	util_list_init(&list_pmu_event, struct pmu_events, node);
	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	/* Read currently online CPUs and create a bit mask.
	 * This bitmap of online CPUs is used to check command line parameter
	 * for valid CPUs
	 */
	ch = libcpumf_cpuset_fn(S390_CPUS_ONLINE, &cpu_online_mask);
	if (ch)
		err(EXIT_FAILURE, "Cannot read file " S390_CPUS_ONLINE);

	while ((ch = util_opt_getopt_long(argc, argv)) != -1) {
		switch (ch) {
		default:
			util_opt_print_parse_error(ch, argv);
			return EXIT_FAILURE;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		case 'c':
			record_cpus_crypto(optarg);
			crypto_record = true;
			break;
		case 'i':
			errno = 0;
			read_interval = (unsigned int)strtoul(optarg, &slash, 0);
			if (errno || !read_interval || *slash)
				errx(EXIT_FAILURE, "Invalid argument for -%c", ch);
			break;
		case 'm':
			errno = 0;
			mapsize = strtoul(optarg, &slash, 0);
			mapsize = check_mapsize(mapsize);
			if (errno || !mapsize || *slash)
				errx(EXIT_FAILURE, "Invalid argument for -%c", ch);
			break;
		case 'n':
			record_cpus_nnpa(optarg);
			nnpa_record = true;
			break;
		case 'r':
			report = true;
			break;
		case 'S':
			summary = true;
			break;
		case 'H':
			humantime = 1;
			break;
		case 'V':
			++verbose;
			break;
		}
	}

	/* Without options do report on all files */
	if (!crypto_record && !nnpa_record && !report) {
		warnx("No action specified assume report");
		report = true;
	}

	if (crypto_record || nnpa_record) {
		/* In record mode command line parameter is run-time */
		if (optind < argc) {
			errno = 0;
			loop_count = strtoul(argv[optind], &slash, 0);
			if (errno || !loop_count || *slash)
				errx(EXIT_FAILURE, "Invalid argument for runtime");
		}

		ev_install(group);
		ev_enable();

		collect(loop_count);

		ev_disable();
		ev_deinstall();
		ev_dealloc();
		return EXIT_SUCCESS;
	}

	/* Must be reporting */
	ch = 0;
	if (optind < argc) {	/* Report mode command line has files */
		for (; optind < argc; ++optind)
			ch += map_check(argv[optind], evt_scan);
	} else {		/* Scan files in local directory */
		struct dirent **de_vec;
		int count = util_scandir(&de_vec, alphasort, ".",
					 "pai(crypto|nnpa).[0-9]+");
		for (int i = 0; i < count; i++)
			if (de_vec[i]->d_type == DT_REG)
				ch += map_check(de_vec[i]->d_name, evt_scan);
		util_scandir_free(de_vec, count);
	}

	if (summary && report) {
		show_events();
		remove_events();
	}
	return ch ? EXIT_FAILURE : EXIT_SUCCESS;
}
