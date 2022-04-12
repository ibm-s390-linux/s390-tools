/*
 * cpacfstats - display and maintain CPACF perf counters
 *
 * low level perf functions
 *
 * Copyright IBM Corp. 2015, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <asm/unistd.h>
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <limits.h>
#include <linux/perf_event.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <libudev.h>

#include "cpacfstats.h"
#include "../include/lib/zt_common.h"

#define NUM_COUNTER ALL_COUNTER

/* correlation between counter and perf counter string */
static const struct {
	char pmu[20];
	char pfm_name[60];
	enum ctr_e ctr;
} pmf_counter_name[NUM_COUNTER] = {
	{"cpum_cf", "DEA_FUNCTIONS", DES_FUNCTIONS},
	{"cpum_cf", "AES_FUNCTIONS", AES_FUNCTIONS},
	{"cpum_cf", "SHA_FUNCTIONS", SHA_FUNCTIONS},
	{"cpum_cf", "PRNG_FUNCTIONS", PRNG_FUNCTIONS},
	{"cpum_cf", "ECC_FUNCTION_COUNT", ECC_FUNCTIONS}
};

static struct pmf_data {
	int pmutype;
	int eventid;
} pmf_counter_data[NUM_COUNTER];

struct percpucounter {
	int                   ctr_fds[NUM_COUNTER];
	unsigned int          cpunum;
	struct percpucounter *next;
};

static struct percpucounter *root;
pthread_mutex_t rootmux = PTHREAD_MUTEX_INITIALIZER;
static volatile int hotplugdetected;
static unsigned int enabledcounter;
pthread_t hotplugthread;

#define foreachcpu(PCPU) if (pthread_mutex_lock(&rootmux)) return -1; \
	for ((PCPU) = root; (PCPU) != NULL; (PCPU) = (PCPU)->next)
#define endforeachcpu() pthread_mutex_unlock(&rootmux)

static int ctr_state[NUM_COUNTER];

static volatile int stoprequested;

static struct percpucounter *allocpercpucounter(unsigned int cpunum)
{
	struct percpucounter *ppc;

	ppc = malloc(sizeof(struct percpucounter));
	if (ppc) {
		int i;

		for (i = 0; i < NUM_COUNTER; ++i)
			ppc->ctr_fds[i] = -1;
		ppc->cpunum = cpunum;
		ppc->next = NULL;
	}
	return ppc;
}

static void freepercpucounter(struct percpucounter *pcpu)
{
	int i;

	for (i = 0; i < NUM_COUNTER; ++i)
		(void)close(pcpu->ctr_fds[i]);
	free(pcpu);
}

static struct percpucounter *findcpu(unsigned int cpunum, int unlinkflag)
{
	struct percpucounter **prev = &root, *walk = root;

	while (walk) {
		if (walk->cpunum == cpunum) {
			if (unlinkflag)
				*prev = walk->next;
			return walk;
		}
		prev = &(walk->next);
		walk = walk->next;
	}
	return NULL;
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
			    int cpu, int group_fd, unsigned long flags)
{
	int ret;

	ret = syscall(__NR_perf_event_open, hw_event, pid, cpu,
		group_fd, flags);
	return ret;
}

static int perf_supported(void)
{
	return !access("/proc/sys/kernel/perf_event_paranoid", R_OK);
}

static int perf_counter_supported(const char *pmu, const char *counter)
{
	char buf[PATH_MAX];

	if (snprintf(buf, PATH_MAX, "/sys/bus/event_source/devices/%s/events/%s",
		     pmu, counter) >= PATH_MAX) {
		eprint("overflow in path name");
		return 0;
	}
	return !access(buf, R_OK);
}

static int perf_event_encode(int *pmutype, int *eventid,
			     const char *pmu, const char *event)
{
	FILE *f;
	char buf[PATH_MAX];

	if (snprintf(buf, PATH_MAX, "/sys/bus/event_source/devices/%s/events/%s",
		     pmu, event) >= PATH_MAX) {
		eprint("overflow in path name");
		return -1;
	}
	f = fopen(buf, "r");
	if (!f) {
		eprint("Event %s for pmu %s not found (%d:%s)\n", event, pmu,
		       errno, strerror(errno));
		return -1;
	}
	if (fscanf(f, "event=0x%x\n", eventid) != 1) {
		fclose(f);
		eprint("Event file %s has invalid format\n", buf);
		return -1;
	}
	fclose(f);
	if (snprintf(buf, PATH_MAX, "/sys/bus/event_source/devices/%s/type",
		     pmu) >= PATH_MAX) {
		eprint("overflow in path name");
		return -1;
	}
	f = fopen(buf, "r");
	if (!f) {
		eprint("Event %s for pmu %s not found (%d:%s)\n", event, pmu,
		       errno, strerror(errno));
		return -1;
	}
	if (fscanf(f, "%d\n", pmutype) != 1) {
		fclose(f);
		eprint("Type file %s has invalid format\n", buf);
		return -1;
	}
	return 0;
}

static int activatecpu(unsigned int cpu)
{
	struct perf_event_attr pfm_event;
	struct percpucounter *ppc;
	int fd, i, rc = 0;

	ppc = allocpercpucounter(cpu);
	if (ppc == NULL) {
		eprint("Failed to allocate per cpu counter data");
		return -1;
	}
	if (pthread_mutex_lock(&rootmux)) {
		freepercpucounter(ppc);
		return -1;
	}
	for (i = 0; i < NUM_COUNTER; ++i) {
		if (ctr_state[i] == UNSUPPORTED)
			continue;
		memset(&pfm_event, 0, sizeof(pfm_event));
		pfm_event.size = sizeof(pfm_event);
		pfm_event.type = pmf_counter_data[i].pmutype;
		pfm_event.config = pmf_counter_data[i].eventid;

		/* fetch file descriptor for this perf event
		 * the counter event should start disabled
		 */
		pfm_event.disabled = ctr_state[i] == DISABLED;
		fd = perf_event_open(
			&pfm_event,
			-1,  /* pid -1 means all processes */
			cpu,
			-1,  /* group filedescriptor */
			0);  /* flags */
		if (fd < 0) {
			eprint("Perf_event_open() failed with errno=%d [%s]\n",
				errno, strerror(errno));
			rc = -1;
			ctr_state[i] = UNSUPPORTED;
		} else {
			ppc->ctr_fds[i] = fd;
		}
	}
	ppc->next = root;
	root = ppc;
	if (enabledcounter)
		hotplugdetected = 1;
	pthread_mutex_unlock(&rootmux);
	return rc;
}

static void deactivatecpu(unsigned int cpunum)
{
	struct percpucounter *pcpu;
	int i;

	if (pthread_mutex_lock(&rootmux))
		return;
	pcpu = findcpu(cpunum, 1);
	if (pcpu != NULL) {
		for (i = 0; i < NUM_COUNTER; ++i)
			(void)close(pcpu->ctr_fds[i]);
		free(pcpu);
		if (enabledcounter)
			hotplugdetected = 1;
	}
	pthread_mutex_unlock(&rootmux);
}

static int addallcpus(void)
{
	unsigned int start, end;
	int scanned, rc = 0;
	FILE *fp;

	/* comma separated list of intervals */
	if ((fp = fopen("/sys/devices/system/cpu/online", "r")) == NULL) {
		eprint("Failed to get online cpus (%d:%s)\n",
			errno, strerror(errno));
		return -1;
	}
		
	while (!feof(fp)) {
		/* scan all intervals of online cpus */
		scanned = fscanf(fp, "%u-%u", &start, &end);
		/* take care of singleton intervals */
		if (scanned == 1)
			end = start;
		for (; start <= end; ++start) {
			if (activatecpu(start)) {
				rc = -1;
				goto out;
			}
		}
		/* Skip comma separator */
		(void)fgetc(fp);
	}
out:
	fclose(fp);
	return rc;
}

static int perf_load_counter_data(void)
{
	int i, res = 0;

	for (i = 0; i < NUM_COUNTER; ++i) {
		if (ctr_state[i] != UNSUPPORTED)
			res |= perf_event_encode(&pmf_counter_data[i].pmutype,
						 &pmf_counter_data[i].eventid,
						 pmf_counter_name[i].pmu,
						 pmf_counter_name[i].pfm_name);
	}
	return res;
}

static void *hotplughandler(void *UNUSED(unused))
{
	struct udev *hotplug;
	struct udev_monitor *monitor;
	struct pollfd item;
	
	hotplug = udev_new();
	if (!hotplug) {
		eprint("Failed to create hotplug device\n");
		return NULL;
	}
	monitor = udev_monitor_new_from_netlink(hotplug, "udev");
	udev_monitor_filter_add_match_subsystem_devtype(monitor, "cpu", NULL);
	udev_monitor_enable_receiving(monitor);
	item.fd = udev_monitor_get_fd(monitor);
	item.events = POLLIN;
	item.revents = 0;
	while (!stoprequested) {
		struct udev_device *dev;
		const char *path, *action;
		unsigned int cpunum;
		int rc, on, off;

		errno = 0;
		rc = poll(&item, 1, -1);
		if (rc == -1) {
			if (errno == EINTR)
				continue;
			break;
		}
		dev = udev_monitor_receive_device(monitor);
		if (dev == NULL)
			continue;
		action = udev_device_get_action(dev);
		if (action == NULL)
			continue;
		off = strcmp(action, "offline") == 0;
		on = strcmp(action, "online") == 0;
		if (!on && !off)
			continue;
		path = udev_device_get_devpath(dev);
		if (sscanf(path, "/devices/system/cpu/cpu%u", &cpunum) != 1)
			continue;
		if (on && activatecpu(cpunum))
			eprint("Failed to attach to hotplugged CPU %u\n", cpunum);
		if (off)
			deactivatecpu(cpunum);
	}
	udev_monitor_unref(monitor);
	udev_unref(hotplug);
	return NULL;
}

int perf_init(void)
{
	int ecc_supported;

	/*  initialize performance monitoring library */
	if (!perf_supported()) {
		eprint("Performance counter not supported");
		return -1;
	}

	/* Check if ECC is supported on current hardware */
	ecc_supported = perf_counter_supported("cpum_cf", "ECC_FUNCTION_COUNT");
	if (!ecc_supported)
		ctr_state[ECC_FUNCTIONS] = UNSUPPORTED;

	if (perf_load_counter_data())
		return -1;
	if (pthread_create(&hotplugthread, NULL, hotplughandler, NULL)) {
		eprint("Failed to start hotplug handler thread\n");
		return -1;
	}
	return addallcpus();
}


void perf_stop(void)
{
	stoprequested = 1;
}


void perf_close(void)
{
	struct percpucounter *walk, *next;

	pthread_kill(hotplugthread, SIGINT);
	pthread_join(hotplugthread, NULL);
	walk = root;
	while (walk) {
		next = walk->next;
		freepercpucounter(walk);
		walk = next;
	}
}


int perf_enable_ctr(enum ctr_e ctr)
{
	struct percpucounter *pcpu;
	int ec, rc = 0;

	if (ctr == ALL_COUNTER) {
		for (ctr = 0; ctr < ALL_COUNTER; ctr++) {
			rc = perf_enable_ctr(ctr);
			if (rc != 0)
				return rc;
		}
	} else if (ctr < ALL_COUNTER) {
		foreachcpu(pcpu) {
			ec = ioctl(pcpu->ctr_fds[ctr], PERF_EVENT_IOC_ENABLE, 0);
			if (ec < 0) {
				eprint("Ioctl(PERF_EVENT_IOC_ENABLE) failed with errno=%d [%s]\n",
				       errno, strerror(errno));
				rc = -1;
			}
		}
		ctr_state[ctr] = ENABLED;
		++enabledcounter;
		endforeachcpu();
	} else {
		rc = -1;
	}

	return rc;
}


int perf_disable_ctr(enum ctr_e ctr)
{
	struct percpucounter *pcpu;
	int ec, rc = 0;

	if (ctr == ALL_COUNTER) {
		for (ctr = 0; ctr < ALL_COUNTER; ctr++) {
			rc = perf_disable_ctr(ctr);
			if (rc != 0)
				return rc;
		}
	} else if (ctr < ALL_COUNTER) {
		foreachcpu(pcpu) {
			ec = ioctl(pcpu->ctr_fds[ctr], PERF_EVENT_IOC_DISABLE, 0);
			if (ec < 0) {
				eprint("Ioctl(PERF_EVENT_IOC_DISABLE) failed with errno=%d [%s]\n",
				       errno, strerror(errno));
				rc = -1;
			}
		}
		ctr_state[ctr] = DISABLED;
		--enabledcounter;
		if (enabledcounter == 0)
			hotplugdetected = 0;
		endforeachcpu();
	} else {
		rc = -1;
	}

	return rc;
}


int perf_reset_ctr(enum ctr_e ctr)
{
	struct percpucounter *pcpu;
	int ec, rc = 0;

	if (ctr == ALL_COUNTER) {
		for (ctr = 0; ctr < ALL_COUNTER; ctr++) {
			rc = perf_reset_ctr(ctr);
			if (rc != 0)
				return rc;
		}
	} else if (ctr < ALL_COUNTER) {
		foreachcpu(pcpu) {
			ec = ioctl(pcpu->ctr_fds[ctr], PERF_EVENT_IOC_RESET, 0);
			if (ec < 0) {
				eprint("Ioctl(PERF_EVENT_IOC_RESET) failed with errno=%d [%s]\n",
				       errno, strerror(errno));
				rc = -1;
			}
		}
		endforeachcpu();
	} else {
		rc = -1;
	}

	return rc;
}


int perf_read_ctr(enum ctr_e ctr, uint64_t *value)
{
	struct percpucounter *pcpu;
	int ec, rc = -1;
	uint64_t val;

	if (!value)
		return -1;
	if (ctr == HOTPLUG_DETECTED) {
		*value = hotplugdetected;
		return 0;
	}
	if (ctr >= ALL_COUNTER)
		return -1;
	*value = 0;

	foreachcpu(pcpu) {
		ec = read(pcpu->ctr_fds[ctr], &val, sizeof(val));
		if (ec != sizeof(val)) {
			eprint("Read() on perf file descriptor failed with errno=%d [%s]\n",
			       errno, strerror(errno));
		} else {
			*value += val;
			rc = 0;
		}
	}
	endforeachcpu();

	return rc;
}

int  perf_ecc_supported(void)
{
	return ctr_state[ECC_FUNCTIONS] != UNSUPPORTED;
}

int perf_ctr_state(enum ctr_e ctr) {
	if (ctr < ALL_COUNTER)
		return ctr_state[ctr];
	return UNSUPPORTED;
}
