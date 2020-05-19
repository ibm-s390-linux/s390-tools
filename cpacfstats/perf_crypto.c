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

#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <perfmon/perf_event.h>
#include <perfmon/pfmlib.h>
#include <perfmon/pfmlib_perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cpacfstats.h"

#define PERF_ECC_COUNTER_NAME "cpum_cf::ECC_FUNCTION_COUNT"

/* correlation between counter and perf counter string */
static const struct {
	char pfm_name[80];
	enum ctr_e ctr;
} pmf_counter_name[ALL_COUNTER] = {
	{"cpum_cf::DEA_FUNCTIONS", DES_FUNCTIONS},
	{"cpum_cf::AES_FUNCTIONS", AES_FUNCTIONS},
	{"cpum_cf::SHA_FUNCTIONS", SHA_FUNCTIONS},
	{"cpum_cf::PRNG_FUNCTIONS", PRNG_FUNCTIONS},
	{PERF_ECC_COUNTER_NAME, ECC_FUNCTIONS}
};

/*
 * We need one filedescriptor per CPU per counter.
 * So perf_init builds this:
 *
 * ctr_fds - is an array of pointers to file descriptor arrays.
 * Each file descriptor array has space for number of logical CPUs + 1
 * filedescriptors (int values). The last element of each file descriptor
 * array is always 0, assuming there will never appear a filedescriptor
 * with value 0:
 *
 * ctr_fds:
 *   ctr_fds[0]             -> [file descriptor 0] [fd1] ... [fd cpus-1][0]
 *   ctr_fds[1]             -> [file descriptor 0] [fd1] ... [fd cpus-1][0]
 *   ...
 *   ctr_fds[ALL_COUNTER-1] -> [file descriptor 0] [fd1] ... [fd cpus-1][0]
 */
static int *ctr_fds[ALL_COUNTER];

static int ecc_supported;

int perf_init(void)
{
	int i, cpus, ctr, cpu, ec, *fds;

	memset(ctr_fds, 0, sizeof(ctr_fds));

	/*  initialize performance monitoring library */
	ec = pfm_initialize();
	if (ec != PFM_SUCCESS) {
		eprint("Pfm_initialize() returned with failure (%d:%s)\n",
		       ec, pfm_strerror(ec));
		return -1;
	}

	/* Check if ECC is supported on current hardware */
	if (pfm_find_event(PERF_ECC_COUNTER_NAME) >= 0)
		ecc_supported = 1;

	/* get number of logical processors */
	cpus = sysconf(_SC_NPROCESSORS_ONLN);

	/* for each counter */
	for (ctr = 0; ctr < ALL_COUNTER; ctr++) {

		/* Skip ECC counters completely if unsupported */
		if (ctr == ECC_FUNCTIONS && !ecc_supported)
			continue;

		/*
		 * allocate an array of ints to store for each CPU
		 * one filedescriptor + a terminating 0
		 */
		fds = (int *) calloc(sizeof(int), cpus+1);
		if (!fds) {
			eprint("Malloc() of %d byte failed, errno=%d [%s]\n",
			       (int)(sizeof(int) * (cpus+1)),
			       errno, strerror(errno));
			return -1;
		}

		ctr_fds[ctr] = fds;

		/* search for the counter's corresponding pfm name */
		for (i = ALL_COUNTER-1; i >= 0; i--)
			if ((int) pmf_counter_name[i].ctr == ctr)
				break;
		if (i < 0) {
			eprint("Pfm ctr name not found for counter %d, please adjust pmf_counter_name[] in %s\n",
			       ctr, __FILE__);
			return -1;
		}

		for (cpu = 0; cpu < cpus; cpu++) {
			pfm_perf_encode_arg_t pfm_arg;
			struct perf_event_attr pfm_event;
			int fd;

			memset(&pfm_arg, 0, sizeof(pfm_arg));
			memset(&pfm_event, 0, sizeof(pfm_event));
			pfm_arg.attr = &pfm_event;
			pfm_arg.size = sizeof(pfm_arg);
			pfm_event.size = sizeof(pfm_event);

			/* encode the counters perf event into pfm_arg.attr */
			ec = pfm_get_os_event_encoding(
				pmf_counter_name[i].pfm_name,
				PFM_PLM0,
				PFM_OS_PERF_EVENT,
				&pfm_arg);
			if (ec != PFM_SUCCESS) {
				eprint("Pfm_initialize() for %s failed (%d:%s)\n",
				       pmf_counter_name[i].pfm_name,
				       ec, pfm_strerror(ec));
				return -1;
			}

			/* fetch file descriptor for this perf event
			 * the counter event should start disabled
			 */
			pfm_event.disabled = 1;
			fd = perf_event_open(
				&pfm_event,
				-1,  /* pid -1 means all processes */
				cpu,
				-1,  /* group filedescriptor */
				0);  /* flags */
			if (fd < 0) {
				eprint("Perf_event_open() failed with errno=%d [%s]\n",
				       errno, strerror(errno));
				return -1;
			}
			fds[cpu] = fd;
		}
	}

	return 0;
}


void perf_close(void)
{
	int ctr, *fds;

	for (ctr = 0; ctr < ALL_COUNTER; ctr++) {
		for (fds = ctr_fds[ctr]; fds && *fds; fds++) {
			close(*fds);
			*fds = 0;
		}
		free(ctr_fds[ctr]);
		ctr_fds[ctr] = NULL;
	}
}


int perf_enable_ctr(enum ctr_e ctr)
{
	int *fds, ec, rc = 0;

	if (ctr == ALL_COUNTER) {
		for (ctr = 0; ctr < ALL_COUNTER; ctr++) {
			rc = perf_enable_ctr(ctr);
			if (rc != 0)
				return rc;
		}
	} else {
		for (fds = ctr_fds[ctr]; fds && *fds; fds++) {
			ec = ioctl(*fds, PERF_EVENT_IOC_ENABLE, 0);
			if (ec < 0) {
				eprint("Ioctl(PERF_EVENT_IOC_ENABLE) failed with errno=%d [%s]\n",
				       errno, strerror(errno));
				rc = -1;
			}
		}
	}

	return rc;
}


int perf_disable_ctr(enum ctr_e ctr)
{
	int *fds, ec, rc = 0;

	if (ctr == ALL_COUNTER) {
		for (ctr = 0; ctr < ALL_COUNTER; ctr++) {
			rc = perf_disable_ctr(ctr);
			if (rc != 0)
				return rc;
		}
	} else {
		for (fds = ctr_fds[ctr]; fds && *fds; fds++) {
			ec = ioctl(*fds, PERF_EVENT_IOC_DISABLE, 0);
			if (ec < 0) {
				eprint("Ioctl(PERF_EVENT_IOC_DISABLE) failed with errno=%d [%s]\n",
				       errno, strerror(errno));
				rc = -1;
			}
		}
	}

	return rc;
}


int perf_reset_ctr(enum ctr_e ctr)
{
	int *fds, ec, rc = 0;

	if (ctr == ALL_COUNTER) {
		for (ctr = 0; ctr < ALL_COUNTER; ctr++) {
			rc = perf_reset_ctr(ctr);
			if (rc != 0)
				return rc;
		}
	} else {
		for (fds = ctr_fds[ctr]; fds && *fds; fds++) {
			ec = ioctl(*fds, PERF_EVENT_IOC_RESET, 0);
			if (ec < 0) {
				eprint("Ioctl(PERF_EVENT_IOC_RESET) failed with errno=%d [%s]\n",
				       errno, strerror(errno));
				rc = -1;
			}
		}
	}

	return rc;
}


int perf_read_ctr(enum ctr_e ctr, uint64_t *value)
{
	int *fds, ec, rc = -1;
	uint64_t val;

	if (!value)
		return -1;
	*value = 0;

	for (fds = ctr_fds[ctr]; fds && *fds; fds++) {
		ec = read(*fds, &val, sizeof(val));
		if (ec != sizeof(val)) {
			eprint("Read() on perf file descriptor failed with errno=%d [%s]\n",
			       errno, strerror(errno));
		} else {
			*value += val;
			rc = 0;
		}
	}

	return rc;
}

int  perf_ecc_supported(void)
{
	return ecc_supported;
}
