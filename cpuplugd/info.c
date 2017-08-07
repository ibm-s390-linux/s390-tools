/*
 * cpuplugd - Linux for System z Hotplug Daemon
 *
 * /proc info functions
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <sys/stat.h>
#include <sys/types.h>

#include "cpuplugd.h"

/*
 * Return current load average and runnable processes based on /proc/loadavg
 *
 * Example: 0.20 0.18 0.12 1/80 11206
 *
 * The first three columns measure CPU utilization of the last 1, 5,
 * and 15 minute periods.
 * The fourth column shows the number of currently running processes
 * and the total number of processes.
 * The last column displays the last process ID used.
 */
void get_loadavg_runnable(double *loadavg, double *runnable)
{
	FILE *filp;
	double dummy;
	int rc;

	filp = fopen("/proc/loadavg", "r");
	if (!filp)
		cpuplugd_exit("cannot open kernel loadaverage "
			      "statistics: %s\n", strerror(errno));
	rc = fscanf(filp, "%lf %lf %lf %lf/", loadavg, &dummy, &dummy,
		    runnable);
	if (rc != 4)
		cpuplugd_exit("cannot parse kernel loadaverage "
			      "statistics: %s\n", strerror(errno));
	fclose(filp);
	return;
}

void proc_cpu_read(char *procinfo)
{
	FILE *filp;
	unsigned int rc, onumcpus;
	unsigned long user, nice, system, idle, iowait, irq, softirq, steal,
		      guest, guest_nice, total_ticks;
	double loadavg, runnable;

	guest = guest_nice = 0;		/* set to 0 if not present in kernel */
	filp = fopen("/proc/stat", "r");
	if (!filp)
		cpuplugd_exit("/proc/stat open failed: %s\n", strerror(errno));
	rc = fscanf(filp, "cpu %ld %ld %ld %ld %ld %ld %ld %ld %ld %ld", &user,
		    &nice, &system, &idle, &iowait, &irq, &softirq, &steal,
		    &guest, &guest_nice);

	get_loadavg_runnable(&loadavg, &runnable);
	onumcpus = get_num_online_cpus();
	total_ticks = user + nice + system + idle + iowait + irq + softirq +
		      steal + guest + guest_nice;

	rc = snprintf(procinfo, cpustat_size, "onumcpus %d\nloadavg %f\n"
		      "runnable_proc %f\nuser %ld\nnice %ld\nsystem %ld\n"
		      "idle %ld\niowait %ld\nirq %ld\nsoftirq %ld\nsteal %ld\n"
		      "guest %ld\nguest_nice %ld\ntotal_ticks %ld\n",
		      onumcpus, loadavg, runnable, user, nice, system, idle,
		      iowait, irq, softirq, steal, guest, guest_nice,
		      total_ticks);
	if (rc >= cpustat_size)
		cpuplugd_exit("cpustat buffer too small: need %d, have %ld "
			      "(bytes)\n", rc, cpustat_size);
	fclose(filp);
	return;
}

void proc_read(char *procinfo, char *path, unsigned long size)
{
	size_t bytes_read;
	FILE *filp;

	filp = fopen(path, "r");
	if (!filp)
		cpuplugd_exit("%s open failed: %s\n", path, strerror(errno));

	bytes_read = fread(procinfo, 1, size, filp);
	if (bytes_read == 0)
		cpuplugd_exit("%s read failed\n", path);
	if (bytes_read == size)
		cpuplugd_exit("procinfo buffer too small for %s\n", path);

	procinfo[bytes_read] = '\0';
	fclose(filp);
	return;
}

unsigned long proc_read_size(char *path)
{
	FILE *filp;
	char buf[PROCINFO_LINE];
	char *linep, *linep_offset;
	unsigned long size;

	filp = fopen(path, "r");
	if (!filp)
		cpuplugd_exit("%s open failed: %s\n", path, strerror(errno));

	size = 0;
	while ((linep = fgets(buf, sizeof(buf), filp))) {
		if (!(linep_offset = strchr(linep, '\n')))
			cpuplugd_exit("buf too small for line\n");
		size = size + linep_offset - linep + 1;
	}
	fclose(filp);
	return size;
}

double get_proc_value(char *procinfo, char *name, char separator)
{
	char buf[PROCINFO_LINE];
	char *proc_offset;
	unsigned long proc_length, name_length;
	double value;
	int found;

	value = -1;
	found = 0;
	name_length = strlen(name);
	while ((proc_offset = strchr(procinfo, separator))) {
		proc_length = proc_offset - procinfo;
		/*
		 * proc_read_size() made sure that proc_length < PROCINFO_LINE
		 */
		memcpy(buf, procinfo, proc_length);
		buf[proc_length] = '\0';
		procinfo = proc_offset + 1;
		if (strncmp(buf, name, MAX(proc_length, name_length)) == 0) {
			errno = 0;
			value = strtod(procinfo, NULL);
			if (errno)
				cpuplugd_exit("strtod failed\n");
			found = 1;
			break;
		}
		proc_offset = strchr(procinfo, '\n');
		procinfo = proc_offset + 1;
	}
	if (!found)
		cpuplugd_exit("Symbol %s not found, check your config file\n",
			      name);
	return value;
}
