/*
 * cpuplugd - Linux for System z Hotplug Daemon
 *
 * CPU hotplug functions
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <limits.h>
#include "cpuplugd.h"


/*
 * Return overall number of available cpus. This does not necessarily
 * mean that those are currently online
 */
int get_numcpus()
{
	int i;
	char path[PATH_MAX];
	int number = 0;

	for (i = 0; ; i++) {
		/* check whether file exists and is readable */
		sprintf(path, "/sys/devices/system/cpu/cpu%d/online", i);
		if (access(path, R_OK) == 0)
			number++;
		else
			break;
	}
	return number;
}

/*
 * Return number of online cpus
 */
int get_num_online_cpus()
{
	FILE *filp;
	int i;
	char path[PATH_MAX];
	int status = 0;
	int value_of_onlinefile, rc;

	for (i = 0; i <= get_numcpus(); i++) {
		/* check wether file exists and is readable */
		sprintf(path, "/sys/devices/system/cpu/cpu%d/online", i);
		if (access(path, R_OK) != 0)
			continue;
		filp = fopen(path, "r");
		if (!filp)
			cpuplugd_exit("Cannot open cpu online file: "
				      "%s\n", strerror(errno));
		else {
			rc = fscanf(filp, "%d", &value_of_onlinefile);
			if (rc != 1)
				cpuplugd_exit("Cannot read cpu online file: "
					      "%s\n", strerror(errno));
			if (value_of_onlinefile == 1)
				status++;
		}
		fclose(filp);
	}
	return status;
}

/*
 * Enable a certain cpu
 */
int hotplug(int cpuid)
{
	FILE *filp;
	char path[PATH_MAX];
	int status, rc;

	sprintf(path, "/sys/devices/system/cpu/cpu%d/online", cpuid);
	if (access(path, W_OK) == 0) {
		filp = fopen(path, "w");
		if (!filp)
			cpuplugd_exit("Cannot open cpu online file: %s\n",
				      strerror(errno));
		fprintf(filp, "1");
		fclose(filp);
		/*
		 * check if the attempt to enable the cpus really worked
		 */
		filp = fopen(path, "r");
		rc = fscanf(filp, "%d", &status);
		if (rc != 1)
			cpuplugd_exit("Cannot open cpu online file: %s\n",
				      strerror(errno));
		fclose(filp);
		if (status == 1) {
			cpuplugd_debug("cpu with id %d enabled\n", cpuid);
			return 1;
		} else {
			cpuplugd_debug("failed to enable cpu with id %d\n",
				      cpuid);
			return -1;
		}
	} else {
		cpuplugd_error("hotplugging cpu with id %d failed\n", cpuid);
		return -1;
	}
	return -1;
}

/*
 * Disable a certain cpu
 */
int hotunplug(int cpuid)
{
	FILE *filp;
	int state, rc;
	int retval = -1;
	char path[PATH_MAX];

	state = -1;
	sprintf(path, "/sys/devices/system/cpu/cpu%d/online", cpuid);
	if (access(path, W_OK) == 0) {
		filp = fopen(path, "w");
		fprintf(filp, "0");
		fclose(filp);
		/*
		 * Check if the attempt to enable the cpus really worked
		 */
		filp = fopen(path, "r");
		rc = fscanf(filp, "%d", &state);
		if (rc != 1)
			cpuplugd_error("Failed to disable cpu with id %d\n",
				       cpuid);
		fclose(filp);
		if (state == 0)
			return 1;
	} else {
		cpuplugd_error("unplugging cpu with id %d failed\n", cpuid);
	}
	return retval;
}

/*
 * Check if a certain cpu is currently online
 */
int is_online(int cpuid)
{
	FILE *filp;
	int state;
	int retval, rc;
	char path[PATH_MAX];

	retval = -1;
	sprintf(path, "/sys/devices/system/cpu/cpu%d/online", cpuid);
	if (access(path, R_OK) == 0) {
		filp = fopen(path, "r");
		rc = fscanf(filp, "%d", &state);
		if (rc == 1) {
			if (state == 1)
				retval = 1;
			if (state == 0)
				retval = 0;
			fclose(filp);
		}
	}
	return retval;
}

/*
 * Cleanup method. If the daemon is stopped, we (re)activate all cpus
 */
void reactivate_cpus()
{
	/*
	 * Only enable the number of cpus which where
	 * available at daemon startup time
	 */
	int cpuid, nc;

	cpuid = 0;
	/* suppress verbose messages on exit */
	debug = 0;
       /*
	* We check for num_cpu_start != 0 because we might want to
	* clean up, before we queried for the number on cpus at
	* startup
	*/
	if (num_cpu_start == 0)
		return;
	while (get_num_online_cpus() != num_cpu_start && cpuid < get_numcpus()) {
		nc = get_num_online_cpus();
		if (nc == num_cpu_start)
			return;
		if (nc > num_cpu_start && is_online(cpuid) == 1)
			hotunplug(cpuid);
		if (nc < num_cpu_start && is_online(cpuid) == 0)
			hotplug(cpuid);
		cpuid++;
	}
}

/*
 * In kernels > 2.6.24 cpus can be deconfigured. The following functions is used
 * to check if a certain cpus is in a deconfigured state.
 */
int cpu_is_configured(int cpuid)
{
	FILE *filp;
	int retval, state, rc;
	char path[4096];

	retval = -1;
	sprintf(path, "/sys/devices/system/cpu/cpu%d/configure", cpuid);
	if (access(path, R_OK) == 0) {
		filp = fopen(path, "r");
		rc = fscanf(filp, "%d", &state);
		if (rc == 1) {
			if (state == 1)
				retval = 1;
			if (state == 0)
				retval = 0;
			fclose(filp);
		}
	}
	return retval;
}
