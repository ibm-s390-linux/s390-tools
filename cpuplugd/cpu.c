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

#define NUM_BASE		(10)
#define CPU_OFFLINE		(0)
#define CPU_ONLINE		(1)
#define CPU_DECONFIGURED	(0)
#define CPU_CONFIGURED		(1)
#define CPU_LIST_LEN		(4096)

static int get_sysfs_attribute_cpu_count(char *path)
{
	char cpu_list[CPU_LIST_LEN];
	int number, start, end;
	char *sub_list;

	if (util_file_read_line(cpu_list, sizeof(cpu_list), path))
		cpuplugd_exit("Cannot open %s file: %s\n", path, strerror(errno));
	number = 0;
	sub_list = strtok(cpu_list, ",");
	while (sub_list) {
		if (strchr(sub_list, '-')) {
			if (sscanf(sub_list, "%d-%d", &start, &end) != 2)
				cpuplugd_exit("Malformed content of %s: %s\n", path, sub_list);
			number += (end - start) + 1;
		} else {
			number++;
		}
		sub_list = strtok(NULL, ",");
	}
	return number;
}

/*
 * get_numcpus() - return number of present cpus by sysfs'
 * cpu/present attribute.
 * This number represents the total number of usable cpus,
 * this includes offline or deconfigured cpus as well.
 */
int get_numcpus(void)
{
	int number;
	char *path;

	path = util_path_sysfs("devices/system/cpu/present");
	number = get_sysfs_attribute_cpu_count(path);
	free(path);
	if (number <= 0)
		cpuplugd_exit("number of present cpus (%d) <= 0\n", number);
	return number;
}

/*
 * get_num_online_cpus() - return number of online cpus
 * by parsing sysfs cpu/online attribute
 */
int get_num_online_cpus(void)
{
	int number;
	char *path;

	path = util_path_sysfs("devices/system/cpu/online");
	number = get_sysfs_attribute_cpu_count(path);
	free(path);
	if (number <= 0)
		cpuplugd_exit("number of online cpus (%d) <= 0\n", number);
	return number;
}

/*
 * is_cpu_hotpluggable() - check if cpuhotplug operations are supported
 * for the given cpu.
 */
static int is_cpu_hotpluggable(int cpuid)
{
	char *path;
	int rc;

	path = util_path_sysfs("devices/system/cpu/cpu%d/online", cpuid);
	rc = util_path_exists(path);
	free(path);
	return rc;
}

/*
 * hotplug() - perform cpu hotplug on given cpuid
 */
static int hotplug(int cpuid)
{
	char *path;
	int rc;

	path = util_path_sysfs("devices/system/cpu/cpu%d/online", cpuid);
	rc = util_file_write_l(CPU_ONLINE, NUM_BASE, path);
	if (rc < 0)
		cpuplugd_debug("failed to enable cpu with id %d\n", cpuid);
	free(path);
	return rc;
}

/*
 * hotunplug() - perform cpu hotunplug on given cpuid
 */
static int hotunplug(int cpuid)
{
	char *path;
	int rc;

	path = util_path_sysfs("devices/system/cpu/cpu%d/online", cpuid);
	rc = util_file_write_l(CPU_OFFLINE, NUM_BASE, path);
	if (rc < 0)
		cpuplugd_debug("failed to disable cpu with id %d\n", cpuid);
	free(path);
	return rc;
}

/*
 * get_cpu_attribute() - get a certain cpu's selected attribute
 */
static int get_cpu_attribute(int cpuid, char *attribute)
{
	int status;
	char *path;

	path = util_path_sysfs("devices/system/cpu/cpu%d/%s", cpuid, attribute);
	if (util_file_read_i(&status, NUM_BASE, path) < 0) {
		status = -1;
		cpuplugd_debug("failed to read %s status of cpu with id %d\n", attribute, cpuid);
	}
	free(path);
	return status;
}

/*
 * hotplug_one_cpu() - perform hotplugging on the first available cpu
 */
int hotplug_one_cpu(void)
{
	struct dirent **cpu_dir;
	int cpuid, count, i, rc;
	char *path;

	rc = -1;
	path = util_path_sysfs("devices/system/cpu/");
	count = util_scandir(&cpu_dir, alphasort, path, "cpu[0-9]*");
	for (i = 0; (i < count) && (rc != 0); i++) {
		if (sscanf(cpu_dir[i]->d_name, "cpu%d", &cpuid) != 1)
			cpuplugd_exit("Malformed content of %s: %s\n", path, cpu_dir[i]->d_name);
		if (!is_cpu_hotpluggable(cpuid))
			continue;
		if (get_cpu_attribute(cpuid, "configure") == CPU_CONFIGURED &&
		    get_cpu_attribute(cpuid, "online") == CPU_OFFLINE) {
			cpuplugd_debug("cpu%d will be enabled", cpuid);
			rc = hotplug(cpuid);
		}
	}
	util_scandir_free(cpu_dir, count);
	free(path);
	return rc;
}

/*
 * hotunplug_one_cpu() - perform hotunplugging on the first available cpu
 */
int hotunplug_one_cpu(void)
{
	struct dirent **cpu_dir;
	int cpuid, count, i, rc;
	char *path;

	rc = -1;
	path = util_path_sysfs("devices/system/cpu/");
	count = util_scandir(&cpu_dir, alphasort, path, "cpu[0-9]*");
	for (i = 0; (i < count) && (rc != 0); i++) {
		if (sscanf(cpu_dir[i]->d_name, "cpu%d", &cpuid) != 1)
			cpuplugd_exit("Malformed content of %s: %s\n", path, cpu_dir[i]->d_name);
		if (!is_cpu_hotpluggable(cpuid))
			continue;
		if (get_cpu_attribute(cpuid, "online") == CPU_ONLINE) {
			cpuplugd_debug("cpu%d will be disabled\n", cpuid);
			rc = hotunplug(cpuid);
		}
	}
	util_scandir_free(cpu_dir, count);
	free(path);
	return rc;
}

/*
 * Cleanup method. If the daemon is stopped, we (re)activate all cpus
 */
void reactivate_cpus(void)
{
	struct dirent **cpu_dir;
	int cpuid, nc, count, i;
	char *path;

	/* suppress verbose messages on exit */
	debug = 0;
	/*
	 * Only enable the number of cpus which where available at
	 * daemon startup time by checking num_cpu_start.
	 * We check for num_cpu_start != 0 because we might want to
	 * clean up, before we queried for the number on cpus at
	 * startup
	 */
	if (num_cpu_start == 0)
		return;
	nc = 0;
	path = util_path_sysfs("devices/system/cpu/");
	count = util_scandir(&cpu_dir, alphasort, path, "cpu[0-9]*");
	for (i = 0; (i < count) && (nc != num_cpu_start); i++) {
		nc = get_num_online_cpus();
		if (sscanf(cpu_dir[i]->d_name, "cpu%d", &cpuid) != 1)
			cpuplugd_exit("Malformed content of %s: %s\n", path, cpu_dir[i]->d_name);
		if (nc > num_cpu_start &&
		    get_cpu_attribute(cpuid, "online") == CPU_ONLINE)
			hotunplug(cpuid);
		if (nc < num_cpu_start &&
		    get_cpu_attribute(cpuid, "online") == CPU_OFFLINE)
			hotplug(cpuid);
	}
	util_scandir_free(cpu_dir, count);
	free(path);
}

