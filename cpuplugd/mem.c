/*
 * cpuplugd - Linux for System z Hotplug Daemon
 *
 * cmm functions
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "cpuplugd.h"

/*
 * The cmm_pages value defines the size of the balloon of blocked memory.
 * Increasing the value is removing memory from Linux, which is an memunplug.
 * Decreasing the value is adding memory back to Linux, which is memplug.
 */

/*
 * Set the value of cmm_pages
 */
void set_cmm_pages(long pages)
{
	FILE *filp;

	filp = fopen("/proc/sys/vm/cmm_pages", "w");
	if (!filp)
		cpuplugd_exit("Cannot open /proc/sys/vm/cmmpages: %s\n",
			      strerror(errno));
	cpuplugd_debug("changing number of pages permanently reserved to %ld\n",
		       pages);
	fprintf(filp, "%ld\n", pages);
	fclose(filp);
	return;
}

/*
 * Read number of pages permanently reserved
 */
long get_cmmpages_size()
{
	FILE *filp;
	long size;
	int rc;

	filp = fopen("/proc/sys/vm/cmm_pages", "r");
	if (!filp)
		cpuplugd_exit("Cannot open /proc/sys/vm/cmm_pages: %s\n",
			      strerror(errno));
	rc = fscanf(filp, "%ld", &size);
	if (rc == 0)
		cpuplugd_exit("Can not read /proc/sys/vm/cmm_pages: %s\n",
			      strerror(errno));
	fclose(filp);
	return size;
}

/*
 * Reset cmm pagesize to value we found prior to daemon startup
 */
void cleanup_cmm()
{
	set_cmm_pages(cmm_pagesize_start);
	return;
}

/*
 * Function to check if the cmm kernel module is loaded and the required
 * files below /proc exit
 */
int check_cmmfiles(void)
{
	FILE *filp;

	filp = fopen("/proc/sys/vm/cmm_pages", "r");
	if (!filp)
		return -1;
	fclose(filp);
	return 0;
}

