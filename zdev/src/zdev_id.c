/*
 * zdev_id - Determine system characteristics required by zdev udev rules
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "zdev_id.h"

#define	SYSINFO		"/proc/sysinfo"
#define	CMDLINE		"/proc/cmdline"
#define LOADPARM	"/sys/firmware/ipl/loadparm"
#define IPL_DEV_ID	"/sys/firmware/ipl/device"
#define IPL_DEV_TYPE	"/sys/firmware/ipl/ipl_type"
#define SITE_FALLBACK	10

#define	WHITESPACE	" \t\n"

static void array_add(char ***array_p, int *num_p, const char *str)
{
	char **array = *array_p, *copy;
	int num = *num_p + 1;

	array = realloc(array, num * sizeof(char *));
	copy = strdup(str);
	if (!array || !copy)
		err(1, "Could not allocate memory");
	array[num - 1] = copy;
	*array_p = array;
	*num_p = num;
}

static void array_free(char **array, int num)
{
	int i;

	for (i = 0; i < num; i++)
		free(array[i]);
	free(array);
}

static void process_sysinfo(const char *filename)
{
	char *line = NULL, *substr, **cps = NULL;
	int is_dpm = 0, num_cps = 0, level, i;
	FILE *fd;
	size_t n;

	fd = fopen(filename, "r");
	if (!fd)
		err(1, "Could not open sysinfo file '%s'", filename);

	while (getline(&line, &n, fd) != -1) {
		if (sscanf(line, "LPAR %m[^:]", &substr) == 1) {
			if (strcmp(substr, "UUID") == 0) {
				/* Heuristic: only DPM LPARs have UUIDs. */
				is_dpm = 1;
			} else if (strcmp(substr, "Number") == 0) {
				array_add(&cps, &num_cps, "LPAR");
			}
			free(substr);
		} else if (sscanf(line, "VM%*d Control Program: %ms ",
				  &substr) == 1) {
			array_add(&cps, &num_cps, substr);
			free(substr);
		}
	}

	free(line);
	fclose(fd);

	/*
	 * ZDEV_NEST_LEVEL=n
	 *
	 * Virtualization nesting level of running system:
	 *  1: LPAR
	 *  2: first level VM
	 *  3: second level VM
	 */
	printf("ZDEV_NEST_LEVEL=%d\n", num_cps);

	/*
	 * ZDEV_HYPERVISOR_<n>=LPAR|z/VM|KVM/Linux
	 *
	 * Type of hypervisor that provides virtualization at nesting level <n>.
	 */
	for (i = 0; i < num_cps; i++) {
		/* Sysinfo lists VMs in reverse order .*/
		level = (i == 0) ? i : (num_cps - i);
		printf("ZDEV_HYPERVISOR_%d=\"%s\"\n", i, cps[level]);
	}
	array_free(cps, num_cps);

	/*
	 * ZDEV_IS_DPM=0|1
	 *
	 * Indicator if top-level LPAR is managed by Dynamic Partition
	 * Manager (DPM):
	 *  0: Classic mode
	 *  1: DPM mode
	 */
	printf("ZDEV_IS_DPM=%d\n", is_dpm);
}

static void process_cmdline(const char *filename)
{
	char *line = NULL, *substr, *next = NULL, *value;
	int no_auto = 0;
	size_t n;
	FILE *fd;

	fd = fopen(filename, "r");
	if (!fd)
		err(1, "Could not open cmdline file '%s'", filename);

	if (getline(&line, &n, fd) == -1)
		goto out;

	for (substr = strtok_r(line, WHITESPACE, &next); substr;
	     substr = strtok_r(NULL, WHITESPACE, &next)) {
		if (sscanf(substr, "rd.zdev=%ms ", &value) != 1)
			continue;
		if (strstr(value, "no-auto"))
			no_auto = 1;

		free(value);
	}

out:
	free(line);
	fclose(fd);

	/*
	 * ZDEV_NO_AUTO=0|1
	 *
	 * Indicator if auto-configuration is requested.
	 *  0: Perform auto-configuration
	 *  1: Skip auto-configuration
	 */
	printf("ZDEV_NO_AUTO=%d\n", no_auto);
}

/*
 * If the erraneous loadparm provides a site_id which is not valid,
 * default it to the common-site id.
 */
static int validate_site(int site_id)
{
	if (site_id < SITE_FALLBACK)
		return site_id;
	return SITE_FALLBACK;
}

/* get the ipl device and extract the SSID */
static int get_site_id(void)
{
	FILE *fd;
	char *line;
	size_t n;
	int site_id = SITE_FALLBACK, ssid;

	fd = fopen(IPL_DEV_ID, "r");
	if (!fd)
		goto fail_safe;

	if (getline(&line, &n, fd) == -1)
		goto out;

	if (sscanf(line, "%*d.%d.%*d", &ssid) == 1)
		site_id = validate_site(ssid);

out:
	free(line);
	fclose(fd);
fail_safe:
	return site_id;
}

/*
 * Find the ipl type and see if it belongs to ccw  or zfcp, if different,
 * default it to common-site.
 */
static int read_ssid(void)
{
	FILE *fd;
	char *line = NULL;
	size_t n;
	int site_id = SITE_FALLBACK;

	fd = fopen(IPL_DEV_TYPE, "r");
	if (!fd)
		goto out;

	if (getline(&line, &n, fd) != -1) {
		if (strcmp(line, "ccw") == 0 || strcmp(line, "zfcp"))
			site_id =  get_site_id();
	}

	free(line);
	fclose(fd);
out:
	return site_id;
}

static void write_zdev_site_id(int site_id)
{
	FILE *fd;
	int tmpfd, rc;
	const char zdev_id_file[] = ZDEV_SITE_ID_FILE;
	char zdev_id_tmpfile[] = ZDEV_SITE_ID_FILE "-XXXXXX";

	tmpfd = mkstemp(zdev_id_tmpfile);
	if (tmpfd == -1)
		goto err;

	/* Open the temp file to use with fprintf */
	fd = fdopen(tmpfd, "w");
	if (!fd)
		goto err;

	if (site_id == SITE_FALLBACK)
		rc = fprintf(fd, "ZDEV_SITE_ID=\"\"\n");
	else
		rc = fprintf(fd, "ZDEV_SITE_ID=%d\n", site_id);

	if (rc < 0) {
		fclose(fd);
		goto err;
	}

	if (fclose(fd))
		goto err;

	/* Rename the temporary file to ZDEV_SITE_ID_FILE*/
	if (rename(zdev_id_tmpfile, zdev_id_file) == -1) {
		remove(zdev_id_tmpfile);
		goto err;
	}

	return;
err:
	err(1, "Could not write to zdev_site_id file");
}

/* Read the loadparm and extract the current site_id.
 * loadparm can contains either Sn or "Ss". Sn indicate the site_id, where
 * 'n' is the integer which could be one of the valid site_ids from 0 to 9.
 * When loadparm value is "Ss", zdev_id extracts the site_id from the SSID
 * of the current ipl device. For ccw and zfcp devices, the current ipl
 * device-id can be found at /sys/firmware/ipl/device.
 * For all other invalid cases, set ZDEV_SITE_ID to NULL.
 */

static void process_loadparm(const char *filename)
{
	size_t n;
	FILE *fd;
	char *line = NULL, *substr;
	int site_id = SITE_FALLBACK;

	fd = fopen(filename, "r");
	if (!fd)
		goto out;

	/*
	 * We expect the value here to be either SX, where X is the site-id
	 * or SS,in which case, the site-id will be derived from the SSID
	 */
	if ((getline(&line, &n, fd)) != -1) {
		substr = strchr(line, 'S');
		if (!substr)
			goto out;

		if (isdigit(substr[1]))
			site_id = validate_site(atoi(&substr[1]));
		else if (substr[1] == 'S')
			site_id = read_ssid();
	}

	free(line);
	fclose(fd);
out:
	write_zdev_site_id(site_id);
	if (site_id == SITE_FALLBACK)
		printf("ZDEV_SITE_ID=\"\"\n");
	else
		printf("ZDEV_SITE_ID=%d\n", site_id);
}

int main(int argc, char *argv[])
{
	char *sysinfo, *cmdline, *loadparm;

	sysinfo = argc < 2 ? SYSINFO : argv[1];
	cmdline = argc < 3 ? CMDLINE : argv[2];
	loadparm = argc < 4 ? LOADPARM : argv[3];

	process_sysinfo(sysinfo);
	process_cmdline(cmdline);
	process_loadparm(loadparm);

	return 0;
}
