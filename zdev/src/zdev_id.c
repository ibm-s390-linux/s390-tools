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
#include <stdarg.h>

#include "sanitize.h"
#include "zdev.h"
#include "zdev_id.h"

#define	SYSINFO		"/proc/sysinfo"
#define	CMDLINE		"/proc/cmdline"
#define LOADPARM	"/sys/firmware/ipl/loadparm"
#define IPL_DEV_ID	"/sys/firmware/ipl/device"
#define IPL_DEV_TYPE	"/sys/firmware/ipl/ipl_type"
#define UID_CHECKING	"/sys/firmware/clp/uid_checking"

#define	WHITESPACE	" \t\n"

static int g_cleanup;
static FILE *g_zdev_file;
static char g_zdev_tmpfile[] = ZDEV_ID_FILE "-XXXXXX";

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

/* Writes format string to both stdout and zdev_id file */
static void emit(const char *fmt, ...)
{
	char *str = NULL;
	va_list args;
	int ret;

	/* Initialize variable arguments */
	va_start(args, fmt);
	ret = vasprintf(&str, fmt, args);
	va_end(args);

	if (ret < 0 || !str)
		err(1, "Error formatting output string");

	/* Write to temp file */
	if (fprintf(g_zdev_file, "%s", str) < 0) {
		free(str);
		err(1, "Error in writing to temp file: %s", str);
	}

	/* Write to stdout */
	if (printf("%s", str) < 0) {
		free(str);
		err(1, "Error in writing to stdout: %s", str);
	}

	free(str);
}

static void cleanup_temp_file(void)
{
	if (g_cleanup)
		remove(g_zdev_tmpfile);
}

/*
 * Initialize the global file pointer for writing zdev env data. Creates a
 * temporary file that will be renamed after all updates
 */
static void zdev_file_init(void)
{
	int tmpfd;

	/* Register clean up function to run */
	atexit(cleanup_temp_file);

	/*
	 * Create a temporary file. Implementation will replace terminating
	 * 'X' characters into random characters
	 */
	tmpfd = mkstemp(g_zdev_tmpfile);
	if (tmpfd == -1)
		err(1, "Could not create temp file");

	/* Indicate clean up routine to remove temp file */
	g_cleanup = 1;

	/* Open the temp file for writing */
	g_zdev_file = fdopen(tmpfd, "w");
	if (!g_zdev_file)
		err(1, "Could not open temp file");

	/* Write header */
	emit("%s\n", CHZDEV_HEADER);
}

/*
 * Close the global file pointer and rename the temporary file. Should be
 * called after all updates are complete.
 */
static void zdev_file_close(void)
{
	/* Close the file */
	if (fclose(g_zdev_file) != 0)
		err(1, "Error in closing temp file");

	/* Rename the temporary file to the final name */
	if (rename(g_zdev_tmpfile, ZDEV_ID_FILE) != 0)
		err(1, "Error in renaming temp file as: %s", ZDEV_ID_FILE);

	/* Clear flag to prevent atexit() handler from running */
	g_cleanup = 0;
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
			sanitize(substr, VALID_CPNAME);
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
	emit("ZDEV_NEST_LEVEL=%d\n", num_cps);

	/*
	 * ZDEV_HYPERVISOR_<n>=LPAR|z/VM|KVM/Linux
	 *
	 * Type of hypervisor that provides virtualization at nesting level <n>.
	 */
	for (i = 0; i < num_cps; i++) {
		/* Sysinfo lists VMs in reverse order .*/
		level = (i == 0) ? i : (num_cps - i);
		emit("ZDEV_HYPERVISOR_%d=\"%s\"\n", i, cps[level]);
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
	emit("ZDEV_IS_DPM=%d\n", is_dpm);
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
	emit("ZDEV_NO_AUTO=%d\n", no_auto);
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
	if (site_id == SITE_FALLBACK)
		emit("ZDEV_SITE_ID=\"\"\n");
	else
		emit("ZDEV_SITE_ID=%d\n", site_id);
}

/* Export sysfs attr uid_checking to env file */
static void process_uid_checking(const char *filename)
{
	int value;
	FILE *fd;

	fd = fopen(filename, "r");
	if (!fd)
		err(1, "Error in opening uid_checking file: %s", filename);

	if (fscanf(fd, "%d", &value) != 1) {
		fclose(fd);
		err(1, "Error in reading uid_checking file: %s", filename);
	}

	emit("ZDEV_UID_CHECKING=%d\n", value);
	fclose(fd);
}

int main(int argc, char *argv[])
{
	char *sysinfo, *cmdline, *loadparm, *uid_checking;

	sysinfo = argc < 2 ? SYSINFO : argv[1];
	cmdline = argc < 3 ? CMDLINE : argv[2];
	loadparm = argc < 4 ? LOADPARM : argv[3];
	uid_checking = argc < 5 ? UID_CHECKING : argv[4];

	/* Initialize file handle to collect zdev env */
	zdev_file_init();

	process_sysinfo(sysinfo);
	process_cmdline(cmdline);
	process_loadparm(loadparm);
	process_uid_checking(uid_checking);

	/* Close file handle to commit zdev env */
	zdev_file_close();

	return 0;
}
