/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * Shared system functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/util_path.h"
#include "lib/util_file.h"
#include "ipl_tools.h"

/*
 * Check if we are running in an LPAR environment
 */
int is_lpar(void)
{
	size_t bytes_read;
	char buf[2048];
	int rc = 0;
	FILE *fh;

	fh = fopen("/proc/cpuinfo", "r");
	if (fh == NULL)
		ERR_EXIT_ERRNO("Could not open \"/proc/cpuinfo\"");
	bytes_read = fread(buf, 1, sizeof(buf), fh);
	if (bytes_read == 0)
		ERR_EXIT("Could not read \"/proc/cpuinfo\"");
	buf[bytes_read] = '\0';
	if (strstr(buf, "version = FF") == NULL)
		rc = 1;
	fclose(fh);
	return rc;
}

/*
 * Check whether we are started as root
 */
int is_root(void)
{
	if (geteuid() == 0)
		return 1;
	else
		return 0;
}

/*
 * Read a string from a particular /sys/firmware file
 */
char *read_fw_str(const char *file)
{
	char *string;
	char *path;

	path = util_path_sysfs("firmware/%s", file);
	string = util_file_read_text_file(path, 1);
	free(path);
	return string;
}

/*
 * Print content of a file (path = dir/file)
 */
void print_fw_str(const char *fmt, const char *dir, const char *file)
{
	char path[PATH_MAX];
	char *str;

	snprintf(path, sizeof(path), "%s/%s", dir, file);
	str = read_fw_str(path);
	printf(fmt, str);
	free(str);
}

/*
 * Write a string to a file
 */
void write_str(char *string, char *file)
{
	char value[4096];
	char *path;
	int fh;

	path = util_path_sysfs("firmware/%s", file);
	snprintf(value, sizeof(value), "%s\n", string);
	fh = open(path, O_WRONLY);
	if (fh < 0)
		ERR_EXIT_ERRNO("Could not open \"%s\"", file);
	if (write(fh, value, strlen(value)) < 0)
		ERR_EXIT_ERRNO("Could not set \"%s\"", file);
	close(fh);
	free(path);
}

/*
 * Write a string to a file and return ERRNO
 */
int write_str_errno(char *string, char *file)
{
	char value[4096];
	char *path;
	int fh;

	path = util_path_sysfs("firmware/%s", file);
	snprintf(value, sizeof(value), "%s\n", string);
	fh = open(path, O_WRONLY);
	if (fh < 0)
		return errno;
	if (write(fh, value, strlen(value)) < 0)
		return errno;
	close(fh);
	free(path);
	return 0;
}
