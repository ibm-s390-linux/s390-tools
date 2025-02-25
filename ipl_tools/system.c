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

#include "lib/util_libc.h"
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
 * Convert a string to lower case
 */
void strlow(char *s)
{
	while (*s) {
		*s = tolower(*s);
		s++;
	}
}

/*
 * Read a string from a particular file
 */
void read_str(char *string, const char *path, size_t len)
{
	size_t rc;
	FILE *fh;

	fh = fopen(path, "rb");
	if (fh == NULL)
		ERR_EXIT_ERRNO("Could not open \"%s\"", path);
	rc = fread(string, 1, len - 1, fh);
	if (rc == 0 && ferror(fh))
		ERR_EXIT_ERRNO("Could not read \"%s\"", path);
	fclose(fh);
	string[rc] = 0;
	if (string[strlen(string) - 1] == '\n')
		string[strlen(string) - 1] = 0;
}

/*
 * Read a string from a particular /sys/firmware file
 */
void read_fw_str(char *string, const char *file, size_t len)
{
	char *path;

	util_asprintf(&path, "/sys/firmware/%s", file);
	read_str(string, path, len);
	free(path);
}

/*
 * Print content of a file (path = dir/file)
 */
void print_fw_str(const char *fmt, const char *dir, const char *file)
{
	char path[PATH_MAX], str[4096];

	snprintf(path, sizeof(path), "%s/%s", dir, file);
	read_fw_str(str, path, sizeof(str));
	printf(fmt, str);
}

/*
 * Write a string to a file
 */
void write_str(char *string, char *file)
{
	char path[PATH_MAX], value[4096];
	int fh;

	snprintf(value, sizeof(value), "%s\n", string);
	snprintf(path, sizeof(path), "/sys/firmware/%s", file);
	fh = open(path, O_WRONLY);
	if (fh < 0)
		ERR_EXIT_ERRNO("Could not open \"%s\"", file);
	if (write(fh, value, strlen(value)) < 0)
		ERR_EXIT_ERRNO("Could not set \"%s\"", file);
	close(fh);
}

/*
 * Write a string to a file and return ERRNO
 */
int write_str_errno(char *string, char *file)
{
	char path[PATH_MAX], value[4096];
	int fh;

	snprintf(value, sizeof(value), "%s\n", string);
	snprintf(path, sizeof(path), "/sys/firmware/%s", file);
	fh = open(path, O_WRONLY);
	if (fh < 0)
		return errno;
	if (write(fh, value, strlen(value)) < 0)
		return errno;
	close(fh);
	return 0;
}
