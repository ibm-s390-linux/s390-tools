/*
 * util - Utility function library
 *
 * Work with paths
 *
 * Copyright IBM Corp. 2016, 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"

/*
 * Verify that directory exists
 */
static void verify_dir(const char *dir)
{
	struct stat sb;
	int rc;

	rc = stat(dir, &sb);
	if (rc < 0)
		err(EXIT_FAILURE, "Could not access directory: %s", dir);
	if (!S_ISDIR(sb.st_mode))
		errx(EXIT_FAILURE, "Is not a directory: %s", dir);
}

/*
 * Return sysfs mount point
 *
 * The caller must free the memory for mount_point.
 */
static void sys_mount_point(char **mount_point)
{
	char *dir;

	/* Check the environment variable */
	dir = secure_getenv("SYSFS_ROOT");
	if (dir)
		*mount_point = util_strdup(dir);
	else
		*mount_point = util_strdup("/sys");
	verify_dir(*mount_point);
}

/**
 * Construct a sysfs path
 *
 * The arguments of the function are used to specify a subdirectory under
 * sysfs root.
 *
 * @param[in] fmt  Format string for path
 * @param[in] ...  Variable arguments for format string
 *
 * @returns        Allocated path
 */
char *util_path_sysfs(const char *fmt, ...)
{
	char *path, *fmt_path, *sysfs;
	va_list ap;

	va_start(ap, fmt);
	util_vasprintf(&fmt_path, fmt, ap);
	va_end(ap);
	sys_mount_point(&sysfs);
	 /* Format and return full sysfs path */
	util_asprintf(&path, "%s/%s", sysfs, fmt_path);
	free(fmt_path);
	free(sysfs);

	return path;
}

/**
 * Test if path exists and is readable
 *
 * This function has the same semantics as "-r path" in bash.
 *
 * @param[in] fmt   Format string for path to test
 * @param[in] ...   Variable arguments for format string
 *
 * @returns   true  Path exists and is readable
 *            false Otherwise
 */
bool util_path_is_readable(const char *fmt, ...)
{
	va_list ap;
	char *path;
	bool rc;

	UTIL_VASPRINTF(&path, fmt, ap);
	rc = access(path, R_OK) == 0;
	free(path);

	return rc;
}

/**
 * Test if path exists and is writable
 *
 * This function has the same semantics as "-w path" in bash.
 *
 * @param[in] fmt   Format string for path to test
 * @param[in] ...   Variable arguments for format string
 *
 * @returns   true  Path exists and is writable
 *            false Otherwise
 */
bool util_path_is_writable(const char *fmt, ...)
{
	va_list ap;
	char *path;
	bool rc;

	UTIL_VASPRINTF(&path, fmt, ap);
	rc = access(path, W_OK) == 0;
	free(path);

	return rc;
}

/**
 * Test if path exists and is a regular file
 *
 * This function has the same semantics as "-f path" in bash.
 *
 * @param[in] fmt   Format string for path to test
 * @param[in] ...   Variable arguments for format string
 *
 * @returns   true  Path exists and is a regular file
 *            false Otherwise
 */
bool util_path_is_reg_file(const char *fmt, ...)
{
	bool rc = false;
	struct stat sb;
	va_list ap;
	char *path;

	UTIL_VASPRINTF(&path, fmt, ap);
	if (stat(path, &sb) == 0)
		rc = S_ISREG(sb.st_mode);
	free(path);
	return rc;
}

/**
 * Test if path exists and is a directory
 *
 * This function has the same semantics as "-d path" in bash.
 *
 * @param[in] fmt   Format string for path to test
 * @param[in] ...   Variable arguments for format string
 *
 * @returns   true  Path exists and is a directory
 *            false Otherwise
 */
bool util_path_is_dir(const char *fmt, ...)
{
	bool rc = false;
	struct stat sb;
	va_list ap;
	char *path;

	UTIL_VASPRINTF(&path, fmt, ap);
	if (stat(path, &sb) == 0)
		rc = S_ISDIR(sb.st_mode);
	free(path);
	return rc;
}

/**
 * Test if path to directory or file exists
 *
 * This function has the same semantics as "-e path" in bash.
 *
 * @param[in] fmt   Format string for path to test
 * @param[in] ...   Variable arguments for format string
 *
 * @returns   true  Path exists
 *            false Otherwise
 */
bool util_path_exists(const char *fmt, ...)
{
	va_list ap;
	char *path;
	bool rc;

	UTIL_VASPRINTF(&path, fmt, ap);
	rc = access(path, F_OK) == 0;
	free(path);
	return rc;
}

/**
 * Test if path exists, is a regular file, and permission is read-only
 *
 * @param[in] fmt   Format string for path to test
 * @param[in] ...   Variable arguments for format string
 *
 * @returns   true  Path exists, is a regular file, and permission does
 *                  not allow any write but allows read
 *            false Otherwise
 */
bool util_path_is_readonly_file(const char *fmt, ...)
{
	bool rc = false;
	struct stat sb;
	va_list ap;
	char *path;

	UTIL_VASPRINTF(&path, fmt, ap);
	if (stat(path, &sb) == 0) {
		rc = S_ISREG(sb.st_mode) &&
		     (sb.st_mode & 0222) == 0 &&
		     (sb.st_mode & 0444) != 0;
	}
	free(path);
	return rc;
}

/**
 * Test if path exists, is a regular file, and permission is write-only
 *
 * @param[in] fmt   Format string for path to test
 * @param[in] ...   Variable arguments for format string
 *
 * @returns   true  Path exists, is a regular file, and permission does
 *                  not allow any read but allows write
 *            false Otherwise
 */
bool util_path_is_writeonly_file(const char *fmt, ...)
{
	bool rc = false;
	struct stat sb;
	va_list ap;
	char *path;

	UTIL_VASPRINTF(&path, fmt, ap);
	if (stat(path, &sb) == 0) {
		rc = S_ISREG(sb.st_mode) &&
		     (sb.st_mode & 0222) != 0 &&
		     (sb.st_mode & 0444) == 0;
	}
	free(path);
	return rc;
}

