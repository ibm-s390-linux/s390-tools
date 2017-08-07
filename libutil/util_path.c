/*
 * util - Utility function library
 *
 * Work with paths
 *
 * Copyright IBM Corp. 2016, 2017
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
#include "lib/util_proc.h"

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
 */
static char *sys_mount_point(void)
{
	struct util_proc_mnt_entry mnt_entry;
	static char *mount_point;
	char *dir;

	if (mount_point)
		return mount_point;
	/* Check the environment variable */
	dir = getenv("SYSFS_ROOT");
	if (dir) {
		mount_point = util_strdup(dir);
	} else {
		if (util_proc_mnt_get_entry("/proc/mounts", "sysfs",
					    &mnt_entry))
			errx(EXIT_FAILURE, "No mount point found for sysfs");
		mount_point = util_strdup(mnt_entry.file);
		util_proc_mnt_free_entry(&mnt_entry);
	}
	verify_dir(mount_point);
	return mount_point;
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
	char *path, *fmt_tot;
	va_list ap;

	util_asprintf(&fmt_tot, "%s/%s", sys_mount_point(), fmt);
	 /* Format and return full sysfs path */
	va_start(ap, fmt);
	util_vasprintf(&path, fmt_tot, ap);
	va_end(ap);
	free(fmt_tot);

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
	rc = access(path, R_OK) == 0 ? true : false;
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
	rc = access(path, W_OK) == 0 ? true : false;
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
	struct stat sb;
	va_list ap;
	char *path;
	bool rc;

	UTIL_VASPRINTF(&path, fmt, ap);
	if (stat(path, &sb)) {
		rc = false;
		goto free_str;
	}
	rc = (sb.st_mode & S_IFREG) ? true : false;
free_str:
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
	struct stat sb;
	va_list ap;
	char *path;
	bool rc;

	UTIL_VASPRINTF(&path, fmt, ap);
	if (stat(path, &sb)) {
		rc = false;
		goto free_str;
	}
	rc = (sb.st_mode & S_IFDIR) ? true : false;
free_str:
	free(path);
	return rc;
}
