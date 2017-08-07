/*
 * Misc - Local helper functions
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <sys/stat.h>
#include <sys/types.h>

#include <argz.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_prg.h"

#include "misc.h"

#define STR_LEN		256

/*
 * Check if the specified string presents in the predefined string array.
 *
 * @param[in].--str		String to search for.
 * @param[in].--strings[]	Array of strings to look through.
 *
 * @retval.-----true	Equal string presents in the array.
 * @retval.-----false	String does not found in the array.
 */
bool misc_str_in_list(const char *str, const char *strings[], int array_size)
{
	int i;

	for (i = 0; i < array_size; i++) {
		if (strcmp(str, strings[i]) == 0)
			return true;
	}
	return false;
}

/*
 * Get the path where a symbolic link points to
 *
 * @param[in] fmt  Format string for path
 * @param[in] ...  Variable arguments for format string
 *
 * @retval	!=0	Pointer to a string with the path name
 * @retval	NULL	Error case
 */
char *misc_link_target(const char *fmt, ...)
{
	char *lnk, *path;
	va_list ap;
	ssize_t rc;

	path = util_malloc(PATH_MAX);
	/* Construct the file name */
	UTIL_VASPRINTF(&lnk, fmt, ap);
	rc = readlink(lnk, path, PATH_MAX);
	free(lnk);
	if (rc < 0) {
		free(path);
		return NULL;
	}
	util_assert(rc < (PATH_MAX - 1),
		    "Internal error: Symlink name too long");
	path[rc] = '\0';
	return path;
}

/*
 * Adds the strings read from the file to the end of the
 * array **argz and updates **argz and *argz_len
 *
 * @param[in,out]	argz	argz vector
 * @param[in,out]	argz_len	argz length
 * @param[in]	fmt	Format string for path
 * @param[in]	...	Variable arguments for format string
 *
 * @retval	!0	Number of string elemnts added to argz array
 * @retval	0	File is empty or cannot be processed
 */
int misc_argz_add_from_file(char **argz, size_t *argz_len, const char *fmt, ...)
{
	char path[PATH_MAX];
	char str[STR_LEN];
	int count = 0;
	va_list ap;
	FILE *fp;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	/* Open the file for reading */
	fp = fopen(path, "r");
	if (!fp)
		return 0;
	errno = 0;
	/* Read the strings */
	while (fscanf(fp, "%s", str) == 1 && errno == 0) {
		argz_add(argz, argz_len, str);
		count++;
	}
	fclose(fp);
	return count;
}

/*
 * Read at most COUNT bytes from FD into memory at location BUF
 *
 * @param[in]      fd      File descriptor of the opened file
 * @param[in,out]  buf     Buffer for writing the result
 * @param[in]      count   Size of buffer
 *
 * @retval         >=0     Number of bytes read on success
 * @retval         -1      Read error
 */
ssize_t misc_read_buf(int fd, char *buf, size_t count)
{
	ssize_t rc, done;

	for (done = 0; done < (ssize_t)count; done += rc) {
		rc = read(fd, &buf[done], count - done);
		if (rc == -1 && errno == EINTR)
			continue;
		if (rc == -1)
			return -1;
		if (rc == 0)
			break;
	}
	return done;
}

