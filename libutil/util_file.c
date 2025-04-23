/*
 * util - Utility function library
 *
 * Read and write files
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_exit_code.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_prg.h"

#define READ_CHUNK_SIZE		4096

extern const char *toolname;

/*
 * Read the first line of a file into given buffer
 */
static int file_gets(char *str, size_t size, const char *path)
{
	char *p, *end;
	FILE *fp;
	int rc;

	/* In case of error we always return empty string */
	str[0] = 0;
	/* Read the string */
	fp = fopen(path, "r");
	if (!fp)
		return -1;
	p = fgets(str, size, fp);
	if (p) {
		/* Check for end of line */
		end = memchr(str, '\n', size);
		if (end)
			*end = 0;
		else
			str[size - 1] = 0;
	}
	if (strlen(str) == 0) {
		rc = -1;
		goto out_fclose;
	}
	rc = 0;
out_fclose:
	fclose(fp);
	return rc;
}

/**
 * Read the first line of a file
 *
 * If read is successful 'str' contains first line of a file without the
 * trailing newline. If read fails, an empty string is returned for 'str'
 * The resulting string will always be null-terminated.
 *
 * @param[out] str    Result buffer
 * @param[in]  size   Size of the result buffer
 * @param[in]  fmt    Format string for generation of the path name
 * @param[in]  ...    Parameters for format string
 *
 * @retval     0      File was read
 * @retval    -1      Error while reading file
 */
int util_file_read_line(char *const str, size_t size, const char *fmt, ...)
{
	char path[PATH_MAX];
	va_list ap;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	return file_gets(str, size, path);
}

/*
 * Write string to a file
 */
static int file_puts(const char *str, const char *path)
{
	FILE *fp;
	int rc;

	/* write the string */
	fp = fopen(path, "w");
	if (!fp)
		return -1;
	if (fputs(str, fp) == EOF) {
		rc = -1;
		goto out_fclose;
	}
	rc = 0;
out_fclose:
	if (fclose(fp))
		return -1;
	return rc;
}

/**
 * Write string to a file without the terminating null byte
 *
 * @param[in] str       Content is to be written
 * @param[in] fmt       Format string for generation of the path name
 * @param[in] ...       Parameters for format string
 *
 * @retval    0         Write was successful
 * @retval   -1         Error while writing file
 */
int util_file_write_s(const char *str, const char *fmt, ...)
{
	char path[PATH_MAX];
	va_list ap;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	return file_puts(str, path);
}

/**
 * Write signed long value to a file according to given base
 *
 * @param[in] val       Value is to be written
 * @param[in] base      Base for conversion, either 8, 10, or 16
 * @param[in] fmt       Format string for generation of the path name
 * @param[in] ...       Parameters for format string
 *
 * @retval    0         Write was successful
 * @retval   -1         Error while writing file
 */
int util_file_write_l(long val, int base, const char *fmt, ...)
{
	char *str, path[PATH_MAX];
	va_list ap;
	int rc;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	switch (base) {
	case 8:
		util_asprintf(&str, "%lo", val);
		break;
	case 10:
		util_asprintf(&str, "%ld", val);
		break;
	case 16:
		util_asprintf(&str, "%lx", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	rc = file_puts(str, path);
	free(str);
	return rc;
}

/**
 * Write signed long long value to a file according to given base
 *
 * @param[in] val       Value is to be written
 * @param[in] base      Base for conversion, either 8, 10, or 16
 * @param[in] fmt       Format string for generation of the path name
 * @param[in] ...       Parameters for format string
 *
 * @retval    0         Write was successful
 * @retval   -1         Error while writing file
 */
int util_file_write_ll(long long val, int base, const char *fmt, ...)
{
	char *str, path[PATH_MAX];
	va_list ap;
	int rc;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	switch (base) {
	case 8:
		util_asprintf(&str, "%llo", val);
		break;
	case 10:
		util_asprintf(&str, "%lld", val);
		break;
	case 16:
		util_asprintf(&str, "%llx", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	rc = file_puts(str, path);
	free(str);
	return rc;
}

/**
 * Write unsigned long value to a file according to given base
 *
 * @param[in] val       Value is to be written
 * @param[in] base      Base for conversion, either 8, 10, or 16
 * @param[in] fmt       Format string for generation of the path name
 * @param[in] ...       Parameters for format string
 *
 * @retval    0         Write was successful
 * @retval   -1         Error while writing file
 */
int util_file_write_ul(unsigned long val, int base, const char *fmt, ...)
{
	char *str, path[PATH_MAX];
	va_list ap;
	int rc;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	switch (base) {
	case 8:
		util_asprintf(&str, "%lo", val);
		break;
	case 10:
		util_asprintf(&str, "%lu", val);
		break;
	case 16:
		util_asprintf(&str, "%lx", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	rc = file_puts(str, path);
	free(str);
	return rc;
}

/**
 * Write unsigned long long value to a file according to given base
 *
 * @param[in] val       Value is to be written
 * @param[in] base      Base for conversion, either 8, 10, or 16
 * @param[in] fmt       Format string for generation of the path name
 * @param[in] ...       Parameters for format string
 *
 * @retval    0         Write was successful
 * @retval   -1         Error while writing file
 */
int util_file_write_ull(unsigned long long val, int base, const char *fmt, ...)
{
	char *str, path[PATH_MAX];
	va_list ap;
	int rc;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	switch (base) {
	case 8:
		util_asprintf(&str, "%llo", val);
		break;
	case 10:
		util_asprintf(&str, "%llu", val);
		break;
	case 16:
		util_asprintf(&str, "%llx", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	rc = file_puts(str, path);
	free(str);
	return rc;
}

/**
 * Read a file and convert it to signed int according to given base
 *
 * @param[out] val      Buffer for value
 * @param[in]  base     Base for conversion, either 8, 10, or 16
 * @param[in]  fmt      Format string for generation of the path name
 * @param[in]  ...      Parameters for format string
 *
 * @retval     0        Integer has been read correctly
 * @retval    -1        Error while reading file
 */
int util_file_read_i(int *val, int base, const char *fmt, ...)
{
	char path[PATH_MAX], buf[512];
	va_list ap;
	int count;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	if (file_gets(buf, sizeof(buf), path))
		return -1;
	switch (base) {
	case 8:
		count = sscanf(buf, "%o", val);
		break;
	case 10:
		count = sscanf(buf, "%d", val);
		break;
	case 16:
		count = sscanf(buf, "%x", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	return (count == 1) ? 0 : -1;
}

/**
 * Read a file and convert it to signed long according to given base
 *
 * @param[out] val      Buffer for value
 * @param[in]  base     Base for conversion, either 8, 10, or 16
 * @param[in]  fmt      Format string for generation of the path name
 * @param[in]  ...      Parameters for format string
 *
 * @retval     0        Long integer has been read correctly
 * @retval    -1        Error while reading file
 */
int util_file_read_l(long *val, int base, const char *fmt, ...)
{
	char path[PATH_MAX], buf[512];
	va_list ap;
	int count;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	if (file_gets(buf, sizeof(buf), path))
		return -1;
	switch (base) {
	case 8:
		count = sscanf(buf, "%lo", val);
		break;
	case 10:
		count = sscanf(buf, "%ld", val);
		break;
	case 16:
		count = sscanf(buf, "%lx", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	return (count == 1) ? 0 : -1;
}

/**
 * Read a file and convert it to signed long long according to given base
 *
 * @param[out] val      Buffer for value
 * @param[in]  base     Base for conversion, either 8, 10, or 16
 * @param[in]  fmt      Format string for generation of the path name
 * @param[in]  ...      Parameters for format string
 *
 * @retval     0        Long integer has been read correctly
 * @retval    -1        Error while reading file
 */
int util_file_read_ll(long long *val, int base, const char *fmt, ...)
{
	char path[PATH_MAX], buf[512];
	va_list ap;
	int count;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	if (file_gets(buf, sizeof(buf), path))
		return -1;
	switch (base) {
	case 8:
		count = sscanf(buf, "%llo", val);
		break;
	case 10:
		count = sscanf(buf, "%lld", val);
		break;
	case 16:
		count = sscanf(buf, "%llx", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	return (count == 1) ? 0 : -1;
}

/**
 * Read a file and convert it to unsigned int according to given base
 *
 * @param[out] val      Buffer for value
 * @param[in]  base     Base for conversion, either 8, 10, or 16
 * @param[in]  fmt      Format string for generation of the path name
 * @param[in]  ...      Parameters for format string
 *
 * @retval     0        Integer has been read correctly
 * @retval    -1        Error while reading file
 */
int util_file_read_ui(unsigned int *val, int base, const char *fmt, ...)
{
	char path[PATH_MAX], buf[512];
	va_list ap;
	int count;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	if (file_gets(buf, sizeof(buf), path))
		return -1;
	switch (base) {
	case 8:
		count = sscanf(buf, "%o", val);
		break;
	case 10:
		count = sscanf(buf, "%u", val);
		break;
	case 16:
		count = sscanf(buf, "%x", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	return (count == 1) ? 0 : -1;
}

/**
 * Read a file and convert it to unsigned long according to given base
 *
 * @param[out] val      Buffer for value
 * @param[in]  base     Base for conversion, either 8, 10, or 16
 * @param[in]  fmt      Format string for generation of the path name
 * @param[in]  ...      Parameters for format string
 *
 * @retval     0        Long integer has been read correctly
 * @retval    -1        Error while reading file
 */
int util_file_read_ul(unsigned long *val, int base, const char *fmt, ...)
{
	char path[PATH_MAX], buf[512];
	va_list ap;
	int count;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	if (file_gets(buf, sizeof(buf), path))
		return -1;
	switch (base) {
	case 8:
		count = sscanf(buf, "%lo", val);
		break;
	case 10:
		count = sscanf(buf, "%lu", val);
		break;
	case 16:
		count = sscanf(buf, "%lx", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	return (count == 1) ? 0 : -1;
}

/**
 * Read a file and convert it to unsigned long long according to given base
 *
 * @param[out] val      Buffer for value
 * @param[in]  base     Base for conversion, either 8, 10, or 16
 * @param[in]  fmt      Format string for generation of the path name
 * @param[in]  ...      Parameters for format string
 *
 * @retval     0        Long integer has been read correctly
 * @retval    -1        Error while reading file
 */
int util_file_read_ull(unsigned long long *val, int base, const char *fmt, ...)
{
	char path[PATH_MAX], buf[512];
	va_list ap;
	int count;

	/* Construct the file name */
	UTIL_VSPRINTF(path, fmt, ap);

	if (file_gets(buf, sizeof(buf), path))
		return -1;
	switch (base) {
	case 8:
		count = sscanf(buf, "%llo", val);
		break;
	case 10:
		count = sscanf(buf, "%llu", val);
		break;
	case 16:
		count = sscanf(buf, "%llx", val);
		break;
	default:
		util_panic("Invalid base: %d\n", base);
	}
	return (count == 1) ? 0 : -1;
}

/**
 * Read a file and convert it according to format string
 *
 * @param[in]  path     File name to read
 * @param[in]  fmt      Format string for parsing the content
 * @param[out] ...      Parameters for format string
 *
 * @retval     != -1    Number of values parsed correctly
 * @retval    -1        Error while reading file
 */

int util_file_read_va(const char *path, const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	int ret;

	if (file_gets(buf, sizeof(buf), path))
		return -1;

	va_start(ap, fmt);
	ret = vsscanf(buf, fmt, ap);
	va_end(ap);
	if (ret == EOF)
		return -1;
	return ret;
}

/**
 * Print an error message indicating an out-of-memory situation and exit.
 */
static void oom(void)
{
	fprintf(stderr, "Out of memory\n");

	/* We can't rely on our clean-up routines to work reliably during an
	 * OOM situation, so just exit here.
	 */
	exit(UTIL_EXIT_OUT_OF_MEMORY);
}

/**
 * Read all data from @fd and return address of resulting buffer in
 * @buffer_ptr. If @size_ptr is non-zero, use it to store the size of the
 * resulting buffer. Return %UTIL_EXIT_OK on success.
 *
 * @param[in]      fd         File descriptor to read data from
 * @param[in, out] buffer_ptr Buffer to read data into
 * @param[in, out] size_ptr   Buffer to save size of data read into buffer_ptr
 *
 * @retval         0                       read was successful
 * @retval         UTIL_EXIT_RUNTIME_ERROR error while reading file
 */
util_exit_code_t util_file_read_fd_buf(FILE *fd, void **buffer_ptr,
				       size_t *size_ptr)
{
	char *buffer = NULL;
	size_t done = 0;

	while (!feof(fd)) {
		buffer = realloc(buffer, done + READ_CHUNK_SIZE);
		if (!buffer)
			oom();
		done += fread(&buffer[done], 1, READ_CHUNK_SIZE, fd);
		if (ferror(fd)) {
			free(buffer);
			return UTIL_EXIT_RUNTIME_ERROR;
		}
	}

	buffer = realloc(buffer, done);
	if (!buffer && done > 0)
		oom();

	*buffer_ptr = buffer;
	if (size_ptr)
		*size_ptr = done;

	return UTIL_EXIT_OK;
}

/**
 * Read text from @fd and return resulting NULL-terminated text buffer.
 * If @chomp is non-zero, remove trailing newline character. Return %NULL
 * on error or when unprintable characters are read.
 *
 * @param[in]  fd         File descriptor to read data from
 * @param[in]  chomp      Flag to indicate trailing newlines should be removed
 *
 * @retval     NULL       Error reading from fd
 * @retval     != 0       Data read successfully, buffer returned
 */
char *util_file_read_fd(FILE *fd, int chomp)
{
	char *buffer;
	size_t done, i;

	if (util_file_read_fd_buf(fd, (void **) &buffer, &done))
		return NULL;

	/* Prevent over-read if buffer is larger than amount of read characters */
	if (buffer)
		done = MIN(done, strnlen(buffer, done));

	/* Check if this is a text file at all (required to filter out
	 * binary sysfs attributes).
	 */
	for (i = 0; i < done; i++) {
		if (!isgraph(buffer[i]) && !isspace(buffer[i])) {
			free(buffer);
			return NULL;
		}
	}

	/* Remove trailing new-line character if requested. */
	if (chomp && done > 0 && buffer[done - 1] == '\n')
		done--;

	/* NULL-terminate. */
	buffer = realloc(buffer, done + 1);
	if (!buffer)
		oom();
	buffer[done] = 0;

	return buffer;
}

/**
 * Read file as text and return NULL-terminated contents. Remove trailing
 * newline if CHOMP is specified.
 *
 * @param[in]  path       Path to the file that will be read from
 * @param[in]  chomp      Flag to indicate trailing newlines should be removed
 *
 * @retval     NULL       Error reading from file
 * @retval     != 0       File read successfully, contents returned in buffer
 */
char *util_file_read_text_file(const char *path, int chomp)
{
	char *buffer = NULL;
	FILE *fd;

	fd = fopen(path, "r");
	if (!fd)
		goto out;

	buffer = util_file_read_fd(fd, chomp);
	fclose(fd);

out:
	if (!buffer) {
		fprintf(stderr, "Could not read file %s: %s\n", path,
			strerror(errno));
	}

	return buffer;
}
