/*
 * util - Utility function library
 *
 * Handle standard errors for libc functions
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"

/*
 * Return size as string of largest unit, e.g. 1025 = "1 KiB"
 */
static void format_size(char *str, size_t size)
{
	static const char * const unit_vec[] =
		{"byte", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(unit_vec); i++) {
		if (size / 1024 == 0) {
			sprintf(str, "%zu %s", size, unit_vec[i]);
			return;
		}
		size /= 1024;
	}
	sprintf(str, "huge");
}

static void __util_oom(const char *func, const char *file, int line,
		       size_t size)
{
	char size_str[256];

	fprintf(stderr, "%s: Failed to allocate memory",
		program_invocation_short_name);
	if (size > 0) {
		format_size(size_str, size);
		fprintf(stderr, " (%s)", size_str);
	}
	fprintf(stderr, " at %s:%d %s()\n", file, line, func);
	exit(EXIT_FAILURE);
}

/*
 * Allocate memory or exit in case of failure
 */
void *__util_malloc(const char *func, const char *file, int line, size_t size)
{
	void *buf;

	buf = malloc(size);

	if (buf == NULL)
		__util_oom(func, file, line, size);

	return buf;
}

/*
 * Allocate zero-initialized memory or exit in case of failure
 */
void *__util_zalloc(const char *func, const char *file, int line, size_t size)
{
	void *buf = __util_malloc(func, file, line, size);

	memset(buf, 0, size);

	return buf;
}

/*
 * Re-allocate memory or exit in case of failure
 */
void *__util_realloc(const char *func, const char *file, int line,
		     void *ptr, size_t size)
{
	void *buf;

	buf = realloc(ptr, size);

	if (buf == NULL)
		__util_oom(func, file, line, size);

	return buf;
}

/*
 * Duplicate a string buffer or exit in case of failure
 */
void *__util_strdup(const char *func, const char *file, int line,
		    const char *str)
{
	void *buf = strdup(str);

	if (buf == NULL)
		__util_oom(func, file, line, strlen(str) + 1);

	return buf;
}

/**
 * Concatenate two strings or exit in case of failure
 *
 * The first string \a str1 is resized and a copy of the second
 * string \a str2 is appended to it.
 *
 * Therefore the first string \a str1 must either have been allocated
 * using malloc(), calloc(), or realloc() or must be NULL.
 *
 * @param[in] str1 Pointer to first string to concatenate, which
 *                 becomes invalid
 * @param[in] str2 Constant pointer to second string to concatenate
 *
 * @returns Pointer to concatenated string
 */
char *util_strcat_realloc(char *str1, const char *str2)
{
	char *buf;

	if (str1) {
		buf = util_realloc(str1, strlen(str1) + strlen(str2) + 1);
		strcat(buf, str2);
	} else {
		buf = util_strdup(str2);
	}
	return buf;
}

/**
 * Convert string to uppercase
 *
 * String \a str is converted to uppercase
 *
 * @param[in,out] str String to convert
 */
void util_str_toupper(char *str)
{
	int i;

	for (i = 0; str[i] != '\0'; i++)
		str[i] = toupper(str[i]);
}

/*
 * Print to newly allocated string or exit in case of failure
 */
int __util_vasprintf(const char *func, const char *file, int line,
		     char **strp, const char *fmt, va_list ap)
{
	int rc;

	rc = vasprintf(strp, fmt, ap);
	if (rc == -1)
		__util_oom(func, file, line, 0);

	return rc;
}

/*
 * Print to newly allocated string or exit in case of failure
 */
int __util_asprintf(const char *func, const char *file, int line,
		    char **strp, const char *fmt, ...)
{
	va_list ap;
	int rc;

	va_start(ap, fmt);
	rc = __util_vasprintf(func, file, line, strp, fmt, ap);
	va_end(ap);
	return rc;
}

/*
 * Print to string buffer or exit in case of failure
 */
int __util_vsprintf(const char *func, const char *file, int line,
		    char *str, const char *fmt, va_list ap)
{
	int rc;

	rc = vsprintf(str, fmt, ap);
	if (rc == -1)
		__util_assert("rc != -1", func, file, line,
			      rc != -1, "Could not format string\n");
	return rc;
}

/**
 * Strip leading and trailing spaces from string
 *
 * Remove string \a s leading and trailing spaces
 *
 * @param[in,out] s String to manipulate
 *
 * @returns Pointer to first non-space character in string \a s
 */
char *util_strstrip(char *s)
{
	size_t size;
	char *end;

	size = strlen(s);

	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

	while (*s && isspace(*s))
		s++;

	return s;
}

/**
 * Copy \a src to buffer \a dest of size \a size. At most size - 1
 * chars will be copied. \a dest will always be NUL terminated.
 *
 * Note: If the return value is greater than or equal to size truncation
 * occurred.
 *
 * @param[in] dest   Destination buffer
 * @param[in] src    Source string
 * @param[in] size   Size of destination buffer
 *
 * @returns   strlen Length of \a src string
 */
size_t util_strlcpy(char *dest, const char *src, size_t size)
{
	size_t str_len = strlen(src);
	size_t len;

	if (size) {
		len = MIN(size - 1, str_len);
		memcpy(dest, src, len);
		dest[len] = '\0';
	}

	return str_len;
}
