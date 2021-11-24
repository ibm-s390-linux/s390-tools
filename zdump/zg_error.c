/*
 * Copyright IBM Corp. 2001, 2017, 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdarg.h>

#include "lib/util_libc.h"
#include "zg.h"

static inline void _zg_err(const char *fmt, va_list ap)
{
	fprintf(stderr, "%s: ", "zgetdump");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
}

static inline void _zg_err_errno(const char *fmt, va_list ap)
{
	fflush(stdout);
	fprintf(stderr, "%s: ", "zgetdump");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, " (%s)", strerror(errno));
	fprintf(stderr, "\n");
}

void zg_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_zg_err(fmt, ap);
	va_end(ap);
}

void zg_err_exit(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_zg_err(fmt, ap);
	va_end(ap);
	zg_exit(1);
}

void zg_err_exit_errno(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_zg_err_errno(fmt, ap);
	va_end(ap);
	zg_exit(1);
}

void zg_abort(const char *fmt, ...)
{
	char *newfmt;
	va_list ap;

	newfmt = util_strcat_realloc(util_strdup("Internal Error: "), fmt);
	va_start(ap, fmt);
	_zg_err(newfmt, ap);
	va_end(ap);
	free(newfmt);

	abort();
}
