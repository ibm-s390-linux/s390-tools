/*
 * Copyright IBM Corp. 2001, 2017, 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdarg.h>

#include "zg.h"

static inline void _zg_stderr(const char *fmt, va_list ap)
{
	vfprintf(stderr, fmt, ap);
	fflush(stderr);
}

static inline void _zg_stderr_pr(const char *fmt, va_list ap)
{
	fprintf(stderr, "\r%s: ", "zgetdump");
	vfprintf(stderr, fmt, ap);
}

static inline void _zg_stdout(const char *fmt, va_list ap)
{
	vfprintf(stdout, fmt, ap);
	fflush(stdout);
}

void zg_stderr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_zg_stderr(fmt, ap);
	va_end(ap);
}

void zg_stderr_pr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_zg_stderr_pr(fmt, ap);
	va_end(ap);
}

void zg_stdout(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_zg_stdout(fmt, ap);
	va_end(ap);
}
