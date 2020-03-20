/*
 * util - Utility function library
 *
 * Collect FFDC data for unexpected errors
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <execinfo.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "lib/util_base.h"
#include "lib/util_panic.h"

/*
 * Obtain a backtrace and print it to stderr
 *
 * To get symbols, compile the code with "-rdynamic".
 */
static void print_backtrace(void)
{
	void *array[256];
	size_t i, size;
	char **strings;

	fprintf(stderr, "Backtrace:\n\n");
	size = backtrace(array, ARRAY_SIZE(array));
	strings = backtrace_symbols(array, size);
	if (strings == NULL) {
		fprintf(stderr, " Could not obtain backtrace (ENOMEM)\n");
		return;
	}
	for (i = 0; i < size; i++)
		fprintf(stderr, "  %s\n", strings[i]);

	free(strings);
}

/*
 * Check for core ulimit
 */
static void ulimit_core_check(void)
{
	struct rlimit limit;

	if (getrlimit(RLIMIT_CORE, &limit) != 0)
		return;
	if (limit.rlim_cur != 0)
		return;
	fprintf(stderr, "Core dump size is zero. To get a full core dump use 'ulimit -c unlimited'.\n");
}

/*
 * Print FFDC data and then abort
 */
static void panic_finish(const char *func, const char *file, int line,
			 const char *fmt, va_list ap)
{
	/* Write panic error string */
	fprintf(stderr, "\n");
	fprintf(stderr, "Error string:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	/* Write file, line number, and function name */
	fprintf(stderr, "Location:\n\n");
	fprintf(stderr, "  %s:%d: %s()\n", file, line, func);
	fprintf(stderr, "\n");

	/* Print the function backtrace */
	print_backtrace();
	fprintf(stderr, "\n");

	ulimit_core_check();
	fprintf(stderr, "----------------------------------------------------------------------->8-----\n");
	abort();
}

/*
 * Do panic processing if the assumption is not true
 */
void __util_assert(const char *assertion_str,
		   const char *func, const char *file, int line,
		   int assumption, const char *fmt, ...)
{
	va_list ap;

	if (assumption)
		return;
	va_start(ap, fmt);
	fprintf(stderr, "---8<-------------------------------------------------------------------------\n");
	fprintf(stderr, "ASSERTION FAILED: The application terminated due to an internal or OS error\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "The following assumption was *not* true:\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  %s\n", assertion_str);
	panic_finish(func, file, line, fmt, ap);
}

/*
 * Do panic processing
 */
void __noreturn __util_panic(const char *func, const char *file, int line,
		  const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "---8<-------------------------------------------------------------------------\n");
	fprintf(stderr, "PANIC: The application terminated due to an unrecoverable error\n");
	panic_finish(func, file, line, fmt, ap);
	while(1);
}
