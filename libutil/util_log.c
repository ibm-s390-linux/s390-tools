/*
 * Multi-level message logging
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdarg.h>

#include "lib/util_log.h"

static int current_log_level = UTIL_LOG_INFO;

static const char *log_level_to_str(int log_level)
{
	switch (log_level) {
	case UTIL_LOG_ERROR:
		return "ERROR";
	case UTIL_LOG_WARN:
		return "WARN";
	case UTIL_LOG_INFO:
		return "INFO";
	case UTIL_LOG_DEBUG:
		return "DEBUG";
	case UTIL_LOG_TRACE:
		return "TRACE";
	default:
		return "UNKNW";
	}
}

static void log_helper(FILE *fp, int log_level, const char *fmt, va_list args)
{
	if (current_log_level < log_level)
		return;

	fprintf(fp, "%5s: ", log_level_to_str(log_level));
	vfprintf(fp, fmt, args);
}

/**
 * Changes the current log level
 *
 * @param[in] log_level A new log level to be set as the current one
 */
void util_log_set_level(int log_level)
{
	current_log_level = log_level;
}

/**
 * Outputs the given message on stderr
 *
 * The given message is printed only if the current log level is >= than the given one.
 *
 * @param[in] log_level Log level starting from which the given message shall be printed
 * @param[in] fmt       Format string for generation of the log message
 * @param[in] ...       Parameters for format string
 */
void util_log_print(int log_level, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_helper(stderr, log_level, fmt, args);
	va_end(args);
}
