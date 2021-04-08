/**
 * @defgroup util_log_h util_file: Multi-level message logging interface
 * @{
 * @brief Multi-level message logging
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_LOG_H
#define LIB_UTIL_LOG_H

enum util_log_level {
	UTIL_LOG_ERROR,
	UTIL_LOG_WARN,
	UTIL_LOG_INFO,
	UTIL_LOG_DEBUG,
	UTIL_LOG_TRACE,
	UTIL_LOG_NUM_LEVELS	/* Must be the last one. */
};

void util_log_set_level(int log_level);

void util_log_print(int log_level, const char *fmt, ...);

#endif /** LIB_UTIL_LOG_H @} */
