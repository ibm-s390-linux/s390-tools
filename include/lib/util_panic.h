/**
 * @defgroup util_panic_h util_panic: Panic interface
 * @{
 * @brief Collect FFDC data for unexpected errors
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_PANIC_H
#define LIB_UTIL_PANIC_H

#include "zt_common.h"

/**
 * Write message, print backtrace and then call the abort() function
 *
 * @param[in] ...     Format string and parameters describing the panic reason
 */
#define util_panic(...) \
	__util_panic(__func__, __FILE__, __LINE__, ##__VA_ARGS__)

void __noreturn __util_panic(const char *func, const char *file, int line,
		  const char *fmt, ...);

/**
 * Ensure that assumption is not true, otherwise panic
 *
 * Example: util_assert(ptr == NULL, "The ptr must be NULL, but is %p", ptr)
 *
 * @param[in] assumption  This assumption has to be true
 * @param[in] ...         Format string and parameters describing the assumption
 */
#define util_assert(assumption, ...) \
	__util_assert(#assumption, __func__, __FILE__, __LINE__, \
		      assumption, ##__VA_ARGS__)

void __util_assert(const char *assertion_string,
		   const char *func, const char *file, int line,
		   int assumption, const char *fmt, ...);

#endif /** LIB_UTIL_PANIC_H @} */
