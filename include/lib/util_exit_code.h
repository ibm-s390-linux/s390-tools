/**
 * @defgroup util_exit_code_h util_exit_code: General purpose exit codes
 * @{
 * @brief General purpose exit codes
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_EXIT_CODE_H
#define LIB_UTIL_EXIT_CODE_H

typedef enum {
	UTIL_EXIT_OK		= 0,  /* Program finished successfully */
	UTIL_EXIT_RUNTIME_ERROR	= 15, /* A run-time error occurred */
	UTIL_EXIT_OUT_OF_MEMORY	= 22, /* Not enough available memory */
} util_exit_code_t;

#endif /** LIB_UTIL_EXIT_CODE_H @} */
