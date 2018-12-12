/**
 * @defgroup util_path_h util_path: Path interface
 * @{
 * @brief Work with paths
 *
 * Copyright IBM Corp. 2016, 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_PATH_H
#define LIB_UTIL_PATH_H

#include <stdbool.h>

char *util_path_sysfs(const char *fmt, ...);

bool util_path_is_readable(const char *fmt, ...);
bool util_path_is_writable(const char *fmt, ...);
bool util_path_is_dir(const char *fmt, ...);
bool util_path_is_reg_file(const char *fmt, ...);
bool util_path_exists(const char *fmt, ...);
bool util_path_is_readonly_file(const char *fmt, ...);
bool util_path_is_writeonly_file(const char *fmt, ...);

#endif /** LIB_UTIL_PATH_H @} */
