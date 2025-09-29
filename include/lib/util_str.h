/**
 * @defgroup util_str_h util_str: String functions
 * @{
 * @brief Manipulate and work with strings
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_STR_H
#define LIB_UTIL_STR_H

void util_str_rm_whitespace(const char *src, char *dest);
const char *util_startswith(const char *s, const char *prefix);
const char *util_startswith_no_case(const char *s, const char *prefix);

#endif /** LIB_UTIL_STR_H @} */
