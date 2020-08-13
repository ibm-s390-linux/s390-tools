/**
 * @defgroup util_file_h util_file: File read/write interface
 * @{
 * @brief Read and write files
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef LIB_UTIL_FILE_H
#define LIB_UTIL_FILE_H

int util_file_read_line(char *str, size_t size, const char *fmt, ...);
int util_file_read_i(int *val, int base, const char *fmt, ...);
int util_file_read_l(long *val, int base, const char *fmt, ...);
int util_file_read_ll(long long *val, int base, const char *fmt, ...);
int util_file_read_ui(unsigned int *val, int base, const char *fmt, ...);
int util_file_read_ul(unsigned long *val, int base, const char *fmt, ...);
int util_file_read_ull(unsigned long long *val, int base, const char *fmt, ...);

int util_file_write_s(const char *str, const char *fmt, ...);
int util_file_write_l(long val, int base, const char *fmt, ...);
int util_file_write_ll(long long val, int base, const char *fmt, ...);
int util_file_write_ul(unsigned long val, int base, const char *fmt, ...);
int util_file_write_ull(unsigned long long val, int base, const char *fmt, ...);

int util_file_read_va(const char *path, const char *fmt, ...);
#endif /** LIB_UTIL_FILE_H @} */
