/*
 * Misc - Local helper functions
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MISC_H
#define MISC_H

#include <stdbool.h>

char *misc_link_target(const char *fmt, ...);
bool misc_str_in_list(const char *str, const char *strings[], int array_size);
int misc_argz_add_from_file(char **argz, size_t *argz_len,
			    const char *fmt, ...);
ssize_t misc_read_buf(int fd, char *buf, size_t count);

#endif /* MISC_H */
