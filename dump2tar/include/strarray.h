/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Dynamically growing string arrays
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef STRARRAY_H
#define STRARRAY_H

/* A string array that can grow in size */
struct strarray {
	unsigned int num;
	char **str;
};

void free_strarray(struct strarray *array);
void add_str_to_strarray(struct strarray *array, const char *str);
void add_vstr_to_strarray(struct strarray *array, const char *fmt, ...);
int add_file_to_strarray(struct strarray *array, const char *filename);

#endif /* STRARRAY_H */
