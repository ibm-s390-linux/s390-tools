/*
 * util - Utility function library
 *
 * General helper functions
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_BASE_H
#define LIB_UTIL_BASE_H

#include <stdio.h>
#include <stdlib.h>
#include "zt_common.h"

void util_hexdump(FILE *fh, const char *tag, const void *data, int cnt);
void util_hexdump_grp(FILE *fh, const char *tag, const void *data, int group,
		      int cnt, int indent);
void util_print_indented(const char *str, int indent);

static inline void util_ptr_vec_free(void **ptr_vec, int count)
{
	int i;

	if (!ptr_vec || count < 0)
		return;

	for (i = 0; i < count; i++)
		free(ptr_vec[i]);
	free(ptr_vec);
}

#endif /* LIB_UTIL_BASE_H */
