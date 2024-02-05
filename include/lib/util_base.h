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
#include <string.h>

#include "zt_common.h"
#include "lib/util_libc.h"

void util_hexdump(FILE *fh, const char *tag, const void *data, int cnt);
void util_hexdump_grp(FILE *fh, const char *tag, const void *data, int group,
		      int cnt, int indent);
void util_print_indented(const char *str, int indent);
const char *util_libdir(void);
const char *util_libdir_path(const char *filename);
const char *util_datadir(void);
const char *util_datadir_path(const char *filename);

static inline void util_ptr_vec_free(void **ptr_vec, int count)
{
	int i;

	if (!ptr_vec || count < 0)
		return;

	for (i = 0; i < count; i++)
		free(ptr_vec[i]);
	free(ptr_vec);
}

/*
 * Expand size of dynamic array (element_t *) by one element
 *
 * @param[in,out]  array  Pointer to array (element_t **)
 * @param[in,out]  num    Pointer to integer containing number of elements
 */
#define util_expand_array(array, num) \
	do { \
		unsigned int __size = sizeof(*(*(array))); \
		*(array) = util_realloc(*(array), ++(*(num)) * __size); \
		memset(&((*(array))[*(num) - 1]), 0, __size); \
	} while (0)

/*
 * Append one element to dynamic array (element_t *)
 *
 * @param[in,out]  array    Pointer to array (element_t **)
 * @param[in,out]  num      Pointer to integer containing number of elements
 * @param[in]      element  Element to add (element_t)
 */
#define util_add_array(array, num, element) \
	do { \
		util_expand_array(array, num); \
		(*(array))[*(num) - 1] = (element) ; \
	} while (0)

#endif /* LIB_UTIL_BASE_H */
