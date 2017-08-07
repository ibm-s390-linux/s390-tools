/*
 * Misc - Local helper functions
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>
#include "lib/util_base.h"

/*
 * Helper function that copies a string safely
 */
size_t misc_strlcpy(char *dest, const char *src, size_t size)
{
	size_t str_len = strlen(src);
	size_t len;

	if (size) {
		len = MIN(size - 1, str_len);
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return str_len;
}
