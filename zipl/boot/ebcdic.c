/*
 * EBCDIC specific functions
 *
 * Copyright IBM Corp. 2013, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include <limits.h>

#include "ebcdic.h"

/*
 * Convert EBCDIC string to number with given base. In case of an overflow,
 * ULONG_MAX is returned and @endptr is not updated.
 */
unsigned long ebcdic_strtoul(char *nptr, char **endptr, int base)
{
	unsigned long val = 0;

	while (ebcdic_isdigit(*nptr)) {
		if (val != 0)
			val *= base;
		if (__builtin_uaddl_overflow(val, *nptr - 0xf0, &val))
			return ULONG_MAX;
		nptr++;
	}
	if (endptr)
		*endptr = (char *)nptr;
	return val;
}
