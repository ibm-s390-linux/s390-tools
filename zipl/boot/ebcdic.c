/*
 * EBCDIC specific functions
 *
 * Copyright IBM Corp. 2013, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include "ebcdic.h"


/*
 * Convert ebcdic string to number with given base
 */
unsigned long ebcdic_strtoul(char *nptr, char **endptr, int base)
{
	unsigned long val = 0;

	while (ebcdic_isdigit(*nptr)) {
		if (val != 0)
			val *= base;
		val += *nptr - 0xf0;
		nptr++;
	}
	if (endptr)
		*endptr = (char *)nptr;
	return val;
}
