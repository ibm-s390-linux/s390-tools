/*
 * EBCDIC specific functions
 *
 * Copyright IBM Corp. 2013, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef EBCDIC_H
#define EBCDIC_H

#include "lib/zt_common.h"


#ifndef __ASSEMBLER__

unsigned long ebcdic_strtoul(char *, char **, int);

static __always_inline int ecbdic_isspace(char c)
{
	return (c == 0x40) || (c == 0x05) || (c == 0x15) || (c == 0x25) ||
		(c == 0x0b) || (c == 0x0c) || (c == 0x0d);
}

static __always_inline int ebcdic_isdigit(char c)
{
	return (c >= 0xf0) && (c <= 0xf9);
}

static __always_inline int ebcdic_isupper(char c)
{
	return (c >= 0xC1 && c <= 0xC9) || (c >= 0xD1 && c <= 0xD9) ||
		(c >= 0xE2 && c <= 0xE9);
}

static __always_inline char ebcdic_tolower(char c)
{
	if (ebcdic_isupper(c))
		c -= 0x40;
	return c;
}
#endif /* __ASSEMBLER__ */
#endif /* EBCDIC_H */
