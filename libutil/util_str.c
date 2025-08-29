/*
 * util - Utility function library
 *
 * Manipulate and work with strings
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>

#include "lib/util_str.h"

/**
 * Copy characters from \a src to \a dest, omitting all blank characters
 * (spaces and tabs). The resulting string in \a dest will be NUL terminated.
 *
 * @param[in]  src   Source string
 * @param[out] dest  Destination buffer
 */
void util_str_rm_whitespace(const char *src, char *dest)
{
	while (*src != '\0') {
		if (!isblank(*src)) {
			*dest = *src;
			dest++;
		}
		src++;
	}
	*dest = '\0';
}
