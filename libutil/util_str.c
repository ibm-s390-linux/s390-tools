/*
 * util - Utility function library
 *
 * Manipulate and work with strings
 *
 * Copyright IBM Corp. 2026
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <string.h>

#include "lib/util_panic.h"
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

/**
 * Check if string \a s starts with \a prefix
 *
 * @param[in] s       String to check
 * @param[in] prefix  Prefix to match
 *
 * @returns Pointer to the character after the prefix if match is found,
 *          NULL otherwise
 */
const char *util_startswith(const char *s, const char *prefix)
{
	size_t sz;

	util_assert(s != NULL, "Internal error: s input is NULL");
	util_assert(prefix != NULL, "Internal error: prefix input is NULL");
	sz = strlen(prefix);
	if (strncmp(s, prefix, sz) == 0)
		return s + sz;
	return NULL;
}

/**
 * Check if string \a s starts with \a prefix (case-insensitive)
 *
 * @param[in] s       String to check
 * @param[in] prefix  Prefix to match (case-insensitive)
 *
 * @returns Pointer to the character after the prefix if match is found,
 *          NULL otherwise
 */
const char *util_startswith_no_case(const char *s, const char *prefix)
{
	size_t sz;

	util_assert(s != NULL, "Internal error: s input is NULL");
	util_assert(prefix != NULL, "Internal error: prefix input is NULL");
	sz = strlen(prefix);
	if (strncasecmp(s, prefix, sz) == 0)
		return s + sz;
	return NULL;
}
