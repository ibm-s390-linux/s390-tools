/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2026
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef SANITIZE_H
#define SANITIZE_H

#include <ctype.h>
#include <string.h>

/* Valid control-program identifier special characters */
#define VALID_CPNAME	"/"

/* Valid attribute key special characters */
#define VALID_ATTRKEY	"/:_"

/* Valid attribute value special characters */
#define VALID_ATTRVAL	"/-+:.,_ "

static inline int is_safe_char(unsigned char c, const char *set)
{
	return isalnum(c) || strchr(set, c);
}

static inline void sanitize(char *s, const char *set)
{
	for (; *s; s++) {
		if (!is_safe_char((unsigned char)*s, set))
			*s = '_';
	}
}

#endif /* SANITIZE_H */
