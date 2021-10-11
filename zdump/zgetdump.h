/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Main include file - Should be included by all source files
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZGETDUMP_H
#define ZGETDUMP_H

#include "zg.h"
#include "opts.h"

/*
 * zgetdump globals
 */
extern struct zgetdump_globals {
	struct zg_fh	*fh;
	struct options	opts;
} g;

#endif /* ZGETDUMP_H */
