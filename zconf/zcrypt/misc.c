/*
 * Misc - Local helper functions
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <regex.h>
#include <sys/types.h>

#include "lib/util_panic.h"
#include "misc.h"

/**
 * Test string against regular expression
 *
 * @param[in] str   String to investigate
 * @param[in] regex Regular expression
 *
 * @returns   true  String matches with regular expression
 *            false No match
 */
bool misc_regex_match(const char *str, const char *regex)
{
	regmatch_t pmatch[1];
	regex_t preg;
	int rc;

	rc = regcomp(&preg, regex, REG_EXTENDED);
	util_assert(rc == 0, "The regcomp() function failed: rc = %d\n", rc);

	rc = regexec(&preg, str, (size_t) 1, pmatch, 0);
	regfree(&preg);
	return rc == 0 ? true : false;
}
