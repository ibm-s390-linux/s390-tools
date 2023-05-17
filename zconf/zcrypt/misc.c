/*
 * Misc - Local helper functions
 *
 * Copyright IBM Corp. 2016, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <regex.h>
#include <string.h>
#include <sys/types.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
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

/**
 * Test if AP bus has SB support available.
 *
 * @returns   true  Yes, SB support is available
 *            false No
 */
bool ap_bus_has_SB_support(void)
{
	static int sb_support = -1;

	if (sb_support < 0) {
		char *ap, buf[256];

		ap = util_path_sysfs("bus/ap");
		if (!util_path_is_dir(ap)) {
			sb_support = 0;
		} else {
			if (!util_path_is_readable("%s/features", ap)) {
				sb_support = 0;
			} else {
				util_file_read_line(buf, sizeof(buf),
						    "%s/features", ap);
				if (strstr(buf, "APSB"))
					sb_support = 1;
			}
		}
		free(ap);
	}

	return sb_support > 0 ? true : false;
}
