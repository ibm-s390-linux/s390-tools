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

/*
 * Helper function: for a given hex string return the bit value.
 * Bit count starts on the left with 0.
 * Returns 0 or 1 or -1 on failure.
 */
int check_mask_bit(const char *mask, int bit)
{
	int b;

	if (mask && mask[0] == '0' && mask[1] == 'x')
		mask += 2;

	while (*mask && bit >= 4) {
		mask++;
		bit -= 4;
	}
	if (*mask >= '0' && *mask <= '9')
		b = *mask - '0';
	else if (*mask >= 'a' && *mask <= 'f')
		b = *mask + 10 - 'a';
	else if (*mask >= 'A' && *mask <= 'F')
		b = *mask + 10 - 'A';
	else
		return -1;

	return b & (0x08 >> bit) ? 1 : 0;
}
