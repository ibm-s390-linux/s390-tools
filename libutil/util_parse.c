/* SPDX-License-Identifier: MIT */
/*
 * util - Utility function library
 *
 * String parsing utility functions
 *
 * Copyright IBM Corp. 2026
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_libc.h"
#include "lib/util_parse.h"
#include "lib/util_str.h"
#include "lib/zt_common.h"

enum size_unit {
	UNIT_BYTES = 0,
	UNIT_KIB, /* 1024 */
	UNIT_K,	  /* 1000 */
	UNIT_MIB, /* 1024^2 */
	UNIT_M,	  /* 1000^2 */
	UNIT_GIB, /* 1024^3 */
	UNIT_G,	  /* 1000^3 */
	UNIT_TIB, /* 1024^4 */
	UNIT_T,	  /* 1000^4 */
	UNIT_PIB, /* 1024^5 */
	UNIT_P,	  /* 1000^5 */
	UNIT_EIB, /* 1024^6 */
	UNIT_E,	  /* 1000^6 */
};

struct unit_mapping {
	const char *suffix;
	enum size_unit unit;
	uint64_t multiplier;
};

static const struct unit_mapping unit_table[] = {
	{ "EiB", UNIT_EIB, 1024ULL * 1024 * 1024 * 1024 * 1024 * 1024 },
	{ "E", UNIT_E, 1000ULL * 1000 * 1000 * 1000 * 1000 * 1000 },
	{ "PiB", UNIT_PIB, 1024ULL * 1024 * 1024 * 1024 * 1024 },
	{ "P", UNIT_P, 1000ULL * 1000 * 1000 * 1000 * 1000 },
	{ "TiB", UNIT_TIB, 1024ULL * 1024 * 1024 * 1024 },
	{ "T", UNIT_T, 1000ULL * 1000 * 1000 * 1000 },
	{ "GiB", UNIT_GIB, 1024ULL * 1024 * 1024 },
	{ "G", UNIT_G, 1000ULL * 1000 * 1000 },
	{ "MiB", UNIT_MIB, 1024ULL * 1024 },
	{ "M", UNIT_M, 1000ULL * 1000 },
	{ "KiB", UNIT_KIB, 1024ULL },
	{ "K", UNIT_K, 1000ULL },
	{ "", UNIT_BYTES, 1ULL }
};

static const char *const bool_false_values[] = { "0", "n", "no", "f", "false", "off" };
static const char *const bool_true_values[] = { "1", "y", "yes", "t", "true", "on" };

/* Ensure both arrays have the same size for consistency */
STATIC_ASSERT(ARRAY_SIZE(bool_false_values) == ARRAY_SIZE(bool_true_values));

static const struct unit_mapping *find_unit_suffix(const char *suffix)
{
	size_t i;

	if (!suffix || *suffix == '\0')
		return &unit_table[ARRAY_SIZE(unit_table) - 1];
	for (i = 0; i < ARRAY_SIZE(unit_table); i++) {
		if (strcasecmp(suffix, unit_table[i].suffix) == 0)
			return &unit_table[i];
	}
	return NULL;
}

/**
 * util_parse_bool - Parse a boolean value from a string
 * @input: Input string to parse
 *
 * Returns: 1 for true, 0 for false, -EINVAL on error
 */
int util_parse_bool(const char *input)
{
	size_t i;

	if (!input)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(bool_false_values); i++) {
		if (strcasecmp(input, bool_false_values[i]) == 0)
			return 0;
	}

	for (i = 0; i < ARRAY_SIZE(bool_true_values); i++) {
		if (strcasecmp(input, bool_true_values[i]) == 0)
			return 1;
	}

	return -EINVAL;
}

int util_parse_byte_size(const char *input, size_t *bytes)
{
	const struct unit_mapping *unit;
	uint64_t multiplier = 1;
	unsigned long value;
	char *endptr;

	if (!input || !bytes)
		return -EINVAL;

	errno = 0;
	value = strtoul(input, &endptr, 10);
	if (errno == ERANGE)
		return -ERANGE;
	if (errno != 0)
		return -errno;
	if (endptr == input)
		return -EINVAL;

	if (*endptr != '\0') {
		unit = find_unit_suffix(endptr);
		if (!unit)
			return -EINVAL;
		multiplier = unit->multiplier;
	}

	if (value > SIZE_MAX / multiplier)
		return -ERANGE;

	*bytes = (size_t)(value * multiplier);
	return 0;
}

int util_parse_range(const char *input, struct util_range *range)
{
	char *start_str, *end_str;
	char *input_copy;
	char *dash_pos;
	int ret = 0;

	if (!input || !range)
		return -EINVAL;

	input_copy = util_strdup(input);

	dash_pos = strchr(input_copy, '-');
	if (!dash_pos) {
		ret = -EINVAL;
		goto out;
	}

	*dash_pos = '\0';
	start_str = input_copy;
	end_str = dash_pos + 1;

	ret = util_parse_int(start_str, &range->start);
	if (ret)
		goto out;

	ret = util_parse_int(end_str, &range->end);
	if (ret)
		goto out;

	if (range->start > range->end) {
		ret = -ERANGE;
		goto out;
	}

out:
	free(input_copy);
	return ret;
}

int util_parse_int(const char *input, size_t *value)
{
	const char *num_start, *rest;
	char *endptr = NULL;
	int base = 0;

	if (!input || !value)
		return -EINVAL;
	if (*input == '\0')
		return -EINVAL;

	num_start = input;

	/* Determine base from prefix */
	/* Supports: 0x (hex), 0b (binary), 0o/0 (octal), decimal */
	rest = util_startswith_no_case(input, "0b");
	if (rest) {
		base = 2;
		num_start = rest;
		if (*num_start == '\0')
			return -EINVAL;
	} else {
		rest = util_startswith_no_case(input, "0o");
		if (rest) {
			base = 8;
			num_start = rest;
			if (*num_start == '\0')
				return -EINVAL;
		}
		/* base=0: strtoull handles 0x (hex) and 0 (octal) */
	}

	errno = 0;
	*value = strtoull(num_start, &endptr, base);

	if (errno == ERANGE)
		return -ERANGE;
	if (!endptr || endptr == num_start || *endptr != '\0')
		return -EINVAL;

	return 0;
}
