/* SPDX-License-Identifier: MIT */
/*
 * Command line utilities - for lshwc
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LSHWC_CLI_H
#define LSHWC_CLI_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

static struct util_opt lshwc_opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "all", no_argument, NULL, 'a' },
		.desc = "Displays all CPUs in output"
	},
	{
		.option = { "loop", required_argument, NULL, 'l' },
		.argument = "NUMBER",
		.desc = "Specifies loop count for next read"
	},
	{
		.option = { "interval", required_argument, NULL, 'i' },
		.argument = "NUMBER",
		.desc = "Specifies interval between read operations (seconds)"
	},
	{
		.option = { "short", no_argument, NULL, 's' },
		.desc = "Abbreviate counter name with counter set letter and number"
	},
	{
		.option = { "hex0x", no_argument, NULL, 'X' },
		.desc = "Counter values in hexadecimal format with leading 0x"
	},
	{
		.option = { "hex", no_argument, NULL, 'x' },
		.desc = "Counter values in hexadecimal format"
	},
	{
		.option = { "hide", no_argument, NULL, 'H' },
		.desc = "Do not display undefined counters of a counter set"
	},
	{
		.option = { "delta", no_argument, NULL, 'd' },
		.desc = "Display delta counter values"
	},
	{
		.option = { "timeout", required_argument, NULL, 't' },
		.argument = "NUMBER",
		.desc = "run time in s (seconds) m (minutes) h (hours) and d (days)"
	},
	{
		.option = { "quote-all", no_argument, NULL, 'q' },
		.desc = "Apply quoting to all output elements"
	},
	{
		.option = { "format", required_argument, NULL, 'f' },
		.argument = "FORMAT",
		.desc = "List counters in specified FORMAT (" FMT_TYPE_NAMES ")"
	},
	{
		.option = { "counters", required_argument, NULL, 'c' },
		.argument = "LIST",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Specify comma separated list of counters to display"
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
