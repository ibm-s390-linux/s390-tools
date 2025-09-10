/* SPDX-License-Identifier: MIT */
/*
 * Command line utilities - for lspai
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LSPAI_CLI_H
#define LSPAI_CLI_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

#define STR_SUB(x) #x
#define STR(x)	   STR_SUB(x)

#define OPT_FORMAT		256	/* --format XXX option */
#define DEFAULT_LOOP_INTERVAL	60	/* loop interval in seconds */

static struct util_opt lspai_opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "all", no_argument, NULL, 'a' },
		.desc = "Displays all CPUs in output"
	},
	{
		.option = { "delta", no_argument, NULL, 'd' },
		.desc = "Display delta counter values"
	},
	{
		.option = { "counters", required_argument, NULL, 'c' },
		.argument = "LIST",
		.desc = "Specify comma separated list of counters to display"
	},
	{
		.option = { "format", required_argument, NULL, OPT_FORMAT },
		.argument = "FORMAT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List counters in specified FORMAT (" FMT_TYPE_NAMES ")"
	},
	{
		.option = { "loops", required_argument, NULL, 'l' },
		.argument = "COUNT",
		.desc = "Number of read operations"
	},
	{
		.option = { "interval", required_argument, NULL, 'i' },
		.argument = "SECONDS",
		.desc = "Time to wait between loop iterations (default "
			STR(DEFAULT_LOOP_INTERVAL) "s)"
	},
	{
		.option = { "numeric", no_argument, NULL, 'n' },
		.desc = "Sort PAI counters by counter number"
	},
	{
		.option = { "short", no_argument, NULL, 's' },
		.desc = "Abbreviate counter name with counter set letter and number"
	},
	{
		.option = { "type", required_argument, NULL, 't' },
		.argument = "TYPE",
		.desc = "Type of PAI counters to show: crypto, nnpa"
	},
	{
		.option = { "hex0x", no_argument, NULL, 'X' },
		.desc = "Counter values in hexadecimal format with leading 0x"
	},
	{
		.option = { "hex", no_argument, NULL, 'x' },
		.desc = "Counter values in hexadecimal format"
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
