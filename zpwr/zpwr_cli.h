/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef ZPWR_CLI_H
#define ZPWR_CLI_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

#define OPT_FORMAT	256

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "format", required_argument, NULL, OPT_FORMAT },
		.argument = "FORMAT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List data in specified FORMAT (" FMT_TYPE_NAMES ")",
	},
	{
		.option = { "delay", required_argument, NULL, 'd' },
		.argument = "NUMBER",
		.desc = "Power readings after delay (seconds)",
	},
	{
		.option = { "count", required_argument, NULL, 'c' },
		.argument = "NUMBER",
		.desc = "Number of power readings",
	},
	{
		.option = { "stream", no_argument, NULL, 's' },
		.desc = "Power readings in stream mode",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
