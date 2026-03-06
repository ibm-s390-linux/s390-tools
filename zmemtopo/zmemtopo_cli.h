/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef ZMEMTOPO_CLI_H
#define ZMEMTOPO_CLI_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

#define OPT_FORMAT 256

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OUTPUT FORMAT OPTIONS"),
	{
		.option = { "level", required_argument, NULL, 'l' },
		.argument = "NESTING_LEVEL",
		.desc = "Set the topology display depth to NESTING_LEVEL"
	}, {
		.option = { "format", required_argument, NULL, OPT_FORMAT },
		.argument = "FORMAT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List data in specified FORMAT (" FMT_TYPE_NAMES ")",
	}, {
		.option = { "full", no_argument, NULL, 'f' },
		.desc = "Display tree view with padded elements"
	}, {
		.option = { "reverse", no_argument, NULL, 'r' },
		.desc = "Reverse tree view hierarchy direction"
	}, {
		.option = { "table", no_argument, NULL, 't' },
		.desc = "Use table view to display topology"
	}, {
		.option = { "sort", required_argument, NULL, 's' },
		.argument = "FIELD",
		.desc = "Sort view by FIELD (nr, lpar, size)"
	}, {
		.option = { "ascii", no_argument, NULL, 'i' },
		.desc = "Use only ASCII characters",
	},
	UTIL_OPT_SECTION("GENERAL OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
