/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef TUNEDASD_CLI_H
#define TUNEDASD_CLI_H

#include "lib/util_opt.h"

/* Defines for options with no short command */
#define OPT_PATH_RESET_ALL	128
#define OPT_ENABLE_STATS	129
#define OPT_DISABLE_STATS	130

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("CACHING MODES (ECKD ONLY)"),
	{
		.option = { "cache", required_argument, NULL, 'c' },
		.argument = "BEHAVIOUR",
		.desc = "Specify caching behaviour on storage server: "
			"normal, bypass, inhibit, sequential, prestage, or record",
	},
	{
		.option = { "no_cyl", required_argument, NULL, 'n' },
		.argument = "NUM",
		.desc = "NUM cylinders to be cached (only valid with -c/--cache)",
	},
	{
		.option = { "get_cache", no_argument, NULL, 'g' },
		.desc = "Get current storage server caching behaviour",
	},
	UTIL_OPT_SECTION("RESERVE / RELEASE"),
	{
		.option = { "release", no_argument, NULL, 'L' },
		.desc = "Release device",
	},
	{
		.option = { "slock", no_argument, NULL, 'O' },
		.desc = "Unconditional reservce device\n"
			"NOTE: Use with care, this breaks an existing lock",
	},
	{
		.option = { "query_reserve", no_argument, NULL, 'Q' },
		.desc = "Print reserve status of device",
	},
	{
		.option = { "reserve", no_argument, NULL, 'S' },
		.desc = "Reserve device",
	},
	UTIL_OPT_SECTION("PERFORMANCE STATISTICS"),
	{
		.option = {
			"enable-stats", no_argument, NULL, OPT_ENABLE_STATS
		},
		.desc = "Enable performance statistics globally",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {
			"disable-stats", no_argument, NULL, OPT_DISABLE_STATS
		},
		.desc = "Disable performance statistics globally",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "prof_item", required_argument, NULL, 'I' },
		.argument = "ROW",
		.desc = "Print single profile item: reqs, sects, sizes, total, "
			"totsect, start, irq, irqsect, end, or queue",
	},
	{
		.option = { "profile", no_argument, NULL, 'P' },
		.desc = "Print profile info of device",
	},
	{
		.option = { "reset_prof", no_argument, NULL, 'R' },
		.desc = "Reset profile info of device",
	},
	UTIL_OPT_SECTION("MISC"),
	{
		.option = { "path_reset", required_argument, NULL, 'p' },
		.argument = "CHPID",
		.desc = "Reset channel path CHPID of a device",
	},
	{
		.option = {
			"path_reset_all", no_argument, NULL, OPT_PATH_RESET_ALL
		},
		.desc = "Reset all channel paths of a device",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "copy-pair-swap", required_argument, NULL, 's' },
		.argument = "COPY_PAIR",
		.desc = "Swap a specified, comma separated copy pair.",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
