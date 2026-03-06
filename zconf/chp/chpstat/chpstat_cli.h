/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef CHPSTAT_H
#define CHPSTAT_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

enum {
	OPT_STATUS       = 's',
	OPT_ENABLE       = 'e',
	OPT_DISABLE      = 'd',
	OPT_LIST_COLUMNS = 'l',
	OPT_LIST_KEYS    = 'L',
	OPT_ITERATIONS   = 'n',
	OPT_INTERVAL     = 'i',
	OPT_COLUMNS      = 'c',
	OPT_KEYS         = 'k',
	OPT_ALL          = 'a',
	/* Options without short version below. */
	OPT_FORMAT       = 0x80, /* First non-printable character. */
	OPT_CHARS,
	OPT_UTIL,
	OPT_METRICS,
	OPT_CMG,
	OPT_SCALE,
	OPT_NO_ANSI,
	OPT_NO_PREFIX,
	OPT_DEBUG,
};

/*
 * Configuration of command line options
 */
static struct util_opt opt_vec[] = {
	{
		.desc = "ACTIONS",
		.flags = UTIL_OPT_FLAG_SECTION,
	},
	{
		.option = { "status", no_argument, NULL, OPT_STATUS },
		.desc = "Show channel-path statistics status",
	},
	{
		.option = { "enable", no_argument, NULL, OPT_ENABLE },
		.desc = "Enable channel-path statistics",
	},
	{
		.option = { "disable", no_argument, NULL, OPT_DISABLE },
		.desc = "Disable channel-path statistics",
	},
	{
		.option = { "list-columns", no_argument, NULL,
			    OPT_LIST_COLUMNS},
		.desc = "List available table columns",
	},
	{
		.option = { "list-keys", no_argument, NULL, OPT_LIST_KEYS},
		.desc = "List available data keys",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	{
		.desc = "OPTIONS",
		.flags = UTIL_OPT_FLAG_SECTION,
	},
	{
		.option = { "iterations", required_argument, NULL,
			    OPT_ITERATIONS },
		.argument = "NUM",
		.desc = "Display NUM reports before ending (0 for no end)",
	},
	{
		.option = { "interval", required_argument, NULL,
			    OPT_INTERVAL },
		.argument = "NUM",
		.desc = "Pause NUM seconds between display",
	},
	{
		.option = { "columns", required_argument, NULL, OPT_COLUMNS },
		.argument = "COL,..",
		.desc = "Show only specified columns in table output",
	},
	{
		.option = { "keys", required_argument, NULL, OPT_KEYS },
		.argument = "KEY,..",
		.desc = "Show only data for specified keys in list output",
	},
	{
		.option = { "all", no_argument, NULL, OPT_ALL },
		.desc = "Show all table columns and key data",
	},
	{
		.option = { "scale", required_argument, NULL, OPT_SCALE },
		.argument = "UNIT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Scale BPS values by UNIT (number, suffix or auto)",
	},
	{
		.option = { "cmg", required_argument, NULL, OPT_CMG },
		.argument = "CMG,..",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show data for specified CMGs only",
	},
	{
		.option = { "format", required_argument, NULL, OPT_FORMAT },
		.argument = "FORMAT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List data in specified FORMAT (" FMT_TYPE_NAMES ")",
	},
	{
		.option = { "chars", no_argument, NULL, OPT_CHARS },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List channel-path measurement characteristics",
	},
	{
		.option = { "util", no_argument, NULL, OPT_UTIL },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List unprocessed utilization data",
	},
	{
		.option = { "metrics", no_argument, NULL, OPT_METRICS },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List performance metrics",
	},
	{
		.option = { "no-ansi", no_argument, NULL, OPT_NO_ANSI },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Do not use ANSI terminal codes in output",
	},
	{
		.option = { "no-prefix", no_argument, NULL, OPT_NO_PREFIX },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Hide key prefix in pairs output format",
	},
	{
		.option = { "debug", no_argument, NULL, OPT_DEBUG },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Print debugging information",
	},
	UTIL_OPT_END
};

#endif
