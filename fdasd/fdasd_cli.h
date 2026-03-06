/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef FDASD_CLI_H
#define FDASD_CLI_H

#include "lib/util_opt.h"

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("NON-INTERACTIVE MODE"),
	{
		.option = { "auto", no_argument, NULL, 'a' },
		.desc = "Create a single partition spanning the entire disk",
	},
	{
		.option = { "config", required_argument, NULL, 'c' },
		.argument = "FILE",
		.desc = "Create partitions(s) based on content of FILE",
	},
	{
		.option = { "keep_volser", no_argument, NULL, 'k' },
		.desc = "Do not change the current volume serial",
	},
	{
		.option = { "label", required_argument, NULL, 'l' },
		.argument = "VOLSER",
		.desc = "Set the volume serial to VOLSER",
	},
	UTIL_OPT_SECTION("MISC"),
	{
		.option = { "check_host_count", no_argument, NULL, 'C' },
		.desc = "Check if device is in use by other hosts",
	},
	{
		.option = { "force", optional_argument, NULL, 'f' },
		.argument = "TYPE,SIZE",
		.desc = "Force fdasd to work on non DASD devices with assumed "
			"TYPE (3390, 3380, or 9345) and blocksize SIZE",
	},
	{
		.option = { "volser", no_argument, NULL, 'i' },
		.desc = "Print volume serial",
	},
	{
		.option = { "table", no_argument, NULL, 'p' },
		.desc = "Print partition table",
	},
	{
		.option = { "verbose", no_argument, NULL, 'r' },
		.desc = "Provide more verbose output",
	},
	{
		.option = { "silent", no_argument, NULL, 's' },
		.desc = "Suppress messages",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
