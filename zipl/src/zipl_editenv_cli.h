/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef ZIPL_EDITENV_CLI_H
#define ZIPL_EDITENV_CLI_H

#include "lib/util_opt.h"

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS WITHOUT ARGUMENTS"),
	{
		.option = { "list", no_argument, NULL, 'l'},
		.desc = "print list of zIPL environment variables with their values",
	},
	{
		.option = { "reset", no_argument, NULL, 'r'},
		.desc = "remove all variables from zIPL environment",
	},
	{
		.option = { "verbose", no_argument, NULL, 'V'},
		.desc = "provide more information",
	},
	UTIL_OPT_SECTION("OPTIONS WITH ARGUMENTS"),
	{
		.option = { "target", required_argument, NULL, 't'},
		.argument = "DIR",
		.desc = "specify directory, where bootmap file is located",
	},
	{
		.option = { "site", required_argument, NULL, 'S'},
		.argument = "SITE",
		.desc = "specify site ID",
	},
	{
		.option = { "effective-site", required_argument, NULL, 'E'},
		.argument = "SITE",
		.desc = "specify effective site ID",
	},
	{
		.option = { "set", required_argument, NULL, 's'},
		.argument = "NAME=VALUE",
		.desc = "assign value VALUE to variable NAME",
	},
	{
		.option = { "unset", required_argument, NULL, 'u'},
		.argument = "NAME",
		.desc = "remove variable NAME from zIPL environment",
	},
	UTIL_OPT_SECTION("STANDARD OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END,
};

#endif
