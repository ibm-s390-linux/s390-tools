/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef LSCHP_CLI_H
#define LSCHP_CLI_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

#define OPT_FORMAT 262	/* --format */

/*
 * Configuration of command line options
 */
static struct util_opt lschp_opt_vec[] = {
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	{
		.option = { "format", required_argument, NULL, OPT_FORMAT},
		.argument = "FORMAT",
		.desc = "Output format (" FMT_TYPE_NAMES ")",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	UTIL_OPT_END
};

#endif
