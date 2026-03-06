/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef LSQETH_CLI_H
#define LSQETH_CLI_H

#include "lib/util_opt.h"

/*
 * Command line options
 */
static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "proc", no_argument, NULL, 'p'},
		.desc = "List all devices in the former /proc/qeth format"
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
