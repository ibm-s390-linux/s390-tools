/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef VMCP_CLI_H
#define VMCP_CLI_H

#include "lib/util_opt.h"

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "keepcase", no_argument, NULL, 'k' },
		.desc = "Do not convert CP-command string to uppercase",
	},
	{
		.option = { "buffer", required_argument, NULL, 'b' },
		.argument = "SIZE",
		.desc = "Specify buffer size in bytes, kilobytes (k) "
			"or megabytes (M). SIZE range from 4096 to 1048576 "
			"bytes"
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
