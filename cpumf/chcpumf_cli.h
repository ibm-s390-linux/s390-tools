/* SPDX-License-Identifier: MIT */
/*
 * Command line utilities - for chcpumf
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CHCPUMF_CLI_H
#define CHCPUMF_CLI_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

static struct util_opt chcpumf_opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "min", required_argument, NULL, 'm' },
		.argument = "num_sdb",
		.desc = "Specifies the initial size of the sampling buffer.\n"
			"A sample-data-block (SDB) consumes about 4 kilobytes.",
	},
	{
		.option = { "max", required_argument, NULL, 'x' },
		.argument = "num_sdb",
		.desc = "Specifies the maximum size of the sampling buffer.\n"
			"A sample-data-block (SDB) consumes about 4 kilobytes.",
	},
	{
		.option = { "verbose", no_argument, NULL, 'V' },
		.desc = "Verbose, display new sample-data-block values.",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
