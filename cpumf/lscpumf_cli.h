/* SPDX-License-Identifier: MIT */
/*
 * Command line utilities - for lscpumf
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LSCPUMF_CLI_H
#define LSCPUMF_CLI_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

static struct util_opt lscpumf_opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "list-counters", no_argument, NULL, 'c' },
		.desc = "Lists counters for which the LPAR is authorized.",
	},
	{
		.option = { "list-all-counters", no_argument, NULL, 'C' },
		.desc = "Lists counters regardless of LPAR authorization.",
	},
	{
		.option = { "name", no_argument, NULL, 'n' },
		.desc = "Displays counter names.",
	},
	{
		.option = { "info", no_argument, NULL, 'i' },
		.desc = "Displays detailed information.",
	},
	{
		.option = { "list-sampling-events", no_argument, NULL, 's' },
		.desc = "Lists sampling events for which the LPAR is authorized.",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
