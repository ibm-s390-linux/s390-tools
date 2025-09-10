/* SPDX-License-Identifier: MIT */
/*
 * Command line utilities - for pai
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PAI_CLI_H
#define PAI_CLI_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

static struct util_opt pai_opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "crypto", optional_argument, NULL, 'c' },
		.argument = "CPULIST[:DATA]",
		.desc = "Collect PAI crypto counters"
	},
	{
		.option = { "nnpa", optional_argument, NULL, 'n' },
		.argument = "CPULIST[:DATA]",
		.desc = "Collect PAI nnpa counters"
	},
	{
		.option = { "mapsize", required_argument, NULL, 'm' },
		.argument = "SIZE",
		.desc = "Specifies number of 4KB pages for event ring buffer"
	},
	{
		.option = { "report", no_argument, NULL, 'r' },
		.desc = "Report file contents"
	},
	{
		.option = { "realtime", required_argument, NULL, 'R' },
		.argument = "PRIO",
		.desc = "Collect data with this RT SCHED_FIFO priority"
	},
	{
		.option = { "interval", required_argument, NULL, 'i' },
		.argument = "NUMBER",
		.desc = "Specifies interval between read operations in milliseconds"
	},
	{
		.option = { "verbose", no_argument, NULL, 'V' },
		.desc = "Verbose output"
	},
	{
		.option = { "humantime", no_argument, NULL, 'H' },
		.desc = "Human readable timestamp in seconds.nanoseconds"
	},
	{
		.option = { "summary", no_argument, NULL, 'S' },
		.desc = "Print summary of all non-zero counter values"
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
