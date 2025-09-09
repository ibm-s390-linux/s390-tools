/* SPDX-License-Identifier: MIT */
/*
 * Command line utilities - for dasdfmt
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DASDFMT_CLI_H
#define DASDFMT_CLI_H

#include "lib/util_fmt.h"
#include "lib/util_opt.h"

/* Defines for options with no short command */
#define OPT_CHECK       128
#define OPT_NOZERO      129
#define OPT_NODISCARD   130

static struct util_opt opt_vec[] = {
UTIL_OPT_SECTION("FORMAT ACTIONS"),
	{
		.option = { "mode", required_argument, NULL, 'M' },
		.argument = "MODE",
		.desc = "Specify scope of operation using MODE:\n"
			"  full: Full device (default)\n"
			"  quick: Only the first two tracks\n"
			"  expand: Unformatted tracks at device end",
	},
	{
		.option = { "check", no_argument, NULL, OPT_CHECK },
		.desc = "Perform complete format check on device",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	UTIL_OPT_SECTION("FORMAT OPTIONS"),
	{
		.option = { "blocksize", required_argument, NULL, 'b' },
		.argument = "SIZE",
		.desc = "Format blocks to SIZE bytes (default 4096)",
	},
	{
		.option = { "disk_layout", required_argument, NULL, 'd' },
		.argument = "LAYOUT",
		.desc = "Specify the disk layout:\n"
			"  cdl: Compatible Disk Layout (default)\n"
			"  ldl: Linux Disk Layout",
	},
	{
		.option = { "keep_volser", no_argument, NULL, 'k' },
		.desc = "Do not change the current volume serial",
	},
	{
		.option = { "label", required_argument, NULL, 'l' },
		.argument = "VOLSER",
		.desc = "Specify volume serial number",
	},
	{
		.option = { "no_label", no_argument, NULL, 'L' },
		.desc = "Don't write a disk label",
	},
	{
		.option = { "requestsize", required_argument, NULL, 'r' },
		.argument = "NUM",
		.desc = "Process NUM cylinders in one formatting step",
	},
	{
		.option = { "norecordzero", no_argument, NULL, OPT_NOZERO },
		.desc = "Prevent storage server from modifying record 0",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "no-discard", no_argument, NULL, OPT_NODISCARD },
		.desc = "Do not discard space before formatting",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { NULL, no_argument, NULL, 'y' },
		.desc = "Start formatting without further user-confirmation",
		.flags = UTIL_OPT_FLAG_NOLONG,
	},
	UTIL_OPT_SECTION("DISPLAY PROGRESS"),
	{
		.option = { "hashmarks", required_argument, NULL, 'm' },
		.argument = "NUM",
		.desc = "Show a hashmark every NUM cylinders",
	},
	{
		.option = { "progressbar", no_argument, NULL, 'p' },
		.desc = "Show a progressbar",
	},
	{
		.option = { "percentage", no_argument, NULL, 'P' },
		.desc = "Show progress in percent",
	},
	UTIL_OPT_SECTION("MISC"),
	{
		.option = { "check_host_count", no_argument, NULL, 'C' },
		.desc = "Check if device is in use by other hosts",
	},
	{
		.option = { "force", no_argument, NULL, 'F' },
		.desc = "Format without performing sanity checking",
	},
	{
		.option = { "test", no_argument, NULL, 't' },
		.desc = "Run in dry-run mode without modifying the DASD",
	},
	{
		.option = { NULL, no_argument, NULL, 'v' },
		.desc = "Print verbose messages when executing",
		.flags = UTIL_OPT_FLAG_NOLONG,
	},
	UTIL_OPT_HELP,
	{
		.option = { "version", no_argument, NULL, 'V' },
		.desc = "Print version information, then exit",
	},
	UTIL_OPT_END
};

#endif
