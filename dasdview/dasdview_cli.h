/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef DASDVIEW_CLI_H
#define DASDVIEW_CLI_H

#include "lib/util_opt.h"

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("DUMP OPTIONS"),
	{
		.option = { NULL, no_argument, NULL, '1' },
		.desc = "Show DASD content in short Hex/EBCDIC/ASCII format",
		.flags = UTIL_OPT_FLAG_NOLONG,
	},
	{
		.option = { NULL, no_argument, NULL, '2' },
		.desc = "Show DASD content in detailed Hex/EBCDIC/ASCII format",
		.flags = UTIL_OPT_FLAG_NOLONG,
	},
	{
		.option = { "begin", required_argument, NULL, 'b' },
		.argument = "BEGIN",
		.desc = "Specify start of dump in kilobytes (suffix k), "
			"megabytes (m), blocks (b), tracks (t), or cylinders (c)",
	},
	{
		.option = { "size", required_argument, NULL, 's' },
		.argument = "SIZE",
		.desc = "Specify size of dump in kilobytes (suffix k), "
			"megabytes (m), blocks (b), tracks (t), or cylinders (c)",
	},
	UTIL_OPT_SECTION("MISC"),
	{
		.option = { "characteristic", no_argument, NULL, 'c' },
		.desc = "Print the characteristics of a device",
	},
	{
		.option = { "info", no_argument, NULL, 'i' },
		.desc = "Print general DASD information and geometry",
	},
	{
		.option = { "volser", no_argument, NULL, 'j' },
		.desc = "Print the volume serial number",
	},
	{
		.option = { "label", no_argument, NULL, 'l' },
		.desc = "Print information about the volume label",
	},
	{
		.option = { "vtoc", required_argument, NULL, 't' },
		.argument = "SPEC",
		.desc = "Print the table of content (VTOC)",
	},
	{
		.option = { "extended", no_argument, NULL, 'x' },
		.desc = "Print extended DASD information",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
