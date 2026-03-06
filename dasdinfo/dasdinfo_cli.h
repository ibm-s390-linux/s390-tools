/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef DASDINFO_CLI_H
#define DASDINFO_CLI_H

#include "lib/util_opt.h"

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("DEVICE"),
	{
		.option = { "block", required_argument, NULL, 'b' },
		.argument = "BLOCKDEV",
		.desc = "Block device name, e.g. dasdb",
	},
	{
		.option = { "devnode", required_argument, NULL, 'd' },
		.argument = "DEVNODE",
		.desc = "Device node, e.g. /dev/dasda",
	},
	{
		.option = { "busid", required_argument, NULL, 'i' },
		.argument = "BUSID",
		.desc = "Bus ID, e.g. 0.0.e910",
	},
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "label", no_argument, NULL, 'l' },
		.desc = "Print DASD volume label (volser)",
	},
	{
		.option = { "uid", no_argument, NULL, 'u' },
		.desc = "Print DASD uid (without z/VM minidisk token)",
	},
	{
		.option = { "extended-uid", no_argument, NULL, 'x' },
		.desc = "Print DASD uid (including z/VM minidisk token)",
	},
	{
		.option = { "all", no_argument, NULL, 'a' },
		.desc = "Same as -u -x -l",
	},
	{
		.option = { "export", no_argument, NULL, 'e' },
		.desc = "Export ID_BUS, ID_TYPE, ID_SERIAL for use in udev",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
