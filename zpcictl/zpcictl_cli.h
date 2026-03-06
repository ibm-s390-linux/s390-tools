/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef ZPCICTL_CLI_H
#define ZPCICTL_CLI_H

#include "lib/util_opt.h"

/* Defines for options with no short command */
#define OPT_RESET	128
#define OPT_DECONF	129
#define OPT_REPORT_ERR	130
#define OPT_RESET_FW	131

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("ERROR HANDLING OPTIONS"),
	{
		.option = { "reset", no_argument, NULL, OPT_RESET },
		.desc = "Reset the device and report an error to the Support Element (SE). "
			"The reset consists of a controlled shutdown and a subsequent "
			"re-enabling of the device. As a result, higher level interfaces such "
			"as network interfaces and block devices are destroyed and re-created.\n"
			"Manual configuration steps might be required to re-integrate the device, "
			"for example, in bonded interfaces or software RAIDs.\n"
			"Use this option only if the automatic recovery failed, or if it did "
			"not succeed to restore regular operations of the device and manual "
			"intervention is required.\n",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "reset-fw", no_argument, NULL, OPT_RESET_FW },
		.desc = "Reset the device through a firmware driven reset that triggers "
			"automatic recovery and reports an error to the Support Element (SE).\n",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "deconfigure", no_argument, NULL, OPT_DECONF },
		.desc = "Deconfigure the device to prepare for any repair action",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "report-error", no_argument, NULL, OPT_REPORT_ERR },
		.desc = "Report a device error to the Support Element (SE)",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	UTIL_OPT_SECTION("GENERAL OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
