/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef OPTICSMON_CLI_H
#define OPTICSMON_CLI_H

#include "lib/util_opt.h"

#define OPT_DUMP 128

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPERATION OPTIONS"),
	{
		.option = { "monitor", no_argument, NULL, 'm' },
		.desc = "Run continuously and report on link state changes "
			"collecting optics health data when a change is detected",
	},
	{
		.option = { "send-report", no_argument, NULL, 'r' },
		.desc = "Report the optics health data to the Support Element",
	},
	{
		.option = { "quiet", no_argument, NULL, 'q' },
		.desc = "Be quiet and don't print optics health summary",
	},
	{
		.option = { "module-info", no_argument, NULL, OPT_DUMP },
		.desc = "Include a base64 encoded binary dump of the module's "
			"SFF-8636/8472/8024 standard data for each netdev. "
			"This matches 'ethtool --module-info <netdev> raw on'",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	UTIL_OPT_SECTION("OPTIONS WITH ARGUMENTS"),
	{
		.option = { "interval", required_argument, NULL, 'i' },
		.argument = "seconds",
		.desc = "Interval in seconds at which to collect monitoring data "
			"in the absence of link state changes. A value larger than "
			"24 hours (86400 seconds) is clamped down to 24 hours.",
	},
	UTIL_OPT_SECTION("GENERAL OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
