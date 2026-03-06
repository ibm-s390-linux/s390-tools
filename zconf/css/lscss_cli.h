/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef LSCSS_CLI_H
#define LSCSS_CLI_H

#include "lib/util_opt.h"

/*
 * Numbers for lscss command options that do not have a short form
 */
#define OPT_AVAIL	256	/* --avail */
#define OPT_VPM		257	/* --vpm */
#define OPT_IO		258	/* --io */
#define OPT_CHSC	259	/* --chsc */
#define OPT_EADM	260	/* --eadm */
#define OPT_VFIO	261	/* --vfio */

/*
 * Command line options
 */
static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "short", no_argument, NULL, 's'},
		.desc = "Shorten IDs by removing leading '0.0.' "
			"Note: only IDs beginning with '0.0.' "
			"will be displayed in this case.",
	},
	{
		.option = { "devtype", required_argument, NULL, 't'},
		.argument = "TYPE (DEVTYPE[/MODEL])",
		.desc = "For IO subchannels, limit output to devices of "
			"the given type",
	},
	{
		.option = { "devrange", no_argument, NULL, 'd'},
		.desc = "Indicate that RANGE refers to device identifiers",
	},
	{
		.option = { "avail", no_argument, NULL, OPT_AVAIL},
		.desc = "Show availability attribute of IO devices",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "vpm", no_argument, NULL, OPT_VPM},
		.desc = "Show verified path mask",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "uppercase", no_argument, NULL, 'u'},
		.desc = "Print values using uppercase",
	},
	{
		.option = { "io", no_argument, NULL, OPT_IO},
		.desc = "Show IO subchannels (default)",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "chsc", no_argument, NULL, OPT_CHSC},
		.desc = "Show CHSC subchannels",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "eadm", no_argument, NULL, OPT_EADM},
		.desc = "Show EADM subchannels",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "vfio", no_argument, NULL, OPT_VFIO},
		.desc = "Show VFIO subchannel information",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "all", no_argument, NULL, 'a'},
		.desc = "Show subchannels of all types",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
