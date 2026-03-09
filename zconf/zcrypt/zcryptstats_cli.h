/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef ZCRYPTSTATS_CLI_H
#define ZCRYPTSTATS_CLI_H

#include "lib/util_opt.h"

/*
 * Configuration of command line options
 */
static struct util_opt zcryptstats_opt_vec[] = {
	/***********************************************************/
	{
		.flags = UTIL_OPT_FLAG_SECTION,
		.desc = "OPTIONS",
	},
	{
		.option = {"interval", required_argument, NULL, 'i'},
		.argument = "INTERVAL",
		.desc = "Specifies the interval time in seconds. If omitted, a "
			"default interval of 10 seconds is used",
	},
	{
		.option = {"count", required_argument, NULL, 'c'},
		.argument = "COUNT",
		.desc = "Specifies  the  number of reports that are generated "
			"at INTERVAL seconds apart. If omitted, reports are "
			"generated continuously, until stopped with control-C",
	},
	{
		.option = {"output", required_argument, NULL, 'o'},
		.argument = "JSON|TABLE|CSV",
		.desc = "Displays the statistics in the specified format. If "
			"this option is omitted, a comprehensive report is "
			"displayed. Supported output formats are: JSON, TABLE, "
			"CSV. With TABLE and CSV the display of the individual "
			"counters are omitted, and only the totals are "
			"displayed. CSV and TABLE output formats imply option "
			"--only-totals",
	},
	{
		.option = {"no-totals", 0, NULL, 't'},
		.desc = "Excludes the totals of all counters of a card "
			"device or queue device (APQN). It can not be "
			"specified together with option --only-totals or "
			"option --output TABLE|CSV",
	},
	{
		.option = {"only-totals", 0, NULL, 'T'},
		.desc = "Displays only the totals of all counters of a card "
			"device or a queue device (APQN), but not the "
			"individual counters. This option is implied with "
			"option --output TABLE|CSV",
	},
	{
		.option = {"no-apqn", 0, NULL, 'a'},
		.desc = "Displays only the counters of the card device, but "
			"omits the counters of the queue device (APQN). If the "
			"system does not support obtaining cryptographic "
			"performance measurement data on the queue devices, "
			"then this option is implied",
	},
	{
		.option = {"map-type", required_argument, NULL, 'M'},
		.argument = "MAPPING",
		.desc = "Maps unknown cryptographic device types and modes to "
			"known types and modes. This option should only be "
			"used when new, so far unknown cryptographic devices "
			"are found. You can then map them to known devices and "
			"modes, provided that the new cryptographic devices "
			"report the same counters as the known cryptographic "
			"device to which it is mapped. The mapping "
			"specification consists of a comma-separated list of "
			"FROM-TYPE:FROM-MODE=TO-TYPE:TO-MODE specifications. "
			"The type and mode values must be specified in decimal "
			"notation",
	},
	{
		.option = {"all", 0, NULL, 'A'},
		.desc = "Displays all cards devices and queue devices (APQNs), "
			"not only those that are available to the Linux "
			"system. Using this option additional cryptographic "
			"devices that are available in the CEC, but not "
			"available to the Linux system are also monitored. "
			"This option can not be specified together with option "
			"--only-online",
	},
	{
		.option = {"only-online", 0, NULL, 'O'},
		.desc = "Displays only online cards devices and queue devices "
			"(APQNs). This option can not be specified together "
			"with option --all"
	},
	{
		.option = {"verbose", 0, NULL, 'V'},
		.desc = "Prints additional information messages during "
			"processing",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
