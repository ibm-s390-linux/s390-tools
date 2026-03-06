/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef CHCHP_CLI_H
#define CHCHP_CLI_H

#include "lib/util_opt.h"

/*
 * Configuration of command line options
 */
static struct util_opt chchp_opt_vec[] = {
	{
		.option = { "vary", required_argument, NULL, 'v'},
		.argument = "VALUE",
		.desc = "Logically vary channel-path to VALUE (1=on, 0=off)",
	},
	{
		.option = { "configure", required_argument, NULL, 'c'},
		.argument = "VALUE",
		.desc = "Configure channel-path to VALUE (1=on, 0=standby)",
	},
	{
		.option = { "attribute", required_argument, NULL, 'a'},
		.argument = "KEY=VALUE",
		.desc = "Set channel-path attribute KEY to VALUE",
	},
	UTIL_OPT_HELP,
	{
		.option = { "version", 0, NULL, 'V'},
		.desc = "Print version information, then exit",
	},
	UTIL_OPT_END
};

#endif
