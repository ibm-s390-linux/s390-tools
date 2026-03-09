/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef CHZCRYPT_CLI_H
#define CHZCRYPT_CLI_H

#include "lib/util_opt.h"

/*
 * Configuration of command line options
 */

#define OPT_CONFIG_ON  0x80
#define OPT_CONFIG_OFF 0x81
#define OPT_SE_ASSOC   0x82
#define OPT_SE_BIND    0x83
#define OPT_SE_UNBIND  0x84

static struct util_opt chzcrypt_opt_vec[] = {
	{
		.option = { "enable", no_argument, NULL, 'e'},
		.argument = "DEVICE_IDS",
		.desc = "Set the given cryptographic device(s) online"
	},
	{
		.option = { "disable", no_argument, NULL, 'd'},
		.argument = "DEVICE_IDS",
		.desc = "Set the given cryptographic device(s) offline",
	},
	{
		.option = { "all", no_argument, NULL, 'a'},
		.desc = "Set all available cryptographic device(s) "
			"online/offline, must be used in conjunction "
			"with the enable or disable option",
	},
	{
		.option = { "config-on", no_argument, NULL, OPT_CONFIG_ON},
		.argument = "DEVICE_IDS",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Set the given cryptographic card device(s) configured"
	},
	{
		.option = { "config-off", no_argument, NULL, OPT_CONFIG_OFF},
		.argument = "DEVICE_IDS",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Set the given cryptographic card device(s) deconfigured"
	},
	{
		.option = { "poll-thread-enable", no_argument, NULL, 'p'},
		.desc = "Enable zcrypt's poll thread",
	},
	{
		.option = { "poll-thread-disable", no_argument, NULL, 'n'},
		.desc = "Disable zcrypt's poll thread",
	},
	{
		.option = { "config-time", required_argument, NULL, 'c'},
		.argument = "TIMEOUT",
		.desc = "Set configuration timer for re-scanning the AP bus "
			"to TIMEOUT seconds",
	},
	{
		.option = { "poll-timeout", required_argument, NULL, 't'},
		.argument = "TIMEOUT",
		.desc = "Set poll timer to run poll tasklet all TIMEOUT "
			"nanoseconds after a request has been queued",
	},
	{
		.option = { "default-domain", required_argument, NULL, 'q'},
		.argument = "DOMAIN",
		.desc = "Set new default domain to DOMAIN",
	},
	{
		.option = { "verbose", no_argument, NULL, 'V'},
		.desc = "Print verbose messages",
	},
	{
		.option = { "se-associate", required_argument, NULL, OPT_SE_ASSOC},
		.argument = "assoc_idx",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "SE guest with AP support only: Associate the given queue device",
	},
	{
		.option = { "se-bind", no_argument, NULL, OPT_SE_BIND},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "SE guest with AP support only: Bind the given queue device",
	},
	{
		.option = { "se-unbind", no_argument, NULL, OPT_SE_UNBIND},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "SE guest with AP support only: Unbind the given queue device",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
