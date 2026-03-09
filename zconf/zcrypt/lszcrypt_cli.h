/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef LSZCRYPT_CLI_H
#define LSZCRYPT_CLI_H

#include "lib/util_opt.h"

/*
 * Configuration of command line options
 */

#define OPT_ACCELONLY  0x81
#define OPT_CCAONLY    0x82
#define OPT_EP11ONLY   0x83
#define OPT_CARDONLY   0x84
#define OPT_QUEUEONLY  0x85

static struct util_opt lszcrypt_opt_vec[] = {
	{
		.option = {"bus", 0, NULL, 'b'},
		.desc = "Show AP bus attributes then exit",
	},
	{
		.option = { "capability", required_argument, NULL, 'c'},
		.argument = "DEVICE_ID",
		.desc = "Show the capabilities of a cryptographic device",
	},
	{
		.option = {"domains", 0, NULL, 'd'},
		.desc = "Show the configured AP usage and control domains",
	},
	{
		.option = {"verbose", 0, NULL, 'V'},
		.desc = "Print verbose messages",
	},
	{
		.option = {"accelonly", 0, NULL, OPT_ACCELONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from cards/queues in Accelerator mode",
	},
	{
		.option = {"ccaonly", 0, NULL, OPT_CCAONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from cards/queues in CCA-Coprocessor mode",
	},
	{
		.option = {"ep11only", 0, NULL, OPT_EP11ONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from cards/queues in EP11-Coprocessor mode",
	},
	{
		.option = {"cardonly", 0, NULL, OPT_CARDONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from cards but no queue info",
	},
	{
		.option = {"queueonly", 0, NULL, OPT_QUEUEONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from queues but no card info",
	},
	{
		.option = {"serial", 0, NULL, 's'},
		.desc = "Show the serial numbers for CCA and EP11 crypto cards",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
