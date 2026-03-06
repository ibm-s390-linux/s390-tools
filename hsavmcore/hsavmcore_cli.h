/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef HSAVMCORE_CLI_H
#define HSAVMCORE_CLI_H

#include "lib/util_opt.h"

#include "common.h"

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("CONFIGURATION"),
	{
		.option = { "config", required_argument, NULL, 'c' },
		.argument = "CONFIGFILE",
		.desc = "Path to the configuration file.\n"
			"Default: no configuration file is used",
	},
	{
		.option = { "vmcore", required_argument, NULL, 'C' },
		.argument = "VMCOREFILE",
		.desc = "Path to the vmcore file.\n"
			"Default: " PROC_VMCORE,
	},
	{
		.option = { "hsa", required_argument, NULL, 'H' },
		.argument = "ZCOREHSAFILE",
		.desc = "Path to the zcore HSA file.\n"
			"Default: " ZCORE_HSA,
	},
	{
		.option = { "workdir", required_argument, NULL, 'W' },
		.argument = "WORKDIR",
		.desc = "Path to the work directory where temporary files can be "
			"stored.\nDefault: " WORKDIR,
	},
	{
		.option = { "bmvmcore", required_argument, NULL, 'B' },
		.argument = "VMCOREFILE",
		.desc = "Path to the target of the bind mount for the vmcore "
			"replacement.\nDefault: " PROC_VMCORE,
	},
	{
		.option = { "swap", required_argument, NULL, 'S' },
		.argument = "PATH",
		.desc = "Path to a swap device or file. The specified swap "
			"device or file must exist and have the proper swap "
			"format.\nDefault: no swap device or file is activated",
	},
	{
		.option = { "hsasize", required_argument, NULL, 'T' },
		.argument = "HSASIZE",
		.desc = "HSA size in bytes.\n"
			"Default: -1 (read from the zcore HSA file)",
	},
	{
		.option = { "dbgfsmnt", no_argument, NULL, 'D' },
		.desc = "Mount the debug file system.\n"
			"Default: the debug file system is not mounted",
	},
	{
		.option = { "hsamem", no_argument, NULL, 'F' },
		.desc = "Cache the HSA memory in regular memory.\n"
			"Default: the HSA memory is cached as a file within "
			"WORKDIR",
	},
	{
		.option = { "norelhsa", no_argument, NULL, 'R' },
		.desc = "Do NOT release the HSA memory after caching.\n"
			"Default: the HSA memory is released",
	},
	{
		.option = { "nobindmnt", no_argument, NULL, 'N' },
		.desc = "Do NOT replace the system's vmcore.\n"
			"Default: the system's vmcore is replaced",
	},
	UTIL_OPT_SECTION("LOGGING"),
	{
		.option = { "verbose", no_argument, NULL, 'V' },
		.desc = "Print verbose messages to stdout. Repeat this option "
			"for increased verbosity from just error messages to "
			"also include warning,  information, debug, and trace "
			"messages. This option is intended for debugging",
	},
	{
		.option = { "fusedbg", no_argument, NULL, 'G' },
		.desc = "Enable FUSE debugging.\n"
			"Default: FUSE debugging is disabled",
	},
	UTIL_OPT_SECTION("GENERAL OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#endif
