/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/zt_common.h"
#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/util_log.h"

#include "cmdline_options.h"

static const struct util_prg prg = {
	.desc = "hsavmcore is designed to make the dump process with kdump more "
		"efficient. The HSA memory contains a part of the production "
		"kernel's memory. Use hsavmcore to cache this information and "
		"release HSA memory early in the process.",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2021,
			.pub_last = 2021,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

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

void parse_cmdline_options(int argc, char *argv[], struct config *config)
{
	int opt, ret;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	/* Parse given command-line config */
	while (1) {
		opt = util_opt_getopt_long(argc, argv);
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case 'V':
			config->verbose++;
			util_log_set_level(config->verbose);
			break;
		case 'c':
			ret = update_config_from_file(optarg, config);
			if (ret < 0)
				exit(EXIT_FAILURE);
			util_log_set_level(config->verbose);
			break;
		case 'C':
			strncpy(config->vmcore_path, optarg,
				sizeof(config->vmcore_path) - 1);
			/* Ensure null termination */
			config->vmcore_path[sizeof(config->vmcore_path) - 1] =
				'\0';
			break;
		case 'H':
			strncpy(config->zcore_hsa_path, optarg,
				sizeof(config->zcore_hsa_path) - 1);
			/* Ensure null termination */
			config->zcore_hsa_path[sizeof(config->zcore_hsa_path) -
					       1] = '\0';
			break;
		case 'W':
			strncpy(config->workdir_path, optarg,
				sizeof(config->workdir_path) - 1);
			/* Ensure null termination */
			config->workdir_path[sizeof(config->workdir_path) - 1] =
				'\0';
			break;
		case 'B':
			strncpy(config->bind_mount_vmcore_path, optarg,
				sizeof(config->bind_mount_vmcore_path) - 1);
			/* Ensure null termination */
			config->bind_mount_vmcore_path
				[sizeof(config->bind_mount_vmcore_path) - 1] =
				'\0';
			break;
		case 'S':
			strncpy(config->swap, optarg, sizeof(config->swap) - 1);
			/* Ensure null termination */
			config->swap[sizeof(config->swap) - 1] = '\0';
			break;
		case 'T': {
			char *endptr;
			long hsa_size = strtol(optarg, &endptr, 0);

			if (*endptr != '\0' || hsa_size < -1 ||
			    hsa_size > INT_MAX) {
				fprintf(stderr,
					"The given HSA size is invalid.\n");
				exit(EXIT_FAILURE);
			}
			config->hsa_size = hsa_size;
			break;
		}
		case 'D':
			config->mount_debugfs = true;
			break;
		case 'F':
			config->use_hsa_mem = true;
			break;
		case 'R':
			config->release_hsa = false;
			break;
		case 'N':
			config->bind_mount_vmcore = false;
			break;
		case 'G':
			config->fuse_debug = true;
			break;
		case '?':
		default:
			util_opt_print_parse_error(opt, argv);
			exit(EXIT_FAILURE);
		}
	}
}
