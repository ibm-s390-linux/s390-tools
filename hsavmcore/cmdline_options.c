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
#include "hsavmcore_cli.h"

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
