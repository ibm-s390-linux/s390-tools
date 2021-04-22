/**
 * util_log_example - Example program for util_log
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

//! [code]
#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/util_log.h"

static const struct util_prg prg = {
	.desc = "Example for util_log.",
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
	{
		.option = { "verbose", no_argument, NULL, 'V' },
		.desc = "Print verbose messages to stderr. "
			"This option may be given multiple times and "
			"each time this option is given the verbosity level is "
			"increased.",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

int main(int argc, char *argv[])
{
	int verbose = -1;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while (1) {
		int opt = util_opt_getopt_long(argc, argv);

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
			verbose++;
			break;
		case '?':
		default:
			fprintf(stderr, "Try '--help' for more information.\n");
			exit(EXIT_FAILURE);
		}
	}

	util_log_set_level(verbose);

	util_log_print(UTIL_LOG_ERROR, "This is an ERROR message\n");
	util_log_print(UTIL_LOG_WARN, "This is a WARN message\n");
	util_log_print(UTIL_LOG_INFO, "This is an INFO message\n");
	util_log_print(UTIL_LOG_DEBUG, "This is a DEBUG message\n");
	util_log_print(UTIL_LOG_TRACE, "This is a TRACE message\n");

	return EXIT_SUCCESS;
}
//! [code]
