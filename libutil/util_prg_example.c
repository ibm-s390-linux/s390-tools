/**
 * util_prg_example - Example program for util_prg
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

//! [code]
#include <getopt.h>
#include <stdlib.h>

#include "lib/util_prg.h"

/*
 * Program description
 */
const struct util_prg prg = {
	.desc	= "Sample for util_prg library.",
	.args	= "[POS_ARGS]",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2001,
			.pub_last = 2017,
		},
		{
			.owner = "Another Corp.",
			.pub_first = 2017,
			.pub_last = 2017,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static const struct option opt_list[] = {
	{ "help",	no_argument,	NULL, 'h' },
	{ "version",	no_argument,	NULL, 'v' },
	{ NULL,		no_argument,	NULL, 0 },
};

/*
 * Demonstrate the util_prg_print() functions
 */
int main(int argc, char *argv[])
{
	const char *file_name = "i_do_not_exist";
	char optopt_str[3];
	FILE *fp;
	int opt;

	/* Disable the getopt_long() error messages */
	opterr = 0;

	util_prg_init(&prg);

	while ((opt = getopt_long(argc, argv, "vhe", opt_list, NULL)) != -1) {
		switch (opt) {
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		case 'h':
			util_prg_print_help();
			printf(" -e Try to open non-exisiting file\n");
			printf(" -h Print this help, then exit\n");
			printf(" -v Print version information, then exit\n");
			return EXIT_SUCCESS;
		case 'e':
			fp = fopen(file_name, "r");
			if (!fp) {
				err(EXIT_FAILURE, "Open of '%s' failed",
				    file_name);
			}
			return EXIT_SUCCESS;
		case ':':
			/* Option requires an argument */
			util_prg_print_required_arg(argv[optind - 1]);
			return EXIT_FAILURE;
		case '?':
			sprintf(optopt_str, "-%c", optopt);
			util_prg_print_invalid_option(optopt_str);
			return EXIT_FAILURE;
		}
	}
	if (argc > 2) {
		util_prg_print_arg_error(argv[2]);
		return EXIT_FAILURE;
	}
	if (argc == 2) {
		printf("Positional parameter specified: %s\n", argv[1]);
		return EXIT_SUCCESS;
	}
	errx(EXIT_FAILURE, "Specify either -h, -v, -e, or one positional "
			   "parameter");
}
//! [code]
