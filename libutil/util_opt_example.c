/*
 * util_opt_example - Example program for util_opt
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */


//! [code]
#include <stdio.h>
#include <stdlib.h>

#include "lib/util_opt.h"

#define OPT_NOSHORT	256

/*
 * Define the command line options
 */
static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTION WITHOUT ARGUMENTS"),
	/* Our own options */
	{
		.option = { "single", no_argument, NULL, 's'},
		.desc = "A single option without an argument",
	},
	UTIL_OPT_SECTION("OPTIONS WITH ARGUMENTS"),
	{
		.option = { "req_arg", required_argument, NULL, 'r'},
		.argument = "REQ_ARG",
		.desc = "Option with a required argument REQ_ARG",
	},
	{
		/*
		 * NOTE: For specifying an optional parameter OPT_ARG use
		 * either "-oOPT_ARG" or "--opt_arg=OPT_ARG" on the commandline.
		 * Specifying "-o OPT_ARG" or "--opt_arg OPT_ARG" will not work.
		 */
		.option = { "opt_arg", optional_argument, NULL, 'o'},
		.argument = "OPT_ARG",
		.desc = "Option with an optional argument OPT_ARG. " \
			"We don't recommend using this feature.",
	},
	UTIL_OPT_SECTION("OPTION WITHOUT SHORT OPTION"),
	{
		.option = { "noshort", no_argument, NULL, OPT_NOSHORT},
		.desc = "Option with only a long name",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	UTIL_OPT_SECTION("OPTION WITHOUT LONG OPTION"),
	{
		.option = { NULL, no_argument, NULL, 'l'},
		.desc = "Option with only a short name",
		.flags = UTIL_OPT_FLAG_NOLONG,
	},
	UTIL_OPT_SECTION("OPTION WITH MANUALLY FORMATTED DESCRIPTION"),
	{
		.option = { "manual", no_argument, NULL, 'm' },
		.desc = "Option descriptions can be formatted\n" \
			"using the new line character '\\n' to:\n" \
			"  - Display descriptions more meaningful\n" \
			"  - Create lists within the description",
	},
	UTIL_OPT_SECTION("STANDARD OPTIONS"),
	/* Standard option: -h,--help */
	UTIL_OPT_HELP,
	/* Standard option: -v,--version */
	UTIL_OPT_VERSION,
	/* End-marker for option vector */
	UTIL_OPT_END
};

/*
 * Parse the command line options with util_opt functions
 */
int main(int argc, char *argv[])
{
	int c;

	/* Install option vector */
	util_opt_init(opt_vec, NULL);

	/* Parse all options specified in argv[] */
	while (1) {
		/* Get the next option 'c' from argv[] */
		c = util_opt_getopt_long(argc, argv);
		/* No more options on command line? */
		if (c == -1)
			break;
		/* Find the right action for option 'c' */
		switch (c) {
		case 'h':
			util_opt_print_help();
			return EXIT_SUCCESS;
		case 'v':
			printf("Specified: --version\n");
			return EXIT_SUCCESS;
		case 's':
			printf("Specified: --single\n");
			break;
		case 'o':
			if (optarg != NULL)
				printf("Specified: --opt_arg %s\n", optarg);
			else
				printf("Specified: --opt_arg [without arg]\n");
			break;
		case 'r':
			printf("Specified: --req_arg %s\n", optarg);
			break;
		case OPT_NOSHORT:
			printf("Specified: --noshort\n");
			break;
		case 'l':
			printf("Specified: -l\n");
			break;
		case 'm':
			printf("Specified: --manual\n");
			break;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}
//! [code]
