/*
 * util_opt_command_example - Example program for util_opt with commands
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */


//! [code]
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_opt.h"
#include "lib/util_prg.h"

#define OPT_NOSHORT	256

#define COMMAND_PULL	"pull"
#define COMMAND_PUSH	"push"

/*
 * Define the command line options
 */
static struct util_opt opt_vec[] = {
	{
		.desc = "OPTIONS",
		.flags = UTIL_OPT_FLAG_SECTION,
		.command = COMMAND_PULL,
	},
	{
		.option = { "single", no_argument, NULL, 's'},
		.desc = "A single option without an argument",
		.command = COMMAND_PULL,
	},
	{
		.option = { "req_arg", required_argument, NULL, 'r'},
		.argument = "REQ_ARG",
		.desc = "Option with a required argument REQ_ARG",
		.command = COMMAND_PULL,
	},
	{
		.option = { "test", required_argument, NULL, 't'},
		.argument = "TEST",
		.desc = "Option 'test' with a required argument TEST for pull",
		.command = COMMAND_PULL,
	},
	{
		.desc = "OPTIONS",
		.flags = UTIL_OPT_FLAG_SECTION,
		.command = COMMAND_PUSH,
	},
	{
		.option = { "noshort", no_argument, NULL, OPT_NOSHORT},
		.desc = "Option with only a long name",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.command = COMMAND_PUSH,
	},
	{
		.option = { NULL, no_argument, NULL, 'l'},
		.desc = "Option with only a short name",
		.flags = UTIL_OPT_FLAG_NOLONG,
		.command = COMMAND_PUSH,
	},
	{
		.option = { "test", no_argument, NULL, 't'},
		.desc = "Option 'test' without an argument for push",
		.command = COMMAND_PUSH,
	},
	UTIL_OPT_SECTION("COMMON OPTIONS"),
	/* Standard option: -h,--help */
	UTIL_OPT_HELP,
	/* Standard option: -v,--version */
	UTIL_OPT_VERSION,
	/* End-marker for option vector */
	UTIL_OPT_END
};

static char usage_global_start[] =
"Usage: util_opt_command_example [COMMAND] [OPTIONS]\n"
"\n"
"Demonstrate how programs with commands can use the \"util_opt\" library.\n"
"\n"
"COMMANDS\n"
"  push      Push some content to somewhere\n"
"  pull      Pull some content from somewhere\n";

static char usage_global_end[] =
"For more information use 'util_opt_command_example COMMAND --help'.\n";

static char usage_push_start[] =
"Usage: util_opt_command_example push [OPTIONS]\n"
"\n"
"Push some content to somewhere.\n";

static char usage_pull_start[] =
"Usage: util_opt_command_example pull [OPTIONS]\n"
"\n"
"Pull some content from somewhere.\n";

/*
 * Print help header for command or program
 */
static void command_print_help_start(const char *command)
{
	if (command == NULL)
		printf("%s", usage_global_start);
	else if (strcmp(command, COMMAND_PUSH) == 0)
		printf("%s", usage_push_start);
	else if (strcmp(command, COMMAND_PULL) == 0)
		printf("%s", usage_pull_start);
	printf("\n");
}

/*
 * Print help footer
 */
static void command_print_help_end(const char *command)
{
	if (command == NULL)
		printf("\n%s", usage_global_end);
}

/*
 * Parse the command line options with util_opt functions
 */
int main(int argc, char *argv[])
{
	int c, my_argc = argc;
	char **my_argv = argv;
	char *command = NULL;

	/* The command name is the very first argument */
	if (argc >= 2 && strncmp(argv[1], "-", 1) != 0) {
		command = argv[1];
		my_argc--;
		my_argv = &argv[1];

		if (strcasecmp(command, COMMAND_PULL) != 0 &&
		    strcasecmp(command, COMMAND_PUSH) != 0) {
			fprintf(stderr, "%s: Invalid command '%s'\n",
				program_invocation_short_name, argv[1]);
			util_prg_print_parse_error();
			return EXIT_FAILURE;
		}
	}

	/* Set the current command (if any) */
	util_opt_set_command(command);
	util_prg_set_command(command);

	/* Install option vector */
	util_opt_init(opt_vec, NULL);

	/* Parse all options specified in my_argv[] */
	while (1) {
		/* Get the next option 'c' from my_argv[] */
		c = util_opt_getopt_long(my_argc, my_argv);
		/* No more options on command line? */
		if (c == -1)
			break;
		/* Find the right action for option 'c' */
		switch (c) {
		case 'h':
			command_print_help_start(command);
			util_opt_print_help();
			command_print_help_end(command);
			return EXIT_SUCCESS;
		case 'v':
			printf("Specified: --version\n");
			return EXIT_SUCCESS;
		case 's':
			printf("Specified: --single\n");
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
		case 't':
			printf("Specified: --test %s\n", optarg ? optarg : "");
			break;
		default:
			util_opt_print_parse_error(c, my_argv);
			return EXIT_FAILURE;
		}
	}

	if (optind < my_argc) {
		util_prg_print_arg_error(my_argv[optind]);
		return EXIT_FAILURE;
	}

	if (command == NULL) {
		fprintf(stderr, "%s: Command is required\n",
			program_invocation_short_name);
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}

	if (strcasecmp(command, COMMAND_PULL) == 0) {
		printf("Run the pull command\n");
		return EXIT_SUCCESS;
	} else if (!strcasecmp(command, COMMAND_PUSH)) {
		printf("Run the push command\n");
		return EXIT_SUCCESS;
	}

	fprintf(stderr, "%s: Invalid command '%s'\n",
		program_invocation_short_name, argv[1]);
	util_prg_print_parse_error();
	return EXIT_FAILURE;
}
//! [code]
