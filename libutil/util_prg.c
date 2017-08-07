/*
 * util - Utility function library
 *
 * Print standard program messages
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdio.h>

#include "lib/util_base.h"
#include "lib/util_prg.h"
#include "lib/zt_common.h"

/*
 * Private data
 */
static struct util_prg_l {
	const struct util_prg *prg;
	/* Command used for parsing */
	const char *command;
} l;

struct util_prg_l *util_prg_l = &l;

/**
 * Set the current command for command line option processing
 *
 * @param[in] command  The current command or NULL for no command
 */
void util_prg_set_command(const char *command)
{
	l.command = command;
}

/**
 * Print program usage information for the --help option
 */
void util_prg_print_help(void)
{
	/* Print usage */
	printf("Usage: %s", program_invocation_short_name);
	if (l.prg->command_args)
		printf(" %s", l.prg->command_args);
	printf(" [OPTIONS]");
	if (l.prg->args)
		printf(" %s", l.prg->args);
	/* Print usage description */
	printf("\n\n");
	util_print_indented(l.prg->desc, 0);
	printf("\n");
}

/**
 * Print program version information for the --version option
 */
void util_prg_print_version(void)
{
	const struct util_prg_copyright *copyright;

	printf("%s version %s\n", program_invocation_short_name,
	       RELEASE_STRING);
	copyright = l.prg->copyright_vec;
	while (copyright->owner) {
		if (copyright->pub_first == copyright->pub_last)
			printf("Copyright %s %d\n", copyright->owner,
			       copyright->pub_first);
		else
			printf("Copyright %s %d, %d\n", copyright->owner,
			       copyright->pub_first, copyright->pub_last);
		copyright++;
	}
}

/*
 * Ask user to use the --help option
 */
void util_prg_print_parse_error(void)
{
	if (l.command)
		fprintf(stderr, "Try '%s %s --help' for more information.\n",
			program_invocation_short_name, l.command);
	else
		fprintf(stderr, "Try '%s --help' for more information.\n",
			program_invocation_short_name);
}

/**
 * An option has been specified that is not supported
 *
 * @param[in] option  Option string (short or long)
 */
void util_prg_print_invalid_option(const char *opt_name)
{
	fprintf(stderr, "%s: Invalid option '%s'\n",
		program_invocation_short_name, opt_name);
	util_prg_print_parse_error();
}

/**
 * A required argument for an option is missing
 *
 * @param[in] option  Option string
 */
void util_prg_print_required_arg(const char *opt_name)
{
	fprintf(stderr, "%s: Option '%s' requires an argument\n",
		program_invocation_short_name, opt_name);
	util_prg_print_parse_error();
}

/**
 * A superfluous invalid positional argument has been specified
 *
 * @param[in] arg_name  Name of the invalid argument
 */
void util_prg_print_arg_error(const char *arg_name)
{
	fprintf(stderr, "%s: Invalid argument '%s'\n",
		program_invocation_short_name, arg_name);
	util_prg_print_parse_error();
}

/**
 * Initialize the program module
 *
 * @param[in] prg Program description
 */
void util_prg_init(const struct util_prg *prg)
{
	l.prg = prg;
}
