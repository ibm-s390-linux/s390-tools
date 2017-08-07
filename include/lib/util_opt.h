/**
 * @defgroup util_opt_h util_opt: Command line options interface
 * @{
 * @brief Parse the command line options
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_OPT_H
#define LIB_UTIL_OPT_H

#include <getopt.h>
#include <unistd.h>

/* Flag indicating that an option does not have a short form */
#define UTIL_OPT_FLAG_NOSHORT	1

/* Flag indicating that an option does not have a long form */
#define UTIL_OPT_FLAG_NOLONG	2

/* Flag indicating that this is a section heading */
#define UTIL_OPT_FLAG_SECTION	4

/**
 * Command line option
 */
struct util_opt {
	/** Defined by getopt.h, see "man getopt_long" */
	struct option option;
	/** For options with arguments: Argument name */
	char *argument;
	/** Description displayed for --help */
	char *desc;
	/** Flags for this option */
	int flags;
	/** Command to which this option belongs. NULL means all commands */
	char *command;
};

/**
 * Standard option: --help
 */
#define UTIL_OPT_HELP					\
{							\
	.option = { "help", 0, NULL, 'h' },		\
	.desc = "Print this help, then exit",		\
}

/**
 * Standard option: --version
 */
#define UTIL_OPT_VERSION				\
{							\
	.option = { "version", 0, NULL, 'v' },		\
	.desc = "Print version information, then exit",	\
}

/**
 * End-marker for the option pointer vector
 */
#define UTIL_OPT_END					\
{							\
	.option = { NULL, 0, NULL, 0 },			\
}

/**
 * Section header
 */
#define UTIL_OPT_SECTION(title)				\
{							\
	.desc = (title),				\
	.flags = UTIL_OPT_FLAG_SECTION,			\
}

/*
 * Option functions
 */
void util_opt_init(struct util_opt *opt_vec, const char *opt_prefix);
void util_opt_set_command(const char *command);
int util_opt_getopt_long(int argc, char *argv[]);
void util_opt_print_help(void);
void util_opt_print_indented(const char *opt, const char *desc);
void util_opt_print_parse_error(char opt, char *argv[]);

#endif /** LIB_UTIL_OPT_H @} */
