/*
 * util - Utility function library
 *
 * Parse the command line options
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <argz.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_panic.h"
#include "lib/util_prg.h"

/*
 * Private data
 */
/// @cond
static struct util_opt_l {
	/* Option character string for getopt_long() */
	char *opt_str;
	/* Option array for getopt_long() */
	struct option *option_vec;
	/* Original util_opt array */
	struct util_opt *opt_vec;
	/* Length of longest option string */
	int opt_max;
	/* Command used for parsing */
	const char *command;
} l;

struct util_opt_l *util_opt_l = &l;

/// @endcond

#define util_opt_iterate(opt) \
	for (opt = &l.opt_vec[0]; opt->desc != NULL; opt++)

#define MAX_OPTLEN	256

static int opt_max_len(void);
static bool opt_is_active(struct util_opt *opt);

/**
 * Initialize the command line options
 *
 * Build short option string and long option array to be used for getopt_long().
 * The ":" prefix is added to the short option string for handling of "missing
 * required arguments".
 *
 * @param[in] opt_vec  Option array
 * @param[in] opt_prefix  Optional option string prefix
 */
void util_opt_init(struct util_opt *opt_vec, const char *opt_prefix)
{
	int i, j, count;
	char *str;
	size_t prefix_len = opt_prefix ? strlen(opt_prefix) : 0;

	opterr = 0;
	/* Get number of options */
	for (i = 0, count = 0; opt_vec[i].desc != NULL; i++)
		if (opt_is_active(&opt_vec[i]))
			count++;
	/*
	 * Allocate short option string for worst case when all options have
	 * optional parameters e.g "x::" and long option string.
	 */
	l.opt_str = util_malloc(sizeof(char) * count * 3 + 2 + prefix_len);
	l.option_vec = util_malloc(sizeof(struct option) * (count + 1));
	l.opt_vec = opt_vec;

	str = l.opt_str;
	if (opt_prefix) {
		strcpy(str, opt_prefix);
		str += prefix_len;
	}
	/* Force getopt_long() to return ':' for missing required arguments */
	*str++ = ':';
	/* Construction of input structures for getopt_long() function.  */
	for (i = 0, j = 0; opt_vec[i].desc != NULL; i++) {
		if (!opt_is_active(&opt_vec[i]))
			continue;
		if (opt_vec[i].flags & UTIL_OPT_FLAG_SECTION)
			continue;
		if (!(opt_vec[i].flags & UTIL_OPT_FLAG_NOLONG)) {
			memcpy(&l.option_vec[j++], &opt_vec[i].option,
			       sizeof(struct option));
		}
		if (opt_vec[i].flags & UTIL_OPT_FLAG_NOSHORT)
			continue;
		*str++ = opt_vec[i].option.val;
		switch (opt_vec[i].option.has_arg) {
		case no_argument:
			break;
		case required_argument:
			*str++ = ':';
			break;
		case optional_argument:
			*str++ = ':';
			*str++ = ':';
			break;
		default:
			util_panic("Unexpected \"has_arg\" parameter: %d\n",
				   opt_vec[i].option.has_arg);
		}
	}
	/* Add end marker to option array and short option string */
	memset(&l.option_vec[j], 0, sizeof(struct option));
	*str = '\0';
}

/**
 * Set the current command for command line option processing
 *
 * @param[in] command  The current command or NULL for no command
 */
void util_opt_set_command(const char *command)
{
	l.command = command;
}

/*
 * Return true, if option belongs to current command setting
 */
static bool opt_is_active(struct util_opt *opt)
{
	if (!opt->command || !l.command)
		return true;
	return (strcmp(opt->command, l.command) == 0);
}

/**
 * Wrapper for getopt_long
 *
 * @param[in] argc  Count of command line parameters
 * @param[in] argv  Array of command line parameters
 */
int util_opt_getopt_long(int argc, char *argv[])
{
	struct util_opt *opt;
	int val;

	val = getopt_long(argc, argv, l.opt_str, l.option_vec, NULL);

	switch (val) {
	case ':':
	case '?':
	case -1:
		break;
	default:
		if (!l.command)
			break;
		util_opt_iterate(opt) {
			if (!opt_is_active(opt))
				continue;
			if (opt->option.val == val)
				goto out;
		}
		/* No valid option found for command */
		val = '?';
		if (optarg)
			optind--;
		break;
	}
out:
	return val;
}

/*
 * Format option name: Add short, long option and argument (as applicable)
 */
static void format_opt(char *buf, size_t maxlen, const struct util_opt *opt)
{
	int has_arg, flags, rc;
	char val, *arg_str;
	const char *name;

	has_arg = opt->option.has_arg;
	name = opt->option.name;
	val = opt->option.val;
	flags = opt->flags;

	/* Prepare potential option argument string */
	if (has_arg == optional_argument) {
		if (flags & UTIL_OPT_FLAG_NOLONG)
			util_asprintf(&arg_str, "[%s]", opt->argument);
		else
			util_asprintf(&arg_str, "[=%s]", opt->argument);
	} else if (has_arg == required_argument) {
		util_asprintf(&arg_str, " %s", opt->argument);
	} else {
		util_asprintf(&arg_str, "");
	}

	/* Format the option */
	if (flags & UTIL_OPT_FLAG_NOLONG)
		rc = snprintf(buf, maxlen, "-%c%s", val, arg_str);
	else if (flags & UTIL_OPT_FLAG_NOSHORT)
		rc = snprintf(buf, maxlen, "    --%s%s", name, arg_str);
	else
		rc = snprintf(buf, maxlen, "-%c, --%s%s", val, name, arg_str);

	util_assert(rc < (int)maxlen, "Option too long: %s\n", name);
	free(arg_str);
}

/*
 * Return true, if option is to be printed for the current command setting
 */
static bool should_print_opt(const struct util_opt *opt)
{
	if (l.command) {
		/* Print only options that belong to command */
		return opt->command ? !strcmp(opt->command, l.command) : false;
	} else {
		/* Print only common options (standard for non-command tools) */
		return opt->command ? false : true;
	}
}

/*
 * Return size of the longest formatted option
 */
static int opt_max_len(void)
{
	const struct util_opt *opt;
	unsigned int max = 0;
	char opt_str[MAX_OPTLEN];

	util_opt_iterate(opt) {
		if (opt->flags & UTIL_OPT_FLAG_SECTION)
			continue;
		if (!should_print_opt(opt))
			continue;
		format_opt(opt_str, MAX_OPTLEN, opt);
		max = MAX(max, strlen(opt_str));
	}
	return max;
}

/**
 * Print an option name, followed by a description indented to fit the
 * longest option name
 */
void util_opt_print_indented(const char *opt, const char *desc)
{
	printf(" %-*s ", l.opt_max + 1, opt);
	util_print_indented(desc, 3 + l.opt_max);
}

/**
 * Print the usage of the command line options to the console
 */
void util_opt_print_help(void)
{
	char opt_str[MAX_OPTLEN];
	struct util_opt *opt;
	int first = 1;

	/*
	 * Create format string: " -%c, --%-<long opt size>s %s"
	 *
	 * Example:
	 *
	 *   -p, --print STRING   Print STRING to console
	 */
	l.opt_max = opt_max_len();

	util_opt_iterate(opt) {
		if (!should_print_opt(opt))
			continue;
		if (opt->flags & UTIL_OPT_FLAG_SECTION) {
			printf("%s%s\n", first ? "" : "\n", opt->desc);
			first = 0;
			continue;
		}
		format_opt(opt_str, MAX_OPTLEN, opt);
		util_opt_print_indented(opt_str, opt->desc);
	}
}

/**
 * Print option parsing error message
 *
 * This function should be used when the return code of the
 * util_opt_getopt_long() function returns a character that does
 * not match any of the expected options.
 *
 * @param[in] opt   Short option returned by getopt_long()
 * @param[in] argv  Option array
 */
void util_opt_print_parse_error(char opt, char *argv[])
{
	char optopt_str[3];

	switch (opt) {
	case ':':
		/* A required option argument has not been specified */
		util_prg_print_required_arg(argv[optind - 1]);
		break;
	case '?':
		/* An invalid option has been specified */
		if (optopt) {
			/* Short option */
			sprintf(optopt_str, "-%c", optopt);
			util_prg_print_invalid_option(optopt_str);
		} else {
			/* Long option */
			util_prg_print_invalid_option(argv[optind - 1]);
		}
		break;
	default:
		util_panic("Option '%c' should not be handled here\n", opt);
	}
}

