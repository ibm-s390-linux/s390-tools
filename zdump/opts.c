/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Option parsing
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/zt_common.h"
#include "lib/util_log.h"

#include "opts.h"

static struct option long_opts[] = {
	{"help",    no_argument,       NULL, 'h'},
	{"version", no_argument,       NULL, 'v'},
	{"info",    no_argument,       NULL, 'i'},
	{"device",  no_argument,       NULL, 'd'},
	{"mount",   no_argument,       NULL, 'm'},
	{"umount",  no_argument,       NULL, 'u'},
	{"fmt",     required_argument, NULL, 'f'},
	{"select",  required_argument, NULL, 's'},
	{"debug",   no_argument,       NULL, 'X'},
	{"verbose", no_argument,       NULL, 'V'},
	{NULL,      0,                 NULL,  0 }
};

static const char optstr[] = "hvVidmus:f:X";

/*
 * Text for --help option
 */
static const char help_text[] =
	"Usage: zgetdump    DUMP [-s SYS] [-f FMT] > DUMP_FILE\n"
	"                   DUMP [-s SYS] [-f FMT] DUMP_FILE\n"
	"                -m DUMP [-s SYS] [-f FMT] DIR\n"
	"                -i DUMP [-s SYS]\n"
	"                -d DUMPDEV\n"
	"                -u DIR\n"
	"\n"
	"The zgetdump tool can read different dump formats from a dump device or from\n"
	"a dump file. You can use zgetdump to:\n"
	"\n"
	"  - Write the dump content to standard output or to a file\n"
	"  - Mount the dump content to a Linux directory\n"
	"  - Convert a dump to a different dump format\n"
	"  - Check if a dump is valid\n"
	"  - Check if a DASD contains a valid dump tool.\n"
	"\n"
	"In the syntax description, DUMP specifies a dump device or dump file to be\n"
	"read. The following options are available:\n"
	"\n"
	"-m, --mount    Mount DUMP to mount point DIR\n"
	"-u, --umount   Unmount dump from mount point DIR\n"
	"-i, --info     Print DUMP information\n"
	"-f, --fmt      Specify target dump format FMT (\"elf\" or \"s390\")\n"
	"-s, --select   Select system data SYS (\"kdump\", \"prod\", or \"all\")\n"
	"-d, --device   Print DUMPDEV (dump device) information\n"
	"-v, --version  Print version information, then exit\n"
	"-V, --verbose  Print verbose messages to stdout. Repeat this option\n"
	"               for increased verbosity from just error messages to\n"
	"               also include warning,  information, debug, and trace\n"
	"               messages. This option is intended for debugging\n"
	"-h, --help     Print this help, then exit\n";

static const char copyright_str[] = "Copyright IBM Corp. 2001, 2018";

/*
 * Select option strings
 */
const char *OPTS_SELECT_KDUMP	= "kdump";
const char *OPTS_SELECT_PROD	= "prod";
const char *OPTS_SELECT_ALL	= "all";

/*
 * Initialize default settings
 */
static void init_defaults(struct options *opts)
{
	opts->prog_name = "zgetdump";
	opts->action = ZG_ACTION_COPY;
	opts->output_path = NULL;
#ifdef __s390x__
	opts->fmt = "elf";
#else
	opts->fmt = "s390";
#endif
	/* Verbose logging */
	opts->verbose = UTIL_LOG_ERROR;
	util_log_set_level(opts->verbose);
}

/*
 * Print "help" hint
 */
void __noreturn print_usage_exit(const char *prog_name)
{
	STDERR("Try '%s --help' for more information.\n", prog_name);
	zg_exit(1);
}

/*
 * Print help text
 */
static void __noreturn print_help_exit(void)
{
	STDOUT("%s", help_text);
	zg_exit(0);
}

/*
 * Print version information
 */
static void __noreturn print_version_exit(const char *prog_name)
{
	STDOUT("%s: Tool for copying and converting dumps version %s\n",
	       prog_name, RELEASE_STRING);
	STDOUT("%s\n", copyright_str);
	zg_exit(0);
}

/*
 * Set "--fmt" option
 */
static void fmt_set(struct options *opts, const char *fmt)
{
	opts->fmt_specified = 1;
	opts->fmt = fmt;
}

/*
 * Set "--select" option
 */
static void select_set(struct options *opts, const char *select)
{
	if (strcmp(select, OPTS_SELECT_KDUMP) == 0)
		opts->select = OPTS_SELECT_KDUMP;
	else if (strcmp(select, OPTS_SELECT_PROD) == 0)
		opts->select = OPTS_SELECT_PROD;
	else if (strcmp(select, OPTS_SELECT_ALL) == 0)
		opts->select = OPTS_SELECT_ALL;
	else
		ERR_EXIT("Invalid select argument \"%s\" specified", select);
	opts->select_specified = 1;
}

/*
 * Set mount point
 */
static void mount_point_set(struct options *opts, const char *mount_point)
{
	opts->mount_point = zg_strdup(mount_point);
}

/*
 * Set device
 */
static void device_set(struct options *opts, const char *path)
{
	opts->device = zg_strdup(path);
}

/*
 * Set output path
 */
static void output_set(struct options *opts, const char *path)
{
	opts->output_path = zg_strdup(path);
}

/*
 * Set FUSE debug options
 */
static void argv_fuse_set(struct options *opts, char **argv, int argc)
{
	int i;

	opts->argv_fuse = argv;
	opts->argc_fuse = argc;

	STDERR_PR("Fuse Options: ");
	for (i = 0; i < argc; i++)
		STDERR("%s ", opts->argv_fuse[i]);
	STDERR("\n");
}

/*
 * Set action
 */
static void action_set(struct options *opts, enum zg_action action)
{
	if (opts->action_specified)
		ERR_EXIT("Please specify only one of the \"-i\", \"-d\", "
			 "\"-m\" or \"-u\" option");
	opts->action = action;
	opts->action_specified = 1;
}

/*
 * Verify option combinations
 */
static void verify_opts(struct options *opts)
{
	if (opts->select_specified) {
		if (opts->action != ZG_ACTION_MOUNT &&
		    opts->action != ZG_ACTION_COPY &&
		    opts->action != ZG_ACTION_DUMP_INFO)
			ERR_EXIT("The \"--select\" option can only be "
				 "specified for info, mount, or copy");
	}
	if (!opts->fmt_specified)
		return;

	if (opts->action == ZG_ACTION_DUMP_INFO)
		ERR_EXIT("The \"--fmt\" option cannot be specified "
			 "together with \"--info\"");
	if (opts->action == ZG_ACTION_DEVICE_INFO)
		ERR_EXIT("The \"--fmt\" option cannot be specified "
			 "together with \"--device\"");
	if (opts->action == ZG_ACTION_UMOUNT)
		ERR_EXIT("The \"--fmt\" option cannot be specified "
			 "together with \"--umount\"");
}

/*
 * Parse positional arguments
 */
static void parse_pos_args(struct options *opts, char *argv[], int argc)
{
	int pos_args = argc - optind;

	switch (opts->action) {
	case ZG_ACTION_COPY:
		if (pos_args == 0)
			ERR_EXIT("No device or dump specified");
		if (pos_args > 2)
			ERR_EXIT("Too many positional parameters specified");
		device_set(opts, argv[optind]);
		if (pos_args > 1)
			output_set(opts, argv[optind + 1]);
		break;
	case ZG_ACTION_DUMP_INFO:
	case ZG_ACTION_DEVICE_INFO:
		if (pos_args == 0)
			ERR_EXIT("No device or dump specified");
		if (pos_args > 1)
			ERR_EXIT("Too many positional parameters specified");
		device_set(opts, argv[optind]);
		break;
	case ZG_ACTION_MOUNT:
		if (pos_args == 0)
			ERR_EXIT("No dump specified");
		if (pos_args == 1)
			ERR_EXIT("No mount point specified");
		if (pos_args > 2 && !opts->debug_specified)
			ERR_EXIT("Too many positional parameters specified");
		device_set(opts, argv[optind]);
		mount_point_set(opts, argv[optind + 1]);
		if (opts->debug_specified && pos_args > 2)
			argv_fuse_set(opts, &argv[optind + 2], pos_args - 2);
		break;
	case ZG_ACTION_UMOUNT:
		if (pos_args == 0)
			ERR_EXIT("No mount point specified");
		if (pos_args > 1)
			ERR_EXIT("Too many positional parameters specified");
		mount_point_set(opts, argv[optind]);
		break;
	}
}

/*
 * Main command line parsing function
 */
void opts_parse(int argc, char *argv[], struct options *opts)
{
	int opt, idx;

	init_defaults(opts);
	while ((opt = getopt_long(argc, argv, optstr, long_opts, &idx)) != -1) {
		switch (opt) {
		case 'h':
			print_help_exit();
		case 'v':
			print_version_exit(opts->prog_name);
		case 'V':
			opts->verbose++;
			util_log_set_level(opts->verbose);
			break;
		case 'i':
			action_set(opts, ZG_ACTION_DUMP_INFO);
			break;
		case 'd':
			action_set(opts, ZG_ACTION_DEVICE_INFO);
			break;
		case 'm':
			action_set(opts, ZG_ACTION_MOUNT);
			break;
		case 'u':
			action_set(opts, ZG_ACTION_UMOUNT);
			break;
		case 'f':
			fmt_set(opts, optarg);
			break;
		case 's':
			select_set(opts, optarg);
			break;
		case 'X':
			opts->debug_specified = 1;
			break;
		default:
			print_usage_exit(opts->prog_name);
		}
	}
	parse_pos_args(opts, argv, argc);
	verify_opts(opts);
}
