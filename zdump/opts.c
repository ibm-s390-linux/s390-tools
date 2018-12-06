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
#include "zgetdump.h"

/*
 * Text for --help option
 */
static char help_text[] =
"Usage: zgetdump    DUMP [-s SYS] [-f FMT] > DUMP_FILE\n"
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
"-V, --verbose  Show detailed layout of memory map on printing DUMP information\n"
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
static void init_defaults(void)
{
	g.prog_name = "zgetdump";
	g.opts.action = ZG_ACTION_STDOUT;
#ifdef __s390x__
	g.opts.fmt = "elf";
#else
	g.opts.fmt = "s390";
#endif
	dfo_set(g.opts.fmt);
}

/*
 * Print "help" hint
 */
static void __noreturn print_usage_exit(void)
{
	STDERR("Try '%s --help' for more information.\n", g.prog_name);
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
static void __noreturn print_version_exit(void)
{
	STDOUT("%s: Tool for copying and converting dumps version %s\n",
	       g.prog_name, RELEASE_STRING);
	STDOUT("%s\n", copyright_str);
	zg_exit(0);
}

/*
 * Set "--fmt" option
 */
static void fmt_set(const char *fmt)
{
	if (dfo_set(fmt) != 0)
		ERR_EXIT("Invalid target format \"%s\" specified", fmt);
	g.opts.fmt_specified = 1;
	g.opts.fmt = fmt;
}

/*
 * Set "--select" option
 */
static void select_set(const char *select)
{
	if (strcmp(select, OPTS_SELECT_KDUMP) == 0)
		g.opts.select = OPTS_SELECT_KDUMP;
	else if (strcmp(select, OPTS_SELECT_PROD) == 0)
		g.opts.select = OPTS_SELECT_PROD;
	else if (strcmp(select, OPTS_SELECT_ALL) == 0)
		g.opts.select = OPTS_SELECT_ALL;
	else
		ERR_EXIT("Invalid select argument \"%s\" specified", select);
	g.opts.select_specified = 1;
}

/*
 * Set mount point
 */
static void mount_point_set(const char *mount_point)
{
	g.opts.mount_point = zg_strdup(mount_point);
}

/*
 * Set device
 */
static void device_set(const char *path)
{
	g.opts.device = zg_strdup(path);
}

/*
 * Set FUSE debug options
 */
static void argv_fuse_set(char **argv, int argc)
{
	int i;

	g.opts.argv_fuse = argv;
	g.opts.argc_fuse = argc;

	STDERR_PR("Fuse Options: ");
	for (i = 0; i < argc; i++)
		STDERR("%s ", g.opts.argv_fuse[i]);
	STDERR("\n");
}

/*
 * Set action
 */
static void action_set(enum zg_action action)
{
	if (g.opts.action_specified)
		ERR_EXIT("Please specify only one of the \"-i\", \"-d\", "
			 "\"-m\" or \"-u\" option");
	g.opts.action = action;
	g.opts.action_specified = 1;
}

/*
 * Verify option combinations
 */
static void verify_opts(void)
{
	if (g.opts.select_specified) {
		if (g.opts.action != ZG_ACTION_MOUNT &&
		    g.opts.action != ZG_ACTION_STDOUT &&
		    g.opts.action != ZG_ACTION_DUMP_INFO)
			ERR_EXIT("The \"--select\" option can only be "
				 "specified for info, mount, or copy");
	}
	if (!g.opts.fmt_specified)
		return;

	if (g.opts.action == ZG_ACTION_DUMP_INFO)
		ERR_EXIT("The \"--fmt\" option cannot be specified "
			 "together with \"--info\"");
	if (g.opts.action == ZG_ACTION_DEVICE_INFO)
		ERR_EXIT("The \"--fmt\" option cannot be specified "
			 "together with \"--device\"");
	if (g.opts.action == ZG_ACTION_UMOUNT)
		ERR_EXIT("The \"--fmt\" option cannot be specified "
			 "together with \"--umount\"");
}

/*
 * Parse positional arguments
 */
static void parse_pos_args(char *argv[], int argc)
{
	int pos_args = argc - optind;

	switch (g.opts.action) {
	case ZG_ACTION_STDOUT:
	case ZG_ACTION_DUMP_INFO:
	case ZG_ACTION_DEVICE_INFO:
		if (pos_args == 0)
			ERR_EXIT("No device or dump specified");
		if (pos_args > 1 && !g.opts.debug_specified)
			ERR_EXIT("Too many positional parameters specified");
		device_set(argv[optind]);
		break;
	case ZG_ACTION_MOUNT:
		if (pos_args == 0)
			ERR_EXIT("No dump specified");
		if (pos_args == 1)
			ERR_EXIT("No mount point specified");
		if (pos_args > 2 && !g.opts.debug_specified)
			ERR_EXIT("Too many positional parameters specified");
		device_set(argv[optind]);
		mount_point_set(argv[optind + 1]);
		if (g.opts.debug_specified && pos_args > 2)
			argv_fuse_set(&argv[optind + 2], pos_args - 2);
		break;
	case ZG_ACTION_UMOUNT:
		if (pos_args == 0)
			ERR_EXIT("No mount point specified");
		mount_point_set(argv[optind]);
		break;
	}
}

/*
 * Main command line parsing function
 */
void opts_parse(int argc, char *argv[])
{
	int opt, idx;
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

	init_defaults();
	while ((opt = getopt_long(argc, argv, optstr, long_opts, &idx)) != -1) {
		switch (opt) {
		case 'h':
			print_help_exit();
		case 'v':
			print_version_exit();
		case 'V':
			g.opts.verbose_specified = 1;
			break;
		case 'i':
			action_set(ZG_ACTION_DUMP_INFO);
			break;
		case 'd':
			action_set(ZG_ACTION_DEVICE_INFO);
			break;
		case 'm':
			action_set(ZG_ACTION_MOUNT);
			break;
		case 'u':
			action_set(ZG_ACTION_UMOUNT);
			break;
		case 'f':
			fmt_set(optarg);
			break;
		case 's':
			select_set(optarg);
			break;
		case 'X':
			g.opts.debug_specified = 1;
			break;
		default:
			print_usage_exit();
		}
	}
	parse_pos_args(argv, argc);
	verify_opts();
}
