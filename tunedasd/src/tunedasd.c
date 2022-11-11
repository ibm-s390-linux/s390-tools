/*
 * tunedasd - Adjust tunable parameters on DASD devices
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/util_file.h"
#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/zt_common.h"

#include "disk.h"
#include "error.h"
#include "tunedasd.h"

static const struct util_prg prg = {
	.desc = "Adjust tunable DASD parameters. More than one DEVICE node can "
		"be specified, but at least one (e.g. /dev/dasda)",
	.args = "DEVICE1 [DEVICE2...]",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 1999,
			.pub_last = 2017,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/* Defines for options with no short command */
#define OPT_PATH_RESET_ALL	128
#define OPT_ENABLE_STATS	129
#define OPT_DISABLE_STATS	130

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("CACHING MODES (ECKD ONLY)"),
	{
		.option = { "cache", required_argument, NULL, 'c' },
		.argument = "BEHAVIOUR",
		.desc = "Specify caching behaviour on storage server: "
			"normal, bypass, inhibit, sequential, prestage, or record",
	},
	{
		.option = { "no_cyl", required_argument, NULL, 'n' },
		.argument = "NUM",
		.desc = "NUM cylinders to be cached (only valid with -c/--cache)",
	},
	{
		.option = { "get_cache", no_argument, NULL, 'g' },
		.desc = "Get current storage server caching behaviour",
	},
	UTIL_OPT_SECTION("RESERVE / RELEASE"),
	{
		.option = { "release", no_argument, NULL, 'L' },
		.desc = "Release device",
	},
	{
		.option = { "slock", no_argument, NULL, 'O' },
		.desc = "Unconditional reservce device\n"
			"NOTE: Use with care, this breaks an existing lock",
	},
	{
		.option = { "query_reserve", no_argument, NULL, 'Q' },
		.desc = "Print reserve status of device",
	},
	{
		.option = { "reserve", no_argument, NULL, 'S' },
		.desc = "Reserve device",
	},
	UTIL_OPT_SECTION("PERFORMANCE STATISTICS"),
	{
		.option = {
			"enable-stats", no_argument, NULL, OPT_ENABLE_STATS
		},
		.desc = "Enable performance statistics globally",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = {
			"disable-stats", no_argument, NULL, OPT_DISABLE_STATS
		},
		.desc = "Disable performance statistics globally",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "prof_item", required_argument, NULL, 'I' },
		.argument = "ROW",
		.desc = "Print single profile item: reqs, sects, sizes, total, "
			"totsect, start, irq, irqsect, end, or queue",
	},
	{
		.option = { "profile", no_argument, NULL, 'P' },
		.desc = "Print profile info of device",
	},
	{
		.option = { "reset_prof", no_argument, NULL, 'R' },
		.desc = "Reset profile info of device",
	},
	UTIL_OPT_SECTION("MISC"),
	{
		.option = { "path_reset", required_argument, NULL, 'p' },
		.argument = "CHPID",
		.desc = "Reset channel path CHPID of a device",
	},
	{
		.option = {
			"path_reset_all", no_argument, NULL, OPT_PATH_RESET_ALL
		},
		.desc = "Reset all channel paths of a device",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "copy-pair-swap", required_argument, NULL, 's' },
		.argument = "COPY_PAIR",
		.desc = "Swap a specified, comma separated copy pair.",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

#define CMD_KEYWORD_NUM		17
#define DEVICES_NUM		256

enum cmd_keyword_id {
	cmd_keyword_help,
	cmd_keyword_version,
	cmd_keyword_get_cache,
	cmd_keyword_cache,
	cmd_keyword_no_cyl,
	cmd_keyword_reserve,
	cmd_keyword_release,
	cmd_keyword_slock,
	cmd_keyword_profile,
	cmd_keyword_prof_item,
	cmd_keyword_reset_prof,
	cmd_keyword_query_reserve,
	cmd_keyword_path,
	cmd_keyword_path_all,
	cmd_keyword_enable_stats,
	cmd_keyword_disable_stats,
	cmd_keyword_copy_swap,
};


/* Mapping of keyword IDs to strings */
static const struct {
	char* keyword;
	enum cmd_keyword_id id;
} keyword_list[] = {
	{ "help",           cmd_keyword_help },
	{ "version",        cmd_keyword_version },
	{ "get_cache",      cmd_keyword_get_cache },
	{ "cache",          cmd_keyword_cache },
	{ "no_cyl",         cmd_keyword_no_cyl },
	{ "reserve",        cmd_keyword_reserve },
	{ "release",        cmd_keyword_release },
	{ "slock",          cmd_keyword_slock },
	{ "profile",        cmd_keyword_profile },
	{ "prof_item",      cmd_keyword_prof_item },
	{ "reset_prof",     cmd_keyword_reset_prof },
	{ "query_reserve",  cmd_keyword_query_reserve },
	{ "path_reset",     cmd_keyword_path },
	{ "path_reset_all", cmd_keyword_path_all },
	{ "enable-stats",   cmd_keyword_enable_stats },
	{ "disable-stats",  cmd_keyword_disable_stats },
	{ "copy-swap",      cmd_keyword_copy_swap },
};	


enum cmd_key_state {
	req, /* Keyword is required */
	opt, /* Keyword is optional */
	inv  /* Keyword is invalid */
};


/* Determines which combination of keywords are valid */
static enum cmd_key_state cmd_key_table[CMD_KEYWORD_NUM][CMD_KEYWORD_NUM] = {
	/*		      help vers get_ cach no_c rese rele sloc prof prof rese quer path path enab disa copy
	 *		           ion  cach e    yl   rve  ase  k    ile  _ite t_pr y_re      _all le-s ble- -swa
	 *		               	e                                  m    of  serv            tats stat p
	 */
	/* help  	 */ { req, opt, opt, opt, opt, opt, opt, opt, opt, opt, opt, inv, inv, inv, inv, inv, inv },
	/* version	 */ { inv, req, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv },
	/* get_cache	 */ { opt, opt, req, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv },
	/* cache 	 */ { opt, opt, inv, req, opt, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv },
	/* no_cyl	 */ { opt, opt, inv, req, req, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv },
	/* reserve	 */ { opt, opt, inv, inv, inv, req, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv },
	/* release	 */ { opt, opt, inv, inv, inv, inv, req, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv },
	/* slock 	 */ { opt, opt, inv, inv, inv, inv, inv, req, inv, inv, inv, inv, inv, inv, inv, inv, inv },
	/* profile	 */ { opt, opt, inv, inv, inv, inv, inv, inv, req, opt, inv, inv, inv, inv, inv, inv, inv },
	/* prof_item	 */ { opt, opt, inv, inv, inv, inv, inv, inv, req, req, inv, inv, inv, inv, inv, inv, inv },
	/* reset_prof	 */ { opt, opt, inv, inv, inv, inv, inv, inv, inv, inv, req, inv, inv, inv, inv, inv, inv },
	/* query_reserve */ { inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, req, inv, inv, inv, inv, inv },
	/* path          */ { inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, req, inv, inv, inv, inv },
	/* path_all      */ { inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, req, inv, inv, inv },
	/* enable-stats  */ { inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, req, inv, inv },
	/* disable-stats */ { inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, req, inv },
	/* copy-swap     */ { inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, req },
};

struct parameter {
	int kw_given;
	char *data;
};

struct command_line {
	struct parameter parm[CMD_KEYWORD_NUM];
	char * devices[DEVICES_NUM];
	int device_id;
};

/* Error message string */
#define ERROR_STRING_SIZE	1024
static char error_string[ERROR_STRING_SIZE];


/*
 * Generate and print an error message based on the formatted
 * text string FMT and a variable amount of extra arguments. 
 */
void
error_print (const char* fmt, ...)
{
	va_list args;

	va_start (args, fmt);
	vsnprintf (error_string, ERROR_STRING_SIZE, fmt, args);
	va_end (args);

	fprintf (stderr, "Error: %s\n", error_string);
}


/*
 * Print usage information.
 */
static void print_usage(void)
{
	util_prg_print_help();
	util_opt_print_help();
}

/* 
 * Check whether calling user is root. Return 0 if user is root, non-zero
 * otherwise. 
 */
static int
check_for_root (void)
{
	if (geteuid () != 0) {
		error_print ("Must be root to perform this operation");
		return -1;
	} else {
		return 0;
	}
}


/* 
 * Retrieve name of keyword identified by ID.
 */
static char *get_keyword_name(enum cmd_keyword_id id)
{
	unsigned int i;

	for (i = 0; i < sizeof (keyword_list) / sizeof (keyword_list[0]);
	     i++) {
		if (id == keyword_list[i].id) {
			return keyword_list[i].keyword;
		}
	}
	return "<unknown>";
}


/* 
 * Check the given function for given options and valid combinations of 
 * options
 */
static int check_key_state(struct command_line *cmdline)
{
	int i,j;

	/* Find first given keyword */
	for (i = 0; i < CMD_KEYWORD_NUM && !cmdline->parm[i].kw_given; i++);
	
	if (i >= CMD_KEYWORD_NUM) {
		error_print ("No valid parameter specified");
		print_usage ();
		return -1;
	}

	/* Check keywords */
	for (j = 0; j < CMD_KEYWORD_NUM; j++) {

		switch (cmd_key_table[i][j]) {
		case req:
			/* Missing keyword on command line */
			if (!(cmdline->parm[j].kw_given)) {
				error_print ("Option '%s' required when "
					     "specifying '%s'",
					     get_keyword_name (j),
					     get_keyword_name (i));
				return -1;
			}
			break;
		case inv:
			/* Invalid keyword on command line */
			if (cmdline->parm[j].kw_given) {
				error_print ("Only one of options '%s' and "
					     "'%s' allowed",
					     get_keyword_name (i),
					     get_keyword_name (j));
				return -1;
			}
			break;
		case opt:
			break;
		}
	}

	return 0;
}


/*
 * Save the given command together with its parameter. 
 */
static int
store_option (struct command_line* cmdline, enum cmd_keyword_id keyword,
	      char* value)
{
	if ((cmdline->parm[(int) keyword]).kw_given) {
		error_print ("Option '%s' specified more than once",
			     get_keyword_name (keyword));
		return -1;
	}
	cmdline->parm[(int) keyword].kw_given = 1;
	cmdline->parm[(int) keyword].data = value;
	return 0;
}


/*
 * Parse the command line for valid parameters.
 */
static int get_command_line(int argc, char *argv[], struct command_line *line)
{
	struct command_line cmdline;
	int opt;
	int rc;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	memset ((void *) &cmdline, 0, sizeof (struct command_line));

	/* Process options */
	do {
		opt = util_opt_getopt_long(argc, argv);

		rc = 0;
		switch (opt) {
		case 'h':
			rc = store_option (&cmdline, cmd_keyword_help,
					   optarg);
			break;
		case 'v':
			rc = store_option (&cmdline, cmd_keyword_version,
					   optarg);
			break;
		case 'g':
			rc = store_option (&cmdline, cmd_keyword_get_cache,
					   optarg);
			break;
		case 'c':
			rc = check_cache (optarg);
			if (rc >= 0) {
				rc = store_option (&cmdline, cmd_keyword_cache,
						   optarg);
			}
			break;
		case 'n':
			rc = check_no_cyl (optarg);
			if (rc >= 0) {
				rc = store_option (&cmdline, 
						   cmd_keyword_no_cyl,
						   optarg);
			}
			break;
		case 'p':
			rc = store_option(&cmdline, cmd_keyword_path, optarg);
			break;
		case OPT_PATH_RESET_ALL:
			rc = store_option(&cmdline, cmd_keyword_path_all,
					  optarg);
			break;
		case 'S':
			rc = store_option (&cmdline, cmd_keyword_reserve,
					   optarg);
			break;
		case 'L':
			rc = store_option (&cmdline, cmd_keyword_release,
					   optarg);
			break;
		case 'O':
			rc = store_option (&cmdline, cmd_keyword_slock,
					   optarg);
			break;
		case OPT_ENABLE_STATS:
			rc = store_option(&cmdline, cmd_keyword_enable_stats,
					  optarg);
			break;
		case OPT_DISABLE_STATS:
			rc = store_option(&cmdline, cmd_keyword_disable_stats,
					  optarg);
			break;
		case 'P':
			rc = store_option (&cmdline, cmd_keyword_profile,
					   optarg);
			break;
		case 'I':
			rc = check_prof_item (optarg);
			if (rc >= 0) {
				rc = store_option (&cmdline, 
						   cmd_keyword_prof_item,
						   optarg);
			}
			break;
		case 'R':
			rc = store_option (&cmdline, cmd_keyword_reset_prof,
					   optarg);
			break;
		case 'Q':
			rc = store_option (&cmdline, cmd_keyword_query_reserve,
					   optarg);
			break;
		case 's':
			rc = store_option(&cmdline, cmd_keyword_copy_swap, optarg);
			break;
		case -1:
			/* End of options string - start of devices list */
			cmdline.device_id = optind;
			break;
		default:
			fprintf(stderr, "Try 'tunedasd --help' for more"
					" information.\n");
			rc = -1;
			break;
		}
		if (rc < 0) {
			return rc;
		}
	} while (opt != -1);

	*line = cmdline;
	return 0;
}

/*
 * Execute the command.
 */
static int do_command(char *device, struct command_line cmdline)
{
	int i, rc;

	rc = 0;
	for (i = 0; !cmdline.parm[i].kw_given; i++);

	switch (i) {
	case cmd_keyword_get_cache:
                rc = disk_get_cache (device); 
		break;
	case cmd_keyword_cache:
		rc = disk_set_cache (device, 
				     cmdline.parm[cmd_keyword_cache].data,
				     cmdline.parm[cmd_keyword_no_cyl].data);
		break;
	case cmd_keyword_no_cyl:
		break;
	case cmd_keyword_reserve:
		rc = disk_reserve (device);
		break;
	case cmd_keyword_release:
		rc = disk_release (device);
		break;
	case cmd_keyword_slock:
		rc = disk_slock (device);
		break;
	case cmd_keyword_profile: 
		rc = disk_profile (device, 
				   cmdline.parm[cmd_keyword_prof_item].data);
		break;
	case cmd_keyword_reset_prof:
		rc = disk_reset_prof (device);
		break;
	case cmd_keyword_prof_item:
		break;
	case cmd_keyword_query_reserve:
		rc = disk_query_reserve_status(device);
		break;
	case cmd_keyword_path:
		rc = disk_reset_chpid(device,
				      cmdline.parm[cmd_keyword_path].data);
		break;
	case cmd_keyword_path_all:
		rc = disk_reset_chpid(device, NULL);
		break;
	case cmd_keyword_copy_swap:
		rc = disk_copy_swap(device, cmdline.parm[cmd_keyword_copy_swap].data);
		break;
	default:
		error_print ("Unknown command '%s' specified",
			     get_keyword_name (i));
		break;
	}

	return rc;
}

/*
 * Enable/Disable DASD performance statistics globally by writing
 * 'set on' or 'set off' to /proc/dasd/statistics.
 */
static int tunedasd_set_global_stats(int val)
{
	const char *path = "/proc/dasd/statistics";
	int rc = 0;

	if (val)
		rc = util_file_write_s("set on", path);
	else
		rc = util_file_write_s("set off", path);

	if (rc)
		error_print("Could not enable/disable performance statistics");
	else
		printf("Performance statistics %sabled\n", val ? "en" : "dis");

	return rc;
}

/*
 * Main. 
 */
int
main (int argc, char* argv[])
{
	struct command_line cmdline;
	int rc, finalrc;

	/* Find out what we're supposed to do */
	rc = get_command_line (argc, argv, &cmdline);
	if (rc) {
		return 1;
	}

	rc= check_key_state (&cmdline);
	if (rc) {
		return 1;
	}

	/* Check for priority options --help and --version */
	if (cmdline.parm[cmd_keyword_help].kw_given) {
		print_usage ();
		return 0;
	} else if (cmdline.parm[cmd_keyword_version].kw_given) {
		util_prg_print_version();
		return 0;
	}

	/* Make sure we're running as root */
	if (check_for_root ()) {
		return 1;
	}

	/* Enable/Disable performance statistics */
	if (cmdline.parm[cmd_keyword_enable_stats].kw_given)
		return tunedasd_set_global_stats(1);
	if (cmdline.parm[cmd_keyword_disable_stats].kw_given)
		return tunedasd_set_global_stats(0);

	/* Do each of the commands on each of the devices 
	 * and don't care about the return codes           */
	if (cmdline.device_id >= argc) {
		error_print ("Missing device");
		print_usage ();
		return 1;
	}

	finalrc = 0;
	while (cmdline.device_id < argc) {
		rc = do_command (argv[cmdline.device_id], cmdline);
		if (rc && !finalrc)
			finalrc = rc;
		cmdline.device_id++;
	}
	return finalrc;
}
