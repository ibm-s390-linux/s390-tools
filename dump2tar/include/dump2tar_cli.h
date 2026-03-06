/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright IBM Corp.
 */

#ifndef DUMP2TAR_CLI_H
#define DUMP2TAR_CLI_H

#include "lib/util_opt.h"

#define	OPT_NOSHORT_BASE	256

#define	OPT_DEREFERENCE		(OPT_NOSHORT_BASE + 0)
#define OPT_NORECURSION		(OPT_NOSHORT_BASE + 1)
#define OPT_EXCLUDETYPE		(OPT_NOSHORT_BASE + 2)

/* Definition of command line options */
static struct util_opt dump2tar_opts[] = {
	UTIL_OPT_SECTION("OUTPUT OPTIONS"),
	{
		.option = { "output-file", required_argument, NULL, 'o' },
		.argument = "FILE",
		.desc = "Write archive to FILE (default: standard output)",
	},
#ifdef HAVE_ZLIB
	{
		.option = { "gzip", no_argument, NULL, 'z' },
		.desc = "Write a gzip compressed archive",
	},
#endif /* HAVE_ZLIB */
	{
		.option = { "max-size", required_argument, NULL, 'm' },
		.argument = "N",
		.desc = "Stop adding files when archive size exceeds N bytes",
	},
	{
		.option = { "timeout", required_argument, NULL, 't' },
		.argument = "SEC",
		.desc = "Stop adding files after SEC seconds",
	},
	{
		.option = { "no-eof", no_argument, NULL, 131 },
		.desc = "Do not write an end-of-file marker",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "add-cmd-status", no_argument, NULL, 132 },
		.desc = "Add status of commands as separate file",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "append", no_argument, NULL, 133 },
		.desc = "Append output to end of file",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},

	UTIL_OPT_SECTION("INPUT OPTIONS"),
	{
		.option = { "files-from", required_argument, NULL, 'F' },
		.argument = "FILE",
		.desc = "Read filenames from FILE (- for standard input)",
	},
	{
		.option = { "ignore-failed-read", no_argument, NULL, 'i' },
		.desc = "Continue after read errors",
	},
	{
		.option = { "buffer-size", required_argument, NULL, 'b' },
		.argument = "N",
		.desc = "Read data in chunks of N byte (default: 16384)",
	},
	{
		.option = { "file-timeout", required_argument, NULL, 'T' },
		.desc = "Stop reading file after SEC seconds",
		.argument = "SEC",
	},
	{
		.option = { "file-max-size", required_argument, NULL, 'M' },
		.argument = "N",
		.desc = "Stop reading file after N bytes",
	},
	{
		.option = { "jobs", required_argument, NULL, 'j' },
		.argument = "N",
		.desc = "Read N files in parallel (default: 1)",
	},
	{
		.option = { "jobs-per-cpu", required_argument, NULL, 'J' },
		.argument = "N",
		.desc = "Read N files per CPU in parallel",
	},
	{
		.option = { "exclude", required_argument, NULL, 'x' },
		.argument = "PATTERN",
		.desc = "Don't add files matching PATTERN",
	},
	{
		.option = { "exclude-from", required_argument, NULL, 'X' },
		.argument = "FILE",
		.desc = "Don't add files matching patterns in FILE",
	},
	{
		.option = { "exclude-type", required_argument, NULL,
			    OPT_EXCLUDETYPE },
		.argument = "TYPE",
		.desc = "Don't add files of specified TYPE (one of: fdcbpls)",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "dereference", no_argument, NULL, OPT_DEREFERENCE },
		.desc = "Add link targets instead of links",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "no-recursion", no_argument, NULL,
			    OPT_NORECURSION },
		.desc = "Don't add files from sub-directories",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},

	UTIL_OPT_SECTION("MISC OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	{
		.option = { "verbose", no_argument, NULL, 'V' },
		.desc = "Print additional informational output",
	},
	{
		.option = { "quiet", no_argument, NULL, 'q' },
		.desc = "Suppress printing of informational output",
	},
	UTIL_OPT_END,
};

#endif
