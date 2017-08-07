/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Command line interface
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "lib/util_opt.h"
#include "lib/util_prg.h"

#include "dump.h"
#include "global.h"
#include "idcache.h"
#include "misc.h"
#include "strarray.h"

#define MIN_BUFFER_SIZE		4096

#define	OPT_NOSHORT_BASE	256

#define	OPT_DEREFERENCE		(OPT_NOSHORT_BASE + 0)
#define OPT_NORECURSION		(OPT_NOSHORT_BASE + 1)
#define OPT_EXCLUDETYPE		(OPT_NOSHORT_BASE + 2)

/* Program description */
static const struct util_prg dump2tar_prg = {
	.desc = "Use dump2tar to create a tar archive from the contents "
		"of arbitrary files.\nIt works even when the size of actual "
		"file content is not known beforehand,\nsuch as with FIFOs, "
		"character devices or certain Linux debugfs or sysfs files.\n"
		"\nYou can also add files under different names and add "
		"command output using the\nformat described in section SPECS "
		"below. When no additional options are\nspecified, the "
		"resulting archive is written to the standard output stream\n"
		"in uncompressed tar format.",
	.args = "SPECS",
	.copyright_vec = {
		{ "IBM Corp.", 2016, 2016 },
		UTIL_PRG_COPYRIGHT_END
	},
};

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

/* Split buffer size specification in @arg into two numbers to be stored in
 * @from_ptr and @to_ptr. Return %EXIT_OK on success. */
static int parse_buffer_size(char *arg, size_t *from_ptr, size_t *to_ptr)
{
	char *err;
	unsigned long from, to;

	if (!*arg) {
		mwarnx("Empty buffer size specified");
		return EXIT_USAGE;
	}

	from = strtoul(arg, &err, 10);

	if (*err == '-')
		to = strtoul(err + 1, &err, 10);
	else
		to = *to_ptr;

	if (*err) {
		mwarnx("Invalid buffer size: %s", arg);
		return EXIT_USAGE;
	}

	if (from < MIN_BUFFER_SIZE || to < MIN_BUFFER_SIZE) {
		mwarnx("Buffer size too low (minimum %u)", MIN_BUFFER_SIZE);
		return EXIT_USAGE;
	}

	if (to < from)
		to = from;

	*from_ptr = from;
	*to_ptr = to;

	return EXIT_OK;
}

static void parse_and_add_spec(struct dump_opts *opts, const char *spec)
{
	char *op, *s, *inname, *outname = NULL;
	bool is_cmd = false;

	s = mstrdup(spec);
	op = strstr(s, "|=");
	if (op)
		is_cmd = true;
	else
		op = strstr(s, ":=");

	if (op) {
		*op = 0;
		inname = op + 2;
		outname = s;
	} else {
		inname = s;
	}
	dump_opts_add_spec(opts, inname, outname, is_cmd);
	free(s);
}

static int add_specs_from_file(struct dump_opts *opts, const char *filename)
{
	FILE *fd;
	char *line = NULL;
	size_t line_size;
	int rc = EXIT_RUNTIME;
	bool need_close = false, parse_spec = true;

	if (strcmp(filename, "-") == 0)
		fd = stdin;
	else {
		fd = fopen(filename, "r");
		if (!fd) {
			mwarn("%s: Cannot open file", filename);
			goto out;
		}
		need_close = true;
	}

	while ((getline(&line, &line_size, fd) != -1)) {
		chomp(line, "\n");
		if (line[0] == 0)
			continue;
		if (parse_spec && strcmp(line, "--") == 0) {
			/* After a line containing --, no more := or |= specs
			 * are expected */
			parse_spec = false;
			continue;
		}
		if (parse_spec)
			parse_and_add_spec(opts, line);
		else
			dump_opts_add_spec(opts, line, NULL, false);
	}

	if (ferror(fd))
		mwarn("%s: Cannot read file", filename);
	else
		rc = EXIT_OK;

out:
	if (need_close)
		fclose(fd);
	free(line);

	return rc;
}

static void print_help(void)
{
	static const struct {
		const char *name;
		const char *desc;
	} specs[] = {
		{ "PATH", "Add file or directory at PATH" },
		{ "NEWPATH:=PATH", "Add file or directory at PATH as NEWPATH" },
		{ "NEWPATH|=CMDLINE", "Add output of command line CMDLINE as "
		  "NEWPATH" },
		{ NULL, NULL },
	};
	int i;

	util_prg_print_help();
	printf("SPECS\n");
	for (i = 0; specs[i].name; i++)
		util_opt_print_indented(specs[i].name, specs[i].desc);
	printf("\n");
	util_opt_print_help();
}

int main(int argc, char *argv[])
{
	int rc = EXIT_USAGE, opt;
	long i;
	struct dump_opts *opts;

	if (getenv("DUMP2TAR_DEBUG"))
		global_debug = true;

	util_prg_init(&dump2tar_prg);
	util_opt_init(dump2tar_opts, "-");
	misc_init();

	opts = dump_opts_new();
	opterr = 0;
	while ((opt = util_opt_getopt_long(argc, argv)) != -1) {
		switch (opt) {
		case 'h': /* --help */
			print_help();
			rc = EXIT_OK;
			goto out;
		case 'v': /* --version */
			util_prg_print_version();
			rc = EXIT_OK;
			goto out;
		case 'V': /* --verbose */
			global_verbose = true;
			global_quiet = false;
			opts->verbose = true;
			opts->quiet = false;
			break;
		case 'q': /* --quiet */
			global_quiet = true;
			global_verbose = false;
			opts->quiet = true;
			opts->verbose = false;
			break;
		case 'i': /* --ignore-failed-read */
			opts->ignore_failed_read = true;
			break;
		case 'j': /* --jobs N */
			opts->jobs = atoi(optarg);
			if (opts->jobs < 1) {
				mwarnx("Invalid number of jobs: %s", optarg);
				goto out;
			}
			break;
		case 'J': /* --jobs-per-cpu N */
			opts->jobs_per_cpu = atoi(optarg);
			if (opts->jobs_per_cpu < 1) {
				mwarnx("Invalid number of jobs: %s", optarg);
				goto out;
			}
			break;
		case 'b': /* --buffer-size N */
			if (parse_buffer_size(optarg, &opts->read_chunk_size,
					      &opts->max_buffer_size))
				goto out;
			break;
		case 'x': /* --exclude PATTERN */
			add_str_to_strarray(&opts->exclude, optarg);
			break;
		case 'X': /* --exclude-from FILE */
			if (add_file_to_strarray(&opts->exclude, optarg))
				goto out;
			break;
		case 'F': /* --files-from FILE */
			if (add_specs_from_file(opts, optarg))
				goto out;
			break;
		case 'o': /* --output-file FILE */
			if (opts->output_file) {
				mwarnx("Output file specified multiple times");
				goto out;
			}
			opts->output_file = optarg;
			break;
		case OPT_DEREFERENCE: /* --dereference */
			opts->dereference = true;
			break;
		case OPT_NORECURSION: /* --no-recursion */
			opts->recursive = false;
			break;
		case OPT_EXCLUDETYPE: /* --exclude-type TYPE */
			for (i = 0; optarg[i]; i++) {
				if (dump_opts_set_type_excluded(opts,
								optarg[i]))
					break;

			}
			if (optarg[i]) {
				mwarnx("Unrecognized file type: %c", optarg[i]);
				goto out;
			}
			break;
		case 131: /* --no-eof */
			opts->no_eof = true;
			break;
		case 132: /* --add-cmd-status */
			opts->add_cmd_status = true;
			break;
		case 133: /* --append */
			opts->append = true;
			break;
		case 't': /* --timeout VALUE */
			opts->timeout = atoi(optarg);
			if (opts->timeout < 1) {
				mwarnx("Invalid timeout value: %s", optarg);
				goto out;
			}
			break;
		case 'T': /* --file-timeout VALUE */
			opts->file_timeout = atoi(optarg);
			if (opts->file_timeout < 1) {
				mwarnx("Invalid timeout value: %s", optarg);
				goto out;
			}
			break;
		case 'm': /* --max-size N */
			opts->max_size = atol(optarg);
			if (opts->max_size < 2) {
				mwarnx("Invalid maximum size: %s", optarg);
				goto out;
			}
			break;
		case 'M': /* --file-max-size N */
			opts->file_max_size = atol(optarg);
			if (opts->file_max_size < 2) {
				mwarnx("Invalid maximum size: %s", optarg);
				goto out;
			}
			break;
		case 'z': /* --gzip */
			opts->gzip = true;
			break;
		case 1: /* Filename specification or unrecognized option */
			if (optarg[0] == '-') {
				mwarnx("Invalid option '%s'", optarg);
				goto out;
			}
			parse_and_add_spec(opts, optarg);
			break;
		case '?': /* Unrecognized option */
			if (optopt)
				mwarnx("Invalid option '-%c'", optopt);
			else
				mwarnx("Invalid option '%s'", argv[optind - 1]);
			goto out;
		case ':': /* Missing argument */
			mwarnx("Option '%s' requires an argument",
			      argv[optind - 1]);
			goto out;
		default:
			break;
		}
	}
	if (optind >= argc && opts->num_specs == 0) {
		mwarnx("Please specify files to dump");
		goto out;
	}

	for (i = optind; i < argc; i++)
		dump_opts_add_spec(opts, argv[i], NULL, false);

	rc = dump_to_tar(opts);

out:
	idcache_cleanup();
	misc_cleanup();
	dump_opts_free(opts);

	if (rc == EXIT_USAGE)
		util_prg_print_parse_error();

	return rc;
}
