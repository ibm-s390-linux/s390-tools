/*
 * chcpumf -  Change CPU Measurement Facility Characteristics
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/util_base.h"

#include "defines.h"

static int verbose;
static unsigned long min_sdb, max_sdb;

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "min", required_argument, NULL, 'm' },
		.argument = "num_sdb",
		.desc = "Specifies the initial size of the sampling buffer.\n"
			"A sample-data-block (SDB) consumes about 4 kilobytes.",
	},
	{
		.option = { "max", required_argument, NULL, 'x' },
		.argument = "num_sdb",
		.desc = "Specifies the maximum size of the sampling buffer.\n"
			"A sample-data-block (SDB) consumes about 4 kilobytes.",
	},
	{
		.option = { "verbose", no_argument, NULL, 'V' },
		.desc = "Verbose, display new sample-data-block values.",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static const struct util_prg prg = {
	.desc = "Change CPU Measurement facility charactertics",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2020,
			.pub_last = 2020,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static long parse_buffersize(char *string)
{
	char *suffix;
	long bytes;

	bytes = strtol(string, &suffix, 10);
	if (strlen(suffix) > 1)
		return -1;
	switch (*suffix) {
	case 'k':
	case 'K':
		bytes *= 1024;
		break;
	case 'm':
	case 'M':
		bytes *= 1048576;
		break;
	case '\0':
		break;
	default:
		return 0;
	}
	return bytes;
}

static void read_sfb(unsigned long *min, unsigned long *max)
{
	unsigned long cur_min_sdb, cur_max_sdb;
	FILE *fp;

	if (geteuid())
		errx(EXIT_FAILURE, "Must run as root");
	fp = fopen(PERF_SFB_SIZE, "r");
	if (!fp)
		err(EXIT_FAILURE, PERF_SFB_SIZE);
	if (fscanf(fp, "%ld,%ld", &cur_min_sdb, &cur_max_sdb) != 2) {
		fclose(fp);
		errx(EXIT_FAILURE, "Can not parse file " PERF_SFB_SIZE);
	} else {
		if (*min == 0)
			*min = cur_min_sdb;
		if (*max == 0)
			*max = cur_max_sdb;
	}
	fclose(fp);
	if (*min >= *max)
		errx(EXIT_FAILURE,
		     "The specified maximum must be greater than the minimum");
}

static int write_sfb(unsigned long min, unsigned long max)
{
	int rc = EXIT_SUCCESS;
	char text[64];
	size_t len;
	FILE *fp;

	fp = fopen(PERF_SFB_SIZE, "w");
	if (!fp)
		err(EXIT_FAILURE, PERF_SFB_SIZE);
	snprintf(text, sizeof text, "%ld,%ld", min, max);
	len = strlen(text) + 1;
	if (fwrite(text, 1, len, fp) != len) {
		warn(PERF_SFB_SIZE);
		rc = EXIT_FAILURE;
	}
	if (fclose(fp)) {
		warn(PERF_SFB_SIZE);
		rc = EXIT_FAILURE;
	}
	if (verbose && rc != EXIT_FAILURE)
		warnx("Sampling buffer sizes:\n"
		      "    Minimum:%7ld sample-data-blocks\n"
		      "    Maximum:%7ld sample-data-blocks\n",
		      min, max);
	return rc;
}

static int parse_args(int argc, char **argv)
{
	int opt, action = 0;
	long new;

	while ((opt = util_opt_getopt_long(argc, argv)) != -1) {
		switch (opt) {
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case 'x':
			new = parse_buffersize(optarg);
			if (new < 1)
				errx(EXIT_FAILURE,
				     "The specified number(s) are not valid");
			max_sdb = new;
			action = 1;
			break;
		case 'm':
			new = parse_buffersize(optarg);
			if (new < 1)
				errx(EXIT_FAILURE,
				     "The specified number(s) are not valid");
			min_sdb = new;
			action = 1;
			break;
		case 'V':
			verbose = 1;
			break;
		default:
			util_opt_print_parse_error(opt, argv);
			exit(EXIT_FAILURE);
		}
	}
	if (!action)
		errx(EXIT_FAILURE, "You must specify a valid option");
	return action;
}

int main(int argc, char **argv)
{
	struct stat sbuf;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	parse_args(argc, argv);
	if (stat(PERF_PATH PERF_SF, &sbuf))
		errx(EXIT_FAILURE,
		     "No CPU-measurement sampling facility detected");
	read_sfb(&min_sdb, &max_sdb);
	return write_sfb(min_sdb, max_sdb);
}
