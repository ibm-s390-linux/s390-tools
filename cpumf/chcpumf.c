/*
 * chcpumf -  Change CPU Measurement Facility Characteristics
 *
 * Copyright IBM Corp. 2020, 2022
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

#include "lib/libcpumf.h"

static unsigned int verbose;
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

static int write_sfb(unsigned int min, unsigned int max)
{
	int rc = EXIT_SUCCESS;
	char text[64];
	size_t len;
	FILE *fp;

	fp = fopen(S390_CPUMSF_BUFFERSZ, "w");
	if (!fp)
		err(EXIT_FAILURE, S390_CPUMSF_BUFFERSZ);
	snprintf(text, sizeof(text), "%u,%u", min, max);
	len = strlen(text) + 1;
	if (fwrite(text, 1, len, fp) != len) {
		warn(S390_CPUMSF_BUFFERSZ);
		rc = EXIT_FAILURE;
	}
	if (fclose(fp)) {
		warn(S390_CPUMSF_BUFFERSZ);
		rc = EXIT_FAILURE;
	}
	if (verbose && rc != EXIT_FAILURE)
		warnx("Sampling buffer sizes:\n"
		      "    Minimum:%7d sample-data-blocks\n"
		      "    Maximum:%7d sample-data-blocks\n",
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
	unsigned long my_min, my_max;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	parse_args(argc, argv);
	if (geteuid())
		errx(EXIT_FAILURE, "Must run as root");
	if (!libcpumf_have_sfb())
		errx(EXIT_FAILURE,
		     "No CPU-measurement sampling facility detected");
	libcpumf_sfb_info(&my_min, &my_max);
	if (!min_sdb)
		min_sdb = my_min;
	if (!max_sdb)
		max_sdb = my_max;
	return write_sfb(min_sdb, max_sdb);
}
