/*
 * FCP report generators
 *
 * Utilization report program
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <linux/types.h>
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <assert.h>
#include <limits.h>

#include <list>

#include "lib/zt_common.h"

#include "ziorep_framer.hpp"
#include "ziorep_printers.hpp"
#include "ziorep_frameset.hpp"
#include "ziorep_utils.hpp"
#include "ziorep_collapser.hpp"

extern "C" {
#include "ziomon_msg_tools.h"
}


using std::list;


const char *toolname = "ziorep_utilization";
int verbose=0;


struct options {
	__u64		begin;
	__u64		end;
	__u32		interval;
	list<__u32>	chpids;
	__u64		topline;
	char*		filename;
	bool		print_summary;
	bool		csv_export;
};


static void init_opts(struct options *opts)
{
	opts->begin		= 0;
	opts->end		= UINT64_MAX;
	opts->interval		= UINT32_MAX;
	opts->topline		= 0;
	opts->filename		= NULL;
	opts->print_summary	= false;
	opts->csv_export	= false;
}


static const char help_text[] =
    "Usage: ziorep_utilization [-V] [-v] [-h] [-b <begin>] [-e <end>] [-i <time>]\n"
    "                          [-x] [-s] [-c <chpid>] [-t <num>] <filename>\n\n"
    "-h, --help              Print usage information and exit.\n"
    "-v, --version           Print version information and exit.\n"
    "-V, --verbose           Be verbose.\n"
    "-b, --begin <begin>     Do not consider data earlier than 'begin'.\n"
    "                        Defaults to begin of available data.\n"
    "                        Format is YYYY-MM-DD HH:MM[:SS],\n"
    "                        e.g. '-b \"2008-03-21 09:08\"\n"
    "-e, --end <end>         Do not consider data later than 'end'.\n"
    "                        Defaults to end of available data.\n"
    "                        Format is YYYY-MM-DD HH:MM[:SS],\n"
    "                        e.g. '-e \"2008-03-21 09:08:57\"\n"
    "-i, --interval <time>   Set aggregation interval to 'time' in seconds.\n"
    "                        Must be a multiple of the interval size of the source\n"
    "                        data.\n"
    "                        Set to 0 to aggregate over all data.\n"
    "-s, --summary           Show a summary of the data.\n"
    "-c, --chpid <chpid>     Select physical adapter in hex.\n"
    "                        E.g. '-c 32a'\n"
    "-x, --export-csv        Export data to files in CSV format.\n"
    "-t, --topline <num>     Repeat topline after every 'num' frames.\n"
    "                        0 for no repeat (default).\n";


static void print_help()
{
        printf("%s", help_text);
}


static void print_version()
{
        printf("%s: Utilization report generator version %s\n"
               "Copyright IBM Corp. 2008, 2017\n", toolname, RELEASE_STRING);
}


static int parse_params(int argc, char **argv, struct options *opts)
{
	int c;
	int index;
	int rc;
	__u32 tmp;
	long tmpl;
        static struct option long_options[] = {
                { "version",         no_argument,       NULL, 'v'},
		{ "help",            no_argument,       NULL, 'h'},
		{ "verbose",         no_argument,       NULL, 'V'},
		{ "begin",           required_argument, NULL, 'b'},
                { "end",             required_argument, NULL, 'e'},
		{ "interval",        required_argument, NULL, 'i'},
		{ "summary",         no_argument,       NULL, 's'},
		{ "chpid",           required_argument, NULL, 'c'},
		{ "export-csv",      no_argument,       NULL, 'x'},
		{ "topline",         required_argument, NULL, 't'},
                { 0,                 0,                 0,     0 }
	};

	if (argc < 2) {
		print_help();
		exit(EXIT_FAILURE);
	}

	assert(sizeof(long long int) == sizeof(__u64));
	while ((c = getopt_long(argc, argv, "b:e:i:c:t:xshvV",
				long_options, &index)) != EOF) {
		switch (c) {
		case 'V':
			verbose++;
			break;
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			print_version();
			exit(EXIT_SUCCESS);
		case 'b':
			if (get_datetime_val(optarg, &opts->begin))
				return -1;
			break;
		case 'e':
			if (get_datetime_val(optarg, &opts->end))
				return -1;
			break;
		case 'i':
			if (sscanf(optarg, "%lu", &tmpl) != 1) {
				fprintf(stderr, "%s: Cannot parse %s as an integer value."
					" Please correct and try again.\n", toolname,
					optarg);
				return -1;
			}
			if (tmpl < 0) {
				fprintf(stderr, "%s: Argument %s must be greater than or"
					" equal to 0.", toolname, optarg);
				return -1;
			}
			opts->interval = tmpl;
			break;
		case 's':
			opts->print_summary = true;
			break;
		case 'c':
			rc = sscanf(optarg, "%x", &tmp);
			if (rc != 1) {
				fprintf(stderr, "Error: Could not read chpid"
					" %s\n", optarg);
				return -1;
			}
			opts->chpids.push_back(tmp);
			break;
		case 'x':
			opts->csv_export = true;
			break;
		case 't':
			if (parse_topline_arg(optarg, &opts->topline))
				return -1;
			break;
		default:
			fprintf(stderr, "%s: Try '%s --help' for"
				" more information.\n", toolname, toolname);
			return -1;
		}
	}
	if (optind == argc - 1)
		opts->filename = argv[optind];
	if (optind < argc - 1) {
		fprintf(stderr, "%s: Multiple filenames"
			" specified. Specify only a single one at a time.\n", toolname);
		return -1;
	}

	return 0;
}


static int check_opts(struct options *opts, ConfigReader **cfg)
{
	int rc = 0;

	// check filename
	if (!opts->filename) {
		fprintf(stderr, "%s: No filename"
			" specified.\n", toolname);
		return -2;
	}
	else {
		if (strncmp(opts->filename + strlen(opts->filename)
			    - strlen(DACC_FILE_EXT_LOG), DACC_FILE_EXT_LOG,
			    strlen(DACC_FILE_EXT_LOG)) == 0) {
			verbose_msg("Filename carries " DACC_FILE_EXT_LOG
				    " extension - stripping\n");
			opts->filename[strlen(opts->filename)
					- strlen(DACC_FILE_EXT_LOG)] = '\0';
		}
		if (strncmp(opts->filename + strlen(opts->filename)
			    - strlen(DACC_FILE_EXT_AGG), DACC_FILE_EXT_AGG,
			    strlen(DACC_FILE_EXT_AGG)) == 0) {
			verbose_msg("Filename carries " DACC_FILE_EXT_AGG
				    " extension - stripping\n");
			opts->filename[strlen(opts->filename)
					- strlen(DACC_FILE_EXT_AGG)] = '\0';
		}
		verbose_msg("Filename is %s\n", opts->filename);
	}

	// check config
	*cfg = new ConfigReader(&rc, opts->filename);
	if (rc)
		return -1;

	// check optional chpids
	for (list<__u32>::const_iterator i = opts->chpids.begin();
	      i != opts->chpids.end(); ++i) {
		if (!(*cfg)->verify_chpid(*i)) {
			fprintf(stderr, "Error: Could not find chpid %x in"
				" configuration.\n", *i);
			rc = -2;
		}
	}

	if (opts->csv_export && opts->topline > 0) {
		fprintf(stderr, "%s: Warning: Both, topline"
			" repeat and CSV export activated, deactivating"
			" topline repeat.\n", toolname);
		opts->topline = 0;
	}

	if (!opts->print_summary
		&& adjust_timeframe(opts->filename, &opts->begin, &opts->end,
			     &opts->interval))
		rc = -3;

	return rc;
}


static int print_reports(struct options *opts, ConfigReader &cfg)
{
	int rc = 0;
	PhysAdapterPrinter physPrnt(&cfg, opts->csv_export);
	VirtAdapterPrinter virtPrnt(&cfg, opts->csv_export);
	Aggregator agg = devno;
	StagedDeviceFilter dev_filt;
	NoopCollapser noop_col;
	list<__u32> devnos;
	list<__u32> chpids;
	list<MsgTypes> type_flt;
	AggregationCollapser *col = NULL;
	FILE *fp;

	if (opts->chpids.size())
		chpids = opts->chpids;
	else
		cfg.get_unique_chpids(chpids);

	cfg.get_unique_mms(devnos);

	// add all HBAs and all devices connected to them
	for (list<__u32>::const_iterator i = chpids.begin();
	      i != chpids.end(); ++i) {
		cfg.get_devnos_by_chpid(devnos, *i);
		for (list<__u32>::const_iterator j = devnos.begin();
		      j != devnos.end(); ++j)
			dev_filt.stage_devno(*j);
	}
	dev_filt.finish(cfg, false);

	col = new AggregationCollapser(cfg, agg, dev_filt, &rc);

	type_flt.push_back(utilization);

	if (opts->csv_export) {
		fp = open_csv_output_file(opts->filename,
					  "_util_phys_adpt.csv", &rc);
		if (!fp)
			goto out;
	}
	else
		fp = stdout;

	if ( (rc = print_report(fp, opts->begin, opts->end,
				opts->interval, opts->filename, opts->topline,
				&type_flt, dev_filt, noop_col,
				physPrnt)) < 0 ) {
		rc = -3;
		goto out1;
	}

	if (rc == 0)
		fprintf(stderr, "%s: No eligible data found.\n", toolname);

	if (opts->csv_export) {
		fclose(fp);
		fp = open_csv_output_file(opts->filename,
					  "_util_virt_adpt.csv", &rc);
		if (!fp)
			goto out;
	}
	else {
		fp = stdout;
		fputc('\n', fp);
	}

	if (print_report(fp, opts->begin, opts->end, opts->interval,
			 opts->filename, opts->topline, NULL, dev_filt,
			 *col, virtPrnt)) {
		rc = -4;
		goto out1;
	}

out1:
	if (opts->csv_export)
		fclose(fp);
out:
	delete col;

	return rc;
}


int main(int argc, char **argv)
{
	int rc;
	struct options opts;
	ConfigReader *cfg = NULL;

	verbose = 0;

	init_opts(&opts);
	if ( (rc = parse_params(argc, argv, &opts)) ) {
		if (rc == 1)
			rc = 0;
		goto out;
	}
	if ( (rc = check_opts(&opts, &cfg)) )
		goto out;

	if (opts.print_summary)
		rc = print_summary_report(stdout, opts.filename, *cfg);
	else
		rc = print_reports(&opts, *cfg);

out:
	delete cfg;

	return rc;
}



