/*
 * FCP report generators
 *
 * Traffic report program
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

#include "ziorep_collapser.hpp"
#include "ziorep_utils.hpp"


using std::list;


const char *toolname = "ziorep_traffic";
int verbose=0;


struct options {
	__u64			begin;
	__u64			end;
	__u32			interval;
	list<const char*>	devices;
	list<const char*>	mp_devices;
	__u64			topline;
	char*			filename;
	bool			print_summary;
	bool			details;
	Aggregator		col_crit;
	list<__u32>		chpids;
	list<__u32>		devnos;
	list<__u64>		wwpns;
	list<__u64>		luns;
	bool			csv_export;
};


static void init_opts(struct options *opts)
{
	opts->begin		= 0;
	opts->end		= UINT64_MAX;
	opts->interval		= UINT32_MAX;
	opts->topline		= 0;
	opts->filename		= NULL;
	opts->print_summary	= false;
	opts->details		= false;
	opts->col_crit		= none;
	opts->csv_export	= false;
}


static const char help_text[] =
    "Usage: ziorep_traffic [-V] [-v] [-h] [-b <begin>] [-e <end>]"
    " [-i <time>] [-s]\n"
    "                        [-c <chpid>] [-u <id>] [-t <num>] [-p <port>]\n"
    "                        [-l <lun>] [-d <fdev> ] [-m <mdev>] [-x] [-D]\n"
    "                        [-C a|u|p|m|A] <filename>\n\n"
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
    "-C, --collapse <val>    Collapse data for multiple instances of\n"
    "                        a device into a single one. See man page for details.\n"
    "-c, --chpid <chpid>     Select adapter by CHPID in hex, e.g. '-c 32'\n"
    "-u, --bus-id <id>       Select by bus-ID, e.g. '-u 0.0.7f1d'\n"
    "-p, --port <port>       Select by target port, e.g. '-p 0x500507630040710b'\n"
    "-l, --lun <lun>         Select by lun, e.g. '-l 0x4021402200000000'\n"
    "-d, --device <fdev>     Select by device, e.g. '-d sda'\n"
    "-m, --mdev <mdev>       Select by multipath device,\n"
    "                        e.g. '-m 36005076303ffc1040002120'\n"
    "-D, --detailed          Print histograms instead of min/max/avg/stdev\n"
    "-x, --export-csv        Export data to files in CSV format.\n"
    "-t, --topline <num>     Repeat topline after every 'num' frames.\n"
    "                        0 for no repeat (default).\n";


static void print_help()
{
        printf("%s", help_text);
}


static void print_version()
{
        printf("%s: Traffic report generator version %s\n"
               "Copyright IBM Corp. 2008, 2017\n", toolname, RELEASE_STRING);
}


static int parse_params(int argc, char **argv, struct options *opts)
{
	int c;
	int index;
	int rc;
	__u32 tmp32, tmp32a, tmp32b;
	long long unsigned int tmp64;
	long tmpl;
	char mychar;
        static struct option long_options[] = {
                { "version",         no_argument,       NULL, 'v'},
		{ "help",            no_argument,       NULL, 'h'},
		{ "verbose",         no_argument,       NULL, 'V'},
		{ "begin",           required_argument, NULL, 'b'},
                { "end",             required_argument, NULL, 'e'},
		{ "interval",        required_argument, NULL, 'i'},
		{ "summary",         no_argument,       NULL, 's'},
		{ "collapse",        required_argument, NULL, 'C'},
		{ "chpid",           required_argument, NULL, 'c'},
		{ "bus-id",          required_argument, NULL, 'u'},
		{ "port",            required_argument, NULL, 'p'},
		{ "lun",             required_argument, NULL, 'l'},
		{ "device",          required_argument, NULL, 'd'},
		{ "mdev",            required_argument, NULL, 'm'},
		{ "detailed",        required_argument, NULL, 'D'},
		{ "export-csv",      no_argument,       NULL, 'x'},
		{ "topline",         required_argument, NULL, 't'},
                { 0,                 0,                 0,     0 }
	};

	if (argc < 2) {
		print_help();
		exit(EXIT_FAILURE);
	}

	assert(sizeof(long long int) == sizeof(__u64));
	while ((c = getopt_long(argc, argv, "m:C:b:e:i:c:u:p:l:d:t:xDshvV",
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
				fprintf(stderr, "%s:"
					" Cannot parse %s as an integer value."
					" Please correct and try again.\n", toolname,
					optarg);
				return -1;
			}
			if (tmpl < 0) {
				fprintf(stderr, "%s:"
					" Argument %s must be greater than or"
					" equal to 0.", toolname, optarg);
				return -1;
			}
			opts->interval = tmpl;
			break;
		case 's':
			opts->print_summary = true;
			break;
		case 'c':
			rc = sscanf(optarg, "%x%c", &tmp32, &mychar);
			if (rc < 1) {
				fprintf(stderr, "%s: Could"
					" not read chpid %s\n", toolname, optarg);
				return -1;
			}
			if (rc > 1) {
				fprintf(stderr, "%s: %s is not a valid chpid\n", toolname, optarg);
				return -1;
			}
			opts->chpids.push_back(tmp32);
			break;
		case 'p':
			 rc = sscanf(optarg, "0x%Lx", &tmp64);
			 if (rc != 1) {
				 fprintf(stderr, "%s: Could"
					 " not read port number %s\n", toolname, optarg);
				 return -1;
			 }
			 opts->wwpns.push_back(tmp64);
			 break;
		case 'l':
			rc = sscanf(optarg, "0x%Lx", &tmp64);
			if (rc != 1) {
				fprintf(stderr, "%s: Could"
					" not read lun %s\n", toolname, optarg);
				return -1;
			}
			opts->luns.push_back(tmp64);
			break;
		case 'u':
			rc = sscanf(optarg, "%x.%x.%x", &tmp32, &tmp32a, &tmp32b);
			if (rc != 3) {
				fprintf(stderr, "%s: Could not read bus-ID"
					" %s\n", toolname, optarg);
				return -1;
			}
			opts->devnos.push_back(ZIOREP_BUSID_PACKED(tmp32, tmp32a, tmp32b));
			break;
		case 'd':
			opts->devices.push_back(optarg);
			break;
		case 'm':
			opts->mp_devices.push_back(optarg);
			break;
		case 'D':
			opts->details = true;
			break;
		case 't':
			if (parse_topline_arg(optarg, &opts->topline))
				return -1;
			break;
		case 'x':
			opts->csv_export = true;
			break;
		case 'C':
			rc = 0;
			switch (*optarg) {
			case 'a': opts->col_crit = chpid;
				break;
			case 'u': opts->col_crit = devno;
				break;
			case 'p': opts->col_crit = wwpn;
				break;
			case 'm': opts->col_crit = multipath_device;
				break;
			case 'A': opts->col_crit = all;
				break;
			default:
				rc = -1;
			}
			if (rc || strlen(optarg) > 1) {
				fprintf(stderr, "%s:"
				    " Unrecognized switch '%s' to parameter"
				    " '-C'. Please check the help for a list"
				    " of valid switches, correct and try"
				    " again.\n", toolname, optarg);
				return -2;
			}
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
		fprintf(stderr, "%s: No filename specified.\n", toolname);
		return -2;
	}
	else {
		if (strncmp(opts->filename + strlen(opts->filename) - strlen(DACC_FILE_EXT_LOG),
			    DACC_FILE_EXT_LOG, strlen(DACC_FILE_EXT_LOG)) == 0) {
			verbose_msg("Filename carries " DACC_FILE_EXT_LOG " extension - stripping\n");
			opts->filename[strlen(opts->filename) - strlen(DACC_FILE_EXT_LOG)] = '\0';
		}
		if (strncmp(opts->filename + strlen(opts->filename) - strlen(DACC_FILE_EXT_AGG),
			    DACC_FILE_EXT_AGG, strlen(DACC_FILE_EXT_AGG)) == 0) {
			verbose_msg("Filename carries " DACC_FILE_EXT_AGG " extension - stripping\n");
			opts->filename[strlen(opts->filename) - strlen(DACC_FILE_EXT_AGG)] = '\0';
		}
		verbose_msg("Filename is %s\n", opts->filename);
	}

	// check config
	*cfg = new ConfigReader(&rc, opts->filename);
	if (rc)
		return -1;

	for (list<__u32>::const_iterator i = opts->chpids.begin();
	      i != opts->chpids.end(); ++i) {
		if (!(*cfg)->verify_chpid(*i)) {
			fprintf(stderr, "Error: Could not find chpid %x in"
				" configuration.\n", *i);
			rc = -2;
		}
	}
	for (list<__u32>::const_iterator i = opts->devnos.begin();
	      i != opts->devnos.end(); ++i) {
		if (!(*cfg)->verify_devno(*i)) {
			fprintf(stderr, "Error: Could not find bus-ID %x.%x.%04x in"
				" configuration.\n", ZIOREP_BUSID_UNPACKED(*i));
			rc = -3;
		}
	}
	for (list<__u64>::const_iterator i = opts->wwpns.begin();
	      i != opts->wwpns.end(); ++i) {
		if (!(*cfg)->verify_wwpn(*i)) {
			fprintf(stderr, "Error: Could not find WWPN %016Lx in"
				" configuration.\n", (long long unsigned int)*i);
			rc = -4;
		}
	}
	for (list<__u64>::const_iterator i = opts->luns.begin();
	      i != opts->luns.end(); ++i) {
		if (!(*cfg)->verify_lun(*i)) {
			fprintf(stderr, "Error: Could not find LUN %016Lx in"
				" configuration.\n", (long long unsigned int)*i);
			rc = -5;
		}
	}
	for (list<const char*>::iterator i = opts->devices.begin();
	      i != opts->devices.end(); ++i) {
		if (!(*cfg)->verify_device(*i)) {
			fprintf(stderr, "Error: Could not find device %s in"
				" configuration.\n", *i);
			rc = -6;
		}
	}
	for (list<const char*>::iterator i = opts->mp_devices.begin();
	      i != opts->mp_devices.end(); ++i) {
		if (!(*cfg)->verify_mp_device(*i)) {
			fprintf(stderr, "Error: Could not find multipath"
				" device %s in configuration.\n", *i);
			rc = -7;
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
		rc = -8;

	return rc;
}


static int configure_coarse_devices(struct options *opts, ConfigReader &cfg,
				     StagedDeviceFilter &dev_flt)
{
	list<__u32> mms;
	int rc = 0;

	for (list<const char *>::const_iterator i = opts->devices.begin();
	      i != opts->devices.end(); ++i) {
		__u32 mm = cfg.get_mm_by_device(*i, &rc);
		dev_flt.add_device(mm, cfg.get_ident_by_mm_internal(mm, &rc));
	}
	for (list<__u64>::const_iterator i = opts->luns.begin();
	      i != opts->luns.end(); ++i) {
		cfg.get_mms_by_lun(mms, *i);
		for (list<__u32>::const_iterator j = mms.begin();
		      j != mms.end(); j++)
			dev_flt.add_device(*j, cfg.get_ident_by_mm_internal(*j, &rc));
	}
	for (list<const char *>::const_iterator i = opts->mp_devices.begin();
	      i != opts->mp_devices.end(); ++i)
		dev_flt.stage_mp_mm(cfg.get_mp_mm_by_multipath(*i, &rc));
	if (rc)
		return -1;
	for (list<__u64>::const_iterator i = opts->wwpns.begin();
	      i != opts->wwpns.end(); ++i)
		dev_flt.stage_wwpn(*i);
	for (list<__u32>::const_iterator i = opts->devnos.begin();
	      i != opts->devnos.end(); ++i)
		dev_flt.stage_devno(*i);
	for (list<__u32>::const_iterator i = opts->chpids.begin();
	      i != opts->chpids.end(); ++i)
		dev_flt.stage_chpid(*i);

	return dev_flt.finish(cfg, false);
}


static int configure_device_filter(struct options *opts, ConfigReader &cfg,
				   DeviceFilter **dev_filt)
{
	int rc = 0;
	list<__u32> mm_lst;
	list<__u32>::const_iterator i_32, j_32;

	verbose_msg("Configure device filter\n");
	// verify and sort out devices
	if (opts->devices.size() > 0 ||  opts->luns.size() > 0
		 || opts->wwpns.size() > 0 || opts->mp_devices.size() > 0
		 || opts->devnos.size() > 0 || opts->chpids.size() > 0) {
		verbose_msg("    devices specified via coarse criteria"
			    " - let's see...\n");
		StagedDeviceFilter *stgd_flt = new StagedDeviceFilter;
		*dev_filt = stgd_flt;
		rc = configure_coarse_devices(opts, cfg, *stgd_flt);
	}
	else {
		verbose_msg("    no devices specified - accept all\n");
		*dev_filt = new DeviceFilter;
		add_all_devices(cfg, **dev_filt);
	}

	verbose_msg("Device filter configured (total: %zd devices)\n",
		    (*dev_filt)->get_mm_list().size());

	return rc;
}


static int print_report(struct options *opts, ConfigReader &cfg)
{
	int rc = 0;
	FILE *fp;
	MsgTypeFilter msgtype_filter;
	Printer *printer = NULL;
	DeviceFilter *dev_filt;
	Collapser *col = NULL;
	list<MsgTypes> type_flt;

	type_flt.push_back(zfcpdd);
	type_flt.push_back(blkiomon);

	if (configure_device_filter(opts, cfg, &dev_filt)) {
		rc = -1;
		goto out;
	}

	if (opts->col_crit == none)
		col = new NoopCollapser();
	else if (opts->col_crit == all)
		col = new TotalCollapser();
	else {
		col = new AggregationCollapser(cfg,
					       opts->col_crit,
					       *dev_filt,
					       &rc);
		if (rc)
			goto out;
	}

	if (opts->details) {
		if (opts->csv_export) {
			fp = open_csv_output_file(opts->filename,
						  "_traffic_detailed.csv", &rc);
			if (rc)
				goto out;
		}
		else
			fp = stdout;
		printer = new DetailedTrafficPrinter(&cfg, *col,
						     opts->csv_export);
	}
	else {
		if (opts->csv_export) {
			fp = open_csv_output_file(opts->filename,
						  "_traffic.csv",
						  &rc);
			if (rc)
				goto out;
		}
		else
			fp = stdout;
		printer = new SummaryTrafficPrinter(&cfg, *col,
						    opts->csv_export);
	}

	if ( (rc = print_report(fp, opts->begin, opts->end,
				opts->interval, opts->filename, opts->topline,
				&type_flt, *dev_filt, *col, *printer)) < 0 )
		rc = -3;

	if (opts->csv_export)
		fclose(fp);
out:
	delete dev_filt;
	delete col;
	delete printer;

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
		rc = print_report(&opts, *cfg);

out:
	delete cfg;

	return rc;
}

