/*
 * FCP adapter trace utility
 *
 * Central message collection tool
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <linux/types.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "lib/zt_common.h"

#include "ziomon_dacc.h"
#include "ziomon_msg_tools.h"
#include "ziomon_tools.h"
#include "ziomon_util.h"
#include "ziomon_zfcpdd.h"
#include "blkiomon.h"



const char *toolname = "ziomon_mgr";
int verbose=0;
static int keep_running = 1;


struct options {
	char   		       *msg_q_path;
	int			msg_q_id;
	int			msg_q;
	long			msg_id_utilization;
	long			msg_id_ioerr;
	long			msg_id_blkiomon;
	long			msg_id_zfcpdd;
	int			estimate;
	int			interval_length;
	int			force;
	long                    version;
	char   		       *outfile_name;
	char   		       *outfile_name_agg;
	FILE   		       *outfile;
	FILE		       *outfile_agg;
	struct aggr_data	agg_data;
	long			size_limit;
	short			wrapped;
	struct file_header	f_hdr;
};


static void init_opts(struct options *opts)
{
	opts->msg_q_path = NULL;
	opts->msg_q_id = -1;
	opts->msg_q = -1;
	opts->msg_id_blkiomon = LONG_MIN;
	opts->msg_id_utilization = LONG_MIN;
	opts->msg_id_ioerr = LONG_MIN;
	opts->msg_id_zfcpdd = LONG_MIN;
	opts->outfile_name = NULL;
	opts->outfile_name_agg = NULL;
	opts->outfile = NULL;
	opts->outfile_agg = NULL;
	opts->size_limit = LONG_MAX;
	opts->wrapped = 0;
	opts->interval_length = -1;
	opts->force = 0;
	opts->estimate = 0;
	opts->version = 3;
}


static void deinit_opts(struct options *opts)
{
	if (opts->msg_q >= 0) {
		verbose_msg("shutting down message queue\n");
		if (msgctl(opts->msg_q, IPC_RMID, 0) == -1)
			fprintf(stderr, "%s: Error encountered"
				" while shutting down message queue: %s\n",
				toolname, strerror(errno));
	}
	if (opts->outfile)
		fclose(opts->outfile);
	free(opts->outfile_name);
	free(opts->outfile_name_agg);
	if (opts->outfile_agg) {
		fclose(opts->outfile_agg);
		discard_aggr_data_struct(&opts->agg_data);
	}
}


static const char help_text[] =
  "Usage: ziomon_mgr [-h] [-v] [-V] [-e] [-f] [-l <size>] [-x <version>]"
  " -o <filename> -i <length>\n"
  "                  -Q <msgq-path> -q <msgq-id> -u <util-id> -r <ioerr-id>\n"
  "                  -b <blkiomon-id> -z <ziomon_zfcpdd-id>\n"
  "Start the message server for the ziomon framework.\n"
  "\n"
  "-h, --help              Print usage information and exit.\n"
  "-v, --version           Print version information and exit.\n"
  "-V, --verbose           Be verbose.\n"
  "-e, --binary-offsets    Print a list of binary data structure"
                         " sizes and exit.\n"
  "-f, --force             Force message queue creation.\n"
  "-i, --interval-length   Specify interval length in seconds.\n"
  "-Q, --msg-queue-name    Specify the message queue path name.\n"
  "-q, --msg-queue-id      Specify the message queue id.\n"
  "-u, --util-id           Specify the id for utilization messages from\n"
  "                        ziomon_util.\n"
  "-r, --ioerr-id          Specify the id for ioerr messages from"
			   " ziomon_util.\n"
  "-b, --blkiomon-id       Specify the id for messages from blkiomon.\n"
  "-z, --ziomon-zfcpdd-id  Specify the id for messages from ziomon_zfcpdd.\n"
  "-o, --output            Specify the name of the output file(s).\n"
  "-l, --size-limit        Maximum size of data collected in MB.\n"
  "-x, --enforce-version   Enforce specific version for .log and .agg files.\n";

static void print_help(void)
{
        fprintf(stdout, "%s", help_text);
}


static void print_version(void)
{
        fprintf(stdout, "%s: ziomon manager, version %s\n"
               "Copyright IBM Corp. 2008, 2017\n",
               toolname, RELEASE_STRING);
}


static int setup_msg_q(struct options *opts)
{
	key_t util_q;
	int flags;

	util_q = ftok(opts->msg_q_path, opts->msg_q_id);

	if (util_q == -1) {
		fprintf(stderr, "%s: Cannot create"
			" message queue with path %s and id %d: %s\n",
			toolname, opts->msg_q_path, opts->msg_q_id, strerror(errno));
		return -1;
	}

	verbose_msg("message queue key is %d\n", util_q);

	flags = IPC_CREAT | S_IRWXU;
	if (!opts->force)
		flags |= IPC_EXCL;
	opts->msg_q = msgget(util_q, flags);
	if (opts->msg_q < 0) {
		fprintf(stderr, "%s: Could not open message queue"
			": %s\n", toolname, strerror(errno));
		if (!opts->force)
			fprintf(stderr, "%s: Retry using the 'force'"
				" option\n", toolname);
		return -1;
	}
	verbose_msg("message queue id is %d\n", opts->msg_q);

	return 0;
}


static int add_to_aggregated(struct message **msgs, int num_msgs,
			     struct options *opts)
{
	int i;

	if (!opts->outfile_agg) {
		opts->outfile_agg = fopen(opts->outfile_name_agg, "w+");
		if (!opts->outfile_agg) {
			fprintf(stderr, "%s: Could not open file"
				" for aggregated data: %s\n", toolname,
				strerror(errno));
			return -1;
		}
		init_aggr_data_struct(&opts->agg_data);
	}

	/* aggregate data */
	for (i = 0; i < num_msgs; ++i) {
		if (add_to_agg(&opts->agg_data, msgs[i], &opts->f_hdr))
			return -1;
		discard_msg(msgs[i]);
		free(msgs[i]);
	}
	free(msgs);

	/* write back to file */
	conv_aggr_data_msg_data_to_BE(&opts->agg_data);
	i = write_aggr_file(opts->outfile_agg, &opts->agg_data);
	conv_aggr_data_msg_data_from_BE(&opts->agg_data);

	return i;
}

static int compare_msg_ids(const void *a, const void *b)
{
	return (*(long*)b - *(long*)a);
}

static int check_msg_ids(struct options *opts)
{
	int i;
	long msg_ids[4];

	msg_ids[0] = opts->msg_id_utilization;
	msg_ids[1] = opts->msg_id_ioerr;
	msg_ids[2] = opts->msg_id_blkiomon;
	msg_ids[3] = opts->msg_id_zfcpdd;

	qsort(msg_ids, 4, sizeof(long), compare_msg_ids);

	for (i = 0; i < 4; ++i) {
		if (msg_ids[i] <= 0) {
			fprintf(stderr, "%s: ids for messages must be"
				" greater than 0\n", toolname);
			return -1;
		}
		if (i != 0 && msg_ids[i] == msg_ids[i-1]) {
			fprintf(stderr, "%s: ids for messages must be"
				" different from another\n", toolname);
			return -1;
		}
	}

	return 0;
}


void print_bin_struct_sizes(void)
{
	fprintf(stdout, "%ld %ld %ld %ld %ld %ld\n",
		(unsigned long int)sizeof(struct utilization_data),
		(unsigned long int)sizeof(struct adapter_utilization),
		(unsigned long int)sizeof(struct ioerr_data),
		(unsigned long int)sizeof(struct ioerr_cnt),
		(unsigned long int)sizeof(struct zfcpdd_dstat),
		(unsigned long int)sizeof(struct blkiomon_stat));
}


static int convert_long_optarg(long *tgt, char *option_str)
{
	if (!optarg) {
		fprintf(stderr, "%s: Error: Argument missing to"
			" option %s\n", toolname, option_str);
		return -1;
	}
	*tgt = strtol(optarg, NULL, 0);
	if (errno) {
		fprintf(stderr, "%s: Error converting %s to"
			" long: %s\n", toolname, optarg, strerror(errno));
		return -1;
	}

	return 0;
}


static int parse_params(int argc, char **argv, struct options *opts)
{
	int c;
	int error=0;
	int index;
        static struct option long_options[] = {
                { "version",         no_argument,       NULL, 'v'},
		{ "help",            no_argument,       NULL, 'h'},
		{ "binary-offsets",  no_argument,       NULL, 'e'},
                { "interval-length", required_argument, NULL, 'i'},
		{ "msg-queue-name",  required_argument, NULL, 'Q'},
		{ "msg-queue-id",    required_argument, NULL, 'q'},
		{ "util-id",         required_argument, NULL, 'u'},
		{ "ioerr-id",        required_argument, NULL, 'r'},
		{ "blkiomon-id",     required_argument, NULL, 'b'},
		{ "ziomon-zfcp-id",  required_argument, NULL, 'z'},
		{ "verbose",         no_argument,       NULL, 'V'},
		{ "size-limit",      required_argument, NULL, 'l'},
		{ "enforce-version", required_argument, NULL, 'x'},
		{ "output",          required_argument, NULL, 'o'},
		{ "force",           no_argument,       NULL, 'f'},
                { 0,                 0,                 0,     0 }
	};

	if (argc <= 1) {
		print_help();
		return 1;
	}

	while ((c = getopt_long(argc, argv, "r:Q:q:u:b:z:i:l:o:x:Vhfev",
				long_options, &index)) != EOF) {
		switch (c) {
		case 'V':
			verbose++;
			break;
		case 'Q':
			if (!optarg) {
				fprintf(stderr, "%s: Error:"
					" Argument missing to option '-Q'\n",
					toolname);
				return -1;
			}
			opts->msg_q_path = optarg;
			break;
		case 'q':
			if (!optarg) {
				fprintf(stderr, "%s: Error:"
					" Argument missing to option '-q'\n",
					toolname);
				return -1;
			}
			opts->msg_q_id = atoi(optarg);
			if (opts->msg_q_id < 0) {
				fprintf(stderr, "%s: Error:"
					" Parameter to option '-q' must be"
					" greater than 0\n", toolname);
				return -1;
			}
			break;
		case 'u':
			if (convert_long_optarg(&opts->msg_id_utilization,
						"'-u'"))
				return -1;
			break;
		case 'r':
			if (convert_long_optarg(&opts->msg_id_ioerr,
						"'-r"))
				return -1;
			break;
		case 'b':
			if (convert_long_optarg(&opts->msg_id_blkiomon,
						"'-b'"))
				return -1;
			break;
		case 'z':
			if (convert_long_optarg(&opts->msg_id_zfcpdd,
						"'-z'"))
				return -1;
			break;
		case 'h':
			print_help();
			return 1;
		case 'e':
			print_bin_struct_sizes();
			return 1;
		case 'f':
			opts->force = 1;
			break;
		case 'i':
			if (!optarg) {
				fprintf(stderr, "%s: Argument missing to"
					" option '-i'\n", toolname);
				return -1;
			}
			opts->interval_length = atoi(optarg);
			if (opts->interval_length <= 0) {
				fprintf(stderr, "%s: Interval"
					" length must be >0\n", toolname);
				return -1;
			}
			break;
		case 'o':
			if (!optarg) {
				fprintf(stderr, "%s: Argument missing to"
					" option '-o'\n", toolname);
				return -1;
			}
			if (opts->outfile_name) {
				fprintf(stderr, "%s: Multiple instance of "
					" option '-o'\n", toolname);
				return -2;
			}
			opts->outfile_name = malloc(strlen(optarg)
					+ strlen(DACC_FILE_EXT_LOG) + 1);
			if (!opts->outfile_name) {
				fprintf(stderr, "%s: Memory allocation "
					"error\n", toolname);
				return -3;
			}
			opts->outfile_name_agg = malloc(strlen(optarg)
					+ strlen(DACC_FILE_EXT_AGG) + 1);
			sprintf(opts->outfile_name, "%s" DACC_FILE_EXT_LOG,
				optarg);
			sprintf(opts->outfile_name_agg, "%s" DACC_FILE_EXT_AGG,
				optarg);
			break;
		case 'l':
			if (!optarg) {
				fprintf(stderr, "%s: Argument missing to"
					" option '-o'\n", toolname);
				return -1;
			}
			opts->size_limit = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "%s: Error during conversion:"
					" %s\n", toolname, strerror(errno));
				return -1;
			}
			if (opts->size_limit < 1) {
				fprintf(stderr, "%s: Size limit must be >=1.\n",
					toolname);
				return -1;
			}
			opts->size_limit *= 1024*1024;
			break;
		case 'x':
			if (!optarg) {
				fprintf(stderr, "%s: Argument missing to"
					" option '-x'\n", toolname);
				return -1;
			}
			opts->version = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "%s: Error during conversion:"
					" %s\n", toolname, strerror(errno));
				return -1;
			}
			if (opts->version < 2 || opts->version > 3) {
				fprintf(stderr, "%s: Enforced version can only be"
					"2 or 3.\n", toolname);
				return -1;
			}
			break;
		case 'v':
			print_version();
			return 1;
		default:
			fprintf(stderr, "Try '%s --help' for"
				" more information.\n", toolname);
			return -1;
		}
	}

	if (!opts->msg_q_path) {
		fprintf(stderr, "%s: No message queue path specified\n",
				toolname);
		error++;
	}
	if (opts->msg_q_id < 0) {
		fprintf(stderr, "%s: No message queue"
			" id specified\n", toolname);
		error++;
	}
	if (opts->msg_id_blkiomon == LONG_MIN) {
		fprintf(stderr, "%s: No id for blkiomon"
			" messages specified\n", toolname);
		error++;
	}
	if (opts->msg_id_utilization == LONG_MIN) {
		fprintf(stderr, "%s: No id for"
			" utilizaton messages specified\n", toolname);
		error++;
	}
	if (opts->msg_id_ioerr == LONG_MIN) {
		fprintf(stderr, "%s: No id for"
			" ioerr messages specified\n", toolname);
		error++;
	}
	if (opts->msg_id_zfcpdd == LONG_MIN) {
		fprintf(stderr, "%s: No id for"
			" ziomon_zfcpdd messages specified\n", toolname);
		error++;
	}
	if (opts->interval_length < 0) {
		fprintf(stderr, "%s: No interval length"
			" specified\n", toolname);
		error++;
	}
	if (!opts->outfile_name) {
		fprintf(stderr, "%s: No filename for"
			" output specified\n", toolname);
		error++;
	}
	if (error)
		return -1;

	if (check_msg_ids(opts))
		return -1;

	opts->outfile = fopen(opts->outfile_name, "w+");
	if (!opts->outfile) {
		fprintf(stderr, "%s: Could not open output"
			" file: %s\n", toolname, strerror(errno));
		return -1;
	}

	if (setup_msg_q(opts))
		return -1;

	verbose_msg("interval length      : %d\n", opts->interval_length);
	verbose_msg("force                : %d\n", opts->force);
	verbose_msg("message queue path   : %s\n", opts->msg_q_path);
	verbose_msg("message queue id     : %d\n", opts->msg_q_id);
	verbose_msg("message queue        : %d\n", opts->msg_q);
	verbose_msg("msg id utilization   : %ld\n", opts->msg_id_utilization);
	verbose_msg("msg id ioerr         : %ld\n", opts->msg_id_ioerr);
	verbose_msg("msg id blkiomon      : %ld\n", opts->msg_id_blkiomon);
	verbose_msg("msg id ziomon_zfcpdd : %ld\n", opts->msg_id_zfcpdd);
	verbose_msg("outfile name         : %s\n", opts->outfile_name);
	if (opts->size_limit == LONG_MAX)
		verbose_msg("size limit           : no limit\n");
	else
		verbose_msg("size limit           : %ld Bytes\n", opts->size_limit);

	return 0;
}


static void void_handler(int sig)
{
	verbose_msg("interrupted by signal %u\n", sig);
	keep_running = 0;
}


static void print_timestamp(struct tm *my_tm, const char *type, __u32 length,
			    struct timeval *t)
{
	verbose_msg("%02d:%02d:%02d.%06ld: received %s"
		    " message of %u bytes\n", my_tm->tm_hour,
		    my_tm->tm_min, my_tm->tm_sec, t->tv_usec, type, length);
}


static int handle_msg(struct message *msg, struct options *opts)
{
	struct message **msgs;
	int count;
	int rc = 0;
	struct timeval t;
	struct tm *my_tm = NULL;

	if (verbose) {
		gettimeofday(&t, NULL);
		my_tm = localtime(&t.tv_sec);
	}

	if ((long)msg->type == opts->msg_id_utilization)
		print_timestamp(my_tm, "utilization", msg->length, &t);
	else if ((long)msg->type == opts->msg_id_ioerr)
		print_timestamp(my_tm, "ioerr", msg->length, &t);
	else if ((long)msg->type == opts->msg_id_blkiomon)
		print_timestamp(my_tm, "blkiomon", msg->length, &t);
	else if ((long)msg->type == opts->msg_id_zfcpdd)
		print_timestamp(my_tm, "zfcpdd", msg->length, &t);
	else {
		fprintf(stderr, "%s: Received message of "
				"unrecognized type %d, length %d bytes, "
				"discarding\n", toolname, msg->type, msg->length);
		return 1;
	}

	if (add_msg(opts->outfile, msg, &opts->f_hdr, &msgs, &count)) {
		fprintf(stderr, "%s: Error while writing"
			" message\n", toolname);
		rc = -1;
	} else
		verbose_msg("message written\n");
	if (count) {
		if (add_to_aggregated(msgs, count, opts)) {
			fprintf(stderr, "%s: Failed to aggregate"
				" %d messages\n", toolname, count);
			rc = -1;
		}
	}

	return rc;
}


int main(int argc, char **argv)
{
	int rc = 0;
	struct options opts;
	int len;
	int data_sz = 1024;
	long *data = malloc(data_sz + sizeof(long));
	int tmperr;
	struct message msg;

	verbose = 0;

	signal(SIGALRM, void_handler);
	signal(SIGINT,  void_handler);
	signal(SIGTERM, void_handler);
	signal(SIGQUIT, void_handler);

	init_opts(&opts);

	if (parse_params(argc, argv, &opts))
		goto out;

	/* first write to file, init section for cumulatives */
	verbose_msg("init file...\n");
	opts.f_hdr.msgid_utilization = opts.msg_id_utilization;
	opts.f_hdr.msgid_ioerr = opts.msg_id_ioerr;
	opts.f_hdr.msgid_blkiomon = opts.msg_id_blkiomon;
	opts.f_hdr.msgid_zfcpdd = opts.msg_id_zfcpdd;
	opts.f_hdr.size_limit = opts.size_limit;
	opts.f_hdr.interval_length = opts.interval_length;
	if (init_file(opts.outfile, &opts.f_hdr, opts.version))
		goto out;

	verbose_msg("wait for messages...\n");
	do {
		len = msgrcv(opts.msg_q, data, data_sz, 0, 0);
		if (!keep_running)
			break;
		if (len < 0) {
			tmperr = errno;
			if (tmperr == E2BIG) {
				data_sz *= 2;
				data = realloc(data, data_sz + sizeof(long));
				verbose_msg("message buffer too small,"
					    " increasing to %d\n", data_sz);
				continue;
			}
			fprintf(stderr, "%s: Error receiving"
				" message: %s\n", toolname, strerror(errno));
			verbose_msg("msgrcv() returned error %d\n", tmperr);
			break;
		}
		msg.length = len;
		msg.data = data + 1;
		msg.type = *data;
		handle_msg(&msg, &opts);

	} while (keep_running);

out:
	deinit_opts(&opts);
	free(data);

	return rc;
}



