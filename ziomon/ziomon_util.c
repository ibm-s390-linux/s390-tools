/*
 * FCP adapter trace utility
 *
 * Utilization data collector for zfcp adapters
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <time.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "ziomon_util.h"


#ifdef WITH_MAIN
const char *toolname = "ziomon_util";
#else
extern const char *toolname;
#endif


struct overall_result_wrp {
	long			mtype;	/* must be long due to msg-passing
					   interface */
	struct utilization_data   o_res;
};

struct ioerr_wrp {
	long			mtype;
	struct ioerr_data	data;
};

__u32 get_result_sz(struct utilization_data *res)
{
	return (sizeof(struct utilization_data)
		+ res->num_adapters * sizeof(struct adapter_utilization));
}


__u32 get_ioerr_data_sz(struct ioerr_data *wrp)
{
	return (sizeof(struct ioerr_data)
		+ wrp->num_luns * sizeof(struct ioerr_cnt));
}


void print_utilization_result(struct utilization_data *res)
{
	int i;
	struct adapter_utilization	*a_res;
	struct utilization_stats	*u_res;
	time_t			 t;

	t = res->timestamp;
	printf("timestamp     : %s", ctime(&t));
	printf("num adapters  : %d\n", res->num_adapters);
	for (i = 0; i < res->num_adapters; ++i) {
		a_res = &res->adapt_utils[i];
		u_res = &a_res->stats;
		if (i != 0)
			printf("\n");
		printf("utilization of host adapter %d\n", a_res->adapter_no);
		printf("\tnum samples: %llu\n", (unsigned long long)u_res->count);
		if (u_res->count > 0) {
			printf("\tqueue full incidents: %d\n", u_res->queue_full);
			printf("\taverage queue utilization: %.1lf slots\n",
				u_res->queue_util_integral / (double)u_res->queue_util_interval);
			printf("\tadapter:\n");
			print_abbrev_stat(&u_res->adapter, u_res->count);
			printf("\tbus:\n");
			print_abbrev_stat(&u_res->bus, u_res->count);
			printf("\tprocessor:\n");
			print_abbrev_stat(&u_res->cpu, u_res->count);
		}
	}
}


static void swap_overall_result(struct utilization_data *res)
{
	int i;
	struct adapter_utilization *a_res;
	struct utilization_stats *u_res;

	swap_64(res->timestamp);

	for (i = 0; i < res->num_adapters; ++i) {
		a_res = &res->adapt_utils[i];
		swap_32(a_res->adapter_no);
		swap_16(a_res->valid);
		u_res = &a_res->stats;
		swap_64(u_res->count);
		swap_32(u_res->queue_full);
		swap_64(u_res->queue_util_integral);
		swap_64(u_res->queue_util_interval);
		swap_abbrev_stat(&u_res->adapter);
		swap_abbrev_stat(&u_res->bus);
		swap_abbrev_stat(&u_res->cpu);
	}
}


void conv_overall_result_to_BE(struct utilization_data *res)
{
	swap_overall_result(res);
	swap_16(res->num_adapters);
}


void conv_overall_result_from_BE(struct utilization_data *res)
{
	swap_16(res->num_adapters);
	swap_overall_result(res);
}


int compare_hctl_idents(const struct hctl_ident *src,
			const struct hctl_ident *tgt)
{
	if (src->host == tgt->host) {
		if (src->channel == tgt->channel) {
			if (src->target == tgt->target)
				return (src->lun - tgt->lun);
			else
				return (src->target - tgt->target);
		}
		else
			return (src->channel - tgt->channel);
	}
	else
		return (src->host - tgt->host);
}

void aggregate_utilization_data(const struct utilization_data *src,
				struct utilization_data *tgt)
{
	int i;

	assert(tgt->timestamp = src->timestamp);
	tgt->timestamp = src->timestamp;

	if (src->num_adapters != tgt->num_adapters)
		fprintf(stderr, "%s: Warning: inconsistent"
			" number of adapters: %d %d\n", toolname,
			src->num_adapters, tgt->num_adapters);

	for (i = 0; i < src->num_adapters; ++i)
		aggregate_adapter_result(&src->adapt_utils[i], &tgt->adapt_utils[i]);

	return;
}


void aggregate_adapter_result(const struct adapter_utilization *src,
			      struct adapter_utilization *tgt)
{
	if (src->valid) {
		/* in case we aggregate over different adapters,
		   we clearly indicate that this is not valid anymore */
		if (src->adapter_no != tgt->adapter_no)
			tgt->adapter_no = -1;

		tgt->stats.queue_full += src->stats.queue_full;
		tgt->stats.queue_util_integral +=
					src->stats.queue_util_integral;
		tgt->stats.queue_util_interval +=
					src->stats.queue_util_interval;
		tgt->stats.count += src->stats.count;
		aggregate_abbrev_stat(&src->stats.adapter,
				&tgt->stats.adapter);
		aggregate_abbrev_stat(&src->stats.bus,
				&tgt->stats.bus);
		aggregate_abbrev_stat(&src->stats.cpu,
				&tgt->stats.cpu);
	}
}


void print_ioerr_data(struct ioerr_data *data)
{
	__u64 i;
	struct ioerr_cnt *cnt;
	time_t		  t;

	t = data->timestamp;
	fprintf(stdout, "timestamp : %s", ctime(&t));
	fprintf(stdout, "num luns  : %lld\n", (long long)data->num_luns);
	for (i = 0; i < data->num_luns; ++i) {
		cnt = &data->ioerrors[i];
		fprintf(stdout, "\t%d:%d:%d:%d: %lld I/O errors\n",
			cnt->identifier.host, cnt->identifier.channel,
			cnt->identifier.target, cnt->identifier.lun,
			(long long)cnt->num_ioerr);
	}
}

static void swap_ioerr_data(struct ioerr_data *data)
{
	__u64 i;
	struct ioerr_cnt *cnt;

	swap_64(data->timestamp);
	for (i = 0; i < data->num_luns; ++i) {
		cnt = &data->ioerrors[i];
		swap_32(cnt->identifier.host);
		swap_32(cnt->identifier.channel);
		swap_32(cnt->identifier.target);
		swap_32(cnt->identifier.lun);
		swap_64(cnt->num_ioerr);
	}
}

void conv_ioerr_data_to_BE(struct ioerr_data *data)
{
	swap_ioerr_data(data);
	swap_64(data->num_luns);
}


void conv_ioerr_data_from_BE(struct ioerr_data *data)
{
	swap_64(data->num_luns);
	swap_ioerr_data(data);
}


void aggregate_ioerr_cnt(const struct ioerr_cnt *src, struct ioerr_cnt *tgt)
{
	/* in case we aggregate over different devices,
	   we clearly indicate that this is not valid anymore */
	if (compare_hctl_idents(&src->identifier, &tgt->identifier) != 0)
		memset(&tgt->identifier, 0xff, sizeof(struct hctl_ident));

	tgt->num_ioerr += src->num_ioerr;
}


void aggregate_ioerr_data(const struct ioerr_data *src, struct ioerr_data *tgt)
{
	__u64 i;

	assert(tgt->timestamp <= src->timestamp);
	tgt->timestamp = src->timestamp;
	for (i=0; i<src->num_luns; ++i)
		aggregate_ioerr_cnt(&src->ioerrors[i], &tgt->ioerrors[i]);
}


#ifdef WITH_MAIN

#define	SAMPLE_INTERVAL_DFT	2
#define	SAMPLE_INTERVAL_DFT_STR	"2"


static int keep_running;
int verbose=0;


struct util_data {
	int 			queue_full; /* # queue full instances in frame */
	int			queue_full_prev; /* previous absolut value
						    of queue_full */
	__u64			queue_util_integral;
	__u64			queue_util_interval;
	__u64			queue_util_prev; /* previous absolut value
						    of queue_util_integral */
	struct timeval		queue_util_timestamp;
	struct abbrev_stat 	adapter;
	struct abbrev_stat 	bus;
	struct abbrev_stat 	cpu;
	long count;
};

struct adapter_data {
	int			host_nr;
	char		       *path;
	char		       *q_full_path;
	int			status;	/* 0 if good != 0 in case of failure */
	struct util_data	data;
};

struct adapters {
	int			num_adapters;
	struct adapter_data	adapters[0];
};

#define MAX_HOST_PATH_LEN	42
#define MAX_LUN_PATH_LEN	strlen("/sys/bus/scsi/devices/4000000000:4000000000:4000000000:4000000000/ioerr_cnt")

struct options {
	int   	num_hosts;	/* total number of hosts */
	int   	num_hosts_a;	/* number of allocated host & lun structures */
	long   *host_nr;	/* array if host numbers. to trace */
	char  **host_path;	/* array of paths to utilization files */
	int     num_luns;	/* number of luns */
	char  **luns;		/* array of luns to monitor */
	__u32  *luns_prev;	/* array of previous values of luns */
	long  	duration;	/* overall duration in seconds */
	long  	s_duration;	/* ssample duration in seconds */
	long  	i_duration;	/* interval duration in seconds */
	char   *msg_q_path;
	int	msg_q_id;
	int	msg_q;		/* msg q handle */
	long	msg_id;		/* msg id to use in msg q */
	long	msg_id_ioerr;	/* msg id to use in msg q for ioerr messages*/
};


static void init_opts(struct options *opts)
{
	opts->i_duration   = -1;
	opts->duration     = -1;
	opts->s_duration   = SAMPLE_INTERVAL_DFT;
	opts->num_hosts	   = 0;
	opts->num_hosts_a  = 0;
	opts->host_nr	   = NULL;
	opts->host_path    = NULL;
	opts->num_luns	   = 0;
	opts->luns	   = NULL;
	opts->luns_prev	   = NULL;
	opts->msg_q_path   = NULL;
	opts->msg_q_id	   = -1;
	opts->msg_q	   = -1;
	opts->msg_id	   = LONG_MIN;
	opts->msg_id_ioerr = LONG_MIN;
}


static void deinit_opts(struct options *opts)
{
	int i;

	free(opts->host_nr);
	opts->host_nr = NULL;
	if (opts->host_path) {
		for (i = 0; i < opts->num_hosts_a; ++i)
			free(opts->host_path[i]);
		free(opts->host_path);
		opts->host_path = NULL;
	}
	for (i=0; i<opts->num_hosts_a; ++i)
		free(opts->luns[i]);
	opts->num_hosts_a = 0;
	opts->msg_q = -1;
	free(opts->luns);
	free(opts->luns_prev);
}


static void init_util_data(struct util_data *data)
{
	init_abbrev_stat(&data->adapter);
	init_abbrev_stat(&data->bus);
	init_abbrev_stat(&data->cpu);
	data->count = 0;
}


static int init_ioerr_cnt(struct ioerr_cnt *cnt, char *str)
{
	cnt->num_ioerr = 0;
	return (sscanf(str, "%d:%d:%d:%d", &cnt->identifier.host,
		       &cnt->identifier.channel, &cnt->identifier.target,
		       &cnt->identifier.lun) == 5);
}


static int init_host_opts(struct options *opts, int num_hosts)
{
	int i;

	free(opts->host_nr);
	if (opts->host_path) {
		for (i = 0; i < opts->num_hosts_a; ++i)
			free(opts->host_path[i]);
		free(opts->host_path);
	}

	opts->host_nr = calloc(num_hosts, sizeof(long));
	if (!opts->host_nr) {
	     fprintf(stderr, "%s: calloc opts->host_nr: %s\n",
			toolname, strerror(errno));
	     return -1;
	}
	opts->host_path = malloc(num_hosts * sizeof(char *));
	if (!opts->host_path) {
	     fprintf(stderr, "%s: malloc opts->host_path: %s\n",
			toolname, strerror(errno));
	     return -1;
	}
	for (i = 0; i < num_hosts; ++i) {
		opts->host_path[i] = malloc(sizeof(char) * MAX_HOST_PATH_LEN + 1);
		if (!opts->host_path[i]) {
			fprintf(stderr, "%s: malloc opts->host_path[]: %s\n",
				toolname, strerror(errno));
			return -1;
		}
	}

	free(opts->luns);
	opts->luns = calloc(num_hosts, sizeof(char *));
	free(opts->luns_prev);
	opts->luns_prev = calloc(num_hosts, sizeof(__u32));
	if (!opts->luns || !opts->luns_prev) {
	     fprintf(stderr, "%s: malloc opts->luns: %s\n",
			toolname, strerror(errno));
	     return -1;
	}
	for (i = 0; i < num_hosts; ++i) {
		opts->luns[i] = malloc(sizeof(char) * MAX_LUN_PATH_LEN + 1);
		if (!opts->host_path[i]) {
			fprintf(stderr, "%s: malloc opts->luns[]: %s\n",
				toolname, strerror(errno));
			return -1;
		}
	}
	opts->num_hosts_a = num_hosts;

	return 0;
}


#define LINE_LEN	255

static int read_attribute(char *path, char *line, int *status)
{
	int fd;
	int rc = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		rc = -1;		/* adapter gone */
		goto out;
	}
	rc = read(fd, line, LINE_LEN);
	if (rc < 0) {
		rc = -2;		/* I/O error */
		goto out;
	}
	rc = 0;
	close(fd);
out:
	if (status)
		*status = rc;

	return rc;
}


static int poll_utilization(struct adapters *all_adapters)
{
	char line[LINE_LEN];
	int cpu, bus, adapter;
	int rc = 0, grc = 0;
	struct adapter_data *adpt;
	struct util_data    *u_data;
	int i;

	for (i = 0; i < all_adapters->num_adapters; ++i) {
		adpt = &all_adapters->adapters[i];
		u_data = &adpt->data;
		/* read utilization attribute */
		if (read_attribute(adpt->path, line, &adpt->status)) {
			grc++;
			continue;
		}
		rc = sscanf(line, "%d %d %d", &cpu, &bus, &adapter);
		if (rc != 3) {
			fprintf(stderr, "%s: Warning:"
				" Could not parse %s: %s\n", toolname,
				line, strerror(errno));
			adpt->status = 3;
			continue;
		}
		update_abbrev_stat(&u_data->adapter, adapter);
		update_abbrev_stat(&u_data->bus, bus);
		update_abbrev_stat(&u_data->cpu, cpu);

		verbose_msg("data read for adapter %d: adapter=%d, bus=%d,"
			    " cpu=%d\n",
			    adpt->host_nr, adapter, bus, cpu);

		u_data->count++;
	}

	return grc;
}


static int calc_overflow(__u64 old_val, __u64 new_val)
{
	double ofl_val = 0;
	int i = 0;

	assert(old_val > new_val);

	while (ofl_val < old_val) {
		ofl_val = pow(2, i);
		++i;
	}

	return (new_val + (int)(ofl_val - old_val));
}


static int poll_queue_full(int init, struct adapters *all_adapters)
{
	char line[LINE_LEN];
	int rc = 0;
	struct adapter_data *adpt;
	struct util_data    *u_data;
	int queue_full_tmp;
	long long unsigned int queue_util_tmp;
	int i;
	struct timeval tmp, cur_time;

	for (i = 0; i < all_adapters->num_adapters; ++i) {
		adpt = &all_adapters->adapters[i];
		u_data = &adpt->data;

		/* read queue_full attribute */
		if (read_attribute(adpt->q_full_path, line, &adpt->status))
			continue;
		rc = sscanf(line, "%d %Lu", &queue_full_tmp, &queue_util_tmp);
		if (rc == 1) {
			fprintf(stderr, "%s: Only one value in"
				" %s, your kernel level is probably too old.\n",
				toolname, adpt->q_full_path);
			return -1;
		}
		if (rc != 2) {
			fprintf(stderr, "%s: Warning:"
				" Could not parse %s: %s\n",
				toolname, line,	strerror(errno));
			adpt->status = 6;
			continue;
		}
		gettimeofday(&cur_time, NULL);
		if (!init) {
			if (queue_full_tmp < u_data->queue_full_prev)
				u_data->queue_full =
					calc_overflow(u_data->queue_full_prev,
						      queue_full_tmp);
			else
				u_data->queue_full = queue_full_tmp
						- u_data->queue_full_prev;
			if (queue_util_tmp < u_data->queue_util_prev)
				u_data->queue_util_integral =
					calc_overflow(u_data->queue_util_prev,
							queue_util_tmp);
			else
				u_data->queue_util_integral = queue_util_tmp
						- u_data->queue_util_prev;
			timersub(&cur_time, &u_data->queue_util_timestamp, &tmp);
			u_data->queue_util_interval = tmp.tv_sec * 1000000
							+ tmp.tv_usec;
		}
		u_data->queue_full_prev = queue_full_tmp;
		u_data->queue_util_prev = queue_util_tmp;
		u_data->queue_util_timestamp = cur_time;
	}

	return 0;
}


static int poll_ioerr_cnt(int init, struct ioerr_data *data,
			  struct options *opts)
{
	char line[LINE_LEN];
	int rc = 0, grc = 0;
	int i;
	__u32 tmp;

	if (!init)
		data->timestamp = time(NULL);
	for (i=0; i<opts->num_luns; ++i) {
		/* read ioerr_cnt attribute */
		if (read_attribute(opts->luns[i], line, NULL)) {
			fprintf(stderr, "%s: Warning: Could not read %s\n",
				toolname, opts->luns[i]);
			grc++;
			continue;
		}
		rc = sscanf(line, "%i", &tmp);
		if (rc != 1) {
			fprintf(stderr, "%s: Warning:"
				" Could not parse ioerr line %s: %s\n",
				toolname, line,	strerror(errno));
			grc++;
			continue;
		}
		if (!init) {
			if (tmp < opts->luns_prev[i])
				data->ioerrors[i].num_ioerr = calc_overflow(
						opts->luns_prev[i], tmp);
			else
				data->ioerrors[i].num_ioerr = tmp
							- opts->luns_prev[i];
			verbose_msg("data read for i/o err %s: ioerr_cnt=%d\n",
			    opts->luns[i], data->ioerrors[i].num_ioerr);
		}
		opts->luns_prev[i] = tmp;
	}

	return grc;
}


static void reinit_adapters(struct adapters *adptrs)
{
	int i;

	for (i = 0; i < adptrs->num_adapters; ++i)
		init_util_data(&adptrs->adapters[i].data);
}


static int init_adapters(struct adapters *all_adapters, struct options *opts)
{
	struct adapter_data *adapter;
	struct stat buf;
	int i, rc = 0;

	if (opts)
		all_adapters->num_adapters = opts->num_hosts;

	for (i = 0; i < all_adapters->num_adapters; ++i) {
		adapter = &all_adapters->adapters[i];
		if (opts) {
			adapter->host_nr = opts->host_nr[i];
			adapter->path = malloc(sizeof(char)*MAX_HOST_PATH_LEN);
			sprintf(adapter->path, "%s/utilization",
				opts->host_path[i]);
			if (stat(adapter->path, &buf)) {
				fprintf(stderr, "%s: Path does not exist: %s - correct kernel version?\n",
					toolname, adapter->path);
				rc++;
			}
			adapter->q_full_path =
				malloc(sizeof(char)*MAX_HOST_PATH_LEN);
			sprintf(adapter->q_full_path, "%s/queue_full",
				opts->host_path[i]);
			if (stat(adapter->path, &buf)) {
				fprintf(stderr, "%s: Path does not exist: %s - correct kernel version?\n",
					toolname, adapter->q_full_path);
				rc++;
			}
			adapter->status = 0;
		}
		init_util_data(&all_adapters->adapters[i].data);
	}
	if (poll_queue_full(1, all_adapters))
		return -1;

	return rc;
}


static void deinit_adapters(struct adapters *all_adapters)
{
	int i;

	for (i = 0; i < all_adapters->num_adapters; ++i) {
		free(all_adapters->adapters[i].path);
		free(all_adapters->adapters[i].q_full_path);
	}
}


/**
 * set up structures for the lun result message and replace lun identifiers
 * with complete path to respective ioerr_cnts.
 */
static int init_ioerr_wrp(struct ioerr_wrp **wrp, struct options *opts)
{
	int i;
	struct stat buf;
	char tmp[255];

	*wrp = malloc(sizeof(struct ioerr_wrp)
		     + opts->num_luns*sizeof(struct ioerr_cnt));
	if (!*wrp) {
		fprintf(stderr, "%s: Memory allocation failed\n", toolname);
		return -1;
	}
	(*wrp)->mtype = opts->msg_id_ioerr;
	(*wrp)->data.num_luns = opts->num_luns;
	for (i=0; i<opts->num_luns; ++i) {
		if (init_ioerr_cnt(&(*wrp)->data.ioerrors[i], opts->luns[i])) {
			fprintf(stderr, "%s: Could not parse %s\n",
				toolname, opts->luns[i]);
			return -2;
		}
		strcpy(tmp, opts->luns[i]);
		sprintf(opts->luns[i], "/sys/bus/scsi/devices/%s/ioerr_cnt", tmp);
		if (stat(opts->luns[i], &buf)) {
			fprintf(stderr, "%s: Could not open %s: %s\n",
				toolname, opts->luns[i], strerror(errno));
			return -3;
		}
	}
	if (poll_ioerr_cnt(1, NULL, opts)) {
		fprintf(stderr, "%s: Could not read initial values of ioerr"
			" attributes.\n", toolname);
		return -1;
	}

	return 0;
}


static void init_result_wrp(struct overall_result_wrp **res, int num_adapters,
			    struct options *opts)
{
	*res = malloc(sizeof(struct overall_result_wrp) + (num_adapters * sizeof(struct adapter_utilization)));
	(*res)->o_res.num_adapters = num_adapters;
	(*res)->mtype = opts->msg_id;
}


static void deinit_result_wrp(struct overall_result_wrp **res)
{
	free(*res);
	res = NULL;
}


static void print_version(void)
{
        fprintf(stdout, "%s: ziomon utilization monitor, version %s\n"
               "Copyright IBM Corp. 2008, 2017\n",
               toolname, RELEASE_STRING);
}


static int get_argument_long(long *param, char opt)
{
	char *p;

	if (!optarg) {
		fprintf(stderr, "%s: Argument missing"
			" to option %c\n", toolname, opt);
		return -1;
	}
	*param = strtol(optarg, &p, 0);
	if (errno) {
		fprintf(stderr, "%s: Unrecognized"
			" parameter to option %c: %s\n", toolname, opt,
			strerror(errno));
		return -2;
	}
	if (*p != '\0') {
		fprintf(stderr, "%s: Unrecognized"
			" parameter to option %c\n", toolname, opt);
		return -3;
	}

	return 0;
}


static int hostdir_filter(const struct dirent *dir)
{
	return !strncmp(dir->d_name, "host", 4);
}


static int check_host_param(long *host_nr, char *host_path)
{
	struct stat 	buf;
	char *tmp;

	if (*host_nr > 9999) {
		fprintf(stderr, "%s: Host number out"
			" of range\n", toolname);
		return -1;
	}

	sprintf(host_path, "/sys/class/scsi_host/host%ld", *host_nr);
	if (stat(host_path, &buf)) {
		fprintf(stderr, "%s: Cannot access %s:"
			" %s\n", toolname, host_path, strerror(errno));
		return -1;
	}
	tmp = malloc(strlen(host_path) + strlen("/queue_full") + 1);
	sprintf(tmp, "%s/queue_full", host_path);
	if (stat(host_path, &buf)) {
		fprintf(stderr, "%s: Cannot access %s."
			" Your installed kernel is probably too old. Please"
			" check that your kernel matches the level in the"
			" documentation.\n", toolname, tmp);
		free(tmp);
		return -1;
	}
	free(tmp);
	verbose_msg("host path           : %s\n", host_path);

	return 0;
}


static int find_all_hosts(struct options *opts)
{
	char *h_path = "/sys/class/scsi_host";
	struct dirent **namelist;
	int num_dirents;
	int i, k;
	int rc = 0;

	verbose_msg("no host adapter(s) specified, scanning...\n");
	num_dirents = scandir(h_path, &namelist, hostdir_filter, alphasort);
	if (num_dirents <= 0) {
		fprintf(stderr, "%s: No host adapter(s) found\n", toolname);
		rc = -3;
		goto out;
	}

	if (init_host_opts(opts, num_dirents))
		return -1;
	opts->num_hosts = num_dirents;

	for (i = 0; i < num_dirents; ++i) {
		k = sscanf(namelist[i]->d_name, "host%ld", &opts->host_nr[i]);
		if (k != 1) {
			fprintf(stderr, "%s: Internal error while scanning"
				" host adapter no\n", toolname);
			rc = -4;
		} else
			check_host_param(&opts->host_nr[i],
					 opts->host_path[i]);
	}

out:
	for (i = 0; i < num_dirents; i++)
		free(namelist[i]);
	free(namelist);

	return rc;
}


static int host_adapter_compare(const void *a, const void *b)
{
	return (*(long *)a > *(long *)b);
}


static int setup_msg_q(struct options *opts)
{
	key_t util_q;
	int wait=0;

	if (opts->msg_id <= 0) {
		fprintf(stderr, "%s: Invalid or missing msg"
			" id for utilization messages\n", toolname);
		return -1;
	}
	if (opts->msg_id_ioerr <= 0) {
		fprintf(stderr, "%s: Invalid or missing msg"
			" id for I/O error messages\n", toolname);
		return -1;
	}
	if (opts->msg_id == opts->msg_id_ioerr) {
		fprintf(stderr, "%s: Message IDs for"
			" I/O error count and utilization messages must be"
			" different\n", toolname);
		return -1;
	}

	util_q = ftok(opts->msg_q_path, opts->msg_q_id);

	verbose_msg("message queue key is %d\n", util_q);

	while (keep_running) {
		opts->msg_q = msgget(util_q, S_IRWXU);
		if (opts->msg_q >= 0) {
			if (wait)
				fprintf(stderr, "%s: Message queue is up!\n",
					toolname);
			break;
		}
		if (!wait) {
			wait = 1;
			fprintf(stderr, "%s: Warning: Message queue not"
				" up yet, waiting...\n", toolname);
		}
		usleep(200000);
	}
	verbose_msg("message queue id is %d\n", opts->msg_q);

	if (opts->msg_q_path) {
		verbose_msg("message queue path	: %s\n", opts->msg_q_path);
		verbose_msg("message queue id	: %d\n", opts->msg_q_id);
		verbose_msg("message id		: %ld\n", opts->msg_id);
		verbose_msg("message id		: %ld\n", opts->msg_id);
	}

	return (opts->msg_q >= 0 ? 0 : -1);
}


static void generate_result(struct utilization_data *ures,
			    struct adapters *all_adapters)
{
	struct adapter_data	*a_data;
	struct util_data	*u_data;
	struct adapter_utilization	*a_res;
	struct utilization_stats	*u_res;
	int i;

	ures->num_adapters = all_adapters->num_adapters;
	ures->timestamp = time(NULL);

	for (i = 0; i < all_adapters->num_adapters; ++i) {
		a_data = &all_adapters->adapters[i];
		a_res = &ures->adapt_utils[i];
		a_res->adapter_no = a_data->host_nr;
		u_data = &a_data->data;
		a_res->valid = u_data->count;
		if (a_res->valid) {
			u_res = &a_res->stats;
			u_res->queue_full = u_data->queue_full;
			u_res->queue_util_integral = u_data->queue_util_integral;
			u_res->queue_util_interval = u_data->queue_util_interval;
			u_res->count = u_data->count;
			copy_abbrev_stat(&u_res->adapter, &u_data->adapter);
			copy_abbrev_stat(&u_res->bus, &u_data->bus);
			copy_abbrev_stat(&u_res->cpu, &u_data->cpu);
		}
	}
}



static const char help_text[] =
    "Usage: ziomon_util [-h] [-v] [-V] [-i n] [-s n] "
            "[-Q <msgq_path> -q <msgq_id>\n"
    "                   -m <msg_id>] -d n -a <n> -l <lun>\n"
    "\n"
    "Start the monitor for the host adapter utilization.\n"
    "Example: ziomon_util -d 60 -i 4 -a 0\n"
    "\n"
    "-h, --help            Print usage information and exit.\n"
    "-v, --version         Print version information and exit.\n"
    "-V, --verbose         Be verbose.\n"
    "-s, --sample-length   Duration between each sample in seconds.\n"
    "                      Defaults to "SAMPLE_INTERVAL_DFT_STR" seconds.\n"
    "-i, --interval-length Aggregate samples over this duration (in seconds).\n"
    "                      Defaults to 'duration'.\n"
    "-d, --duration        Overall duration in seconds.\n"
    "-a, --adapter         Host adapter no. to watch. Specify each host"
			   " adapter\n"
    "                      separately.\n"
    "-l, --lun             watch I/O error count of LUN. Specify each LUN\n"
    "                      separately in h:b:t:l format.\n"
    "-Q, --msg-queue-name  Specify the message queue path name.\n"
    "-q, --msg-queue-id    Specify the message queue id.\n"
    "-m, --msg-id          Specify the message id to use.\n"
    "-L, --msg-id-ioerr    Specify the message id for I/O error count"
			" messages.\n";

static void print_help(void)
{
        fprintf(stdout, "%s", help_text);
}


static int parse_params(int argc, char **argv, struct options *opts)
{
	int c;
	int index, i;
	static struct option long_options[] = {
		{ "version",        no_argument,       NULL, 'v'},
		{ "help",           no_argument,       NULL, 'h'},
		{ "verbose",        no_argument,       NULL, 'V'},
		{ "msg-queue-name", required_argument, NULL, 'Q'},
		{ "msg-queue-id",   required_argument, NULL, 'q'},
		{ "msg-id",         required_argument, NULL, 'm'},
		{ "msg-id-ioerr",   required_argument, NULL, 'L'},
		{ "sample-length",  required_argument, NULL, 's'},
		{ "interval-length",required_argument, NULL, 'i'},
		{ "duration",       required_argument, NULL, 'd'},
		{ "adapter",        required_argument, NULL, 'a'},
		{ "lun",            required_argument, NULL, 'l'},
		{ NULL,             0,                 NULL,  0 }
	};

	if (argc <= 1) {
		print_help();
		return 1;
	}

	/* this is too much, but argc/2 is a reliable upper boundary
	   and saves us the trouble of figuring out how many host
	   adapters were specified up front */
	init_host_opts(opts, argc/2);

	while ((c = getopt_long(argc, argv, "L:l:m:Q:q:a:s:d:i:vhV", long_options,
				&index)) != EOF) {
		switch (c) {
		case 'V':
			verbose = 1;
			break;
		case 'a':
			if (get_argument_long(&opts->host_nr[opts->num_hosts], c))
				return -1;
			(opts->num_hosts)++;
			break;
		case 'l':
			if (!optarg) {
				fprintf(stderr, "%s: Argument missing to"
					" option '-l'\n", toolname);
				return -1;
			}
			strcpy(opts->luns[opts->num_luns], optarg);
			(opts->num_luns)++;
			break;
		case 'L':
			if (get_argument_long(&opts->msg_id_ioerr, c))
				return -1;
			break;
		case 'i':
			if (get_argument_long(&opts->i_duration, c))
				return -1;
			break;
		case 's':
			if (get_argument_long(&opts->s_duration, c))
				return -1;
			break;
		case 'd':
			if (get_argument_long(&opts->duration, c))
				return -1;
			break;
		case 'm':
			if (get_argument_long(&opts->msg_id, c))
				return -1;
			break;
		case 'Q':
			if (!optarg) {
				fprintf(stderr, "%s: Argument missing to"
					" option '-Q'\n", toolname);
				return -1;
			}
			opts->msg_q_path = optarg;
			break;
		case 'q':
			if (!optarg) {
				fprintf(stderr, "%s: Argument missing to"
					" option '-Q'\n", toolname);
				return -1;
			}
			opts->msg_q_id = atoi(optarg);
			if (opts->msg_q_id < 0) {
				fprintf(stderr, "%s: Parameter to option '-q'"
					" must be greater than 0\n", toolname);
				return -1;
			}
			break;
		case 'v':
			print_version();
			return 1;
		case 'h':
			print_help();
			return 1;
		default:
			fprintf(stderr, "%s: Try '%s --help' for more"
				" information.\n", toolname, toolname);
			return -1;
		}
	}

	if (opts->duration < 0) {
		fprintf(stderr, "%s: No duration specified\n", toolname);
		return -1;
	}
	if (opts->i_duration < 0)
		opts->i_duration = opts->duration;
	if (opts->i_duration < opts->s_duration) {
		fprintf(stderr, "%s: Sample duration"
			" must be at least the interval duration\n", toolname);
		return -1;
	}
	if (opts->duration < opts->i_duration) {
		fprintf(stderr, "%s: Overall duration"
			" must be at least the interval duration\n", toolname);
		return -1;
	}
	if (opts->s_duration && opts->i_duration % opts->s_duration) {
		fprintf(stderr, "%s: Sample duration"
			" must be a multiple of sample duration\n", toolname);
		return -1;
	}
	if (opts->i_duration && opts->duration % opts->i_duration) {
		fprintf(stderr, "%s: overall duration"
			" must be a multiple of section duration\n", toolname);
		return -1;
	}
	if (opts->num_hosts > 0) {
		qsort(opts->host_nr, opts->num_hosts, sizeof(long),
		      host_adapter_compare);
		for (c = 0; c < opts->num_hosts; ++c) {
			if (check_host_param(&opts->host_nr[c],
					     opts->host_path[c]))
				return -1;
		}
	} else {
		if (find_all_hosts(opts))
			return -1;
	}
	if (opts->msg_q_path || opts->msg_q_id >= 0
		|| opts->msg_id != LONG_MIN) {
		if (!opts->msg_q_path || opts->msg_q_id < 0
			|| opts->msg_id == LONG_MIN) {
			fprintf(stderr, "%s: Make sure to"
				" specify all required arguments for message"
				" queue.\n", toolname);
			return -1;
		}
	}

	verbose_msg("num adapters        : %d\n", opts->num_hosts);
	verbose_msg("num luns            : %d\n", opts->num_luns);
	for (i=0; i<opts->num_luns; ++i)
		verbose_msg("lun                 : %s\n", opts->luns[i]);
	verbose_msg("overall duration	: %lds\n", opts->duration);
	verbose_msg("interval duration	: %lds\n", opts->i_duration);
	verbose_msg("sample duration	: %lds\n", opts->s_duration);

	return 0;
}


static void send_message(int msg_q, void *data, size_t data_sz)
{
	if (msgsnd(msg_q, data, data_sz, 0) < 0) {
		/* somehow we don't get this signal if queue is shut down
		   though we should... */
		if (errno == EIDRM) {
			keep_running = 0;
			verbose_msg("msgqueue removed, shutting down...\n");
		} else {
			fprintf(stderr, "%s: Failed to send"
				" message: %s\n", toolname, strerror(errno));
			verbose_msg("msgsnd() returned error code %d\n",
				    errno);
		}
	}
}


static int has_ioerrs(struct ioerr_data *ioerr)
{
	__u64 i;

	for (i = 0; i < ioerr->num_luns; ++i) {
		if (ioerr->ioerrors[i].num_ioerr != 0)
			return 1;
	}

	return 0;
}


static int has_non_null_stats(struct abbrev_stat *var)
{
	return !(var->max == 0 && var->min == 0);
}


static int has_adapter_traffic(struct utilization_data *res)
{
	int i;
	struct adapter_utilization *a_res;

	for (i=0; i<res->num_adapters; ++i) {
		a_res = &res->adapt_utils[i];
		if (!a_res->valid)
			return 1;
		if (a_res->stats.queue_full != 0)
			return 1;
		/* makes sure that we don't send messages when essentially no
		   data is processed. Reading the 'utilization' sysfs attribute
		   causes traffic, hence we would always send a message without
		   this threshold! */
		if (a_res->stats.queue_util_integral
			/ (double)a_res->stats.queue_util_interval >= 0.05)
			return 1;
		if (has_non_null_stats(&a_res->stats.adapter)
		    || has_non_null_stats(&a_res->stats.bus)
		    || has_non_null_stats(&a_res->stats.cpu))
			return 1;
	}

	return 0;
}


static void print_to_msg_q(struct overall_result_wrp *res_wrp,
			   struct ioerr_wrp *ioerr,
			   struct options *opts,
			   int force)
{
	size_t msg_size;

	if (has_adapter_traffic(&res_wrp->o_res) || force) {
		msg_size = get_result_sz(&res_wrp->o_res);
		if (verbose)
			print_utilization_result(&res_wrp->o_res);
		verbose_msg("write utilization result to msg q %d (msg-type: %ld, msg-size: %d)\n",
				opts->msg_q, res_wrp->mtype, (unsigned int)msg_size);

		conv_overall_result_to_BE(&res_wrp->o_res);

		send_message(opts->msg_q, res_wrp, msg_size);
	}

	if (has_ioerrs(&ioerr->data) || force) {
		msg_size = get_ioerr_data_sz(&ioerr->data);
		if (verbose)
			print_ioerr_data(&ioerr->data);
		verbose_msg("write ioerr result to msg q %d (msg-type: %ld, msg-size: %d)\n",
				opts->msg_q, ioerr->mtype, (unsigned int)msg_size);
		conv_ioerr_data_to_BE(&ioerr->data);
		send_message(opts->msg_q, ioerr, msg_size);
	}
}


static void void_handler(int sig)
{
	verbose_msg("interrupted by signal %u\n", sig);
	keep_running = 0;
}


static void setup_signals(void)
{
	signal(SIGALRM, void_handler);
	signal(SIGINT,  void_handler);
	signal(SIGTERM, void_handler);
	signal(SIGQUIT, void_handler);
}


static void sleep_until(struct timeval *end)
{
	struct timeval tmp;

	do {
		gettimeofday(&tmp, NULL);
		if (timercmp(&tmp, end, >=))
			break;
		timersub(end, &tmp, &tmp);
		verbose_msg("sleep for %ld msec\n", tmp.tv_sec * 1000000
			    + tmp.tv_usec);
		usleep(tmp.tv_sec * 1000000 + tmp.tv_usec);
	} while (keep_running);
}


/*
 * Params:
 * -h : host nr.
 * -t : duration
 */
int main(int argc, char **argv)
{
	struct options 			opts;
	struct adapters        	       *all_adapters = NULL;
	struct overall_result_wrp      *result_wrp = NULL;
	struct timeval			sample_end;
	struct timeval	       		interval_end;
	struct timeval	       		duration_end;
	struct timeval	       		first_interval;
	struct ioerr_wrp	       *ioerr = NULL;
	int				rc = 0;

	verbose = 0;
	keep_running = 1;

	setup_signals();

	init_opts(&opts);

	if (parse_params(argc, argv, &opts)) {
		rc = -1;
		goto out2;
	}

	if (opts.msg_q_path && setup_msg_q(&opts)) {
		rc = -2;
		goto out2;
	}

	all_adapters = malloc(sizeof(struct adapters)
			      + opts.num_hosts * sizeof(struct adapter_data));
	if (init_adapters(all_adapters, &opts)) {
		rc = -8;
		goto out2;
	}
	init_result_wrp(&result_wrp, all_adapters->num_adapters, &opts);
	if (init_ioerr_wrp(&ioerr, &opts)) {
		rc = -3;
		goto out;
	}

	gettimeofday(&sample_end, NULL);
	timerclear(&interval_end);
	timerclear(&duration_end);
	timerclear(&first_interval);
	timeradd(&interval_end, &sample_end, &interval_end);
	timeradd(&first_interval, &sample_end, &first_interval);
	first_interval.tv_sec += opts.i_duration;
	timeradd(&duration_end, &sample_end, &duration_end);

	duration_end.tv_sec += opts.duration;
	do {
		interval_end.tv_sec += opts.i_duration;
		reinit_adapters(all_adapters);
		do {
			sample_end.tv_sec += opts.s_duration;
			sleep_until(&sample_end);
			poll_utilization(all_adapters);
			if (timercmp(&sample_end, &interval_end, >=)) {
				/* final sample in interval */
				if (poll_queue_full(0, all_adapters)) {
					rc = -3;
					goto out;
				}
				if (poll_ioerr_cnt(0, &ioerr->data, &opts)) {
					rc = -7;
					goto out;
				}
			}
		} while (keep_running
			 && timercmp(&sample_end, &interval_end, <));

		if (!keep_running)
			break;	/* only publish results after a full cycle */

		generate_result(&result_wrp->o_res, all_adapters);

		if (opts.msg_q >= 0)
			/* Always print the first and the last message */
			print_to_msg_q(result_wrp, ioerr, &opts,
				       (timercmp(&interval_end, &first_interval, ==)
					|| timercmp(&interval_end, &duration_end, >=)));
		else {
			print_utilization_result(&result_wrp->o_res);
			print_ioerr_data(&ioerr->data);
		}
		/* we only have to sleep in case d_interval is not
		   a multiple of i_interval */
		sleep_until(&interval_end);
	} while (keep_running && timercmp(&interval_end, &duration_end, <));

	if (!keep_running)
		verbose_msg("signal received, ending...\n");

out:
	deinit_adapters(all_adapters);
	deinit_result_wrp(&result_wrp);
out2:
	deinit_opts(&opts);
	free(all_adapters);
	free(ioerr);

	return rc;
}

#endif

