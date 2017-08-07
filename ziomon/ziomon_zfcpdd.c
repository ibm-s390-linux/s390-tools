/*
 * FCP adapter trace utility
 *
 * I/O monitor based on block queue trace data
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/types.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "lib/zt_common.h"

#include "blktrace.h"
#include "ziomon_zfcpdd.h"
#include "blkiomon.h"


#ifdef WITH_MAIN
const char *toolname = "ziomon_zfcpdd";
int verbose=0;
#endif


static void swap_dstat(struct zfcpdd_dstat *stat)
{
	int i;

	swap_64(stat->time);
	swap_64(stat->count);
	swap_32(stat->device);
	swap_abbrev_stat(&stat->chan_lat);
	swap_abbrev_stat(&stat->fabr_lat);
	swap_abbrev_stat(&stat->inb);
	swap_16(stat->outb_max);
	for (i=0; i<BLKIOMON_CHAN_LAT_BUCKETS; ++i)
		swap_32(stat->chan_lat_hist[i]);
	for (i=0; i<BLKIOMON_FABR_LAT_BUCKETS; ++i)
		swap_32(stat->fabr_lat_hist[i]);
}

void conv_dstat_to_BE(struct zfcpdd_dstat *stat)
{
	swap_dstat(stat);
}

void conv_dstat_from_BE(struct zfcpdd_dstat *stat)
{
	swap_dstat(stat);
}

void aggregate_dstat(struct zfcpdd_dstat *src,
                     struct zfcpdd_dstat *tgt)
{
	int i;

	if (src->device != tgt->device)
		tgt->device = 0xffffffff;
	if (src->time > tgt->time)
		tgt->time = src->time;
	tgt->count += src->count;
	for (i=0; i<BLKIOMON_CHAN_LAT_BUCKETS; ++i)
		tgt->chan_lat_hist[i] += src->chan_lat_hist[i];
	for (i=0; i<BLKIOMON_FABR_LAT_BUCKETS; ++i)
		tgt->fabr_lat_hist[i] += src->fabr_lat_hist[i];
	aggregate_abbrev_stat(&src->chan_lat, &tgt->chan_lat);
	aggregate_abbrev_stat(&src->fabr_lat, &tgt->fabr_lat);
	aggregate_abbrev_stat(&src->inb, &tgt->inb);
	if (src->outb_max > tgt->outb_max)
		tgt->outb_max = src->outb_max;
}

void zfcpdd_print_stats(struct zfcpdd_dstat *stat)
{
	int i;
	time_t t = stat->time;

	printf("timestamp     : %s", ctime(&t));
	printf("device        : %d:%d\n", MAJOR(stat->device),
					MINOR(stat->device));
	printf("count         : %lu\n", (long unsigned int)stat->count);
	printf("\tchannel latency (in nsecs):\n");
	print_abbrev_stat(&stat->chan_lat, stat->count);
	printf("\t\tbuckets:");
	for (i=0; i<BLKIOMON_CHAN_LAT_BUCKETS; ++i)
		printf(" %u", stat->chan_lat_hist[i]);
	printf("\n\tfabric latency (in usecs):\n");
	print_abbrev_stat(&stat->fabr_lat, stat->count);
	printf("\t\tbuckets:");
	for (i=0; i<BLKIOMON_FABR_LAT_BUCKETS; ++i)
		printf(" %u", stat->fabr_lat_hist[i]);
	printf("\n\tinbound queue fill size:\n");
	print_abbrev_stat(&stat->inb, stat->count);
        printf("\toutbound q max   : %hu\n", stat->outb_max);
}


#ifdef WITH_MAIN
struct output {
	char *fn;
	FILE *fp;
	char *buf;
	int pipe;
};

struct hist_log2 {
	int first;
	int delta;
	int num;
};

static struct hist_log2 clat = {
	.first = 0,
	.delta = 1000,
	.num = BLKIOMON_CHAN_LAT_BUCKETS
};

static struct hist_log2 flat = {
	.first = 0,
	.delta = 8,
	.num = BLKIOMON_FABR_LAT_BUCKETS
};

/* struct as in zfcp kernel module */
struct zfcp_blk_drv_data {
#define ZFCP_BLK_DRV_DATA_MAGIC			0x1
       __u32 magic;
#define ZFCP_BLK_LAT_VALID			0x1
#define ZFCP_BLK_REQ_ERROR			0x2
       __u16 flags;
       __u8 inb_usage;
       __u8 outb_usage;
       __u64 chan_lat;
       __u64 fabr_lat;
} __attribute__ ((packed));

struct dstat_msg {
	long mtype;
	struct zfcpdd_dstat stat;
};

struct dstat {
	struct dstat_msg msg;
	struct dstat *next;
};

#define DSTAT_HASH_SIZE 128
struct dhash {
	struct dstat *head[DSTAT_HASH_SIZE];
};

static struct dstat *vacant_dstats_list = NULL;
static struct dhash dstat_hash[2] = {};
static int dstat_curr = 0;

static struct output binary, ascii;
static FILE *ifp;
static int interval;

static pthread_mutex_t dstat_mutex = PTHREAD_MUTEX_INITIALIZER;
static int run = 1;
static int main_run = 1;

static char *msg_q_name = NULL;
static int msg_q_id = -1, msg_q = -1;
static long msg_id = LONG_MIN;

static struct dstat *zfcpdd_dstat_alloc(void)
{
	struct dstat *dstat = vacant_dstats_list;

	if (dstat)
		vacant_dstats_list = dstat->next;
	else
		dstat = malloc(sizeof(*dstat));
	memset(dstat, 0, sizeof(*dstat));
	init_abbrev_stat(&dstat->msg.stat.chan_lat);
	init_abbrev_stat(&dstat->msg.stat.fabr_lat);
	init_abbrev_stat(&dstat->msg.stat.inb);

	return dstat;
}

static struct dstat *zfcpdd_dstat_find(struct dhash *hash,
					  struct blk_io_trace *bit)
{
	int i = bit->device % DSTAT_HASH_SIZE;
	struct dstat *dstat;

	for (dstat = hash->head[i]; dstat; dstat = dstat->next)
		if (dstat->msg.stat.device == bit->device)
			return dstat;
	return NULL;
}

static void zfcpdd_dstat_insert(struct dhash *hash, struct dstat *dstat)
{
	int i = dstat->msg.stat.device % DSTAT_HASH_SIZE;

	dstat->next = hash->head[i];
	hash->head[i] = dstat;
	verbose_msg("insert: device=%d curr=%d hash=%p head=%p dstat=%p\n",
		dstat->msg.stat.device, dstat_curr, hash, hash->head[i], dstat);
}

static __u64 hist_upper_limit(int index, struct hist_log2 *h)
{
	return h->first + (index ? h->delta << (index - 1) : 0);
}

static int hist_index(__u64 val, struct hist_log2 *h)
{
	int i;

	for (i = 0; i < (h->num - 1) && val > hist_upper_limit(i, h); i++);
	return i;
}

static void zfcpdd_account_hist_log2(__u32 *bucket, __u64 val,
					struct hist_log2 *h)
{
	int index = hist_index(val, h);
	bucket[index]++;
}

static void zfcpdd_account_outb(struct zfcpdd_dstat *stat,
					struct zfcp_blk_drv_data *dd)
{
	/* incoming data reports number of _free_ slots! */
	dd->outb_usage = 128 - dd->outb_usage;
	if (dd->outb_usage > stat->outb_max)
		stat->outb_max = dd->outb_usage;
}

static int zfcpdd_account(struct blk_io_trace *bit,
			     struct zfcp_blk_drv_data *dd)
{
	struct dstat *dstat;
	struct zfcpdd_dstat *stat;

	pthread_mutex_lock(&dstat_mutex);

	dstat = zfcpdd_dstat_find(&dstat_hash[dstat_curr], bit);
	if (!dstat) {
		dstat = zfcpdd_dstat_alloc();
		if (!dstat) {
			fprintf(stderr, "%s: could not alloc statistic: %s\n", toolname, strerror(errno));
			pthread_mutex_unlock(&dstat_mutex);
			return 1;
		}
		dstat->msg.stat.device = bit->device;
		zfcpdd_dstat_insert(&dstat_hash[dstat_curr], dstat);
	}

	verbose_msg("account: device=%d curr=%d hash=%p dstat=%p\n",
		dstat->msg.stat.device, dstat_curr, &dstat_hash[dstat_curr], dstat);

	stat = &dstat->msg.stat;
	update_abbrev_stat(&stat->chan_lat, dd->chan_lat);
	update_abbrev_stat(&stat->fabr_lat, dd->fabr_lat / 1000);
	update_abbrev_stat(&stat->inb, dd->inb_usage);
	zfcpdd_account_outb(stat, dd);
	zfcpdd_account_hist_log2(stat->chan_lat_hist, dd->chan_lat,
				    &clat);
	zfcpdd_account_hist_log2(stat->fabr_lat_hist, dd->fabr_lat / 1000,
				    &flat);
	stat->count++;

	pthread_mutex_unlock(&dstat_mutex);
	return 0;
}

static void dump_bit(struct blk_io_trace *bit, const char *descr)
{
	fprintf(stderr, "--- %s: %s ---\n", toolname, descr);
	fprintf(stderr, "magic    %16d\n", bit->magic);
	fprintf(stderr, "sequence %16d\n", bit->sequence);
	fprintf(stderr, "time     %16lu\n", (long unsigned int)bit->time);
	fprintf(stderr, "sector   %16lu\n", (long unsigned int)bit->sector);
	fprintf(stderr, "bytes    %16d\n", bit->bytes);
	fprintf(stderr, "action   %16x\n", bit->action);
	fprintf(stderr, "pid      %16d\n", bit->pid);
	fprintf(stderr, "device   %16d\n", bit->device);
	fprintf(stderr, "cpu      %16d\n", bit->cpu);
	fprintf(stderr, "error    %16d\n", bit->error);
	fprintf(stderr, "pdu_len  %16d\n", bit->pdu_len);
}

static int zfcpdd_output_binary(struct dstat *dstat)
{
	struct zfcpdd_dstat *p = &dstat->msg.stat;

	if (!binary.fn)
		return 0;

	if (fwrite(p, sizeof(*p), 1, binary.fp) != 1)
		goto failed;
	if (binary.pipe && fflush(binary.fp))
		goto failed;
	return 0;

failed:
	fprintf(stderr, "%s: could not write to %s\n", toolname, binary.fn);
	fclose(binary.fp);
	binary.fn = NULL;
	return 1;
}

static void print_hist(FILE *fp, const char *s, __u32 a[], struct hist_log2 *h)
{
	int i;

	fprintf(fp, "%s:\n", s);
	for (i = 0; i < h->num - 1; i++) {
		fprintf(fp, "   %10ld:%6d",
			(unsigned long)(hist_upper_limit(i, h)), a[i]);
		if (!((i + 1) % 4))
			fprintf(fp, "\n");
	}
	fprintf(fp, "    >%8ld:%6d\n",
		(unsigned long)(hist_upper_limit(i - 1, h)), a[i]);
}

static void print_var(FILE *fp, const char *s, struct abbrev_stat *v)
{
	fprintf(fp, "%s: min %ld, max %ld, sum %ld, squ %ld\n", s,
		(unsigned long)v->min, (unsigned long)v->max,
		(unsigned long)v->sum, (unsigned long)v->sos);
}

static void zfcpdd_output_ascii(struct dstat *dstat)
{
	struct zfcpdd_dstat *p = &dstat->msg.stat;
	FILE *fp = ascii.fp;

	if (!ascii.fn)
		return;

	fprintf(fp, "device: %d\t", p->device);
	fprintf(fp, "interval end: %ld\n", (unsigned long)p->time);

	fprintf(fp, "outbound q max: %hu", p->outb_max);
	print_var(fp, "inbound", &p->inb);
	print_var(fp, "channel latency", &p->chan_lat);
	print_var(fp, "fabric latency", &p->fabr_lat);
	print_hist(fp, "channel latency histogram (in usec)",
		   p->chan_lat_hist, &clat);
	print_hist(fp, "fabric latency histogram (in usec)",
		   p->fabr_lat_hist, &flat);
	return;
}

static int zfcpdd_output_msg_q(struct dstat *dstat)
{
	int rc;

	if (!msg_q_name)
		return 0;

	dstat->msg.mtype = msg_id;
	conv_dstat_to_BE(&dstat->msg.stat);
	rc = msgsnd(msg_q, &dstat->msg, sizeof(dstat->msg.stat), 0);
	conv_dstat_from_BE(&dstat->msg.stat);

	return rc;
}

static int zfcpdd_output(struct dstat *dstat)
{
	verbose_msg("consume: device=%d dstat=%p\n",
		dstat->msg.stat.device, dstat);

	dstat->msg.stat.time = time(NULL);
	zfcpdd_output_ascii(dstat);
	if (zfcpdd_output_binary(dstat))
		return 1;
	if (zfcpdd_output_msg_q(dstat))
		return 1;
	return 0;
}

static void zfcpdd_consume(struct dhash *hash)
{
	int i;
	struct dstat *dstat, *head, *tail;

	for (i = 0; i < DSTAT_HASH_SIZE; i++) {
		head = hash->head[i];
		if (!head)
			continue;
		hash->head[i] = NULL;

		verbose_msg("consume: hash=%p head=%p\n", hash, head);

		for (dstat = head; dstat; dstat = dstat->next) {
			zfcpdd_output(dstat);
			tail = dstat;
		}
		pthread_mutex_lock(&dstat_mutex);
		tail->next = vacant_dstats_list;
		vacant_dstats_list = head;
		pthread_mutex_unlock(&dstat_mutex);
	}
}

static pthread_t interval_thread;



static void void_handler(int sig)
{
	verbose_msg("interrupted by signal %u\n", sig);
	main_run = 0;
}

static void register_signals(void)
{
	signal(SIGALRM, void_handler);
	signal(SIGINT,  void_handler);
	signal(SIGTERM, void_handler);
	signal(SIGQUIT, void_handler);
}

static int zfcpdd_open_output(struct output *out)
{
	int mode, vbuf_size;

	if (!out->fn)
		return 0;

	if (!strcmp(out->fn, "-")) {
		out->fp = fdopen(STDOUT_FILENO, "w");
		mode = _IOLBF;
		vbuf_size = 4096;
		out->pipe = 1;
	} else {
		out->fp = fopen(out->fn, "w");
		mode = _IOFBF;
		vbuf_size = 128 * 1024;
		out->pipe = 0;
	}
	if (!out->fp)
		goto failed;
	out->buf = malloc(128 * 1024);
	if (setvbuf(out->fp, out->buf, mode, vbuf_size))
		goto failed;
	return 0;

failed:
	fprintf(stderr, "%s: could not open %s\n", toolname, out->fn);
	out->fn = NULL;
	free(out->buf);
	return 1;
}

static int zfcpdd_open_msg_q(void)
{
	key_t key;

	if (!msg_q_name)
		return 0;
	if (!msg_q_id || msg_id <= 0)
		return 1;
	key = ftok(msg_q_name, msg_q_id);
	if (key == -1)
		return 1;
	while (main_run) {
		msg_q = msgget(key, S_IRWXU);
		if (msg_q >= 0)
			break;
	}

	return (msg_q >= 0 ? 0 : -1);
}

static void zfcpdd_close_output(struct output *out)
{
	if (out->fp)
		fclose(out->fp);
	free(out->buf);
}

static int zfcpdd_do_fifo(void)
{
	struct blk_io_trace bit;
	struct zfcp_blk_drv_data dd;

	while (fread(&bit, sizeof(bit), 1, ifp) == 1 && main_run) {
		if (ferror(ifp)) {
			clearerr(ifp);
			fprintf(stderr, "%s: could not read trace: %s\n", toolname, strerror(errno));
			break;
		}
		if (fread(&dd, bit.pdu_len, 1, ifp) != 1) {
			clearerr(ifp);
			fprintf(stderr, "%s: could not read trace payload: %s\n", toolname, strerror(errno));
			break;
		}
		if (bit.action & 0x40000000) {
			if (bit.pdu_len != sizeof(dd)) {
				clearerr(ifp);
				dump_bit(&bit, "not a valid trace");
				break;
			}
			if (zfcpdd_account(&bit, &dd))
				break;
		}
	}
	if (main_run)
		verbose_msg("pipe ended, exiting\n");

	return 0;
}

static void *zfcpdd_interval(void *data)
{
	struct timespec t;
	int finished;

	clock_gettime(CLOCK_REALTIME, &t);

	while (run) {
		t.tv_sec += interval;
		if (clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &t, NULL)) {
			if (!run)
				break;
			fprintf(stderr, "%s: interrupted sleep:%s\n", toolname, strerror(errno));
			continue;
		}

		/* grab hash and make data gatherer build up another hash */
		pthread_mutex_lock(&dstat_mutex);
		finished = dstat_curr;
		dstat_curr = dstat_curr ? 0 : 1;
		pthread_mutex_unlock(&dstat_mutex);

		zfcpdd_consume(&dstat_hash[finished]);
	}
	return data;
}

#define S_OPTS "a:b:i:Q:q:m:Vvh"

static char usage_str[] = "[-v] [-V] [-h] [-b <file>] [-Q <msgq_path> -q <msgq_id>\n"
	" -m <msg_id>] -i <interval>\n"
	"\n"
	"Collect device statistics from blktrace stream.\n"
	"\n"
	"-h, --help            Print usage information and exit.\n"
	"-v, --version         Print version information and exit.\n"
	"-V, --verbose         Be verbose.\n"
	"-i, --interval-length Specify interval length in seconds.\n"
	"-Q, --msg-queue-name  Specify the message queue path name.\n"
	"-q, --msg-queue-id    Specify the message queue id.\n"
	"-a, --ascii           Specify the file name for ASCII output.\n"
	"-b, --binary          Specify the file name for binary output.\n"
	"-m, --msg-id          Specify the message id to use.\n";

static struct option l_opts[] = {
	{ "ascii",           required_argument, NULL, 'a' },
	{ "binary",          required_argument, NULL, 'b' },
	{ "interval-length", required_argument, NULL, 'i' },
	{ "msg-queue",       required_argument, NULL, 'Q' },
	{ "msg-queue-id",    required_argument, NULL, 'q' },
	{ "msg-id",          required_argument, NULL, 'm' },
	{ "version",         no_argument,       NULL, 'v' },
	{ "verbose",         no_argument,       NULL, 'V' },
	{ "help",            no_argument,       NULL, 'h' },
	{ NULL,              0,                 NULL,  0  }
};

static void zfcpdd_usage(void)
{
	fprintf(stdout, "Usage: %s %s", toolname, usage_str);
}

int main(int argc, char *argv[])
{
	int c;

	register_signals();

	if (argc <= 1) {
		zfcpdd_usage();
		return 1;
	}

	while ((c = getopt_long(argc, argv, S_OPTS, l_opts, NULL)) != -1) {
		switch (c) {
		case 'a':
			ascii.fn = optarg;
			break;
		case 'b':
			binary.fn = optarg;
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 'Q':
			msg_q_name = optarg;
			break;
		case 'q':
			msg_q_id = atoi(optarg);
			break;
		case 'm':
			msg_id = atoi(optarg);
			break;
		case 'V':
			verbose++;
			break;
		case 'h':
			zfcpdd_usage();
			return 0;
		case 'v':
			printf("%s: ziomon fcp monitor version %s\n"
				"Copyright IBM Corp. 2008, 2017\n", toolname,
				RELEASE_STRING);
			return 0;
		default:
			fprintf(stderr, "Try '%s --help' for more"
                                        " information.\n", toolname);
			return 1;
		}
	}

	ifp = fdopen(STDIN_FILENO, "r");
	if (!ifp) {
		fprintf(stderr, "%s: could not open stdin for reading: %s\n", toolname, strerror(errno));
		return 1;
	}

	if (msg_q_name || msg_q_id >= 0 || msg_id != LONG_MIN) {
		if (!msg_q_name || msg_q_id < 0 || msg_id == LONG_MIN) {
			fprintf(stderr, "%s: error: make sure to specify "
				"all required arguments for message queue.\n", toolname);
			return -1;
		}
	}

	if (!interval) {
		fprintf(stderr, "%s: error: interval required\n", toolname);
		zfcpdd_usage();
		return 1;
	}

	if (zfcpdd_open_output(&ascii))
		return 1;
	if (zfcpdd_open_output(&binary))
		return 1;
	if (zfcpdd_open_msg_q())
		return 1;

	/* setup thread which saves data to disk after the specified interval */
	if (pthread_create(&interval_thread, NULL, zfcpdd_interval, NULL)) {
		fprintf(stderr, "%s: could not create thread: %s\n", toolname, strerror(errno));
		return 1;
	}

	zfcpdd_do_fifo();

	/* start cleanup */
	fclose(ifp);
	run = 0; /* thread control variable */
	pthread_kill(interval_thread, SIGINT);
	pthread_join(interval_thread, NULL);

	/* acquire mutex before closing the file to avoid data corruption */
	pthread_mutex_lock(&dstat_mutex);
	zfcpdd_close_output(&binary);
	pthread_mutex_unlock(&dstat_mutex);

	return 0;
}
#endif

