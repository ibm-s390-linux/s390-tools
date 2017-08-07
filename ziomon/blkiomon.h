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

#ifndef BLKIOMON_H
#define BLKIOMON_H

#include <string.h>
#include <time.h>

#include "stats.h"

#define BLKIOMON_SIZE_BUCKETS 16
#define BLKIOMON_D2C_BUCKETS 25
struct blkiomon_stat {
	__u64 time;
	/* Histogram of request sizes in Bytes.
	   Step-size is 1024, starting at 0. */
	__u32 size_hist[BLKIOMON_SIZE_BUCKETS];
	/* Histogram of dispatch to completion request times in u-secs.
	   Step-size is 8, starting at 0. */
	__u32 d2c_hist[BLKIOMON_D2C_BUCKETS];
	__u32 device;	/* device identifier */
	struct minmax size_r;	/* stats of read request sizes in Bytes */
	struct minmax size_w;	/* stats of write request sizes in Bytes */
	struct minmax d2c_r;	/* stats of read request durations in u-secs */
	struct minmax d2c_w;	/* stats of write request durations in u-secs */
	struct minmax thrput_r;	/* stats of read throughput in Kbytes per micro-sec */
	struct minmax thrput_w;	/* stats of write throughput in Kbytes per micro-sec */
	__u64 bidir;	/* number of bi-directional requests, is set exclusive
			(ie. not implicitly adding 1 to rd and wrt as well) */
} __attribute__ ((packed));

/* Previous version of blkiomon statistics, needed for backwards compatibility */
struct blkiomon_stat_v2 {
	__u64 time;
	/* Histogram of request sizes in Bytes.
	   Step-size is 1024, starting at 0. */
	__u32 size_hist[BLKIOMON_SIZE_BUCKETS];
	/* Histogram of dispatch to completion request times in u-secs.
	   Step-size is 8, starting at 0. */
	__u32 d2c_hist[BLKIOMON_D2C_BUCKETS];
	struct minmax size_r;	/* stats of read request sizes in Bytes */
	struct minmax size_w;	/* stats of write request sizes in Bytes */
	struct minmax d2c_r;	/* stats of read request durations in u-secs */
	struct minmax d2c_w;	/* stats of write request durations in u-secs */
	struct minmax thrput_r;	/* stats of read throughput in Kbytes per micro-sec */
	struct minmax thrput_w;	/* stats of write throughput in Kbytes per micro-sec */
	__u64 bidir;	/* number of bi-directional requests, is set exclusive
			(ie. not implicitly adding 1 to rd and wrt as well) */
	__u32 device;	/* device identifier */
} __attribute__ ((packed));



static struct histlog2 size_hist = {0, 1024, BLKIOMON_SIZE_BUCKETS};

static struct histlog2 d2c_hist = {0, 8, BLKIOMON_D2C_BUCKETS};

static inline void blkiomon_stat_init(struct blkiomon_stat *bstat)
{
	memset(bstat, 0, sizeof(*bstat));
	minmax_init(&bstat->size_r);
	minmax_init(&bstat->size_w);
	minmax_init(&bstat->d2c_r);
	minmax_init(&bstat->d2c_w);
	minmax_init(&bstat->thrput_r);
	minmax_init(&bstat->thrput_w);
}

static inline void blkiomon_stat_swap(struct blkiomon_stat *d)
{
	histlog2_swap(d->size_hist, &size_hist);
	histlog2_swap(d->d2c_hist, &d2c_hist);
	minmax_swap(&d->size_r);
	minmax_swap(&d->size_w);
	minmax_swap(&d->d2c_r);
	minmax_swap(&d->d2c_w);
	minmax_swap(&d->thrput_r);
	minmax_swap(&d->thrput_w);
	swap_64(d->bidir);
	swap_64(d->time);
	swap_32(d->device);
}

static inline void blkiomon_conv_to_BE(struct blkiomon_stat *d) {
	blkiomon_stat_swap(d);
}

static inline void blkiomon_conv_from_BE(struct blkiomon_stat *d) {
	blkiomon_stat_swap(d);
}

static inline void blkiomon_stat_merge(struct blkiomon_stat *dst,
				       const struct blkiomon_stat *src)
{
	if (src->device != dst->device)
		dst->device = 0xffffffff;
	if (src->time > dst->time)
		dst->time = src->time;
	histlog2_merge(&size_hist, dst->size_hist, src->size_hist);
	histlog2_merge(&d2c_hist, dst->d2c_hist, src->d2c_hist);
	minmax_merge(&dst->size_r, &src->size_r);
	minmax_merge(&dst->size_w, &src->size_w);
	minmax_merge(&dst->d2c_r, &src->d2c_r);
	minmax_merge(&dst->d2c_w, &src->d2c_w);
	minmax_merge(&dst->thrput_r, &src->thrput_r);
	minmax_merge(&dst->thrput_w, &src->thrput_w);
	dst->bidir += src->bidir;
}

#define MINORBITS	20
#define MINORMASK	((1U << MINORBITS) - 1)
#define MAJOR(dev)	((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)	((unsigned int) ((dev) & MINORMASK))

static inline void blkiomon_stat_print(const struct blkiomon_stat *p)
{
	time_t t = p->time;

	printf("time: %s", ctime(&t));
	printf("device: %d:%d\n", MAJOR(p->device), MINOR(p->device));
	minmax_print("sizes read (bytes)", &p->size_r);
	minmax_print("sizes write (bytes)", &p->size_w);
	minmax_print("d2c read (usec)", &p->d2c_r);
	minmax_print("d2c write (usec)", &p->d2c_w);
	minmax_print("throughput read (bytes/msec)", &p->thrput_r);
	minmax_print("throughput write (bytes/msec)", &p->thrput_w);
	histlog2_print("sizes histogram (bytes)", p->size_hist, &size_hist);
	histlog2_print("d2c histogram (usec)", p->d2c_hist, &d2c_hist);
	printf("bidirectional requests: %ld\n", (unsigned long)p->bidir);
}

#endif
