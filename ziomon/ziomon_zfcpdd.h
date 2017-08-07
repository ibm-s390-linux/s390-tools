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

#ifndef ZFCPIOMON_H_
#define ZFCPIOMON_H_

#include "ziomon_tools.h"

#define BLKIOMON_CHAN_LAT_BUCKETS 20
#define BLKIOMON_FABR_LAT_BUCKETS 25

struct zfcpdd_dstat {
	__u64 time;
	/* Channel latency histogram in n-secs.
	   Step-size is 1000, starting at 0. */
	__u32 chan_lat_hist[BLKIOMON_CHAN_LAT_BUCKETS];
	/* fabric latency histogram in u-secs.
	   Step-size is 8, starting at 0. */
	__u32 fabr_lat_hist[BLKIOMON_FABR_LAT_BUCKETS];
	struct abbrev_stat chan_lat;	/* channel latency in nano-seconds
					   NOTE: often rescaled to micro-seconds
						 later on! */
	struct abbrev_stat fabr_lat;	/* fabric latency in micro-seconds */
	struct abbrev_stat inb;	/* inbound fill size */
	__u64 count;	/* number of samples for abbrev_stats */
	__u32 device;	/* device identifier */
	__u16 outb_max;	/* max used slots in qdio outbound queue */
} __attribute__ ((packed));

void zfcpdd_print_stats(struct zfcpdd_dstat *stat);

void conv_dstat_to_BE(struct zfcpdd_dstat *stat);

void conv_dstat_from_BE(struct zfcpdd_dstat *stat);

void aggregate_dstat(struct zfcpdd_dstat *src,
		     struct zfcpdd_dstat *tgt);

#endif /*ZFCPIOMON_H_*/
