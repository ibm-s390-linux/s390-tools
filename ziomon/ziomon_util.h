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

#ifndef ZIOMON_UTIL_H
#define ZIOMON_UTIL_H

#include <endian.h>
#include <linux/types.h>

#include "ziomon_tools.h"


struct utilization_stats {
	__u64			count;
	struct abbrev_stat 	adapter; /* adapter utilization in percent */
	struct abbrev_stat 	bus;     /* bus utilization in percent */
	struct abbrev_stat 	cpu;     /* cpu utilization in percent */
	__u64			queue_util_integral; /* integral of the queue
					utilization over microseconds */
	__u64			queue_util_interval; /* interval length
							in microseconds */
	__u32			queue_full;	/* number of queue_full
				   instances within the given timeframe */
} __attribute__ ((packed));

struct adapter_utilization {
	struct utilization_stats	stats;
	__u32				adapter_no;	/* device identifier */
	__u16				valid;	/* ==0 in case the result is invalid */
} __attribute__ ((packed));

/** Note that this message will always be transmitted in first and final
 * interval. In-between, only messages with actual traffic will be transmitted.
 */
struct utilization_data {
	__u64				timestamp;
	__u16				num_adapters;
	struct adapter_utilization	adapt_utils[0];
} __attribute__ ((packed));

struct hctl_ident {
	__u32			host;	/* device identifier (1) */
	__u32			channel;/* device identifier (2) */
	__u32			target;	/* device identifier (3) */
	__u32			lun;	/* device identifier (4) */
} __attribute__ ((packed));

/**
 * Returns <0 if src is 'smaller' than tgt, >0 of 'larger' and 0 if identical.
 */
int compare_hctl_idents(const struct hctl_ident *src,
			const struct hctl_ident *tgt);

struct ioerr_cnt {
	struct hctl_ident	identifier;
	__u32			num_ioerr; /* number of io errors
						within timeframe */
} __attribute__ ((packed));

/* Note that this message will always be transmitted in first and final
 * interval. In-between, only messages with actual traffic will be transmitted.
 */
struct ioerr_data {
	__u64			timestamp;
	__u64			num_luns;
	struct ioerr_cnt 	ioerrors[0];	/* number of I/O errors
	                                     within the given timeframe */
} __attribute__ ((packed));


void print_utilization_result(struct utilization_data *res);

void conv_overall_result_to_BE(struct utilization_data *res);

void conv_overall_result_from_BE(struct utilization_data *res);

/**
 * Aggregate a complete utilization result with all included structures */
void aggregate_utilization_data(const struct utilization_data *src,
				struct utilization_data *tgt);

/**
 * Aggregate a result for a single adapter only */
void aggregate_adapter_result(const struct adapter_utilization *src,
			      struct adapter_utilization *tgt);

void print_ioerr_data(struct ioerr_data *data);

void conv_ioerr_data_to_BE(struct ioerr_data *data);

void conv_ioerr_data_from_BE(struct ioerr_data *data);

/**
 * src must be later data than target! We assume that both structs have
 * data for the same LUNs in the same sequence.
 */
void aggregate_ioerr_data(const struct ioerr_data *src, struct ioerr_data *tgt);

/**
 * Aggregate data for a single device only */
void aggregate_ioerr_cnt(const struct ioerr_cnt *src, struct ioerr_cnt *tgt);


#endif

