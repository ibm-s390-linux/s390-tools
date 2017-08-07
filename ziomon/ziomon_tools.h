/*
 * FCP adapter trace utility
 *
 * Various shared utility functions and structs
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZIOMON_TOOLS_H
#define ZIOMON_TOOLS_H

#include <byteswap.h>
#include <endian.h>
#include <linux/types.h>


#define swap_64(num)   (num = be64toh(num))
#define swap_32(num)   (num = be32toh(num))
#define swap_16(num)   (num = be16toh(num))

#define verbose_msg(x...)	do {\
					if (verbose)\
						printf("\t=== " x);\
				} while (0)

#ifdef NDEBUG
#define vverbose_msg(x...)
#else
#define vverbose_msg(x...)	do {\
					if (verbose >= 2)\
						printf("\t===     " x);\
				} while (0)
#endif

/**
 * abbreviated stat (without a count).
 * Used in various places where multiple instances of stats have
 * to be collected, sharing a single count variable to save some space */
struct abbrev_stat {
	__u64 min;
	__u64 max;
	__u64 sum;
	__u64 sos;	/* sum of squares */
} __attribute__ ((packed));

void swap_abbrev_stat(struct abbrev_stat *var);

void print_abbrev_stat(struct abbrev_stat *stats, __u64 count);

void aggregate_abbrev_stat(const struct abbrev_stat *src,
				    struct abbrev_stat *tgt);

void update_abbrev_stat(struct abbrev_stat *stat, __u64 val);

void copy_abbrev_stat(struct abbrev_stat *tgt,
		      const struct abbrev_stat *src);

/**
 * Rebase abbrev_stat structure from 'old_count' to 'new_count' number of
 * sample. Since we assume that the additional samples are all 0, we also
 * fix the respective 'min' value while at it. */
void transform_abbrev_stat(struct abbrev_stat *stat, __u64 old_count,
				 double new_count);

void init_abbrev_stat(struct abbrev_stat *data);

double calc_avg(__u64 sum, __u64 count);

double calc_variance(__u64 sum, __u64 sos, __u64 count);

double calc_std_dev(__u64 sum, __u64 sos, __u64 count);

#endif

