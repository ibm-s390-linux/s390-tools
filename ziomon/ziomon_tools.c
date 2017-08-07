/*
 * FCP adapter trace facility
 *
 * Various shared utility functions and structs
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>

#include "ziomon_tools.h"

extern int verbose;

void swap_abbrev_stat(struct abbrev_stat *var) {
	swap_64(var->min);
	swap_64(var->max);
	swap_64(var->sum);
	swap_64(var->sos);
}

double calc_avg(__u64 sum, __u64 count)
{
	assert(count > 0);
	return (sum / (double)count);
}

double calc_variance(__u64 sum, __u64 sos, __u64 count)
{
	assert(count > 0);
	return ((sos - ((sum * sum) / (double)count)) / (double)count);
}

double calc_std_dev(__u64 sum, __u64 sos, __u64 count)
{
	return sqrt(calc_variance(sum, sos, count));
}

void transform_abbrev_stat(struct abbrev_stat *stat,
				       __u64 old_count,
				       double new_count)
{
	stat->min = 0;
	stat->sum = (__u64)(calc_avg(stat->sum, old_count) * new_count);
	stat->sos = (__u64)(calc_avg(stat->sos, old_count) * new_count);
}

void print_abbrev_stat(struct abbrev_stat *stats, __u64 count)
{
	printf("\t\tmin      : %Lu\n", (long long)stats->min);
	printf("\t\tmax      : %Lu\n", (long long)stats->max);
	vverbose_msg("\t\tsum      : %Lu\n", (long long)stats->sum);
	vverbose_msg("\t\tsos      : %Lu\n", (long long)stats->sos);
	printf("\t\tavg      : %.1lf\n", calc_avg(stats->sum, count));
	printf("\t\tstd dev  : %.1lf\n", calc_std_dev(stats->sum, stats->sos,
						      count));
}

void aggregate_abbrev_stat(const struct abbrev_stat *src,
				    struct abbrev_stat *tgt)
{
	if (src->max > tgt->max)
		tgt->max = src->max;
	if (src->min < tgt->min)
		tgt->min = src->min;
	tgt->sum += src->sum;
	tgt->sos += src->sos;
}

void update_abbrev_stat(struct abbrev_stat *stat, __u64 val)
{
	if (val < stat->min)
		stat->min = val;
	if (val > stat->max)
		stat->max = val;
	stat->sum += val;
	stat->sos += (val * val);
}

void copy_abbrev_stat(struct abbrev_stat *tgt,
			const struct abbrev_stat *src)
{
	tgt->min = src->min;
	tgt->max = src->max;
	tgt->sum = src->sum;
	tgt->sos = src->sos;
}

void init_abbrev_stat(struct abbrev_stat *data)
{
	data->min = UINT64_MAX;
	data->max = 0;
	data->sum = 0;
	data->sos = 0;
}




