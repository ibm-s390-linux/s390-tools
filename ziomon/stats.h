/*
 * FCP adapter trace utility
 *
 * Statistic structs and utility functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef STATS_H
#define STATS_H

#include <endian.h>
#include <linux/types.h>
#include <math.h>
#include <stdio.h>

struct minmax {
	__u64 min;
	__u64 max;
	__u64 sum;
	__u64 sos;
	__u64 num;
};

static inline void minmax_init(struct minmax *mm)
{
	mm->min = -1ULL;
	mm->max = 0;
	mm->sum = 0;
	mm->sos = 0;
	mm->num = 0;
}

static inline void minmax_account(struct minmax *mm, __u64 value)
{
	mm->sum += value;
	mm->sos += value * value;
	if (value < mm->min)
		mm->min = value;
	if (value > mm->max)
		mm->max = value;
	mm->num++;
}

static inline void minmax_merge(struct minmax *dst, const struct minmax *src)
{
	dst->sum += src->sum;
	dst->sos += src->sos;
	if (src->min < dst->min)
		dst->min = src->min;
	if (src->max > dst->max)
		dst->max = src->max;
	dst->num += src->num;
}

static inline void minmax_swap(struct minmax *mm)
{
	swap_64(mm->sum);
	swap_64(mm->sos);
	swap_64(mm->min);
	swap_64(mm->max);
	swap_64(mm->num);
}

static inline double minmax_avg(const struct minmax *mm)
{
	return (mm->sum / (double)mm->num);
}

static inline double minmax_var(const struct minmax *mm)
{
	double num = (double)mm->num;

	return ((mm->sos - ((mm->sum * mm->sum) / num)) / num);
}

static inline double minmax_std_dev(const struct minmax *mm)
{
	return sqrt(minmax_var(mm));
}

static inline int minmax_print(const char *s, const struct minmax *mm)
{
	if (mm->num)
		return printf("%s: num %Lu, min %Lu, max %Lu, sum %Lu, squ %Lu, "
		       "avg %.1lf, std dev %.1lf\n", s, (unsigned long long)mm->num,
		       (unsigned long long)mm->min, (unsigned long long)mm->max,
		       (unsigned long long)mm->sum, (unsigned long long)mm->sos,
		       minmax_avg(mm), minmax_std_dev(mm));
	else
		return printf("%s: (none)\n", s);
}

struct histlog2 {
	int first;
	int delta;
	int num;
};

static inline __u64 histlog2_upper_limit(int index, const struct histlog2 *h)
{
	return h->first + (index ? h->delta << (index - 1) : 0);
}

static inline int histlog2_index(__u64 val, struct histlog2 *h)
{
	int i;

	for (i = 0; i < h->num && val > histlog2_upper_limit(i, h); i++) ;

	return i;
}

static inline void histlog2_account(__u32 *bucket, __u32 val,
				    struct histlog2 *h)
{
	int index = histlog2_index(val, h);
	bucket[index]++;
}

static inline void histlog2_merge(struct histlog2 *h, __u32 *dst, const __u32 *src)
{
	int i;

	for (i = 0; i < h->num; i++) {
		dst[i] += src[i];
	}
}

static inline void histlog2_swap(__u32 a[], struct histlog2 *h)
{
	int i;

	for (i = 0; i < h->num; i++)
		swap_32(a[i]);
}

static inline void histlog2_print(const char *s, const __u32 a[],
				  const struct histlog2 *h)
{
	int i;

	printf("%s:\n", s);
	for (i = 0; i < h->num - 1; i++) {
		printf("   %10ld:%6d",
			(unsigned long)(histlog2_upper_limit(i, h)), a[i]);
		if (!((i + 1) % 4))
			printf("\n");
	}
	printf("    >%8ld:%6d\n",
		(unsigned long)(histlog2_upper_limit(i - 1, h)), a[i]);
}

#endif
