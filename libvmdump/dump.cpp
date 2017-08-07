/*
 * vmdump - z/VM dump conversion library
 *
 * Dump base class
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "dump.h"

int debug   = 0;

void s390TodToTimeval(uint64_t todval, struct timeval *xtime)
{
	/* adjust todclock to 1970 */
	todval -= 0x8126d60e46000000LL - (0x3c26700LL * 1000000 * 4096);

	todval >>= 12;
	xtime->tv_sec  = todval / 1000000;
	xtime->tv_usec = todval % 1000000;
}

Dump::Dump(const char *filename, const char *mode)
{
	fh = fopen(filename, mode);
	if(!fh){
		throw(DumpErrnoException("Open dump file failed!"));
	}
}

Dump::~Dump(void)
{
	if(fh){
		fclose(fh);
	}
}

void ProgressBar::initProgress(void)
{
	progressPercentage = -1;
}

void ProgressBar::displayProgress(uint64_t value, uint64_t maxValue)
{
	char progress_bar[51];
	int j;

	if (progressPercentage == (int) (value * 100 / maxValue))
		fprintf(stderr, "%6lld of %6lld |\r",
			(long long) value, (long long) maxValue);
	else {  /* percent value has changed */
		progressPercentage = (value * 100 / maxValue);
		for (j = 0; j < progressPercentage / 2; j++)
			progress_bar[j] = '#';
		for (j = progressPercentage / 2; j < 50; j++)
			progress_bar[j] = '-';
		progress_bar[50] = 0;
		fprintf(stderr, "%6lld of %6lld |%s| %3d%%  \r",
			(long long) value, (long long) maxValue,
			progress_bar, progressPercentage);
	}
}
