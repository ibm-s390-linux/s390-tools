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

#ifndef DUMP_H
#define DUMP_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

extern int debug;

class DumpException
{
public:
	DumpException(void) {
		msg[0] = 0;
		errorCode = 0;
	}
	DumpException(const char *m) {
		sprintf(msg, "%s", m);
		errorCode = 0;
	}

	const char *what(void) const { return msg; }
	int code(void) const { return errorCode; }
protected:
	char msg[2048];
	int  errorCode;
};

class DumpErrnoException : public DumpException
{
public:
	DumpErrnoException(const char *m) {
		sprintf(msg, "%s (%s)", m, strerror(errno));
		errorCode = errno;
	}
};

class Dump
{
public:
	Dump(const char *filename, const char *mode);
	Dump(void) : fh(0) {}
	virtual ~Dump(void);
	typedef enum {DT_VM32, DT_VM64, DT_VM64_BIG, DT_LKCD32, DT_LKCD64,
			DT_UNKNOWN} DumpType;

	virtual void readMem(char *buf, int size) = 0;
	virtual int  seekMem(uint64_t offset) = 0;
	virtual uint64_t getMemSize(void) const = 0;
	virtual struct timeval getDumpTime(void) const = 0;
protected:
	FILE *fh;
};

class ProgressBar
{
public:
	ProgressBar(void) { progressPercentage = -1; }
	void initProgress(void);
	void displayProgress(uint64_t value, uint64_t maxValue);
private:
	int progressPercentage;
};

void s390TodToTimeval(uint64_t todval, struct timeval *xtime);
int vm_convert(const char *inputFileName, const char *outputFileName,
	       const char *progName);

static inline void dump_read(void *ptr, size_t size, size_t nmemb,
			     FILE *stream)
{
	if (fread(ptr, size, nmemb, stream) != nmemb)
		throw(DumpErrnoException("fread failed"));
}

static inline void dump_seek(FILE *stream, long offset, int whence)
{
	if (fseek(stream, offset, whence) == -1)
		throw(DumpErrnoException("fseek failed"));
}

#endif /* DUMP_H */
