/*
 * iucvtty / iucvconn - IUCV Terminal Applications
 *
 * Functions for session logging/auditing.
 * The session log and timing data files adhere to the format
 * described in script(1).
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "iucvterm/functions.h"

#define OPEN_FILEMODE		(O_WRONLY | O_CREAT | O_EXCL)
#define OPEN_FILEMASK		(S_IRUSR  | S_IWUSR | S_IRGRP)

static int script_fd   = -1;		/* fd of typescript file  */
static int timing_fd   = -1;		/* fd of timing data file */
static FILE *info_file = NULL;		/* FILE of info file      */
static struct timeval last_tv;		/* tv to calculate timing */


/**
 * print_on_time() - Append formatted time string to a message.
 * @prefix:	message
 *
 * Returns a new buffer starting with @prefix and appends
 * a formatted string representation of the current time.
 * Returns NULL if memory allocation has failed.
 *
 * The caller must free the returned buffer after use.
 */
static char *print_on_time(const char *prefix)
{
	char *buf = malloc(64 + strlen(prefix) + 1);
	time_t t  = time(NULL);

	if (buf != NULL) {
		if (t == (time_t) -1)
			sprintf(buf, "%s\n", prefix);
		else {
			sprintf(buf, "%s on ", prefix);
			ctime_r(&t, buf + strlen(prefix) + 4);
		}
	}
	return buf;
}

/**
 * write_session_info() - Write data to the session info file
 * @format:	Format string, shall not be NULL
 *
 * Writes informational messages to the session info file.
 * The info message is prefixed with a timestamp as returned by the
 * time(2) syscall.
 */
void write_session_info(const char *format, ...)
{
	va_list ap;

	if (info_file == NULL)
		return;

	fprintf(info_file, "%lu ", time(NULL));
	va_start(ap, format);
	vfprintf(info_file, format, ap);
	va_end(ap);
	if (strrchr(format, '\n') == NULL)
		fprintf(info_file, "\n");
}

/**
 * write_session_log() - Write session data to the session log file
 * @buf:	Pointer to a buffer with data to log
 * @len:	Copy up to @len bytes from @buf
 *
 * The routines writes up to @len bytes of data from buffer @buf to
 * the session transcript; write appropriate timing data to the timing
 * file.
 */
ssize_t write_session_log(const void* buf, size_t len)
{
	ssize_t rc;
	int count;
	char data[64] = "";
	struct timeval curr_tv;
	long time_diff;

	/* immediately return if there is no fd to write to */
	if (script_fd == -1)
		return -1;

	rc = __write(script_fd, buf, len);
	if (rc < 0)
		return rc;

	/* calculate delay and write timing info */
	if (gettimeofday(&curr_tv, NULL))
		time_diff = 1000000;	/* one second (in usecs) */
	else {
		time_diff = (curr_tv.tv_sec  - last_tv.tv_sec) * 1000000 +
			     curr_tv.tv_usec - last_tv.tv_usec;
		last_tv   = curr_tv;	/* reset last timeval */
	}

	count = sprintf(data, "%.6f %zu\n",
			(double) time_diff / (double) 1000000, len);
	rc = __write(timing_fd, data, (count < 0) ? 0 : count );
	if (rc < 0)
		return rc;

	return 0;
}

/**
 * close_session_log() - Close session logging
 *
 * The routine writes a trailer to the session log file and
 * closes the session log, timing and info file descriptor.
 */
void close_session_log(void)
{
	char *trailer;

	if (script_fd > 0) {
		trailer = print_on_time("Script done");
		if (trailer != NULL) {
			__write(script_fd, trailer, strlen(trailer));
			write_session_info(trailer);
			free(trailer);
		}
		close(script_fd);
	}
	if (timing_fd > 0)
		close(timing_fd);
	if (info_file != NULL)
		fclose(info_file);
}

/**
 * open_session_log() - Open session logging
 * @filepath:	File path to the session transcript
 *
 * Opens the session, timing and info log file.
 * If the session specified by @filepath already exists; or one of the
 * files cannot be opened successfully, return an error.
 */
int open_session_log(const char *filepath)
{
	char *buf;
	int   old_errno;
	int   info_fd;

	buf = calloc(11 + strlen(filepath), sizeof(char));
	if (buf == NULL)
		goto out_no_mem;

	script_fd = open(filepath, OPEN_FILEMODE, OPEN_FILEMASK);
	if (script_fd == -1)
		goto out_error_open;

	sprintf(buf, "%s.timing", filepath);
	timing_fd = open(buf, OPEN_FILEMODE, OPEN_FILEMASK);
	if (timing_fd == -1)
		goto out_error_open;

	sprintf(buf, "%s.info", filepath);
	info_fd = open(buf, OPEN_FILEMODE, OPEN_FILEMASK);
	if (info_fd == -1)
		goto out_error_open;
	info_file = fdopen(info_fd, "w");
	if (info_file == NULL)
		goto out_error_open;

	if(gettimeofday(&last_tv, NULL))
		goto out_error_open;

	free(buf);

	buf = print_on_time("Script started");
	if (buf != NULL) {
		__write(script_fd, buf, strlen(buf));
		write_session_info(buf);
		free(buf);
	}

	return 0;

out_error_open:
	old_errno = errno;	/* preserve errno */
	free(buf);
	close_session_log();
	errno = old_errno;	/* restore errno from failed open call */
out_no_mem:
	return -1;
}
