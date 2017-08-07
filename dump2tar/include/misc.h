/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Helper functions
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MISC_H
#define MISC_H

#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

#include "lib/util_libc.h"
#include "global.h"


#define MSG_LEN	256

#define DBG(...) \
		do { \
			if (global_debug) \
				debug(__FILE__, __LINE__, ##__VA_ARGS__); \
		} while (0)

#define mwarn(fmt, ...)		_mwarn(true, (fmt), ##__VA_ARGS__)
#define mwarnx(fmt, ...)	_mwarn(false, (fmt), ##__VA_ARGS__)

/* Helper macro for constructing messages in variables */
#define HANDLE_RC(rc, max, off, label)  \
	do { \
		if ((rc) > 0) \
			(off) += (rc); \
		if ((off) > (max)) \
			goto label; \
	} while (0)

/* Program exit codes */
#define EXIT_OK				0
#define EXIT_RUNTIME			1
#define EXIT_USAGE			2

/* Number of nanoseconds in a second */
#define NSEC_PER_SEC	1000000000L
#define NSEC_PER_MSEC	1000000L
#define NSEC_PER_USEC	1000L

extern struct timespec main_start_ts;
struct dref;

int misc_write_data(int fd, char *addr, size_t len);
ssize_t misc_read_data(int fd, char *addr, size_t len);
void inc_timespec(struct timespec *ts, time_t sec, long nsec);
void set_timespec(struct timespec *ts, time_t sec, long nsec);
bool ts_before(struct timespec *a, struct timespec *b);
int snprintf_duration(char *buff, size_t len, struct timespec *start,
		      struct timespec *end);
char *get_threadname(void);
void debug(const char *file, unsigned long line, const char *format, ...);
void _mwarn(bool print_errno, const char *format, ...);
void verb(const char *format, ...);
void info(const char *format, ...);
#define mmalloc(len)		util_zalloc(len)
#define mcalloc(n, len)		util_zalloc((n) * (len))
#define mrealloc(ptr, len)	util_realloc((ptr), (len))
#define mstrdup(str)		util_strdup(str)
#define masprintf(fmt, ...)	__masprintf(__func__, __FILE__, __LINE__, \
					    (fmt), ##__VA_ARGS__)
char *__masprintf(const char *func, const char *file, int line,
		  const char *fmt, ...);
#define set_threadname(fmt, ...) __set_threadname(__func__, __FILE__, \
						  __LINE__, (fmt), \
						  ##__VA_ARGS__)
void __set_threadname(const char *func, const char *file, int line,
                      const char *fmt, ...);

void clear_threadname(void);
void chomp(char *str, char *c);
void lchomp(char *str, char *c);
void remove_double_slashes(char *str);
int stat_file(bool dereference, const char *abs, const char *rel,
	      struct dref *dref, struct stat *st);
void set_dummy_stat(struct stat *st);
bool starts_with(const char *str, const char *prefix);
bool ends_with(const char *str, const char *suffix);

int cmd_child(int fd, char *cmd);
int cmd_open(char *cmd, pid_t *pid_ptr);
int cmd_close(int fd, pid_t pid, int *status_ptr);

void misc_init(void);
void misc_cleanup(void);
void set_stdout_data(void);

#endif /* MISC_H */
