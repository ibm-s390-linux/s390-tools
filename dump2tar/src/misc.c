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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dref.h"
#include "global.h"
#include "misc.h"

struct timespec main_start_ts;

static pthread_key_t thread_name_key;
static bool stdout_data;

/* Write @len bytes at @addr to @fd. Return %EXIT_OK on success, %EXIT_RUNTIME
 * otherwise. */
int misc_write_data(int fd, char *addr, size_t len)
{
	ssize_t w;

	while (len > 0) {
		w = write(fd, addr, len);
		if (w < 0)
			return EXIT_RUNTIME;
		len -= w;
		addr += w;
	}

	return EXIT_OK;
}

/* Read at most @len bytes from @fd to @addr. Return the number of bytes read
 * or %-1 on error. */
ssize_t misc_read_data(int fd, char *addr, size_t len)
{
	size_t done = 0;
	ssize_t r;

	while (len > 0) {
		r = read(fd, addr, len);
		if (r < 0)
			return -1;
		if (r == 0)
			break;
		len -= r;
		addr += r;
		done += r;
	}

	return done;
}

/* Advance timespec @ts by @sec seconds and @nsec nanoseconds */
void inc_timespec(struct timespec *ts, time_t sec, long nsec)
{
	ts->tv_nsec += nsec;
	ts->tv_sec += sec;
	if (ts->tv_nsec > NSEC_PER_SEC) {
		ts->tv_nsec -= NSEC_PER_SEC;
		ts->tv_sec++;
	}
}

/* Set timespec @ts to point to @sec seconds and @nsec nanoseconds in the
 * future */
void set_timespec(struct timespec *ts, time_t sec, long nsec)
{
	clock_gettime(CLOCK_MONOTONIC, ts);
	inc_timespec(ts, sec, nsec);
}

/* Return true if timespec @a refers to a point in time before @b */
bool ts_before(struct timespec *a, struct timespec *b)
{
	if (a->tv_sec < b->tv_sec ||
	    (a->tv_sec == b->tv_sec && a->tv_nsec < b->tv_nsec))
		return true;

	return false;
}

/* Store a string representing the time duration between @start and @end in
 * at most @len bytes of @buff. */
int snprintf_duration(char *buff, size_t len, struct timespec *start,
		      struct timespec *end)
{
	time_t sec;
	long nsec, msec, s, m, h;

	sec = end->tv_sec - start->tv_sec;
	nsec = end->tv_nsec - start->tv_nsec;

	if (nsec < 0) {
		nsec += NSEC_PER_SEC;
		sec--;
	}

	msec = nsec / NSEC_PER_MSEC;
	s = sec % 60;
	sec /= 60;
	m = sec % 60;
	sec /= 60;
	h = sec;

	if (h > 0)
		return snprintf(buff, len, "%luh%lum%lu.%03lus", h, m, s, msec);
	else if (m > 0)
		return snprintf(buff, len, "%lum%lu.%03lus", m, s, msec);
	else
		return snprintf(buff, len, "%lu.%03lus", s, msec);
}

/* Return the name of the current thread */
char *get_threadname(void)
{
	return pthread_getspecific(thread_name_key);
}

static int snprintf_timestamp(char *str, size_t size)
{
	struct timespec now_ts;

	set_timespec(&now_ts, 0, 0);
	now_ts.tv_sec -= main_start_ts.tv_sec;
	now_ts.tv_nsec -= main_start_ts.tv_nsec;
	if (now_ts.tv_nsec < 0) {
		now_ts.tv_nsec += NSEC_PER_SEC;
		now_ts.tv_sec--;
	}

	return snprintf(str, size, "[%3lu.%06lu] ", now_ts.tv_sec,
		        now_ts.tv_nsec / NSEC_PER_USEC);
}

/* When DUMP2TAR_DEBUG is set to non-zero, print debugging information */
void debug(const char *file, unsigned long line, const char *format, ...)
{
	char msg[MSG_LEN];
	size_t off = 0;
	int rc;
	va_list args;

	/* Debug marker */
	rc = snprintf(&msg[off], MSG_LEN - off, "DEBUG: ");
	HANDLE_RC(rc, MSG_LEN, off, out);

	/* Timestamp */
	rc = snprintf_timestamp(&msg[off], MSG_LEN - off);
	HANDLE_RC(rc, MSG_LEN, off, out);

	/* Thread name */
	rc = snprintf(&msg[off], MSG_LEN - off, "%s: ", get_threadname());
	HANDLE_RC(rc, MSG_LEN, off, out);

	/* Message */
	va_start(args, format);
	rc = vsnprintf(&msg[off], MSG_LEN - off, format, args);
	va_end(args);
	HANDLE_RC(rc, MSG_LEN, off, out);

	/* Call site */
	rc = snprintf(&msg[off], MSG_LEN - off, "  (%s:%lu)", file, line);

out:
	fprintf(stderr, "%s\n", msg);
}

/* Print a warning message consisting of @format and variable arguments.
 * If @print_errno is true, also print the text corresponding to errno.
 * We're not using err.h's warn since we want timestamps and synchronized
 * output. */
void _mwarn(bool print_errno, const char *format, ...)
{
	char msg[MSG_LEN];
	size_t off = 0;
	int rc;
	va_list args;

	if (global_timestamps) {
		rc = snprintf_timestamp(&msg[off], MSG_LEN - off);
		HANDLE_RC(rc, MSG_LEN, off, out);
	}

	rc = snprintf(&msg[off], MSG_LEN - off, "%s: ",
		      program_invocation_short_name);
	HANDLE_RC(rc, MSG_LEN, off, out);

	va_start(args, format);
	rc = vsnprintf(&msg[off], MSG_LEN - off, format, args);
	va_end(args);
	HANDLE_RC(rc, MSG_LEN, off, out);

	if (print_errno)
		snprintf(&msg[off], MSG_LEN - off, ": %s", strerror(errno));

out:
	fprintf(stderr, "%s\n", msg);
}

/* Provide informational output if --verbose was specified */
void verb(const char *format, ...)
{
	char msg[MSG_LEN];
	size_t off = 0;
	int rc;
	va_list args;
	FILE *fd;

	if (!global_verbose)
		return;
	if (stdout_data)
		fd = stderr;
	else
		fd = stdout;
	if (global_timestamps) {
		rc = snprintf_timestamp(&msg[off], MSG_LEN - off);
		HANDLE_RC(rc, MSG_LEN, off, out);
	}

	va_start(args, format);
	rc = vsnprintf(&msg[off], MSG_LEN - off, format, args);
	va_end(args);

out:
	fprintf(fd, "%s", msg);
}

/* Provide informational output. */
void info(const char *format, ...)
{
	char msg[MSG_LEN];
	size_t off = 0;
	int rc;
	va_list args;
	FILE *fd;

	if (global_quiet)
		return;
	if (stdout_data)
		fd = stderr;
	else
		fd = stdout;

	if (global_timestamps) {
		rc = snprintf_timestamp(&msg[off], MSG_LEN - off);
		HANDLE_RC(rc, MSG_LEN, off, out);
	}

	va_start(args, format);
	rc = vsnprintf(&msg[off], MSG_LEN - off, format, args);
	va_end(args);

out:
	fprintf(fd, "%s", msg);
}

/* Return a newly allocated buffer containing the result of the specified
 * string format arguments */
char *__masprintf(const char *func, const char *file, int line, const char *fmt,
		  ...)
{
	char *str;
	va_list args;

	va_start(args, fmt);
	__util_vasprintf(func, file, line, &str, fmt, args);
	va_end(args);

	return str;
}

/* Set the internal name of the calling thread */
void __set_threadname(const char *func, const char *file, int line,
		      const char *fmt, ...)
{
	char *str;
	va_list args;

	va_start(args, fmt);
	__util_vasprintf(func, file, line, &str, fmt, args);
	va_end(args);

	pthread_setspecific(thread_name_key, str);
}

/* Clear any previously set thread name */
void clear_threadname(void)
{
	void *addr = pthread_getspecific(thread_name_key);

	if (addr) {
		pthread_setspecific(thread_name_key, NULL);
		free(addr);
	}
}

/* Remove any number of trailing characters @c in @str */
void chomp(char *str, char *c)
{
	ssize_t i;

	for (i = strlen(str) - 1; i >= 0 && strchr(c, str[i]); i--)
		str[i] = 0;
}

/* Remove any number of leading characters @c in @str */
void lchomp(char *str, char *c)
{
	char *from;

	for (from = str; *from && strchr(c, *from); from++)
		;
	if (str != from)
		memmove(str, from, strlen(from) + 1);
}

/* Perform a stat on file referenced by either @abs or @rel and @dref. Store
 * results in @stat and return stat()'s return code.  */
int stat_file(bool dereference, const char *abs, const char *rel,
	      struct dref *dref, struct stat *st)
{
	int rc;

	if (dref) {
		if (dereference)
			rc = fstatat(dref->dirfd, rel, st, 0);
		else
			rc = fstatat(dref->dirfd, rel, st, AT_SYMLINK_NOFOLLOW);
	} else {
		if (dereference)
			rc = stat(abs, st);
		else
			rc = lstat(abs, st);
	}

	return rc;
}

/* Fill stat buffer @st with dummy values. */
void set_dummy_stat(struct stat *st)
{
	/* Fake stat */
	memset(st, 0, sizeof(struct stat));
	st->st_mode = S_IRUSR | S_IWUSR | S_IFREG;
	st->st_uid = geteuid();
	st->st_gid = getegid();
	st->st_mtime = time(NULL);
}

/* Redirect all output streams to @fd and execute command @CMD */
int cmd_child(int fd, char *cmd)
{
	char *argv[] = { "/bin/sh", "-c", NULL, NULL };
	char *env[] = { NULL };

	argv[2] = cmd;
	if (dup2(fd, STDOUT_FILENO) == -1 || dup2(fd, STDERR_FILENO) == -1) {
		mwarn("Could not redirect command output");
		return EXIT_RUNTIME;
	}

	execve("/bin/sh", argv, env);

	return EXIT_RUNTIME;
}

#define PIPE_READ	0
#define PIPE_WRITE	1

/* Run command @cmd as a child process and store its PID in @pid_ptr. On
 * success, return a file descriptor that is an output pipe to the standard
 * output and standard error streams of the child process. Return %-1 on
 * error. */
int cmd_open(char *cmd, pid_t *pid_ptr)
{
	int pfd[2];
	pid_t pid;

	if (pipe(pfd) < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		/* Fork error */
		close(pfd[PIPE_READ]);
		close(pfd[PIPE_WRITE]);
		return -1;
	} else if (pid == 0) {
		/* Child process */
		close(pfd[PIPE_READ]);
		exit(cmd_child(pfd[PIPE_WRITE], cmd));
	}

	/* Parent process */
	close(pfd[PIPE_WRITE]);

	*pid_ptr = pid;

	return pfd[PIPE_READ];
}

/* Close the file descriptor @fd and end the process with PID @pid. When
 * not %NULL, use @status_ptr to store the resulting process status. */
int cmd_close(int fd, pid_t pid, int *status_ptr)
{
	int status, rc = EXIT_OK;

	close(fd);
	kill(pid, SIGQUIT);
	if (waitpid(pid, &status, 0) == -1) {
		status = -errno;
		rc = EXIT_RUNTIME;
	}
	if (status_ptr)
		*status_ptr = status;

	return rc;
}

void misc_init(void)
{
	set_timespec(&main_start_ts, 0, 0);
	pthread_key_create(&thread_name_key, free);
	set_threadname("main");
}

void misc_cleanup(void)
{
	clear_threadname();
	pthread_key_delete(thread_name_key);
}

void set_stdout_data(void)
{
	stdout_data = true;
}

bool starts_with(const char *str, const char *prefix)
{
	size_t len;

	len = strlen(prefix);

	if (strncmp(str, prefix, len) == 0)
		return true;
	return false;
}

bool ends_with(const char *str, const char *suffix)
{
	size_t str_len, s_len;

	str_len = strlen(str);
	s_len = strlen(suffix);

	if (str_len < s_len)
		return false;
	if (strcmp(str + str_len - s_len, suffix) != 0)
		return false;

	return true;
}

/* Remove subsequent slashes in @str */
void remove_double_slashes(char *str)
{
	size_t i, to;
	char last;

	last = 0;
	for (i = 0, to = 0; str[i]; i++) {
		if (last != '/' || str[i] != '/')
			last = str[to++] = str[i];
	}
	str[to] = 0;
}
