/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Mini libc implementation
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef LIBC_H
#define LIBC_H

#include <stdint.h>
#include <stddef.h>

#include "lib/zt_common.h"

#define EPERM		 1	/* Operation not permitted */
#define ENOENT		 2	/* No such file or directory */
#define ESRCH		 3	/* No such process */
#define EINTR		 4	/* Interrupted system call */
#define EIO		 5	/* I/O error */
#define ENXIO		 6	/* No such device or address */
#define E2BIG		 7	/* Argument list too long */
#define ENOEXEC		 8	/* Exec format error */
#define EBADF		 9	/* Bad file number */
#define ECHILD		10	/* No child processes */
#define EAGAIN		11	/* Try again */
#define ENOMEM		12	/* Out of memory */
#define EACCES		13	/* Permission denied */
#define EFAULT		14	/* Bad address */
#define ENOTBLK		15	/* Block device required */
#define EBUSY		16	/* Device or resource busy */
#define EEXIST		17	/* File exists */
#define EXDEV		18	/* Cross-device link */
#define ENODEV		19	/* No such device */
#define ENOTDIR		20	/* Not a directory */
#define EISDIR		21	/* Is a directory */
#define EINVAL		22	/* Invalid argument */
#define ENFILE		23	/* File table overflow */
#define EMFILE		24	/* Too many open files */
#define ENOTTY		25	/* Not a typewriter */

#define MIB	(1024ULL * 1024)
#define LINE_LENGTH 80 /* max line length printed by printf */

void printf(const char *, ...);
void snprintf(char *buf, unsigned long size, const char *fmt, ...);
void *memcpy(void *, const void *, unsigned long);
void *memmove(void *, const void *, unsigned long);
void *memset(void *, int c, unsigned long);
char *strcat(char *, const char *);
int strncmp(const char *, const char *, unsigned long);
int strlen(const char *);
char *strcpy(char *, const char *);
unsigned long get_zeroed_page(void);
void free_page(unsigned long);
void initialize(void);
void libc_stop(unsigned long) __noreturn;
void start(void);
void pgm_check_handler(void);
void pgm_check_handler_fn(void);
void panic_notify(unsigned long reason);

#define panic(reason, ...)			\
	do {					\
		printf(__VA_ARGS__);		\
		panic_notify(reason);		\
		libc_stop(reason);		\
	} while (0)

static inline int isdigit(int c)
{
	return (c >= '0') && (c <= '9');
}

static inline int isspace(char c)
{
	return (c == 32) || (c >= 9 && c <= 13);
}

#endif /* LIBC_H */
