/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Helper functions
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZG_H
#define ZG_H

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/zt_common.h"

#define U64_MAX	((u64) -1)
#define U32_MAX	((u32) -1)
#define U16_MAX	((u16) -1)
#define U8_MAX	((u8) -1)

/*
 * IEC definitions
 */
#define KIB	(1024)
#define MIB	(1024 * 1024)
#define GIB	(1024 * 1024 * 1024)

#define TO_MIB(x) ((x + (MIB / 2)) / MIB)
#define TO_KIB(x) ((x + (KIB / 2)) / KIB)

/*
 * Memory functions
 */
void *zg_alloc(unsigned int size);
void *zg_realloc(void *ptr, unsigned int size);
void zg_free(void *ptr);
char *zg_strdup(const char *str);

/*
 * At exit functions
 */
typedef void (*zg_atexit_fn_t)(void);
void zg_atexit(zg_atexit_fn_t fn);
void __noreturn zg_exit(int rc);

/*
 * Temporary device node functions
 */
char *zg_devnode_create(dev_t dev);

/*
 * Progress bar functions
 */
void zg_progress_init(const char *msg, u64 mem_size);
void zg_progress(u64 addr);

/*
 * Error and print functions
 */

void zg_err(const char *fmt, ...);
void zg_err_exit(const char *fmt, ...);
void zg_err_exit_errno(const char *fmt, ...);
void zg_abort(const char *fmt, ...);

#define ERR(fmt, ...)			zg_err(fmt, ## __VA_ARGS__)
#define ERR_EXIT(fmt, ...)		zg_err_exit(fmt, ## __VA_ARGS__)
#define ERR_EXIT_ERRNO(fmt, ...)	zg_err_exit_errno(fmt, ## __VA_ARGS__)
#define ABORT(fmt, ...)			zg_abort(fmt, ## __VA_ARGS__)

void zg_stderr(const char *fmt, ...);
void zg_stderr_pr(const char *fmt, ...);
void zg_stdout(const char *fmt, ...);

#define STDERR(fmt, ...)	zg_stderr(fmt, ## __VA_ARGS__)
#define STDERR_PR(fmt, ...)	zg_stderr_pr(fmt, ## __VA_ARGS__)
#define STDOUT(fmt, ...)	zg_stdout(fmt, ## __VA_ARGS__)
/*
 * Misc
 */
#define PAGE_SIZE 4096UL
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)

static inline u32 zg_csum_partial(const void *buf, int len, u32 sum)
{
	register unsigned long reg2 asm("2") = (unsigned long) buf;
	register unsigned long reg3 asm("3") = (unsigned long) len;

	asm volatile(
		"0:     cksm    %0,%1\n"        /* do checksum on longs */
		"       jo      0b\n"
		: "+d" (sum), "+d" (reg2), "+d" (reg3) : : "cc", "memory");
	return sum;
}

/*
 * Pointer atrithmetic
 */
#define PTR_SUB(x, y) ((void *)(((char *) (x)) - ((unsigned long) (y))))
#define PTR_ADD(x, y) ((void *)(((char *) (x)) + ((unsigned long) (y))))
#define PTR_DIFF(x, y) ((unsigned long)PTR_SUB(x, y))

/*
 * File functions
 */
struct zg_fh {
	const char	*path;
	int		fh;
	struct stat	sb;
};

enum zg_type {
	ZG_TYPE_DASD,
	ZG_TYPE_DASD_PART,
	ZG_TYPE_FILE,
	ZG_TYPE_TAPE,
	ZG_TYPE_UNKNOWN,
};

enum zg_check {
	ZG_CHECK,
	ZG_CHECK_ERR,
	ZG_CHECK_NONE,
};

const char *zg_path(const struct zg_fh *zg_fh);
const struct stat *zg_stat(const struct zg_fh *zg_fh);
struct zg_fh *zg_open(const char *path, int flags, enum zg_check check);
void zg_close(struct zg_fh *zg_fh);
ssize_t zg_read(const struct zg_fh *zg_fh, void *buf, size_t cnt, enum zg_check check);
ssize_t zg_gets(const struct zg_fh *zg_fh, void *buf, size_t cnt, enum zg_check check);
u64 zg_size(const struct zg_fh *zg_fh);
off_t zg_tell(const struct zg_fh *zg_fh, enum zg_check check);
off_t zg_seek(const struct zg_fh *zg_fh, off_t off, enum zg_check check);
off_t zg_seek_end(const struct zg_fh *zg_fh, off_t off, enum zg_check check);
off_t zg_seek_cur(const struct zg_fh *zg_fh, off_t off, enum zg_check check);
int zg_ioctl(const struct zg_fh *zg_fh, int rq, void *data, const char *op, enum zg_check check);
enum zg_type zg_type(const struct zg_fh *zg_fh);

/*
 * zgetdump actions
 */
enum zg_action {
	ZG_ACTION_COPY,
	ZG_ACTION_DUMP_INFO,
	ZG_ACTION_DEVICE_INFO,
	ZG_ACTION_MOUNT,
	ZG_ACTION_UMOUNT,
};

#endif /* ZG_H */
