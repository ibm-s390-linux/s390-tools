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
extern void *zg_alloc(unsigned int size);
extern void *zg_realloc(void *ptr, unsigned int size);
extern void zg_free(void *ptr);
extern char *zg_strdup(const char *str);

/*
 * At exit functions
 */
typedef void (*zg_atexit_fn_t)(void);
extern void zg_atexit(zg_atexit_fn_t fn);
extern void __noreturn zg_exit(int rc);

/*
 * Temporary device node functions
 */
extern char *zg_devnode_create(dev_t dev);

/*
 * Progress bar functions
 */
extern void zg_progress_init(const char *msg, u64 mem_size);
extern void zg_progress(u64 addr);

/*
 * Error and print functions
 */
#define ERR(x...) \
do { \
	fprintf(stderr, "%s: ", "zgetdump"); \
	fprintf(stderr, x); \
	fprintf(stderr, "\n"); \
} while (0)

#define ERR_EXIT(x...) \
do { \
	ERR(x); \
	zg_exit(1); \
} while (0)

#define ABORT(x...) \
do { \
	ERR("Internal Error: " x); \
	abort(); \
} while (0)

#define ERR_EXIT_ERRNO(x...) \
	do { \
		fflush(stdout); \
		fprintf(stderr, "%s: ", "zgetdump"); \
		fprintf(stderr, x); \
		fprintf(stderr, " (%s)", strerror(errno)); \
		fprintf(stderr, "\n"); \
		zg_exit(1); \
	} while (0)

#define STDERR(x...) \
do { \
	fprintf(stderr, x); \
	fflush(stderr); \
} while (0)

#define STDERR_PR(x...) \
do { \
	fprintf(stderr, "\r%s: ", "zgetdump"); \
	fprintf(stderr, x); \
} while (0)

#define STDOUT(x...) \
do { \
	fprintf(stdout, x); \
	fflush(stdout); \
} while (0)

/*
 * Misc
 */
#define PAGE_SIZE 4096UL
#define PAGE_ALIGN(addr) ALIGN(addr, PAGE_SIZE)
#define ROUNDUP(x, y)	((((x) + ((y) - 1)) / (y)) * (y))

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
#define PTR_SUB(x, y) (((char *) (x)) - ((unsigned long) (y)))
#define PTR_ADD(x, y) (((char *) (x)) + ((unsigned long) (y)))
#define PTR_DIFF(x, y) ((unsigned long)(((char *) (x)) - ((unsigned long) (y))))

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

extern const char *zg_path(struct zg_fh *zg_fh);
extern const struct stat *zg_stat(struct zg_fh *zg_fh);
extern struct zg_fh *zg_open(const char *path, int flags, enum zg_check check);
extern void zg_close(struct zg_fh *zg_fh);
extern ssize_t zg_read(struct zg_fh *zg_fh, void *buf, size_t cnt,
		       enum zg_check check);
extern ssize_t zg_gets(struct zg_fh *zg_fh, void *buf, size_t cnt,
		       enum zg_check check);
extern u64 zg_size(struct zg_fh *zg_fh);
extern off_t zg_tell(struct zg_fh *zg_fh, enum zg_check check);
extern off_t zg_seek(struct zg_fh *zg_fh, off_t off, enum zg_check check);
extern off_t zg_seek_end(struct zg_fh *zg_fh, off_t off, enum zg_check check);
extern off_t zg_seek_cur(struct zg_fh *zg_fh, off_t off, enum zg_check check);
extern int zg_ioctl(struct zg_fh *zg_fh, int rq, void *data, const char *op,
		    enum zg_check check);
extern enum zg_type zg_type(struct zg_fh *zg_fh);

/*
 * zgetdump actions
 */
enum zg_action {
	ZG_ACTION_STDOUT,
	ZG_ACTION_DUMP_INFO,
	ZG_ACTION_DEVICE_INFO,
	ZG_ACTION_MOUNT,
	ZG_ACTION_UMOUNT,
};

#endif /* ZG_H */
