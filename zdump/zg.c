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

#include <limits.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <sys/time.h>

#include "zgetdump.h"

#define MAX_EXIT_FN	10
#define MAX_DEV_RETRIES	1000
#define PROGRESS_INTERVAL_SECS	10

/*
 * Progress information
 */
struct prog {
	time_t	time_next;
	u64	mem_size;
};

/*
 * At exit information
 */
struct atexit {
	zg_atexit_fn_t	fn_vec[MAX_EXIT_FN];
	unsigned int	cnt;
};

/*
 * Temp devnode information
 */
struct devnode {
	char	**vec;
	int	cnt;
};

/*
 * File local static data
 */
static struct {
	struct atexit	atexit;
	struct prog	prog;
	struct devnode	devnode;
} l;

/*
 * Call all registered exit handlers
 */
static void exit_fn(void)
{
	unsigned int i;

	for (i = 0; i < l.atexit.cnt; i++)
		l.atexit.fn_vec[i]();
}

/*
 * Register exit handler
 */
void zg_atexit(zg_atexit_fn_t fn)
{
	if (l.atexit.cnt >= MAX_EXIT_FN)
		ABORT("Too many atexit handlers (%d)", l.atexit.cnt + 1);
	l.atexit.fn_vec[l.atexit.cnt] = fn;
	if (l.atexit.cnt == 0)
		atexit(exit_fn);
	l.atexit.cnt++;
}

/*
 * Exit function (For having exit gdb break point)
 */
void __noreturn zg_exit(int rc)
{
	exit(rc);
}

/*
 * Alloc memory and check for errors
 */
void *zg_alloc(unsigned int size)
{
	void *ptr = calloc(size, 1);
	if (!ptr)
		ERR_EXIT("Alloc: Out of memory (%i KiB)", TO_KIB(size));
	return ptr;
}

/*
 * Realloc memory and check for errors
 */
void *zg_realloc(void *ptr, unsigned int size)
{
	void *new_ptr = realloc(ptr, size);
	if (!new_ptr)
		ERR_EXIT("Realloc: Out of memory (%i KiB)", TO_KIB(size));
	return new_ptr;
}

/*
 * Create duplicate for string
 */
char *zg_strdup(const char *str)
{
	char *new_str = strdup(str);

	if (!new_str)
		ERR_EXIT("Strdup: Out of memory (%s)\n", str);
	return new_str;
}

/*
 * Free memory
 */
void zg_free(void *ptr)
{
	free(ptr);
}

/*
 * Return path name of open file
 */
const char *zg_path(struct zg_fh *zg_fh)
{
	return zg_fh->path;
}

/*
 * Return stat buffer of open file
 */
const struct stat *zg_stat(struct zg_fh *zg_fh)
{
	return &zg_fh->sb;
}

/*
 * Open file
 */
struct zg_fh *zg_open(const char *path, int flags, enum zg_check check)
{
	struct zg_fh *zg_fh = zg_alloc(sizeof(*zg_fh));

	zg_fh->fh = open(path, flags);
	if (zg_fh->fh == -1) {
		if (check == ZG_CHECK_NONE)
			goto fail;
		ERR_EXIT_ERRNO("Could not open \"%s\"", path);
	}
	if (stat(path, &zg_fh->sb) == -1) {
		if (check == ZG_CHECK_NONE)
			goto fail;
		ERR_EXIT_ERRNO("Could not access file \"%s\"", path);
	}
	zg_fh->path = zg_strdup(path);
	if (S_ISBLK(zg_fh->sb.st_mode)) {
		/* We have a block device - set correct size */
		zg_fh->sb.st_size = lseek(zg_fh->fh, 0, SEEK_END);
		if (zg_fh->sb.st_size == (off_t)-1)
			goto fail;
		if (lseek(zg_fh->fh, 0, SEEK_SET) == (off_t)-1)
			goto fail;
	}
	return zg_fh;

fail:
	zg_free(zg_fh);
	return NULL;
}

/*
 * Close file
 */
void zg_close(struct zg_fh *zg_fh)
{
	close(zg_fh->fh);
	free(zg_fh);
}

/*
 * Read file
 */
ssize_t zg_read(struct zg_fh *zg_fh, void *buf, size_t cnt, enum zg_check check)
{
	size_t copied = 0;
	ssize_t rc;

	do {
		rc = read(zg_fh->fh, buf + copied, cnt - copied);
		if (rc == -1) {
			if (check == ZG_CHECK_NONE)
				return rc;
			ERR_EXIT_ERRNO("Could not read \"%s\"", zg_fh->path);
		}
		if (rc == 0) {
			if (check != ZG_CHECK)
				return copied;
			ERR_EXIT("Unexpected end of file for \"%s\"",
				 zg_fh->path);
		}
		copied += rc;
	} while (copied != cnt);
	return copied;
}

/*
 * Read line
 */
ssize_t zg_gets(struct zg_fh *zg_fh, void *ptr, size_t cnt, enum zg_check check)
{
	size_t copied = 0;
	char *buf = ptr;
	ssize_t rc;

	if (cnt == 0)
		return 0;
	do {
		rc = read(zg_fh->fh, &buf[copied], 1);
		if (rc == -1) {
			if (check == ZG_CHECK_NONE)
				return rc;
			ERR_EXIT_ERRNO("Could not read \"%s\"", zg_fh->path);
		}
		if (rc == 0 || buf[copied] == '\n' || copied == cnt - 1)
			break;
		copied++;
	} while (1);
	buf[copied] = '\0';
	return copied;
}

/*
 * Return file size
 */
u64 zg_size(struct zg_fh *zg_fh)
{
	return zg_fh->sb.st_size;
}

/*
 * Return file position
 */
off_t zg_tell(struct zg_fh *zg_fh, enum zg_check check)
{
	off_t rc;

	rc = lseek(zg_fh->fh, 0, SEEK_CUR);
	if (rc == -1 && check != ZG_CHECK_NONE)
		ERR_EXIT_ERRNO("Could not get file position for \"%s\"",
			       zg_fh->path);
	return rc;
}

/*
 * Seek to "off" relative to END
 */
off_t zg_seek_end(struct zg_fh *zg_fh, off_t off, enum zg_check check)
{
	off_t rc;

	rc = lseek(zg_fh->fh, off, SEEK_END);
	if (rc == -1 && check != ZG_CHECK_NONE)
		ERR_EXIT_ERRNO("Could not seek \"%s\"", zg_fh->path);
	return rc;
}

/*
 * Seek to "off" in file
 */
off_t zg_seek(struct zg_fh *zg_fh, off_t off, enum zg_check check)
{
	off_t rc;

	if (off >= zg_fh->sb.st_size)
		ERR_EXIT("Trying to seek past file end \"%s\"", zg_fh->path);

	rc = lseek(zg_fh->fh, off, SEEK_SET);
	if (rc == -1 && check != ZG_CHECK_NONE)
		ERR_EXIT_ERRNO("Could not seek \"%s\"", zg_fh->path);
	if (rc != off && check == ZG_CHECK)
		ERR_EXIT("Could not seek \"%s\"", zg_fh->path);
	return rc;
}

/*
 * Seek from current position
 */
off_t zg_seek_cur(struct zg_fh *zg_fh, off_t off, enum zg_check check)
{
	off_t rc;

	rc = lseek(zg_fh->fh, off, SEEK_CUR);
	if (rc == -1 && check != ZG_CHECK_NONE)
		ERR_EXIT_ERRNO("Could not seek \"%s\"", zg_fh->path);
	return rc;
}

/*
 * Do ioctl and exit in case of an error
 */
int zg_ioctl(struct zg_fh *zg_fh, int rq, void *data, const char *op,
	     enum zg_check check)
{
	int rc;

	rc = ioctl(zg_fh->fh, rq, data);
	if (rc == -1 && check != ZG_CHECK_NONE)
		ERR_EXIT_ERRNO("Operation \"%s\" failed on \"%s\"", op,
			       zg_fh->path);
	return rc;
}

/*
 * Return file type
 */
enum zg_type zg_type(struct zg_fh *zg_fh)
{
	struct mtop mtop;
	struct stat *sb = &zg_fh->sb;

	if (S_ISREG(sb->st_mode))
		return ZG_TYPE_FILE;
	if (S_ISBLK(sb->st_mode)) {
		if (minor(sb->st_rdev) % 4 == 0)
			return ZG_TYPE_DASD;
		else
			return ZG_TYPE_DASD_PART;
	}
	if (S_ISCHR(sb->st_mode)) {
		mtop.mt_count = 1;
		mtop.mt_op = MTTELL;
		if (zg_ioctl(zg_fh, MTIOCTOP, &mtop, "MTIOCTOP",
			     ZG_CHECK_NONE) != -1)
			return ZG_TYPE_TAPE;
	}
	return ZG_TYPE_UNKNOWN;
}

/*
 * Initialize progress messages
 */
void zg_progress_init(const char *msg, u64 mem_size)
{
	STDERR("%s:\n", msg);
	l.prog.time_next = 0;
	l.prog.mem_size = mem_size;
}

/*
 * Print progress
 */
void zg_progress(u64 addr)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	if ((tv.tv_sec < l.prog.time_next) && (addr < l.prog.mem_size))
		return;
	STDERR("  %08Lu / %08Lu MB\n", TO_MIB(addr), TO_MIB(l.prog.mem_size));
	l.prog.time_next = tv.tv_sec + PROGRESS_INTERVAL_SECS;
}

/*
 * Try to create device node in "dir"
 */
static char *devnode_create_dir(const char *dir, dev_t dev)
{
	char file_path[PATH_MAX];
	int i, fh, rc;

	for (i = 0; i < MAX_DEV_RETRIES; i++) {
		snprintf(file_path, PATH_MAX, "%s/zgetdump.%04d", dir, i);
		rc = mknod(file_path, S_IFBLK | S_IRWXU, dev);
		if (rc == -1) {
			if (errno == EEXIST)
				continue;
			else
				break;
		}

		/* Need this test to cover 'nodev'-mounted filesystems */
		fh = open(file_path, O_RDWR);
		if (fh == -1) {
			remove(file_path);
			break;
		}
		close(fh);
		return zg_strdup(file_path);
	}
	return NULL;
}

/*
 * Delete temporary device node
 */
static void devnode_remove(char *dev_node)
{
	if (remove(dev_node))
		ERR("Warning: Could not remove temporary file %s: %s",
		    dev_node, strerror(errno));
	zg_free(dev_node);
}

/*
 * Remove all temporary device nodes
 */
static void devnode_remove_all(void)
{
	int i;

	for (i = 0; i < l.devnode.cnt; i++)
		devnode_remove(l.devnode.vec[i]);
	if (l.devnode.vec) {
		zg_free(l.devnode.vec);
		l.devnode.vec = NULL;
	}
	l.devnode.cnt = 0;
}

/*
 * Make temporary device node for input dev identified by its dev_t
 */
char *zg_devnode_create(dev_t dev)
{
	char *dir_vec[] = {getenv("TMPDIR"), "/tmp", getenv("HOME"), ".", "/"};
	char *file_path;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(dir_vec); i++) {
		if (dir_vec[i] == NULL)
			continue;
		file_path = devnode_create_dir(dir_vec[i], dev);
		if (file_path)
			goto found;
	}
	ERR_EXIT_ERRNO("Unable to create temporary dev node");
	return NULL;
found:
	l.devnode.cnt++;
	l.devnode.vec = zg_realloc(l.devnode.vec, l.devnode.cnt *
				   sizeof(void *));
	l.devnode.vec[l.devnode.cnt - 1] = file_path;
	if (l.devnode.cnt == 1)
		zg_atexit(devnode_remove_all);
	return file_path;
}
