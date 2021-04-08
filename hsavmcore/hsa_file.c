/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "lib/util_log.h"

#include "common.h"
#include "hsa.h"
#include "hsa_file.h"

struct hsa_file_reader {
	struct hsa_reader super;
	/* Temporary file containing a copy of the HSA memory */
	int fd;
};

static void destroy(struct hsa_reader *super)
{
	struct hsa_file_reader *self =
		container_of(super, struct hsa_file_reader, super);

	close(self->fd);
	free(self);
}

static int read_at(struct hsa_reader *super, long offset, void *buf, int size)
{
	struct hsa_file_reader *self =
		container_of(super, struct hsa_file_reader, super);
	long n, nread = 0;

	util_log_print(UTIL_LOG_DEBUG, "HSA file read: offset=%lx size=%x\n",
		       offset, size);

	/* Validate given offset */
	if (offset >= super->hsa_size)
		return 0;

	/* Validate given size */
	size = MIN(super->hsa_size - offset, size);

	n = lseek(self->fd, offset, SEEK_SET);
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "lseek syscall failed (%s)\n",
			       strerror(errno));
		return -1;
	}

	while (size) {
		n = read(self->fd, buf + nread, size);
		if (n < 0) {
			util_log_print(UTIL_LOG_ERROR,
				       "read syscall failed (%s)\n",
				       strerror(errno));
			return -1;
		} else if (n == 0) {
			break;
		}

		nread += n;
		size -= n;
	}

	return nread;
}

static int copy_hsa_to_file(const char *vmcore_path, const char *workdir_path,
			    long size, long offset)
{
	int fd_in = -1, fd_out = -1;
	char cache_file_path[PATH_MAX];
	long n;

	snprintf(cache_file_path, sizeof(cache_file_path), "%s/%s",
		 workdir_path, HSA_CACHE_FILE);

	util_log_print(UTIL_LOG_DEBUG,
		       "Copy HSA memory from vmcore %s to cache file %s\n",
		       vmcore_path, cache_file_path);

	/* Open vmcore file */
	fd_in = open(vmcore_path, O_RDONLY);
	if (fd_in < 0) {
		util_log_print(UTIL_LOG_ERROR, "open syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	}

	/* Open cache file */
	fd_out = open(cache_file_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd_out < 0) {
		util_log_print(UTIL_LOG_ERROR, "open syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	}

	/* Unlink cache file to auto-delete it on close */
	n = unlink(cache_file_path);
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "unlink syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	}

	/* Copy HSA memory to cache file */
	n = lseek(fd_in, offset, SEEK_SET);
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "lseek syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	}

	/* Copy HSA memory chunkwise to the temporary file */
	while (size) {
		char buf[1024];
		long nread, nwrite;

		/* Read a chunk from vmcore */
		nread = MIN((long)sizeof(buf), size);

		n = read(fd_in, buf, nread);
		if (n < 0) {
			util_log_print(UTIL_LOG_ERROR,
				       "read syscall failed (%s)\n",
				       strerror(errno));
			goto fail;
		} else if (n == 0) {
			util_log_print(UTIL_LOG_ERROR,
				       "read syscall read less data than expected\n");
			goto fail;
		}

		/* Write a chunk to cache file */
		nwrite = n;
		n = write(fd_out, buf, nwrite);
		if (n < 0) {
			util_log_print(UTIL_LOG_ERROR,
				       "write syscall failed (%s)\n",
				       strerror(errno));
			goto fail;
		} else if (n != nwrite) {
			util_log_print(UTIL_LOG_ERROR,
				       "write syscall wrote less data than expected\n");
			goto fail;
		}

		size -= n;
	}

	/* Reset cache file position */
	n = lseek(fd_out, 0, SEEK_SET);
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "lseek syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	}

	close(fd_in);

	return fd_out;

fail:
	if (fd_in >= 0)
		close(fd_in);
	if (fd_out >= 0)
		close(fd_out);
	return -1;
}

struct hsa_reader *make_hsa_file_reader(const char *zcore_hsa_path,
					const char *vmcore_path,
					const char *workdir_path, long hsa_size,
					bool release_hsa_flag)
{
	struct hsa_file_reader *self;
	long hsa_vmcore_offset;
	int fd;

	/* Calculate HSA size if not given by user */
	if (hsa_size < 0) {
		hsa_size = get_hsa_size(zcore_hsa_path);
		if (hsa_size <= 0)
			return NULL;
	}
	hsa_vmcore_offset = get_hsa_vmcore_offset(vmcore_path);
	if (hsa_vmcore_offset < 0)
		return NULL;

	util_log_print(UTIL_LOG_INFO, "HSA: size=%lx vmcore offset=%lx\n",
		       hsa_size, hsa_vmcore_offset);

	/*
	 * Store the whole HSA memory from /proc/vmcore to a temporary file
	 * before releasing HSA.
	 */
	fd = copy_hsa_to_file(vmcore_path, workdir_path, hsa_size,
			      hsa_vmcore_offset);
	if (fd < 0)
		return NULL;

	if (release_hsa_flag) {
		if (release_hsa(zcore_hsa_path)) {
			close(fd);
			return NULL;
		}
	}

	self = malloc(sizeof(struct hsa_file_reader));
	if (!self) {
		util_log_print(UTIL_LOG_ERROR, "malloc failed\n");
		close(fd);
		return NULL;
	}

	self->super.hsa_size = hsa_size;
	self->super.hsa_vmcore_offset = hsa_vmcore_offset;
	self->super.destroy = destroy;
	self->super.read_at = read_at;
	self->fd = fd;

	return &self->super;
}
