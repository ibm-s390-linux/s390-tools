/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "lib/util_log.h"

#include "hsa.h"
#include "hsa_mem.h"

struct hsa_mem_reader {
	struct hsa_reader super;
	unsigned char cache[];
};

static void destroy(struct hsa_reader *super)
{
	struct hsa_mem_reader *self =
		container_of(super, struct hsa_mem_reader, super);

	free(self);
}

static int read_at(struct hsa_reader *super, long offset, void *buf, int size)
{
	struct hsa_mem_reader *self =
		container_of(super, struct hsa_mem_reader, super);

	util_log_print(UTIL_LOG_DEBUG, "HSA file read: offset=%lx size=%x\n",
		       offset, size);

	/* Validate given offset */
	if (offset >= super->hsa_size)
		return 0;

	/* Validate given size */
	size = MIN(super->hsa_size - offset, size);

	memcpy(buf, self->cache + offset, size);

	return size;
}

static int read_hsa(const char *vmcore_path, long offset, void *buf, int size)
{
	long n, nread = 0;
	int fd = -1;

	util_log_print(UTIL_LOG_DEBUG, "Read HSA memory from vmcore %s\n",
		       vmcore_path);

	/* Open vmcore file */
	fd = open(vmcore_path, O_RDONLY);
	if (fd < 0) {
		util_log_print(UTIL_LOG_ERROR, "open syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	}

	n = lseek(fd, offset, SEEK_SET);
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "lseek syscall failed (%s)\n",
			       strerror(errno));
		goto fail;
	}

	/* Read HSA memory */
	while (size) {
		n = read(fd, buf + nread, size);
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

		nread += n;
		size -= n;
	}

	close(fd);

	return 0;

fail:
	if (fd >= 0)
		close(fd);
	return -1;
}

struct hsa_reader *make_hsa_mem_reader(const char *zcore_hsa_path,
				       const char *vmcore_path, long hsa_size,
				       bool release_hsa_flag)
{
	struct hsa_mem_reader *self;
	long hsa_vmcore_offset;

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

	self = malloc(sizeof(struct hsa_mem_reader) + hsa_size);
	if (!self) {
		util_log_print(UTIL_LOG_ERROR, "malloc failed\n");
		return NULL;
	}

	/* Cache the whole HSA memory from /proc/vmcore before releasing HSA */
	if (read_hsa(vmcore_path, hsa_vmcore_offset, self->cache, hsa_size)) {
		free(self);
		return NULL;
	}

	if (release_hsa_flag) {
		if (release_hsa(zcore_hsa_path)) {
			free(self);
			return NULL;
		}
	}

	self->super.hsa_size = hsa_size;
	self->super.hsa_vmcore_offset = hsa_vmcore_offset;
	self->super.destroy = destroy;
	self->super.read_at = read_at;

	return &self->super;
}
