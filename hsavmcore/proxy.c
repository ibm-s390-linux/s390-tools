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

#include "proxy.h"

struct vmcore_proxy {
	int vmcore_fd;
	long vmcore_size;
	struct hsa_reader *hsa_reader;
};

static int read_file_at(int fd, long offset, void *buf, int size)
{
	long n, nread = 0;

	util_log_print(UTIL_LOG_DEBUG,
		       "vmcore proxy vmcore read: offset=%lx size=%x\n", offset,
		       size);

	n = lseek(fd, offset, SEEK_SET);
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "lseek syscall failed (%s)\n",
			       strerror(errno));
		return -1;
	}

	while (size) {
		n = read(fd, buf + nread, size);
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

static long get_vmcore_size(int fd)
{
	long n, size;

	/* Get vmcore file size */
	n = lseek(fd, 0, SEEK_END);
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "lseek syscall failed (%s)\n",
			       strerror(errno));
		return 0;
	}

	size = n;

	/* Reset vmcore file position */
	n = lseek(fd, 0, SEEK_SET);
	if (n < 0) {
		util_log_print(UTIL_LOG_ERROR, "lseek syscall failed (%s)\n",
			       strerror(errno));
		return 0;
	}

	return size;
}

struct vmcore_proxy *make_vmcore_proxy(const char *vmcore_path,
				       struct hsa_reader *hsa_reader)
{
	struct vmcore_proxy *proxy;
	int vmcore_fd;
	long vmcore_size;

	util_log_print(UTIL_LOG_INFO, "vmcore proxy: vmcore path=%s\n",
		       vmcore_path);

	/* Open vmcore file */
	vmcore_fd = open(vmcore_path, O_RDONLY);
	if (vmcore_fd < 0) {
		util_log_print(UTIL_LOG_ERROR, "open syscall failed (%s)\n",
			       strerror(errno));
		return NULL;
	}

	vmcore_size = get_vmcore_size(vmcore_fd);
	if (!vmcore_size) {
		close(vmcore_fd);
		return NULL;
	}

	util_log_print(UTIL_LOG_INFO, "vmcore proxy: vmcore size=%lx\n",
		       vmcore_size);

	proxy = malloc(sizeof(struct vmcore_proxy));
	if (!proxy) {
		util_log_print(UTIL_LOG_ERROR, "malloc failed\n");
		close(vmcore_fd);
		return NULL;
	}

	proxy->vmcore_fd = vmcore_fd;
	proxy->vmcore_size = vmcore_size;
	proxy->hsa_reader = hsa_reader;

	return proxy;
}

void destroy_vmcore_proxy(struct vmcore_proxy *proxy)
{
	close(proxy->vmcore_fd);
	free(proxy);
}

long vmcore_proxy_size(struct vmcore_proxy *proxy)
{
	return proxy->vmcore_size;
}

int read_vmcore_proxy_at(struct vmcore_proxy *proxy, long offset, void *buf,
			 int size)
{
	const long hsa_size = hsa_get_size(proxy->hsa_reader);
	const long hsa_vmcore_offset = hsa_get_vmcore_offset(proxy->hsa_reader);
	long nread = 0;

	util_log_print(UTIL_LOG_DEBUG,
		       "vmcore proxy read: offset=%lx size=%x\n", offset, size);

	/*
	 * The caller might try to read beyond the maximum length of vmcore.
	 * This guarantees the termination of the loop below in that case.
	 */
	size = MIN(proxy->vmcore_size - offset, size);

	/*
	 * 0                 HSA offset          HSA offset +        vmcore size
	 *                                       HSA size
	 *
	 * +---------------------+---------------------+-----------------------+
	 * |                     |                     |                       |
	 * |  vmcore 1st part    |  HSA memory region  |    vmcore 2nd part    |
	 * |                     |                     |                       |
	 * +---------------------+---------------------+-----------------------+
	 */

	while (size) {
		long n, nbyte;

		if (offset < hsa_vmcore_offset) {
			/* vmcore 1st part */
			nbyte = MIN(hsa_vmcore_offset - offset, size);
			n = read_file_at(proxy->vmcore_fd, offset, buf + nread,
					 nbyte);
		} else if (offset >= hsa_vmcore_offset &&
			   offset < (hsa_vmcore_offset + hsa_size)) {
			/* HSA memory region */
			nbyte = MIN(hsa_vmcore_offset + hsa_size - offset,
				    size);
			n = read_hsa_at(proxy->hsa_reader,
					offset - hsa_vmcore_offset,
					buf + nread, nbyte);
		} else {
			/* vmcore 2nd part */
			nbyte = MIN(proxy->vmcore_size - offset, size);
			n = read_file_at(proxy->vmcore_fd, offset, buf + nread,
					 nbyte);
		}

		if (n != nbyte)
			return -1;

		nread += n;
		size -= n;
		offset += n;
	}

	return nread;
}
