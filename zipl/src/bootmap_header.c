/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions to manipulate with bootmap header
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <string.h>

#include "bootmap.h"
#include "error.h"
#include "misc.h"

int bootmap_header_init(int fd)
{
	struct bootmap_header bh = {
		.header_text =
		"zSeries bootmap file\n"
		"created by zIPL\n",
		.version = BOOTMAP_HEADER_VERSION
	};

	return misc_write(fd, &bh, sizeof(bh));
}

static int bootmap_header_access(int fd, struct bootmap_header *bh, int read)
{
	off_t cur_off;
	int ret;

	cur_off = lseek(fd, 0, SEEK_CUR);
	if (cur_off == -1) {
		error_reason(strerror(errno));
		return -1;
	}
	if (lseek(fd, 0, SEEK_SET) == -1) {
		error_reason(strerror(errno));
		ret = -1;
		goto out;
	}
	if (read)
		ret = misc_read(fd, bh, sizeof(*bh));
	else
		ret = misc_write(fd, bh, sizeof(*bh));
out:
	if (lseek(fd, cur_off, SEEK_SET) == -1)
		return -1;
	return ret;
}

int bootmap_header_read(int fd, struct bootmap_header *bh)
{
	return bootmap_header_access(fd, bh, 1);
}

int bootmap_header_write(int fd, struct bootmap_header *bh)
{
	return bootmap_header_access(fd, bh, 0);
}
