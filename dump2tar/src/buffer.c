/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Data buffering functions
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "buffer.h"
#include "misc.h"

void buffer_print(struct buffer *buffer)
{
	fprintf(stderr, "DEBUG: buffer at %p\n", (void *) buffer);
	if (!buffer)
		return;
	fprintf(stderr, "DEBUG:   total=%zu\n", buffer->total);
	fprintf(stderr, "DEBUG:   off=%zu\n", buffer->off);
	fprintf(stderr, "DEBUG:   size=%zu\n", buffer->size);
	fprintf(stderr, "DEBUG:   addr=%p\n", (void *) buffer->addr);
	fprintf(stderr, "DEBUG:   fd_open=%d\n", buffer->fd_open);
	fprintf(stderr, "DEBUG:   fd=%d\n", buffer->fd);
	if (buffer->fd_open) {
		fprintf(stderr, "DEBUG:   fd->pos=%zu\n",
			lseek(buffer->fd, 0, SEEK_CUR));
	}
}

/* Initialize @buffer to hold @size bytes in memory */
void buffer_init(struct buffer *buffer, size_t size)
{
	memset(buffer, 0, sizeof(struct buffer));
	buffer->addr = mmalloc(size);
	buffer->size = size;
}

/* Allocate a new buffer for holding @size bytes in memory */
struct buffer *buffer_alloc(size_t size)
{
	struct buffer *buffer;

	buffer = mmalloc(sizeof(struct buffer));
	buffer_init(buffer, size);

	return buffer;
}

/* Forget about any data stored in @buffer */
void buffer_reset(struct buffer *buffer)
{
	buffer->total = 0;
	buffer->off = 0;
	if (buffer->fd_open) {
		if (ftruncate(buffer->fd, 0))
			mwarn("Cannot truncate temporary file");
		if (lseek(buffer->fd, 0, SEEK_SET) == (off_t) -1)
			mwarn("Cannot seek in temporary file");
	}
}

/* Close buffer file associated with @buffer */
void buffer_close(struct buffer *buffer)
{
	if (!buffer->fd_open)
		return;

	fclose(buffer->file);
	buffer->fd = 0;
	buffer->fd_open = false;
}

/* Release all resources associated with @buffer. If @dyn is %true, also free
 * @buffer itself. */
void buffer_free(struct buffer *buffer, bool dyn)
{
	if (!buffer)
		return;
	buffer_reset(buffer);
	buffer_close(buffer);
	free(buffer->addr);
	if (dyn)
		free(buffer);
}

/* Open a buffer file for @buffer. Return %EXIT_OK on success, %EXIT_RUNTIME
 * otherwise. */
int buffer_open(struct buffer *buffer)
{
	if (buffer->fd_open)
		return EXIT_OK;

	buffer->file = tmpfile();
	if (!buffer->file) {
		mwarn("Could not create temporary file");
		return EXIT_RUNTIME;
	}

	buffer->fd = fileno(buffer->file);
	buffer->fd_open = true;

	return EXIT_OK;
}

/* Write data in memory of @buffer to buffer file. Return %EXIT_OK on success,
 * %EXIT_RUNTIME otherwise. */
int buffer_flush(struct buffer *buffer)
{
	if (buffer->off == 0)
		return EXIT_OK;
	if (buffer_open(buffer))
		return EXIT_RUNTIME;
	if (misc_write_data(buffer->fd, buffer->addr, buffer->off)) {
		mwarn("Could not write to temporary file");
		return EXIT_RUNTIME;
	}
	buffer->off = 0;

	return EXIT_OK;
}

/* Try to ensure that at least @size bytes are available at
 * @buffer->addr[buffer->off]. Return the actual number of bytes available or
 * @-1 on error.  If @usefile is %true, make use of a buffer file if
 * the total buffer size exceeds @max_buffer_size. */
ssize_t buffer_make_room(struct buffer *buffer, size_t size, bool usefile,
			 size_t max_buffer_size)
{
	size_t needsize;

	if (size > max_buffer_size && usefile)
		size = max_buffer_size;

	needsize = buffer->off + size;
	if (needsize <= buffer->size) {
		/* Room available */
		return size;
	}

	if (needsize > max_buffer_size && usefile) {
		/* Need to write out memory buffer to buffer file */
		if (buffer_flush(buffer))
			return -1;
		if (size <= buffer->size)
			return size;
		needsize = size;
	}

	/* Need to increase memory buffer size */
	buffer->size = needsize;
	buffer->addr = mrealloc(buffer->addr, buffer->size);

	return size;
}

/* Try to read @chunk bytes from @fd to @buffer. Return the number of bytes
 * read on success, %0 on EOF or %-1 on error. */
ssize_t buffer_read_fd(struct buffer *buffer, int fd, size_t chunk,
		       bool usefile, size_t max_buffer_size)
{
	ssize_t c = buffer_make_room(buffer, chunk, usefile, max_buffer_size);

	DBG("buffer_read_fd wanted %zd got %zd", chunk, c);
	if (c < 0)
		return c;

	c = read(fd, buffer->addr + buffer->off, c);
	if (c > 0) {
		buffer->total += c;
		buffer->off += c;
	}

	return c;
}

/* Add @len bytes at @addr to @buffer. If @addr is %NULL, add zeroes. Return
 * %EXIT_OK on success, %EXIT_RUNTIME otherwise. */
int buffer_add_data(struct buffer *buffer, char *addr, size_t len, bool usefile,
		    size_t max_buffer_size)
{
	ssize_t c;

	while (len > 0) {
		c = buffer_make_room(buffer, len, usefile, max_buffer_size);
		if (c < 0)
			return EXIT_RUNTIME;
		if (addr) {
			memcpy(buffer->addr + buffer->off, addr, c);
			addr += c;
		} else {
			memset(buffer->addr + buffer->off, 0, c);
		}
		buffer->total += c;
		buffer->off += c;

		len -= c;
	}

	return EXIT_OK;
}

/* Call @cb for all chunks of data in @buffer. @data is passed to @cb. */
int buffer_iterate(struct buffer *buffer, buffer_cb_t cb, void *data)
{
	int rc;
	ssize_t r;

	if (buffer->total == 0)
		return EXIT_OK;

	if (!buffer->fd_open)
		return cb(data, buffer->addr, buffer->off);

	/* Free memory buffer to be used as copy buffer */
	if (buffer_flush(buffer))
		return EXIT_RUNTIME;
	if (lseek(buffer->fd, 0, SEEK_SET) == (off_t) -1) {
		mwarn("Cannot seek in temporary file");
		return EXIT_RUNTIME;
	}

	/* Copy data from temporary file to target file */
	while ((r = misc_read_data(buffer->fd, buffer->addr,
				   buffer->size)) != 0) {
		if (r < 0) {
			mwarn("Cannot read from temporary file");
			return EXIT_RUNTIME;
		}
		rc = cb(data, buffer->addr, r);
		if (rc)
			return rc;
	}

	return EXIT_OK;
}

/* Truncate @buffer to at most @len bytes */
int buffer_truncate(struct buffer *buffer, size_t len)
{
	size_t delta;

	if (buffer->total <= len)
		return EXIT_OK;

	delta = buffer->total - len;

	buffer->total = len;
	if (buffer->fd_open && delta > buffer->off) {
		/* All of memory and some of file buffer is truncated */
		buffer->off = 0;
		if (ftruncate(buffer->fd, len)) {
			mwarn("Cannot truncate temporary file");
			return EXIT_RUNTIME;
		}
		if (lseek(buffer->fd, len, SEEK_SET) == (off_t) -1) {
			mwarn("Cannot seek in temporary file");
			return EXIT_RUNTIME;
		}
	} else {
		/* Only memory buffer is truncated */
		buffer->off -= delta;
	}

	return EXIT_OK;
}
