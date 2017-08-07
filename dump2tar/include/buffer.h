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

#ifndef BUFFER_H
#define BUFFER_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

/* Buffers for building tar file entries */
struct buffer {
	size_t total;	/* Total number of bytes in buffer */
	size_t off;	/* Current offset to next free byte in memory buffer */
	size_t size;	/* Memory buffer size */
	char *addr;	/* Memory buffer address */
	bool fd_open;	/* Has fd been openend yet? */
	FILE *file;	/* FILE * of file containing previous buffer data */
	int fd;		/* Handle of file containing previous buffer data */
};

void buffer_init(struct buffer *buffer, size_t size);
struct buffer *buffer_alloc(size_t size);
void buffer_reset(struct buffer *buffer);
void buffer_close(struct buffer *buffer);
void buffer_free(struct buffer *buffer, bool dyn);
int buffer_open(struct buffer *buffer);
int buffer_flush(struct buffer *buffer);
ssize_t buffer_make_room(struct buffer *buffer, size_t size, bool usefile,
			 size_t max_buffer_size);
int buffer_truncate(struct buffer *buffer, size_t len);

ssize_t buffer_read_fd(struct buffer *buffer, int fd, size_t chunk,
		       bool usefile, size_t max_buffer_size);
int buffer_add_data(struct buffer *buffer, char *addr, size_t len,
		    bool usefile, size_t max_buffer_size);

typedef int (*buffer_cb_t)(void *data, void *addr, size_t len);
int buffer_iterate(struct buffer *buffer, buffer_cb_t cb, void *data);
void buffer_print(struct buffer *buffer);

#endif /* BUFFER_H */
