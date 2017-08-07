/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * TAR file generation
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TAR_H
#define TAR_H

#include <stdbool.h>
#include <stdlib.h>
#include <sys/stat.h>

#define TYPE_REGULAR	'0'
#define TYPE_LINK	'2'
#define TYPE_DIR	'5'

#define TAR_BLOCKSIZE	512

struct buffer;

/* emit_cb_t - Callback used for emitting chunks of a byte stream
 * @data: Arbitrary pointer passed via the @data parameter of the
 *        tar_emit_file_* functions
 * @addr: Pointer to data
 * @len: Size of data
 * Return %0 on success. Returning non-zero will indicate failure and abort
 * further data emission. */
typedef int (*emit_cb_t)(void *data, void *addr, size_t len);

int tar_emit_file_from_buffer(char *filename, char *link, size_t len,
			      struct stat *stat, char type,
			      struct buffer *content, emit_cb_t emit_cb,
			      void *data);
int tar_emit_file_from_data(char *filename, char *link, size_t len,
			    struct stat *stat, char type, void *addr,
			    emit_cb_t emit_cb, void *data);

#endif /* TAR_H */
