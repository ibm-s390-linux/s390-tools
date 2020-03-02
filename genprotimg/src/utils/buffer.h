/*
 * Buffer definition and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_UTILS_BUFFER_H
#define PV_UTILS_BUFFER_H

#include <glib.h>
#include <stdio.h>

#include "common.h"

typedef struct Buffer {
	void *data;
	gsize size; /* in bytes */
} Buffer;

Buffer *buffer_alloc(gsize size);
void buffer_free(Buffer *buf);
void buffer_clear(Buffer **buf);
gint buffer_write(const Buffer *buf, FILE *file, GError **err);
Buffer *buffer_dup(const Buffer *buf, gboolean page_aligned);

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(Buffer, buffer_free)

#endif
