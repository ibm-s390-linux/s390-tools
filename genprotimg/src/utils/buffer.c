/*
 * Buffer functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "align.h"
#include "buffer.h"
#include "common.h"
#include "file_utils.h"

Buffer *buffer_alloc(gsize size)
{
	Buffer *ret = g_new0(Buffer, 1);

	ret->data = g_malloc0(size);
	ret->size = size;
	return ret;
}

Buffer *buffer_dup(const Buffer *buf, gboolean page_aligned)
{
	Buffer *ret;
	gsize size;

	if (!buf)
		return NULL;

	size = buf->size;
	if (page_aligned)
		size = PAGE_ALIGN(size);

	ret = buffer_alloc(size);

	/* content will be 0-right-padded */
	memcpy(ret->data, buf->data, buf->size);
	return ret;
}

gint buffer_write(const Buffer *buf, FILE *file, GError **err)
{
	return file_write(file, buf->data, buf->size, 1, NULL, err);
}

void buffer_free(Buffer *buf)
{
	if (!buf)
		return;

	g_free(buf->data);
	g_free(buf);
}

void buffer_clear(Buffer **buf)
{
	if (!buf || !*buf)
		return;

	buffer_free(*buf);
	*buf = NULL;
}
