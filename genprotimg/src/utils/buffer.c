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

PvBuffer *pv_buffer_alloc(gsize size)
{
	PvBuffer *ret = g_new0(PvBuffer, 1);

	ret->data = g_malloc0(size);
	ret->size = size;
	return ret;
}

PvBuffer *pv_buffer_dup(const PvBuffer *buf, gboolean page_aligned)
{
	PvBuffer *ret;
	gsize size;

	if (!buf)
		return NULL;

	size = buf->size;
	if (page_aligned)
		size = PAGE_ALIGN(size);

	ret = pv_buffer_alloc(size);

	/* content will be 0-right-padded */
	memcpy(ret->data, buf->data, buf->size);
	return ret;
}

gint pv_buffer_write(const PvBuffer *buf, FILE *file, GError **err)
{
	return file_write(file, buf->data, buf->size, 1, NULL, err);
}

void pv_buffer_free(PvBuffer *buf)
{
	if (!buf)
		return;

	g_free(buf->data);
	g_free(buf);
}

void pv_buffer_clear(PvBuffer **buf)
{
	if (!buf || !*buf)
		return;

	pv_buffer_free(*buf);
	*buf = NULL;
}
