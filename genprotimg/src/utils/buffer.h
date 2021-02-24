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

typedef struct PvBuffer {
	void *data;
	gsize size; /* in bytes */
} PvBuffer;

PvBuffer *pv_buffer_alloc(gsize size);
void pv_buffer_free(PvBuffer *buf);
void pv_buffer_clear(PvBuffer **buf);
gint pv_buffer_write(const PvBuffer *buf, FILE *file, GError **err);
PvBuffer *pv_buffer_dup(const PvBuffer *buf, gboolean page_aligned);

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvBuffer, pv_buffer_free)

#endif
