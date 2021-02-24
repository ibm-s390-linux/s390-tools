/*
 * General file utils
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_FILE_UTILS_H
#define PV_FILE_UTILS_H

#include <glib.h>
#include <stdint.h>
#include <stdio.h>

#include "pv/pv_comp.h"

#include "buffer.h"

FILE *file_open(const gchar *filename, const gchar *mode, GError **err);
gint file_size(const gchar *filename, gsize *size, GError **err);
gint file_read(FILE *in, void *ptr, gsize size, gsize count,
	       gsize *count_read, GError **err);
gint file_write(FILE *out, const void *ptr, gsize size, gsize count,
		gsize *count_written, GError **err);
gint pad_file_right(const gchar *path_out, const gchar *path_in,
		    gsize *size_out, guint padding, GError **err);
gint seek_and_write_buffer(FILE *out, const PvBuffer *buf, uint64_t offset,
			   GError **err);
gint seek_and_write_file(FILE *o, const CompFile *ifile, uint64_t offset,
			 GError **err);

#endif
