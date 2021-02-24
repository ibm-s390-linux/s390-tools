/*
 * General file utils
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pv/pv_error.h"

#include "align.h"
#include "buffer.h"
#include "common.h"
#include "file_utils.h"

FILE *file_open(const gchar *filename, const gchar *mode, GError **err)
{
	FILE *f = fopen(filename, mode);

	if (!f) {
		g_set_error(err, G_FILE_ERROR,
			    (gint)g_file_error_from_errno(errno),
			    _("Failed to open file '%s': %s"), filename,
			    g_strerror(errno));
		return NULL;
	}

	return f;
}

gint file_size(const gchar *filename, gsize *size, GError **err)
{
	GStatBuf st_buf;

	g_assert(size);

	if (g_stat(filename, &st_buf) != 0) {
		g_set_error(err, G_FILE_ERROR,
			    (gint)g_file_error_from_errno(errno),
			    _("Failed to get file status '%s': %s"), filename,
			    g_strerror(errno));
		return -1;
	}

	if (!S_ISREG(st_buf.st_mode)) {
		g_set_error(err, G_FILE_ERROR, PV_ERROR_INTERNAL,
			    _("File '%s' is not a regular file"), filename);
		return -1;
	}

	if (st_buf.st_size < 0) {
		g_set_error(err, G_FILE_ERROR, PV_ERROR_INTERNAL,
			    _("Invalid file size for '%s': %zu"), filename,
			    st_buf.st_size);
		return -1;
	}

	*size = (gsize)st_buf.st_size;
	return 0;
}

/* Returns 0 on success, otherwise -1. Stores the total number of
 * elements successfully read in @count_read
 */
gint file_read(FILE *in, void *ptr, gsize size, gsize count,
	       gsize *count_read, GError **err)
{
	gsize tmp_count_read;

	tmp_count_read = fread(ptr, size, count, in);
	if (count_read)
		*count_read = tmp_count_read;

	if (ferror(in)) {
		g_set_error(err, G_FILE_ERROR, 0, _("Failed to read file"));
		return -1;
	}

	return 0;
}

gint file_write(FILE *out, const void *ptr, gsize size, gsize count,
		gsize *count_written, GError **err)
{
	gsize tmp_count_written;

	tmp_count_written = fwrite(ptr, size, count, out);
	if (count_written)
		*count_written = tmp_count_written;

	if (tmp_count_written != count || ferror(out)) {
		g_set_error(err, G_FILE_ERROR, 0, _("Failed to write file"));
		return -1;
	}

	return 0;
}

static gint file_seek(FILE *f, uint64_t offset, GError **err)
{
	gint rc;

	if (offset > LONG_MAX) {
		g_set_error(err, PV_ERROR, 0, _("Offset is too large"));
		return -1;
	}

	rc = fseek(f, (long)offset, SEEK_SET);
	if (rc != 0) {
		g_set_error(err, G_FILE_ERROR,
			    (gint)g_file_error_from_errno(errno),
			    _("Failed to seek: '%s'"), g_strerror(errno));
		return -1;
	}

	return 0;
}

gint seek_and_write_file(FILE *o, const CompFile *ifile, uint64_t offset,
			 GError **err)
{
	gsize bytes_read, bytes_written;
	gsize total_bytes_read = 0;
	FILE *i = NULL;
	gchar buf[4096];
	gint ret = -1;

	if (file_seek(o, offset, err) < 0)
		return -1;

	i = file_open(ifile->path, "rb", err);
	if (!i)
		return -1;

	do {
		if (file_read(i, buf, 1, sizeof(buf), &bytes_read, err) < 0) {
			g_prefix_error(err, _("Failed to read file '%s': "),
				       ifile->path);
			goto err;
		}

		if (bytes_read == 0)
			break;

		total_bytes_read += bytes_read;

		if (file_write(o, buf, bytes_read, 1, &bytes_written, err) < 0)
			goto err;
	} while (bytes_written != 0);

	if (ifile->size != total_bytes_read) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("'%s' has changed during the preparation"),
			    ifile->path);
		goto err;
	}

	ret = 0;
err:
	fclose(i);
	return ret;
}

gint seek_and_write_buffer(FILE *o, const PvBuffer *buf, uint64_t offset,
			   GError **err)
{
	if (file_seek(o, offset, err) < 0)
		return -1;

	if (pv_buffer_write(buf, o, err) < 0)
		return -1;

	return 0;
}

gint pad_file_right(const gchar *path_out, const gchar *path_in, gsize *size_out,
		    guint padding, GError **err)
{
	FILE *f_in, *f_out = NULL;
	guchar buf[padding];
	gsize num_bytes_written;
	gsize num_bytes_read;
	uint64_t size_in = 0;
	gint ret = -1;

	*size_out = 0;
	f_in = file_open(path_in, "rb", err);
	if (!f_in)
		goto err;

	f_out = file_open(path_out, "wb", err);
	if (!f_out)
		goto err;

	do {
		memset(buf, 0, sizeof(buf));

		if (file_read(f_in, buf, 1, sizeof(buf), &num_bytes_read, err) < 0) {
			g_prefix_error(err, _("Failed to read file '%s': "),
				       path_in);
			goto err;
		}

		size_in += num_bytes_read;

		if (file_write(f_out, buf, 1, sizeof(buf), &num_bytes_written, err)) {
			g_prefix_error(err, _("Failed to write file '%s': "),
				       path_out);
			goto err;
		}

		*size_out += num_bytes_written;
	} while (num_bytes_read == padding);

	g_assert(num_bytes_written == ALIGN(num_bytes_read, padding));

	ret = 0;
err:
	if (f_out)
		fclose(f_out);
	if (f_in)
		fclose(f_in);
	return ret;
}
