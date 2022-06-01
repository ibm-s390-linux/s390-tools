/*
 * Common functions for pvattest.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include <stdio.h>
#include <sys/stat.h>

#include "libpv/glib-helper.h"

#include "types.h"
#include "common.h"

gboolean wrapped_g_file_set_content(const char *filename, GBytes *bytes, mode_t mode,
				    GError **error)
{
	const void *data;
	size_t size;
	gboolean rc;

	data = g_bytes_get_data(bytes, &size);
	rc = g_file_set_contents(filename, data, (ssize_t)size, error);
	if (rc && mode != 0666)
		chmod(filename, mode);
	return rc;
}

GBytes *secure_gbytes_concat(GBytes *lh, GBytes *rh)
{
	g_autoptr(GByteArray) lha = NULL;

	if (!lh && !rh)
		return NULL;
	if (!lh)
		return g_bytes_ref(rh);
	if (!rh)
		return g_bytes_ref(lh);
	lha = g_bytes_unref_to_array(g_bytes_ref(lh));
	g_byte_array_append(lha, g_bytes_get_data(rh, NULL), (guint)g_bytes_get_size(rh));
	return pv_sec_gbytes_new(lha->data, lha->len);
}
