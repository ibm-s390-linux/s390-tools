/*
 * Glib convenience functions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include <errno.h>
#include <openssl/crypto.h>

#include "libpv/glib-helper.h"

struct __data {
	void *data;
	size_t size;
	GFreeFunc free_func;
};

static void __data_clear_and_free(void *p)
{
	struct __data *ptr = p;

	if (!ptr)
		return;

	if (ptr->data) {
		OPENSSL_cleanse(ptr->data, ptr->size);
		ptr->free_func(ptr->data);
	}
	g_free(ptr);
}

static GBytes *pv_sec_gbytes_new_take_func(void *data, size_t size, GFreeFunc free_func)
{
	struct __data *tmp = g_new(struct __data, 1);

	tmp->data = data;
	tmp->size = size;
	tmp->free_func = free_func;

	return g_bytes_new_with_free_func(data, size, __data_clear_and_free, tmp);
}

GBytes *pv_sec_gbytes_new_take(void *data, size_t size)
{
	return pv_sec_gbytes_new_take_func(data, size, g_free);
}

GBytes *pv_sec_gbytes_new(const void *data, size_t size)
{
	g_autofree void *tmp_data = NULL;

	g_return_val_if_fail(data || size != 0, NULL);

	tmp_data = g_malloc(size);
	memcpy(tmp_data, data, size);
	return pv_sec_gbytes_new_take(g_steal_pointer(&tmp_data), size);
}

int pv_file_seek(FILE *file, long offset, int whence, GError **error)
{
	int cached_errno;
	int ret = fseek(file, offset, whence);

	if (ret) {
		cached_errno = errno;
		g_set_error(error, PV_GLIB_HELPER_ERROR, PV_GLIB_HELPER_FILE_ERROR,
			    "Cannot seek: %s", g_strerror(cached_errno));
	}
	return ret;
}

size_t pv_file_write(FILE *file, const void *ptr, size_t size, GError **error)
{
	int cached_errno;
	size_t n = fwrite(ptr, 1, size, file);

	if (n != size) {
		cached_errno = errno;
		g_set_error(error, PV_GLIB_HELPER_ERROR, PV_GLIB_HELPER_FILE_ERROR,
			    "Cannot write: %s", g_strerror(cached_errno));
	}
	return n;
}

long pv_file_close(FILE *file, GError **error)
{
	int cached_errno;
	int ret = fclose(file);

	if (ret) {
		cached_errno = errno;
		g_set_error(error, PV_GLIB_HELPER_ERROR, PV_GLIB_HELPER_FILE_ERROR,
			    "Cannot close: %s", g_strerror(cached_errno));
	}
	return ret;
}

void pv_auto_close_file(FILE *file)
{
	if (!file)
		return;

	(void)pv_file_close(file, NULL);
}

long pv_file_tell(FILE *file, GError **error)
{
	int cached_errno;
	long n = ftell(file);

	if (n < 0) {
		cached_errno = errno;
		g_set_error(error, PV_GLIB_HELPER_ERROR, PV_GLIB_HELPER_FILE_ERROR,
			    "Cannot tell: %s", g_strerror(cached_errno));
	}
	return n;
}

FILE *pv_file_open(const char *filename, const char *mode, GError **error)
{
	FILE *file = fopen(filename, mode);
	int cached_errno;

	if (!file) {
		cached_errno = errno;
		g_set_error(error, PV_GLIB_HELPER_ERROR, PV_GLIB_HELPER_FILE_ERROR,
			    "Cannot open '%s'. %s", filename, g_strerror(cached_errno));
		return NULL;
	}
	return file;
}

GBytes *pv_file_get_content_as_g_bytes(const char *filename, GError **error)
{
	g_autofree char *data = NULL;
	size_t data_size;

	if (!g_file_get_contents(filename, &data, &data_size, error))
		return NULL;

	return g_bytes_new_take(g_steal_pointer(&data), data_size);
}

GBytes *pv_file_get_content_as_secure_bytes(const char *filename)
{
	g_autoptr(FILE) f = fopen(filename, "rb");
	g_autofree char *data = NULL;
	ssize_t file_size;
	size_t data_size;

	if (!f)
		return NULL;

	fseek(f, 0, SEEK_END);
	file_size = ftell(f);
	if (file_size < 0)
		return NULL;
	data_size = (size_t)file_size;
	fseek(f, 0, SEEK_SET);
	data = g_malloc0(data_size);
	if (data_size != fread(data, 1, data_size, f))
		return NULL;
	return pv_sec_gbytes_new_take(g_steal_pointer(&data), data_size);
}

void *pv_gbytes_memcpy(void *dst, size_t dst_size, GBytes *src)
{
	size_t src_size;
	const void *src_data = g_bytes_get_data(src, &src_size);

	if (dst_size < src_size)
		return NULL;
	return memcpy(dst, src_data, src_size);
}
