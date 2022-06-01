/*
 * Libcurl utils
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include <curl/curl.h>
#include <stdio.h>

#include "lib/zt_common.h"
#include "libpv/curl.h"

struct UserData {
	GByteArray *buffer;
	uint max_size;
};

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	g_assert(userdata);
	struct UserData *data = (struct UserData *)userdata;
	GByteArray *buffer = data->buffer;
	uint64_t actual_size;
	size_t err;

	g_assert(buffer);

	if (!g_uint64_checked_mul(&actual_size, size, nmemb))
		g_abort();

	/* Signal an error condition by returning a amount that differs
	 * from the amount passed to the callback. This results in a
	 * CURLE_WRITE_ERROR.
	 */
	err = actual_size + 1;

	if (actual_size > G_MAXUINT)
		return err;

	data->buffer = g_byte_array_append(buffer, (uint8_t *)ptr, (uint)actual_size);
	if (data->buffer->len > data->max_size)
		return err;

	return actual_size;
}

int pv_curl_init(void)
{
	if (curl_global_init(CURL_GLOBAL_ALL) != 0)
		return -1;
	return 0;
}

void pv_curl_cleanup(void)
{
	curl_global_cleanup();
}

GByteArray *curl_download(const char *url, long timeout_ms, uint max_size, GError **err)
{
	g_autoptr(GByteArray) ret = NULL;
	g_autoptr(CURL) handle = NULL;
	g_autofree char *agent = NULL;
	struct UserData userdata;
	CURLcode rc;

	/* set up curl session */
	handle = curl_easy_init();
	if (!handle)
		g_abort();

	/* follow redirection */
	rc = curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
	if (rc != CURLE_OK)
		goto curl_err;
	rc = curl_easy_setopt(handle, CURLOPT_TIMEOUT_MS, timeout_ms);
	if (rc != CURLE_OK)
		goto curl_err;
	rc = curl_easy_setopt(handle, CURLOPT_NOSIGNAL, 1L);
	if (rc != CURLE_OK)
		goto curl_err;
	agent = g_strdup_printf("%s/%s", GETTEXT_PACKAGE, RELEASE_STRING);
	rc = curl_easy_setopt(handle, CURLOPT_USERAGENT, agent);
	if (rc != CURLE_OK)
		goto curl_err;
	rc = curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_callback);
	if (rc != CURLE_OK)
		goto curl_err;
	ret = g_byte_array_new();
	userdata.buffer = ret;
	userdata.max_size = max_size;
	rc = curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&userdata);
	if (rc != CURLE_OK)
		goto curl_err;
	rc = curl_easy_setopt(handle, CURLOPT_URL, url);
	if (rc != CURLE_OK)
		goto curl_err;

	rc = curl_easy_perform(handle);
	if (rc != CURLE_OK) {
		g_set_error(err, PV_CURL_ERROR, PV_CURL_ERROR_DOWNLOAD_FAILED,
			    _("download failed: %s"), curl_easy_strerror(rc));
		return NULL;
	}

	return g_steal_pointer(&ret);
curl_err:
	g_set_error(err, PV_CURL_ERROR, PV_CURL_ERROR_CURL_INIT_FAILED,
		    _("cURL initialization failed: %s"), curl_easy_strerror(rc));
	return NULL;
}
