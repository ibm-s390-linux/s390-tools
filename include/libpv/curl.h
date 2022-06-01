/*
 * Libcurl utils
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef LIBPV_CURL_H
#define LIBPV_CURL_H

#include <curl/curl.h>

#include "libpv/common.h"

#define CRL_DOWNLOAD_TIMEOUT_MS 3000
#define CRL_DOWNLOAD_MAX_SIZE 0x100000

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(CURL, curl_easy_cleanup)

/** curl_download:
 * @url: URL to specify location of data
 * @timeout_ms: time to wait until fail
 * @max_size: Maximum size of the downloaded data
 * @error: return location for a GError
 *
 * Returns: (nullable) (transfer full): Downloaded data as #GByteArray
 */
GByteArray *curl_download(const char *url, long timeout_ms, uint max_size, GError **err);

/** pv_curl_init:
 *
 * Should not be called by user.
 * Use pv_init() instead which
 * calls this function during creation.
 */
int pv_curl_init(void);

/** pv_curl_cleanup:
 *
 * Should not be called by user.
 * Use pv_cleanup() instead which
 * calls this function during creation.
 */
void pv_curl_cleanup(void);

#define PV_CURL_ERROR g_quark_from_static_string("pv-curl-error-quark")
typedef enum {
	PV_CURL_ERROR_CURL_INIT_FAILED,
	PV_CURL_ERROR_DOWNLOAD_FAILED,
} PvCurlErrors;

#endif /* LIBPV_CURL_H */
