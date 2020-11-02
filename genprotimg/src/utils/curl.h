/*
 * Libcurl utils
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_UTILS_LIBCURL_H
#define PV_UTILS_LIBCURL_H

#include <glib.h>
#include <curl/curl.h>

#include "common.h"

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(CURL, curl_easy_cleanup)

GByteArray *curl_download(const gchar *url, long timeout_ms, guint max_size,
			  GError **err);
gint curl_init(void);
void curl_cleanup(void);

#endif /* PV_UTILS_LIBCURL_H */
