/*
 * Libpv common functions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */
/* Must be included before any other header */
#include "config.h"

#include "libpv/common.h"
#include "libpv/cert.h"
#include "libpv/curl.h"

/* setup and tear down */
int pv_init(void)
{
	static size_t openssl_initalized;

	if (g_once_init_enter(&openssl_initalized)) {
		if (OPENSSL_VERSION_NUMBER < 0x1000100fL)
			g_assert_not_reached();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
		SSL_library_init();
		SSL_load_error_strings();
#else
		OPENSSL_init_crypto(0, NULL);
#endif

		if (pv_curl_init() != 0)
			return -1;

		pv_cert_init();
		g_once_init_leave(&openssl_initalized, 1);
	}
	return 0;
}

void pv_cleanup(void)
{
	pv_cert_cleanup();
	pv_curl_cleanup();
}
