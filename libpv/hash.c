/*
 * Hashing functions.

 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include "libpv/crypto.h"
#include "libpv/hash.h"

GBytes *pv_sha256_hash(uint8_t *buf, size_t size, GError **error)
{
	g_autoptr(EVP_MD_CTX) ctx = NULL;

	ctx = pv_digest_ctx_new(EVP_sha256(), error);
	if (!ctx)
		return NULL;

	if (pv_digest_ctx_update_raw(ctx, buf, size, error) != 0)
		return NULL;

	return pv_digest_ctx_finalize(ctx, error);
}

EVP_MD_CTX *pv_digest_ctx_new(const EVP_MD *md, GError **error)
{
	g_autoptr(EVP_MD_CTX) ctx = EVP_MD_CTX_new();

	if (!ctx) {
		g_set_error(error, PV_HASH_ERROR, PV_HASH_ERROR_INTERNAL,
			    _("Hash context generation failed"));
		return NULL;
	}

	if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
		g_set_error(error, PV_HASH_ERROR, PV_HASH_ERROR_INTERNAL,
			    _("EVP_DigestInit_ex failed"));
		return NULL;
	}

	return g_steal_pointer(&ctx);
}

int pv_digest_ctx_update_raw(EVP_MD_CTX *ctx, const uint8_t *buf, size_t size, GError **error)
{
	if (!buf || size == 0)
		return 0;

	if (EVP_DigestUpdate(ctx, buf, size) != 1) {
		g_set_error(error, PV_HASH_ERROR, PV_HASH_ERROR_INTERNAL,
			    _("EVP_DigestUpdate failed"));
		return -1;
	}
	return 0;
}

int pv_digest_ctx_update(EVP_MD_CTX *ctx, GBytes *data, GError **error)
{
	const uint8_t *buf;
	size_t buf_size;

	if (!data)
		return 0;
	buf = g_bytes_get_data((GBytes *)data, &buf_size);
	return pv_digest_ctx_update_raw(ctx, buf, buf_size, error);
}

GBytes *pv_digest_ctx_finalize(EVP_MD_CTX *ctx, GError **error)
{
	int md_size = EVP_MD_size(EVP_MD_CTX_md(ctx));
	g_autofree uint8_t *digest = NULL;
	unsigned int digest_size;

	g_assert(md_size > 0);

	digest = g_malloc0((uint)md_size);
	if (EVP_DigestFinal_ex(ctx, digest, &digest_size) != 1) {
		g_set_error(error, PV_HASH_ERROR, PV_HASH_ERROR_INTERNAL,
			    _("EVP_DigestFinal_ex failed"));
		return NULL;
	}

	g_assert(digest_size == (uint)md_size);
	return g_bytes_new_take(g_steal_pointer(&digest), digest_size);
}

HMAC_CTX *pv_hmac_ctx_new(GBytes *key, const EVP_MD *md, GError **error)
{
	g_autoptr(HMAC_CTX) ctx = HMAC_CTX_new();
	const uint8_t *key_data;
	size_t key_size;

	key_data = g_bytes_get_data(key, &key_size);

	if (HMAC_Init_ex(ctx, key_data, (int)key_size, md, NULL) != 1) {
		g_set_error(error, PV_HASH_ERROR, PV_HASH_ERROR_INTERNAL,
			    "unable to create HMAC context: %s", pv_get_openssl_error());
		return NULL;
	}
	return g_steal_pointer(&ctx);
}

int pv_hmac_ctx_update_raw(HMAC_CTX *ctx, const void *buf, size_t size, GError **error)
{
	if (!buf || size == 0)
		return 0;

	if (HMAC_Update(ctx, buf, size) != 1) {
		g_set_error(error, PV_HASH_ERROR, PV_HASH_ERROR_INTERNAL,
			    "unable to add data to HMAC context: %s", pv_get_openssl_error());
		return -1;
	}
	return 0;
}

int pv_hmac_ctx_update(HMAC_CTX *ctx, GBytes *data, GError **error)
{
	const uint8_t *buf;
	size_t buf_size;

	if (!data)
		return 0;
	buf = g_bytes_get_data((GBytes *)data, &buf_size);
	return pv_hmac_ctx_update_raw(ctx, buf, buf_size, error);
}

GBytes *pv_hamc_ctx_finalize(HMAC_CTX *ctx, GError **error)
{
	int md_size = EVP_MD_size(HMAC_CTX_get_md(ctx));
	g_autofree uint8_t *hmac = NULL;
	unsigned int hmac_size = 0;

	g_assert(md_size > 0);

	hmac = g_malloc0((unsigned int)md_size);

	if (HMAC_Final(ctx, hmac, &hmac_size) != 1) {
		g_set_error(error, PV_HASH_ERROR, PV_HASH_ERROR_INTERNAL,
			    "unable to calculate HMAC: %s", pv_get_openssl_error());
		return NULL;
	}
	return g_bytes_new_take(g_steal_pointer(&hmac), hmac_size);
}
