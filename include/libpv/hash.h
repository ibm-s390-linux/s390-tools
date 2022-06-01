/*
 * Hashing definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef LIBPV_HASH_H
#define LIBPV_HASH_H

#include <openssl/hmac.h>

#include "libpv/common.h"

/** pv_digest_ctx_new:
 * @md: mode of digest, e.g. #EVP_sha256()
 * @error: return location for a #GError
 *
 * Returns: (nullable) (transfer full): a new #EVP_MD_CTX, or %NULL in case of an error
 */
EVP_MD_CTX *pv_digest_ctx_new(const EVP_MD *md, GError **error);

/** pv_digest_ctx_update:
 * @ctx: EVP_MD_CTX to add data
 * @data: #GBytes to add to the context
 * @error: return location for a #GError
 *
 * Adds @data to the digest context. Can be called multiple times.
 *
 * Returns: 0 in case of success, -1 otherwise.
 */
int pv_digest_ctx_update(EVP_MD_CTX *ctx, GBytes *data, GError **error);

/** pv_digest_ctx_update_raw:
 * @ctx: #EVP_MD_CTX to add data
 * @buf: data to add to the context
 * @size: size of @buf
 * @error: return location for a #GError
 *
 * Adds @buf to the digest context. Can be called multiple times.
 *
 * Returns: 0 in case of success, -1 otherwise.
 */
int pv_digest_ctx_update_raw(EVP_MD_CTX *ctx, const uint8_t *buf, size_t size, GError **error);

/** pv_digest_ctx_finalize:
 * @ctx: #EVP_MD_CTX with data to digest
 * @error: return location for a #GError
 *
 * Calculates the digest of all previously added data. Do not use @ctx afterwards.
 *
 * Returns: (nullable) (transfer full): Digest of all data added before as #GBytes, or NULL in case of error.
 */
GBytes *pv_digest_ctx_finalize(EVP_MD_CTX *ctx, GError **error);

/** pv_sha256_hash:
 * @buf: data for which a sha256 hash sould be calculated
 * @size: size of @buf
 * @error: return location for a #GError
 *
 * Shorthand for initializing a sha256-digest ctx, updating, and finalizing.
 *
 * Returns: (nullable) (transfer full): SHA256 of @buf as #GBytes, or NULL in case of error.
 */
GBytes *pv_sha256_hash(uint8_t *buf, size_t size, GError **error);

/** pv_hmac_ctx_new:
 * @key: key used for the HMAC
 * @md: mode of digest, e.g. #EVP_sha512()
 * @error: return location for a #GError
 *
 * Returns: (nullable) (transfer full): New #HMAC_CTX or NULL in case of error
 */
HMAC_CTX *pv_hmac_ctx_new(GBytes *key, const EVP_MD *md, GError **error);

/** pv_hmac_ctx_update_raw:
 * @ctx: #HMAC_CTX to add data
 * @buf: data to add to the context
 * @size: size of @buf
 * @error: return location for a #GError
 *
 * Adds @buf to the HMAC context. Can be called multiple times.
 *
 * Returns: 0 in case of success, -1 otherwise.
 */
int pv_hmac_ctx_update_raw(HMAC_CTX *ctx, const void *data, size_t size, GError **error);

/** pv_hmac_ctx_update:
 * @ctx: #HMAC_CTX to add data
 * @data: #GBytes to add to the context
 * @error: return location for a #GError
 *
 * Adds @data to the HMAC context. Can be called multiple times.
 *
 * Returns: 0 in case of success, -1 otherwise.
 */

int pv_hmac_ctx_update(HMAC_CTX *ctx, GBytes *data, GError **error);

/** pv_hmac_ctx_finalize:
 * @ctx: #HMAC_CTX with data to digest
 * @error: return location for a #GError
 *
 * Calculates the HMAC of all previously added data. Do not use @ctx afterwards.
 *
 * Returns: (nullable) (transfer full): HMAC of all data added before as #GBytes, or NULL in case of error.
 */
GBytes *pv_hamc_ctx_finalize(HMAC_CTX *ctx, GError **error);

#define PV_HASH_ERROR g_quark_from_static_string("pv-crypro-error-quark")
typedef enum {
	PV_HASH_ERROR_INTERNAL,
} PvHashErrors;

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_MD_CTX, EVP_MD_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(HMAC_CTX, HMAC_CTX_free)

#endif /* LIBPV_HASH_H */
