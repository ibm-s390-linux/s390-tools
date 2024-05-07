/*
 * General cryptography helper functions and definitions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef LIBPV_CRYPTO_H
#define LIBPV_CRYPTO_H

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "libpv/common.h"
#define PV_NONNULL(...)

typedef struct pv_cipher_parms {
	const EVP_CIPHER *cipher;
	size_t tag_size;
	GBytes *key;
	union {
		GBytes *iv;
		GBytes *tweak;
	};
} PvCipherParms;

enum PvCryptoMode {
	PV_ENCRYPT,
	PV_DECRYPT,
};

/** pv_get_openssl_errors:
 *
 * Returns the last OpenSSL error messages.
 * Caller is responsible to free the returned value.
 *
 * Returns: String representing the error.
 */
char *pv_get_openssl_errors(void);

/**
 * pv_BIO_reset:
 * @b: BIO to reset
 *
 * Resets a BIO to its initial state.
 *
 * Returns: 0 in case of success, -1 otherwise.
 */
int pv_BIO_reset(BIO *b);

/* Symmetric en/decryption functions */

/**
 * pv_gcm_encrypt:
 * @plain: data to encrypt
 * @aad: (optional): additional data that should be authenticated with the key
 * @parms:
 * @cipher: (out): location to store the ciphertext
 * @tag: (out): location to store the generated GCM tag
 * @error: return location for a #GError
 *
 * Encrypts the @plain data and authenticates @aad data.
 *
 * Returns: number of bytes, or -1 in case of an error
 */
int64_t pv_gcm_encrypt(GBytes *plain, GBytes *aad, const PvCipherParms *parms, GBytes **cipher,
		       GBytes **tag, GError **error) PV_NONNULL(1, 3, 4, 5);

/**
 * pv_gcm_decrypt:
 * @cipher: ciphertext to decrypt
 * @aad: (optional): additional date to authenticate
 * @tag: the GCM tag
 * @parms:
 * @plain: (out): location to store the decrypted data
 * @error: return location for a #GError
 *
 * Decrypts the @cipher data and authenticates the @aad data.
 *
 * Returns: number of bytes, or -1 in case of an error
 */
int64_t pv_gcm_decrypt(GBytes *cipher, GBytes *aad, GBytes *tag, const PvCipherParms *parms,
		       GBytes **plain, GError **error) PV_NONNULL(1, 3, 4, 5);

/** pv_hkdf_extract_and_expand:
 * @derived_key_len: size of the output key
 * @key: input key
 * @salt: salt for the extraction
 * @info: info for the expansion
 * @md: EVP mode of operation
 * @error: return location for a #GError
 *
 * Performs a RFC 5869 HKDF.
 *
 * Returns: (nullable) (transfer full): Result of RFC 5869 HKDF
 *
 */
GBytes *pv_hkdf_extract_and_expand(size_t derived_key_len, GBytes *key, GBytes *salt, GBytes *info,
				   const EVP_MD *md, GError **error) PV_NONNULL(2, 3, 4, 5);

GQuark pv_crypto_error_quark(void);
#define PV_CRYPTO_ERROR pv_crypto_error_quark()
typedef enum {
	PV_CRYPTO_ERROR_HKDF_FAIL,
	PV_CRYPTO_ERROR_INTERNAL,
	PV_CRYPTO_ERROR_NO_MATCH_TAG,
} PvCryptoErrors;

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIO, BIO_free_all)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY, EVP_PKEY_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY_CTX, EVP_PKEY_CTX_free)

#endif /* LIBPV_CRYPTO_H */
