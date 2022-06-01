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

typedef struct pv_cipher_parms {
	const EVP_CIPHER *cipher;
	size_t tag_size;
	GBytes *key;
	union {
		GBytes *iv;
		GBytes *tweak;
	};
} PvCipherParms;

typedef union {
	struct {
		uint8_t x[80];
		uint8_t y[80];
	};
	uint8_t data[160];
} PvEcdhPubKey;
G_STATIC_ASSERT(sizeof(PvEcdhPubKey) == 160);

typedef GSList PvEvpKeyList;

enum PvCryptoMode {
	PV_ENCRYPT,
	PV_DECRYPT,
};

/** pv_get_openssl_error:
 *
 * Returns: (transfer full): String representing the error.
 */
const char *pv_get_openssl_error(void);

/**
 * pv_BIO_reset:
 * @b: BIO to reset
 *
 * Resets a BIO to its initial state.
 *
 * Returns: 0 in case of success, -1 otherwise.
 */
int pv_BIO_reset(BIO *b);

/**
 * pv_generate_rand_data:
 * @size: number of generated random bytes using a crypographically secure pseudo random generator
 * @error: return location for a #GError
 *
 * Creates a new #GBytes with @size random bytes using a cryptographically
 * secure pseudo random generator.
 *
 * Returns: (nullable) (transfer full): a new #GBytes, or %NULL in case of an error
 */
GBytes *pv_generate_rand_data(size_t size, GError **error);

/**
 * pv_generate_key:
 * @cipher: specifies the OpenSSL cipher for which a cryptographically secure key should be generated
 * @error: return location for a #GError
 *
 * Creates a random key for @cipher using a cryptographically secure pseudo
 * random generator.
 *
 * Returns: (nullable) (transfer full): a new #GBytes, or %NULL in case of an error
 */
GBytes *pv_generate_key(const EVP_CIPHER *cipher, GError **error) PV_NONNULL(1);

/**
 * pv_generate_iv:
 * @cipher: specifies the OpenSSL cipher for which a cryptographically secure IV should be generated
 * @error: return location for a #GError
 *
 * Creates a random IV for @cipher using a cryptographically secure pseudo
 * random generator.
 *
 * Returns: (nullable) (transfer full): a new #GBytes, or %NULL in case of an error
 */
GBytes *pv_generate_iv(const EVP_CIPHER *cipher, GError **error) PV_NONNULL(1);

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
 * @info: infor for the expansion
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

/** pv_generate_ec_key:
 *
 * @nid: Numerical identifier of the curve
 * @error: return location for a #GError
 *
 * Returns: (nullable) (transfer full): new random key based on the given curve
 */
EVP_PKEY *pv_generate_ec_key(int nid, GError **error);

/** pv_evp_pkey_to_ecdh_pub_key:
 *
 * @key: input key in EVP_PKEY format
 * @error: return location for a #GError
 *
 * Returns: the public part of the input @key in ECDH format.
 */
PvEcdhPubKey *pv_evp_pkey_to_ecdh_pub_key(EVP_PKEY *key, GError **error) PV_NONNULL(1);

/** pv_derive_exchange_key:
 * @cust: Customer Key
 * @host: Host key
 * @error: return location for a #GError
 *
 * Returns: (nullable) (transfer full): Shared Secret of @cust and @host
 */
GBytes *pv_derive_exchange_key(EVP_PKEY *cust, EVP_PKEY *host, GError **error) PV_NONNULL(1, 2);

GQuark pv_crypto_error_quark(void);
#define PV_CRYPTO_ERROR pv_crypto_error_quark()
typedef enum {
	PV_CRYPTO_ERROR_DERIVE,
	PV_CRYPTO_ERROR_HKDF_FAIL,
	PV_CRYPTO_ERROR_INTERNAL,
	PV_CRYPTO_ERROR_INVALID_KEY_SIZE,
	PV_CRYPTO_ERROR_KEYGENERATION,
	PV_CRYPTO_ERROR_RANDOMIZATION,
	PV_CRYPTO_ERROR_READ_FILE,
	PV_CRYPTO_ERROR_NO_IBM_Z_SIGNING_KEY,
	PV_CRYPTO_ERROR_NO_MATCH_TAG,
} PvCryptoErrors;

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(ASN1_INTEGER, ASN1_INTEGER_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(ASN1_OCTET_STRING, ASN1_OCTET_STRING_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIO, BIO_free_all)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIGNUM, BN_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BN_CTX, BN_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_GROUP, EC_GROUP_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_KEY, EC_KEY_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_POINT, EC_POINT_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY, EVP_PKEY_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY_CTX, EVP_PKEY_CTX_free)

#endif /* LIBPV_CRYPTO_H */
