/*
 * General cryptography helper functions and definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_UTILS_CRYPTO_H
#define PV_UTILS_CRYPTO_H

#include <glib.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdint.h>

#include "common.h"
#include "include/pv_crypto_def.h"
#include "lib/zt_common.h"

#include "buffer.h"

#define AES_256_GCM_IV_SIZE  12
#define AES_256_GCM_TAG_SIZE 16

#define AES_256_XTS_TWEAK_SIZE 16
#define AES_256_XTS_KEY_SIZE   64

enum PvCryptoMode {
	PV_ENCRYPT,
	PV_DECRYPT,
};

typedef GSList HostKeyList;

/* Register auto cleanup functions */
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIGNUM, BN_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BIO, BIO_free_all)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(BN_CTX, BN_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_GROUP, EC_GROUP_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_KEY, EC_KEY_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EC_POINT, EC_POINT_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_MD_CTX, EVP_MD_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY, EVP_PKEY_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(EVP_PKEY_CTX, EVP_PKEY_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509, X509_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_LOOKUP, X509_LOOKUP_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE, X509_STORE_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE_CTX, X509_STORE_CTX_free)

union cmp_index {
	struct {
		uint16_t idx;
		guchar rand[6];
	} __packed;
	uint64_t data;
};

/* The tweak is always stored in big endian format */
union tweak {
	struct {
		union cmp_index cmp_idx;
		uint64_t page_idx; /* page index */
	} __packed;
	uint8_t data[AES_256_XTS_TWEAK_SIZE];
};

struct cipher_parms {
	const EVP_CIPHER *cipher;
	const Buffer *key;
	const Buffer *iv_or_tweak;
};

EVP_PKEY *read_ec_pubkey_cert(X509_STORE *store, gint nid, const gchar *path,
			      GError **err);
Buffer *compute_exchange_key(EVP_PKEY *cust, EVP_PKEY *host, GError **err);
Buffer *generate_aes_key(guint size, GError **err);
Buffer *generate_aes_iv(guint size, GError **err);
EVP_PKEY *generate_ec_key(gint nid, GError **err);
gint generate_tweak(union tweak *tweak, uint16_t i, GError **err);
union ecdh_pub_key *evp_pkey_to_ecdh_pub_key(EVP_PKEY *key, GError **err);
EVP_MD_CTX *digest_ctx_new(const EVP_MD *md, GError **err);
Buffer *digest_ctx_finalize(EVP_MD_CTX *ctx, GError **err);
Buffer *sha256_buffer(const Buffer *buf, GError **err);
int64_t gcm_encrypt(const Buffer *in, const Buffer *aad,
		    const struct cipher_parms *parms, Buffer *out,
		    Buffer *tag, GError **err);
gint encrypt_file(const struct cipher_parms *parms, const gchar *in_path,
		  const gchar *path_out, gsize *in_size, gsize *out_size,
		  GError **err);
Buffer *encrypt_buf(const struct cipher_parms *parms, const Buffer *in,
		    GError **err);
G_GNUC_UNUSED Buffer *decrypt_buf(const struct cipher_parms *parms,
				  const Buffer *in, GError **err);

#endif
