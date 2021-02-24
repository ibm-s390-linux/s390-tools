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
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <openssl/safestack.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdint.h>

#include "common.h"
#include "include/pv_crypto_def.h"
#include "lib/zt_common.h"

#include "buffer.h"

#define AES_256_GCM_IV_SIZE  12
#define AES_256_GCM_TAG_SIZE 16

#define AES_256_XTS_TWEAK_SIZE 16
#define AES_256_XTS_KEY_SIZE   64

#define CRL_DOWNLOAD_TIMEOUT_MS 3000
#define CRL_DOWNLOAD_MAX_SIZE	(1024 * 1024) /* in bytes */

enum PvCryptoMode {
	PV_ENCRYPT,
	PV_DECRYPT,
};

typedef GSList HostKeyList;

/* play nice with g_autoptr */
typedef STACK_OF(DIST_POINT) STACK_OF_DIST_POINT;
typedef STACK_OF(X509) STACK_OF_X509;
typedef STACK_OF(X509_CRL) STACK_OF_X509_CRL;

void STACK_OF_DIST_POINT_free(STACK_OF_DIST_POINT *stack);
void STACK_OF_X509_free(STACK_OF_X509 *stack);
void STACK_OF_X509_CRL_free(STACK_OF_X509_CRL *stack);

typedef struct {
	X509 *cert;
	const gchar *path;
} x509_with_path;

x509_with_path *x509_with_path_new(X509 *cert, const gchar *path);
void x509_with_path_free(x509_with_path *cert);

typedef struct {
	X509 *cert;
	STACK_OF_X509_CRL *crls;
} x509_pair;

x509_pair *x509_pair_new(X509 **cert, STACK_OF_X509_CRL **crls);
void x509_pair_free(x509_pair *pair);

/* Register auto cleanup functions */
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(ASN1_INTEGER, ASN1_INTEGER_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(ASN1_OCTET_STRING, ASN1_OCTET_STRING_free)
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
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(STACK_OF_DIST_POINT, STACK_OF_DIST_POINT_free);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(STACK_OF_X509, STACK_OF_X509_free);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(STACK_OF_X509_CRL, STACK_OF_X509_CRL_free);
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509, X509_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_CRL, X509_CRL_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_LOOKUP, X509_LOOKUP_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_NAME, X509_NAME_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(x509_pair, x509_pair_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE, X509_STORE_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_STORE_CTX, X509_STORE_CTX_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(X509_VERIFY_PARAM, X509_VERIFY_PARAM_free)
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(x509_with_path, x509_with_path_free)

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
	const PvBuffer *key;
	const PvBuffer *iv_or_tweak;
};

int check_crl_valid_for_cert(X509_CRL *crl, X509 *cert,
			     gint verify_flags, GError **err);
void pv_crypto_init(void);
void pv_crypto_cleanup(void);
const ASN1_OCTET_STRING *get_digicert_assured_id_root_ca_skid(void);
gint verify_host_key(X509 *host_key, GSList *issuer_pairs,
		     gint verify_flags, int level, GError **err);
X509 *load_cert_from_file(const char *path, GError **err);
X509_CRL *load_crl_from_file(const gchar *path, GError **err);
GSList *load_certificates(const gchar *const *cert_paths, GError **err);
STACK_OF_X509 *get_x509_stack(const GSList *x509_with_path_list);
X509_STORE *store_setup(const gchar *root_ca_path,
			const gchar * const *crl_paths,
			GError **err);
int store_set_verify_param(X509_STORE *store, GError **err);
X509_CRL *load_crl_by_cert(X509 *cert, GError **err);
STACK_OF_X509_CRL *try_load_crls_by_certs(GSList *certs_with_path);
gint check_chain_parameters(const STACK_OF_X509 *chain,
			    const ASN1_OCTET_STRING *skid, GError **err);
X509_NAME *c2b_name(const X509_NAME *name);

STACK_OF_X509 *delete_ibm_signing_certs(STACK_OF_X509 *certs);
STACK_OF_X509_CRL *store_ctx_find_valid_crls(X509_STORE_CTX *ctx, X509 *cert,
					     GError **err);
X509_STORE_CTX *create_store_ctx(X509_STORE *trusted, STACK_OF_X509 *chain,
				 GError **err);
gint verify_cert(X509 *cert, X509_STORE_CTX *ctx, GError **err);
X509_CRL *get_first_valid_crl(X509_STORE_CTX *ctx, X509 *cert, GError **err);
void store_setup_crl_download(X509_STORE *st);
EVP_PKEY *read_ec_pubkey_cert(X509 *cert, gint nid, GError **err);

PvBuffer *compute_exchange_key(EVP_PKEY *cust, EVP_PKEY *host, GError **err);
PvBuffer *generate_aes_key(guint size, GError **err);
PvBuffer *generate_aes_iv(guint size, GError **err);
EVP_PKEY *generate_ec_key(gint nid, GError **err);
gint generate_tweak(union tweak *tweak, uint16_t i, GError **err);
union ecdh_pub_key *evp_pkey_to_ecdh_pub_key(EVP_PKEY *key, GError **err);
EVP_MD_CTX *digest_ctx_new(const EVP_MD *md, GError **err);
PvBuffer *digest_ctx_finalize(EVP_MD_CTX *ctx, GError **err);
PvBuffer *sha256_buffer(const PvBuffer *buf, GError **err);
int64_t gcm_encrypt(const PvBuffer *in, const PvBuffer *aad,
		    const struct cipher_parms *parms, PvBuffer *out,
		    PvBuffer *tag, GError **err);
gint encrypt_file(const struct cipher_parms *parms, const gchar *in_path,
		  const gchar *path_out, gsize *in_size, gsize *out_size,
		  GError **err);
PvBuffer *encrypt_buf(const struct cipher_parms *parms, const PvBuffer *in,
		      GError **err);
G_GNUC_UNUSED PvBuffer *decrypt_buf(const struct cipher_parms *parms,
				    const PvBuffer *in, GError **err);

#endif
