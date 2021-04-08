/*
 * libseckey - Secure key library
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef SK_OPENSSL_H
#define SK_OPENSSL_H

#include <stddef.h>
#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef OPENSSL_VERSION_PREREQ
	#if defined(OPENSSL_VERSION_MAJOR) && defined(OPENSSL_VERSION_MINOR)
		#define OPENSSL_VERSION_PREREQ(maj, min)		\
			((OPENSSL_VERSION_MAJOR << 16) +		\
			OPENSSL_VERSION_MINOR >= ((maj) << 16) + (min))
	#else
		#define OPENSSL_VERSION_PREREQ(maj, min)		\
			(OPENSSL_VERSION_NUMBER >= (((maj) << 28) |	\
			((min) << 20)))
	#endif
#endif

/**
 * External crypto library definitions
 */

struct sk_ext_cca_lib {
	void *cca_lib; /* Handle of CCA host library loaded via dlopen */
};

typedef uint64_t target_t;

struct sk_ext_ep11_lib {
	void *ep11_lib; /* Handle of EP11 host library loaded via dlopen */
	target_t target; /* single or group target handle */
};

enum sk_ext_lib_type {
	SK_EXT_LIB_CCA = 1,
	SK_EXT_LIB_EP11 = 2,
};

struct sk_ext_lib {
	enum sk_ext_lib_type type;
	union {
		struct sk_ext_cca_lib *cca; /* Used if type = EXT_LIB_CCA */
		struct sk_ext_ep11_lib *ep11; /* Used if type = EXT_LIB_EP11 */
	};
};

/*
 * Secure key library initialization and termination functions
 */

int SK_OPENSSL_init(bool debug);
void SK_OPENSSL_term(void);

/*
 * Secure key generation and reenciphering definitions and functions
 */

enum sk_key_type {
	SK_KEY_TYPE_EC = 1,
	SK_KEY_TYPE_RSA = 2,
};

struct sk_key_gen_info {
	enum sk_key_type type;
	union {
		struct {
			int curve_nid;
		} ec;
		struct {
			size_t modulus_bits;
			unsigned int pub_exp;
			bool x9_31;
		} rsa;
	};
};

int SK_OPENSSL_generate_secure_key(unsigned char *secure_key,
				   size_t *secure_key_size,
				   const struct sk_key_gen_info *info,
				   const struct sk_ext_lib *ext_lib,
				   bool debug);

int SK_OPENSSL_reencipher_secure_key(unsigned char *secure_key,
				     size_t secure_key_size, bool to_new,
				     const struct sk_ext_lib *ext_lib,
				     bool debug);

/*
 * Get an OpenSSL PKEY from a secure key to be used with OpenSSL.
 */
int SK_OPENSSL_get_secure_key_as_pkey(const unsigned char *secure_key,
				      size_t secure_key_size, bool rsa_pss,
				      EVP_PKEY **pkey,
				      const struct sk_ext_lib *ext_lib,
				      bool debug);

/*
 * Get the public key parts from a secure key.
 */
struct sk_pub_key_info {
	enum sk_key_type type;
	union {
		struct {
			int curve_nid;
			size_t prime_len;
			const unsigned char *x;
			const unsigned char *y;
		} ec;
		struct {
			size_t modulus_len;
			const unsigned char *modulus;
			size_t pub_exp_len;
			const unsigned char *pub_exp;
		} rsa;
	};
};

typedef int (*sk_pub_key_func_t)(const struct sk_pub_key_info *pub_key,
				 void *private);

int SK_OPENSSL_get_public_from_secure_key(const unsigned char *secure_key,
					  size_t secure_key_size,
					  sk_pub_key_func_t pub_key_cb,
					  void *private,
					  const struct sk_ext_lib *ext_lib,
					  bool debug);

/*
 * Helper functions to setup a secure key sign context and to generate
 * certificate signing requests or self signed certificates with the secure key
 */

struct sk_rsa_pss_params {
	/*
	 * salt length in bytes, or OpenSSL constants
	 * RSA_PSS_SALTLEN_DIGEST (-1),	RSA_PSS_SALTLEN_AUTO (-2), or
	 * RSA_PSS_SALTLEN_MAX(-3)
	 */
	int salt_len;
	/*
	 * OpenSSl digest nid, or NID_undef to use the same digest algorithm
	 * as the signature algorithm
	 */
	int mgf_digest_nid;
};

int SK_OPENSSL_setup_sign_context(EVP_PKEY *pkey, bool verify, int digest_nid,
				  struct sk_rsa_pss_params *rsa_pss_params,
				  EVP_MD_CTX **md_ctx, EVP_PKEY_CTX **pkey_ctx,
				  bool debug);

int SK_OPENSSL_generate_csr(const unsigned char *secure_key,
			    size_t secure_key_size,
			    const char *subject_rdns[], size_t num_subject_rdns,
			    bool subject_utf8, const X509 *renew_cert,
			    const char *extensions[], size_t num_extensions,
			    int digest_nid,
			    struct sk_rsa_pss_params *rsa_pss_params,
			    X509_REQ **csr,
			    const struct sk_ext_lib *ext_lib, bool debug);

int SK_OPENSSL_generate_ss_cert(const unsigned char *secure_key,
				size_t secure_key_size,
				const char *subject_rdns[],
				size_t num_subject_rdns, bool subject_utf8,
				const X509 *renew_cert,
				const char *extensions[], size_t num_extensions,
				int validity_days, int digest_nid,
				struct sk_rsa_pss_params *rsa_pss_params,
				X509 **ss_cert,
				const struct sk_ext_lib *ext_lib, bool debug);

/*
 * Import secure keys as PKEY, or import clear public keys as PKEY
 */

typedef int (*sk_rsa_sign_t)(const unsigned char *key_blob,
			     size_t key_blob_length,
			     unsigned char *sig, size_t *siglen,
			     const unsigned char *tbs, size_t tbslen,
			     int padding_type, int md_nid,
			     void *private, bool debug);
typedef int (*sk_rsa_pss_sign_t)(const unsigned char *key_blob,
				 size_t key_blob_length, unsigned char *sig,
				 size_t *siglen, const unsigned char *tbs,
				 size_t tbslen, int md_nid, int mfgmd_nid,
				 int saltlen, void *private, bool debug);
typedef int (*sk_ecdsa_sign_t)(const unsigned char *key_blob,
			       size_t key_blob_length, unsigned char *sig,
			       size_t *siglen, const unsigned char *tbs,
			       size_t tbslen, int md_nid, void *private,
			       bool debug);
typedef int (*sk_rsa_decrypt_t)(const unsigned char *key_blob,
				size_t key_blob_length,
				unsigned char *to, size_t *tolen,
				const unsigned char *from, size_t fromlen,
				int padding_type, void *private, bool debug);
typedef int (*sk_rsa_decrypt_oaep_t)(const unsigned char *key_blob,
				     size_t key_blob_length,
				     unsigned char *to, size_t *tolen,
				     const unsigned char *from, size_t fromlen,
				     int oaep_md_nid, int mgfmd_nid,
				     unsigned char *label, int label_len,
				     void *private, bool debug);

struct sk_funcs {
	sk_rsa_sign_t		rsa_sign;
	sk_rsa_pss_sign_t	rsa_pss_sign;
	sk_ecdsa_sign_t		ecdsa_sign;
	sk_rsa_decrypt_t	rsa_decrypt;
	sk_rsa_decrypt_oaep_t	rsa_decrypt_oaep;
};

int SK_OPENSSL_get_pkey(const unsigned char *secure_key, size_t secure_key_size,
			const struct sk_pub_key_info *pub_key, bool rsa_pss,
			const struct sk_funcs *sk_funcs, const void *private,
			EVP_PKEY **pkey, bool debug);

int SK_OPENSSL_get_curve_from_ec_pkey(EVP_PKEY *pkey);

#endif
