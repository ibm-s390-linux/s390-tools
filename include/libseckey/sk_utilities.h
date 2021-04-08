/*
 * libseckey - Secure key library
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef SK_UTILITIES_H
#define SK_UTILITIES_H

#include <stddef.h>
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>

#include "libseckey/sk_openssl.h"

void SK_UTIL_warnx(const char *func, const char *fmt, ...);

#define sk_debug(debug, fmt...)						\
		do {							\
			if (debug)					\
				SK_UTIL_warnx(__func__, fmt);		\
		} while (0)

/* EC curve information definitions and functions */
struct sk_ec_curve_info {
	int curve_nid;
	enum {
		SK_EC_TYPE_PRIME = 0,
		SK_EC_TYPE_BRAINPOOL = 1,
	} type;
	size_t prime_bits;
	size_t prime_len;
	const unsigned char *der; /* DER encoded OID */
	size_t der_size;
};

const struct sk_ec_curve_info *SK_UTIL_ec_get_curve_info(int curve_nid);
int SK_UTIL_ec_get_prime_curve_by_prime_bits(size_t prime_bits);
int SK_UTIL_ec_get_brainpool_curve_by_prime_bits(size_t prime_bits);

int SK_UTIL_ec_calculate_y_coordinate(int nid, size_t prime_len,
				      const unsigned char *x, int y_bit,
				      unsigned char *y);

/* Digest information definitions and functions */
struct sk_digest_info {
	int digest_nid;
	size_t digest_size;
	const char *cca_keyword;
	const unsigned char *der; /* DER encoded SEQ of OID and OCT-STRING */
	size_t der_size;
	unsigned long pkcs11_mech;
	unsigned long pkcs11_mgf;
	unsigned char x9_31_md; /* X9.31 digest identifier */
};

const struct sk_digest_info *SK_UTIL_get_digest_info(int digest_nid);

/* Helper functions for certificate and CSR handling */
int SK_UTIL_build_subject_name(X509_NAME **name, const char *rdns[],
				size_t num_rdns, bool utf8);
int SK_UTIL_build_certificate_extensions(X509 *cert, X509_REQ *req,
					 const char *exts[], size_t num_exts,
					 const STACK_OF(X509_EXTENSION)
								*addl_exts);
int SK_UTIL_generate_x509_serial_number(X509 *cert, size_t sn_bit_size);

int SK_UTIL_build_ecdsa_signature(const unsigned char *raw_sig,
				  size_t raw_sig_len,
				  unsigned char *sig, size_t *sig_len);

/* Functions to read and write keys, certificates, requests, etc. */
int SK_UTIL_read_x509_certificate(const char *pem_filename, X509 **cert);
int SK_UTIL_write_x509_certificate(const char *pem_filename, X509 *cert);
int SK_UTIL_write_x509_request(const char *pem_filename, X509_REQ *req,
			       bool new_hdr);
int SK_UTIL_read_key_blob(const char *filename, unsigned char *key_blob,
			  size_t *key_blob_len);
int SK_UTIL_write_key_blob(const char *filename, unsigned char *key_blob,
			   size_t key_blob_len);
int SK_UTIL_read_public_key(const char *pem_filename, EVP_PKEY **pkey);
int SK_UTIL_write_public_key(const char *pem_filename, EVP_PKEY *pkey);

#endif
