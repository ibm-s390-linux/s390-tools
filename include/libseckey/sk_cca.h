/*
 * libseckey - Secure key library
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef SK_CCA_H
#define SK_CCA_H

#include <stddef.h>
#include <stdbool.h>

#include <openssl/evp.h>

#include "libseckey/sk_openssl.h"

#define CCA_MAX_PKA_KEY_TOKEN_SIZE	3500

int SK_CCA_generate_ec_key_pair(const struct sk_ext_cca_lib *cca_lib,
				int curve_nid, unsigned char *key_token,
				size_t *key_token_length, bool debug);

int SK_CCA_generate_rsa_key_pair(const struct sk_ext_cca_lib *cca_lib,
				 size_t modulus_bits, unsigned int pub_exp,
				 unsigned char *key_token,
				 size_t *key_token_length, bool debug);

int SK_CCA_get_key_type(const unsigned char *key_token, size_t key_token_length,
			int *pkey_type);

int SK_CCA_get_secure_key_as_pkey(const struct sk_ext_cca_lib *cca_lib,
				  const unsigned char *key_token,
				  size_t key_token_length,
				  bool rsa_pss, EVP_PKEY **pkey, bool debug);

int SK_CCA_get_public_from_secure_key(const unsigned char *key_token,
				      size_t key_token_length,
				      sk_pub_key_func_t pub_key_cb,
				      void *private,
				      bool debug);

int SK_CCA_reencipher_key(const struct sk_ext_cca_lib *cca_lib,
			  unsigned char *key_token, size_t key_token_length,
			  bool to_new, bool debug);

#endif
