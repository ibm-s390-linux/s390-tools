/*
 * libekmfweb - EKMFWeb client library
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CCA_H
#define CCA_H

#include <stddef.h>
#include <stdbool.h>

#include <openssl/evp.h>

#include "ekmfweb/ekmfweb.h"

/* CCA PKA Key Generate function */
typedef void (*CSNDPKG_t)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *regeneration_data_length,
			  unsigned char *regeneration_data,
			  long *skeleton_key_token_length,
			  unsigned char *skeleton_key_token,
			  unsigned char *transport_key_identifier,
			  long *generated_key_identifier_length,
			  unsigned char *generated_key_identifier);

/* CCA PKA Key Token Build function */
typedef void (*CSNDPKB_t)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *key_values_structure_length,
			  unsigned char *key_values_structure,
			  long *key_name_ln,
			  unsigned char *key_name,
			  long *reserved_1_length,
			  unsigned char *reserved_1,
			  long *reserved_2_length,
			  unsigned char *reserved_2,
			  long *reserved_3_length,
			  unsigned char *reserved_3,
			  long *reserved_4_length,
			  unsigned char *reserved_4,
			  long *reserved_5_length,
			  unsigned char *reserved_5,
			  long *token_length, unsigned char *token);

/* CCA PKA Key Token Change function */
typedef void (*CSNDKTC_t)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *key_identifier_length,
			  unsigned char *key_identifier);

struct cca_lib {
	CSNDPKB_t dll_CSNDPKB;
	CSNDPKG_t dll_CSNDPKG;
	CSNDKTC_t dll_CSNDKTC;
};

#define CCA_MAX_PKA_KEY_TOKEN_SIZE	3500

int cca_generate_ecc_key_pair(const struct ekmf_cca_lib *cca_lib,
			      int curve_nid, unsigned char *key_token,
			      size_t *key_token_length, bool verbose);

int cca_generate_rsa_key_pair(const struct ekmf_cca_lib *cca_lib,
			      size_t modulus_bits, unsigned int pub_exp,
			      unsigned char *key_token,
			      size_t *key_token_length, bool verbose);

int cca_get_key_type(const unsigned char *key_token, size_t key_token_length,
		     int *pkey_type);

int cca_reencipher_key(const struct ekmf_cca_lib *cca_lib,
		       const unsigned char *key_token, size_t key_token_length,
		       bool to_new, bool verbose);

#endif
