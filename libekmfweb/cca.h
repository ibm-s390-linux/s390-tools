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

#include <json-c/json.h>

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

/* CCA Digital Signature Generate function */
typedef void (*CSNDDSG_t)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *PKA_private_key_identifier_length,
			  unsigned char *PKA_private_key_identifier,
			  long *hash_length,
			  unsigned char *hash,
			  long *signature_field_length,
			  long *signature_bit_length,
			  unsigned char *signature_field);

/* CCA Key Token Build2 function */
typedef void (*CSNBKTB2_t)(long *return_code,
			   long *reason_code,
			   long *exit_data_length,
			   unsigned char *exit_data,
			   long *rule_array_count,
			   unsigned char *rule_array,
			   long *clear_key_bit_length,
			   unsigned char *clear_key_value,
			   long *key_name_length,
			   unsigned char *key_name,
			   long *user_associated_data_length,
			   unsigned char *user_associated_data,
			   long *token_data_length,
			   unsigned char *token_data,
			   long *verb_data_length,
			   unsigned char *verb_data,
			   long *target_key_token_length,
			   unsigned char *target_key_token);

/* CCA EC Diffie-Hellman function */
typedef void (*CSNDEDH_t)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *private_key_identifier_length,
			  unsigned char *private_key_identifier,
			  long *private_KEK_key_identifier_length,
			  unsigned char *private_KEK_key_identifier,
			  long *public_key_identifier_length,
			  unsigned char *public_key_identifier,
			  long *chaining_vector_length,
			  unsigned char *chaining_vector,
			  long *party_info_length,
			  unsigned char *party_info,
			  long *key_bit_length,
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
			  long *output_KEK_key_identifier_length,
			  unsigned char *output_KEK_key_identifier,
			  long *output_key_identifier_length,
			  unsigned char *output_key_identifier);

/* CCA Symmetric Key Import2 function */
typedef void (*CSNDSYI2_t)(long *return_code,
			   long *reason_code,
			   long *exit_data_length,
			   unsigned char *exit_data,
			   long *rule_array_count,
			   unsigned char *rule_array,
			   long *enciphered_key_length,
			   unsigned char *enciphered_key,
			   long *transport_key_identifier_length,
			   unsigned char *transport_key_identifier,
			   long *key_name_length,
			   unsigned char *key_name,
			   long *target_key_identifier_length,
			   unsigned char *target_key_identifier);

struct cca_lib {
	CSNDPKB_t dll_CSNDPKB;
	CSNDPKG_t dll_CSNDPKG;
	CSNDKTC_t dll_CSNDKTC;
	CSNDDSG_t dll_CSNDDSG;
	CSNBKTB2_t dll_CSNBKTB2;
	CSNDEDH_t dll_CSNDEDH;
	CSNDSYI2_t dll_CSNDSYI2;
};

#define CCA_MAX_PKA_KEY_TOKEN_SIZE	3500
#define CCA_MAX_SYM_KEY_TOKEN_SIZE	725

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

int cca_get_ecc_pub_key_as_pkey(const unsigned char *key_token,
				size_t key_token_length,
				EVP_PKEY **pkey, bool verbose);

int cca_get_ecc_pub_key_as_json_web_key(const unsigned char *key_token,
					size_t key_token_length,
					json_object **jwk, bool verbose);

int cca_get_rsa_pub_key_as_pkey(const unsigned char *key_token,
				size_t key_token_length,
				int pkey_type, EVP_PKEY **pkey, bool verbose);

int cca_import_key_from_json_web_key(const struct ekmf_cca_lib *cca_lib,
				     json_object *jwk, unsigned char *key_token,
				     size_t *key_token_length, bool verbose);

enum cca_kdf {
	CCA_KDF_ANS_X9_63_CCA = 1,     /* CCA DERIVE01 method */
	CCA_KDF_ANS_X9_63_SHA224 = 2,  /* CCA DERIVE02 method with SHA-224 */
	CCA_KDF_ANS_X9_63_SHA256 = 3,  /* CCA DERIVE02 method with SHA-256 */
	CCA_KDF_ANS_X9_63_SHA384 = 4,  /* CCA DERIVE02 method with SHA-284 */
	CCA_KDF_ANS_X9_63_SHA512 = 5,  /* CCA DERIVE02 method with SHA-512 */
};

int cca_ec_dh_derive_importer(const struct ekmf_cca_lib *cca_lib,
			      const unsigned char *priv_ecc_key_token,
			      size_t priv_ecc_key_token_length,
			      const unsigned char *pub_ecc_key_token,
			      size_t pub_ecc_key_token_length,
			      const unsigned char *party_info,
			      size_t party_info_length,
			      enum cca_kdf kdf,
			      unsigned char *derived_key_token,
			      size_t *derived_key_token_length,
			      bool verbose);

int cca_import_external_key(const struct ekmf_cca_lib *cca_lib,
			    const unsigned char *external_key_token,
			    size_t external_key_token_length,
			    const unsigned char *importer_key_token,
			    size_t importer_key_token_length,
			    unsigned char *imported_key_token,
			    size_t *imported_key_token_length,
			    bool verbose);

int cca_rsa_sign(const struct ekmf_cca_lib *cca_lib,
		 const unsigned char *key_token, size_t key_token_length,
		 unsigned char *sig, size_t *siglen,
		 const unsigned char *tbs, size_t tbslen,
		 int padding_type, int digest_nid, bool verbose);

int cca_rsa_pss_sign(const struct ekmf_cca_lib *cca_lib,
		     const unsigned char *key_token, size_t key_token_length,
		     unsigned char *sig, size_t *siglen,
		     const unsigned char *tbs, size_t tbslen,
		     int digest_nid, int mgf_digest_nid, int saltlen,
		     bool verbose);

int cca_ecdsa_sign(const struct ekmf_cca_lib *cca_lib,
		   const unsigned char *key_token, size_t key_token_length,
		   unsigned char *sig, size_t *siglen,
		   const unsigned char *tbs, size_t tbslen, int digest_nid,
		   bool verbose);

#endif
