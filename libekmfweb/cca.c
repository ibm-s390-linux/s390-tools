/*
 * libekmfweb - EKMFWeb client library
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include "lib/zt_common.h"

#include "libseckey/sk_utilities.h"

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>

#include "cca.h"
#include "utilities.h"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

/* Internal CCA definitions */

#define CCA_KEYWORD_SIZE		8
#define CCA_KEY_ID_SIZE			64

struct cca_ecc_pub_key_value_struct {
	uint8_t		curve_type;
	uint8_t		reserved;
	uint16_t	curve_length;
	uint16_t	public_key_len;
} __packed;

#define CCA_PRIME_CURVE			0x00
#define CCA_BRAINPOOL_CURVE		0x01

struct cca_token_header {
	uint8_t		token_identifier;
	uint8_t		token_version1; /* Used for PKA key tokens */
	uint16_t	token_length;
	uint8_t		token_version2; /* Used for symmetric key tokens */
	uint8_t		reserved[3];
} __packed;

/* Key token identifiers */
#define CCA_TOKEN_ID_NULL			0x00
#define CCA_TOKEN_ID_INTERNAL_SYMMETRIC		0x01
#define CCA_TOKEN_ID_EXTERNAL_SYMMETRIC		0x02
#define CCA_TOKEN_ID_EXTERNAL_PKA		0x1e
#define CCA_TOKEN_ID_INTERNAL_PKA		0x1f

/* Key token versions */
#define CCA_TOKEN_VERS1_V0			0x00
#define CCA_TOKEN_VERS2_DES_V0			0x00
#define CCA_TOKEN_VERS2_DES_V1			0x01
#define CCA_TOKEN_VERS2_AES_DATA		0x04
#define CCA_TOKEN_VERS2_AES_CIPHER		0x05

/**
 * Gets the CCA library function entry points from the library handle
 */
static int _cca_get_library_functions(const struct ekmf_cca_lib *cca_lib,
				      struct cca_lib *cca)
{
	if (cca_lib == NULL || cca == NULL)
		return -EINVAL;

	cca->dll_CSNDPKB = (CSNDPKB_t)dlsym(cca_lib->cca_lib, "CSNDPKB");
	cca->dll_CSNBKTB2 = (CSNBKTB2_t)dlsym(cca_lib->cca_lib, "CSNBKTB2");
	cca->dll_CSNDEDH = (CSNDEDH_t)dlsym(cca_lib->cca_lib, "CSNDEDH");
	cca->dll_CSNDSYI2 = (CSNDSYI2_t)dlsym(cca_lib->cca_lib, "CSNDSYI2");

	if (cca->dll_CSNDPKB == NULL ||  cca->dll_CSNBKTB2 == NULL ||
	    cca->dll_CSNDEDH == NULL || cca->dll_CSNDSYI2 == NULL)
		return -EIO;

	return 0;
}

/**
 * Import a CCA key from a JSON object representing a key as JSON Web Key (JWK,
 * see RFC7517). The JWK can either be an ECC public key (kty=EC), or an
 * symmetric key (kty=oct) containing an CCA external variable length key token
 * (alg=A256KW-CCA).
 *
 * @param cca_lib           the CCA library structure
 * @param jwk               the JWT JSON object containing the key to import
 * @param key_token         a buffer to store the imported key token
 * @param key_token_length  On entry: the size of the buffer
 *                          On return: the size of the key token

 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_import_key_from_json_web_key(const struct ekmf_cca_lib *cca_lib,
				     json_object *jwk, unsigned char *key_token,
				     size_t *key_token_length, bool verbose)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	long key_value_struct_length, private_key_name_length = 0;
	struct cca_ecc_pub_key_value_struct *key_value_struct = NULL;
	unsigned char private_key_name[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char rule_array[1 * CCA_KEYWORD_SIZE] = { 0, };
	const struct sk_ec_curve_info *curve_info;
	unsigned char *exit_data = NULL;
	size_t prime_len, q_len, len;
	unsigned char *param2 = NULL;
	struct cca_token_header *hdr;
	const char *kty, *crv, *alg;
	struct cca_lib cca;
	long token_length;
	unsigned char *q;
	long param1 = 0;
	int nid, rc = 0;

	if (cca_lib == NULL || jwk == NULL || key_token == NULL ||
	    key_token_length == NULL)
		return -EINVAL;

	rc = _cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CCA functions from library");
		return rc;
	}

	memset(key_token, 0, *key_token_length);

	kty = json_get_string(jwk, "kty");
	if (kty == NULL) {
		pr_verbose(verbose, "JWK does not contain field 'kty'");
		rc = -EIO;
		goto out;
	}

	if (strcmp(kty, "EC") == 0) {
		crv = json_get_string(jwk, "crv");
		if (crv == NULL) {
			pr_verbose(verbose, "JWK does not contain field 'crv'");
			rc = -EIO;
			goto out;
		}

		nid = EC_curve_nist2nid(crv);
		if (nid == NID_undef) {
			pr_verbose(verbose, "curve '%s' not supported", crv);
			rc = -EIO;
			goto out;
		}

		curve_info = SK_UTIL_ec_get_curve_info(nid);
		if (curve_info == NULL) {
			pr_verbose(verbose, "Unsupported curve: %d", nid);
			rc = -EINVAL;
			goto out;
		}

		prime_len = curve_info->prime_len;
		q_len = 1 + 2 * prime_len;
		key_value_struct_length =
			sizeof(struct cca_ecc_pub_key_value_struct) + q_len;
		key_value_struct = (struct cca_ecc_pub_key_value_struct *)
			malloc(key_value_struct_length);
		if (key_value_struct == NULL) {
			pr_verbose(verbose, "malloc failed");
			rc = -ENOMEM;
			goto out;
		}

		memset(key_value_struct, 0, sizeof(*key_value_struct));
		switch (curve_info->type) {
		case SK_EC_TYPE_PRIME:
			key_value_struct->curve_type = CCA_PRIME_CURVE;
			break;
		case SK_EC_TYPE_BRAINPOOL:
			key_value_struct->curve_type = CCA_BRAINPOOL_CURVE;
			break;
		default:
			pr_verbose(verbose, "Unsupported curve: %d", nid);
			rc = -EINVAL;
			goto out;
		}
		key_value_struct->curve_length = curve_info->prime_bits;
		key_value_struct->public_key_len = q_len;

		q = ((unsigned char *)key_value_struct) +
				sizeof(struct cca_ecc_pub_key_value_struct);
		q[0] = POINT_CONVERSION_UNCOMPRESSED;

		len = prime_len;
		rc = json_object_get_base64url(jwk, "x", &q[1], &len);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to get and decode x");
			goto out;
		}
		if (len != prime_len) {
			/* RFC 7517: Must be full size of a coordinate */
			pr_verbose(verbose, "x coordinate length is wrong");
			rc = -EINVAL;
			goto out;
		}

		len = prime_len;
		rc = json_object_get_base64url(jwk, "y", &q[1 + prime_len],
					       &len);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to get and decode y");
			goto out;
		}
		if (len != prime_len) {
			/* RFC 7517: Must be full size of a coordinate */
			pr_verbose(verbose, "y coordinate length is wrong");
			rc = -EINVAL;
			goto out;
		}

		rule_array_count = 1;
		memcpy(rule_array, "ECC-PUBL", CCA_KEYWORD_SIZE);

		token_length = *key_token_length;

		cca.dll_CSNDPKB(&return_code, &reason_code,
				&exit_data_len, exit_data,
				&rule_array_count, rule_array,
				&key_value_struct_length,
				(unsigned char *)key_value_struct,
				&private_key_name_length, private_key_name,
				&param1, param2, &param1, param2,
				&param1, param2, &param1, param2,
				&param1, param2,
				&token_length, key_token);
		if (return_code != 0) {
			pr_verbose(verbose, "CCA CSNDPKB (EC KEY TOKEN BUILD) "
				  "failed: return_code: %ld reason_code: %ld",
				  return_code, reason_code);
			return -EIO;
		}

		*key_token_length = token_length;
	} else if (strcmp(kty, "oct") == 0) {
		alg = json_get_string(jwk, "alg");
		if (alg == NULL) {
			pr_verbose(verbose, "JWK does not contain field 'alg'");
			rc = -EIO;
			goto out;
		}

		if (strcmp(alg, "A256KW-CCA") != 0) {
			pr_verbose(verbose, "JWK alg is not A256KW-CCA");
			rc = -EIO;
			goto out;
		}

		rc = json_object_get_base64url(jwk, "k", key_token,
					       key_token_length);
		if (rc != 0) {
			pr_verbose(verbose, "failed to get and decode k");
			goto out;
		}

		/* Ensure that this is an CCA external AES CIPHER key token */
		if (*key_token_length < sizeof(struct cca_token_header)) {
			pr_verbose(verbose, "key token is too small");
			rc = -EIO;
			goto out;
		}
		hdr = (struct cca_token_header *)key_token;
		if (hdr->token_identifier != CCA_TOKEN_ID_EXTERNAL_SYMMETRIC ||
		    hdr->token_version2 != CCA_TOKEN_VERS2_AES_CIPHER ||
		    *key_token_length < hdr->token_length) {
			pr_verbose(verbose, "key token is not a valid CCA "
				   "external AES CIPHER key");
			rc = -EIO;
			goto out;
		}
	} else {
		pr_verbose(verbose, "Key type '%s' not supported", kty);
		rc = -EIO;
		goto out;
	}

out:
	if (key_value_struct != NULL)
		free(key_value_struct);

	return rc;
}

/**
 * Drives an AES-256 key using the ED-DH key derivation method using a local ECC
 * private/public key pair, a foreign public ECC key, and a shared party
 * information data. The derived key is an internal CCA AES key token containing
 * the derived key in its IMPORTER key form.
 *
 * @param cca_lib           the CCA library structure
 * @param priv_ecc_keyf_token the ECC private key token
 * @param priv_ecc_key_token_length the length of the ECC private key token
 * @param pub_ecc_key_token the ECC public key token of the other side
 * @param pub_ecc_key_token_length the length of the ECC public key token
 * @param party_info        the shared data used on both sides
 * @param party_info_length the length of the shared data
 * @param kdf               the key derivation function to use
 * @param derived_key_token a buffer to store the derived key token
 * @param derived_key_token_length  On entry: the size of the buffer
 *                          On return: the size of the derived key token
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
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
			      bool verbose)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	long priv_length, pub_length, info_length, derived_length;
	unsigned char rule_array[3 * CCA_KEYWORD_SIZE] = { 0, };
	unsigned char key_name[CCA_KEY_ID_SIZE] = { 0, };
	long key_name_length = 0, key_skeleton_length;
	unsigned char *exit_data = NULL;
	unsigned char *param2 = NULL;
	long key_bit_length = 256;
	struct cca_lib cca;
	long param1 = 0;
	int rc;

	if (cca_lib == NULL || priv_ecc_key_token == NULL ||
	    pub_ecc_key_token == NULL || party_info == NULL ||
	    derived_key_token == NULL || derived_key_token_length == NULL)
		return -EINVAL;

	rc = _cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CCA functions from library");
		return rc;
	}

	memset(derived_key_token, 0, *derived_key_token_length);

	rule_array_count = 3;
	memcpy(rule_array, "INTERNAL", CCA_KEYWORD_SIZE);
	memcpy(rule_array + CCA_KEYWORD_SIZE, "AES     ", CCA_KEYWORD_SIZE);
	memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "IMPORTER", CCA_KEYWORD_SIZE);

	key_skeleton_length = *derived_key_token_length;

	cca.dll_CSNBKTB2(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &param1, param2,
			 &key_name_length, key_name,
			 &param1, param2,
			 &param1, param2,
			 &param1, param2,
			 &key_skeleton_length, derived_key_token);
	if (return_code != 0) {
		pr_verbose(verbose, "CCA CSNBKTB2 (KEY TOKEN BUILD2) failed: "
			  "return_code: %ld reason_code: %ld", return_code,
			  reason_code);
		return -EIO;
	}

	switch (kdf) {
	case CCA_KDF_ANS_X9_63_CCA:
		rule_array_count = 1;
		memcpy(rule_array, "DERIV01 ", CCA_KEYWORD_SIZE);
		break;
	case CCA_KDF_ANS_X9_63_SHA224:
		rule_array_count = 2;
		memcpy(rule_array, "DERIV02 ", CCA_KEYWORD_SIZE);
		memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-224 ",
		       CCA_KEYWORD_SIZE);
		break;
	case CCA_KDF_ANS_X9_63_SHA256:
		rule_array_count = 2;
		memcpy(rule_array, "DERIV02 ", CCA_KEYWORD_SIZE);
		memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-256 ",
		       CCA_KEYWORD_SIZE);
		break;
	case CCA_KDF_ANS_X9_63_SHA384:
		rule_array_count = 2;
		memcpy(rule_array, "DERIV02 ", CCA_KEYWORD_SIZE);
		memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-384 ",
		       CCA_KEYWORD_SIZE);
		break;
	case CCA_KDF_ANS_X9_63_SHA512:
		rule_array_count = 2;
		memcpy(rule_array, "DERIV02 ", CCA_KEYWORD_SIZE);
		memcpy(rule_array + CCA_KEYWORD_SIZE, "SHA-512 ",
		       CCA_KEYWORD_SIZE);
		break;
	default:
		pr_verbose(verbose, "Invalid CCA KDF: %d", kdf);
		return -EINVAL;
	}

	priv_length = priv_ecc_key_token_length;
	pub_length = pub_ecc_key_token_length;
	derived_length = *derived_key_token_length;
	info_length = party_info_length;

	cca.dll_CSNDEDH(&return_code, &reason_code,
			&exit_data_len, exit_data,
			&rule_array_count, rule_array,
			&priv_length, (unsigned char *)priv_ecc_key_token,
			&param1, param2,
			&pub_length, (unsigned char *)pub_ecc_key_token,
			&param1, param2,
			&info_length, (unsigned char *)party_info,
			&key_bit_length,
			&param1, param2, &param1, param2,
			&param1, param2, &param1, param2,
			&param1, param2, &param1, param2,
			&derived_length, derived_key_token);

	if (return_code != 0) {
		pr_verbose(verbose, "CCA CSNDEDH (EC DIFFIE-HELLMAN) failed: "
			  "return_code: %ld reason_code: %ld", return_code,
			  reason_code);
		return -EIO;
	}

	*derived_key_token_length = derived_length;

	return 0;
}

/**
 * Imports an CCA external variable length AES key token using a wrapping key
 * in IMPORTER key form.
 *
 * @param cca_lib           the CCA library structure
 * @param external_key_token the external key to import
 * @param external_key_token_length the length of the external key
 * @param importer_key_token the wrapping key in IMPORTER key form
 * @param importer_key_token_length the length of the wrapping key
 * @param imported_key_token a buffer to store the derived key token
 * @param imported_key_token_length  On entry: the size of the buffer
 *                          On return: the size of the imported key token
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_import_external_key(const struct ekmf_cca_lib *cca_lib,
			    const unsigned char *external_key_token,
			    size_t external_key_token_length,
			    const unsigned char *importer_key_token,
			    size_t importer_key_token_length,
			    unsigned char *imported_key_token,
			    size_t *imported_key_token_length,
			    bool verbose)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char rule_array[2 * CCA_KEYWORD_SIZE] = { 0, };
	unsigned char key_name[CCA_KEY_ID_SIZE] = { 0, };
	long ext_length, importer_length, imp_length;
	unsigned char *exit_data = NULL;
	long key_name_length = 0;
	struct cca_lib cca;
	int rc;

	if (cca_lib == NULL || external_key_token == NULL ||
	    importer_key_token == NULL || imported_key_token == NULL ||
	    imported_key_token_length == NULL)
		return -EINVAL;

	rc = _cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CCA functions from library");
		return rc;
	}

	memset(imported_key_token, 0, *imported_key_token_length);

	rule_array_count = 2;
	memcpy(rule_array, "AES     ", CCA_KEYWORD_SIZE);
	memcpy(rule_array + CCA_KEYWORD_SIZE, "AESKW   ", CCA_KEYWORD_SIZE);

	ext_length = external_key_token_length;
	importer_length = importer_key_token_length;
	imp_length = *imported_key_token_length;

	cca.dll_CSNDSYI2(&return_code, &reason_code,
			 &exit_data_len, exit_data,
			 &rule_array_count, rule_array,
			 &ext_length, (unsigned char *)external_key_token,
			 &importer_length, (unsigned char *)importer_key_token,
			 &key_name_length, key_name,
			 &imp_length, imported_key_token);

	if (return_code != 0) {
		pr_verbose(verbose, "CCA CSNDSYI2 (SYMM. KEY IMPORT) failed: "
			  "return_code: %ld reason_code: %ld", return_code,
			  reason_code);
		return -EIO;
	}

	*imported_key_token_length = imp_length;

	return 0;
}

