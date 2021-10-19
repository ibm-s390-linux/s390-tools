/*
 * libseckey - Secure key library
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include "lib/zt_common.h"

#include "libseckey/sk_cca.h"
#include "libseckey/sk_openssl.h"
#include "libseckey/sk_utilities.h"

/* Internal CCA definitions */

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

/* PKA Decrypt */
typedef void (*CSNDPKD_t)(long *return_code,
			  long *reason_code,
			  long *exit_data_length,
			  unsigned char *exit_data,
			  long *rule_array_count,
			  unsigned char *rule_array,
			  long *PKA_enciphered_keyvalue_length,
			  unsigned char *PKA_enciphered_keyvalue,
			  long *data_structure_length,
			  unsigned char *data_structure,
			  long *PKA_key_identifier_length,
			  unsigned char *PKA_key_identifier,
			  long *target_keyvalue_length,
			  unsigned char *target_keyvalue);

struct cca_lib {
	CSNDPKG_t	dll_CSNDPKG;
	CSNDPKB_t	dll_CSNDPKB;
	CSNDKTC_t	dll_CSNDKTC;
	CSNDDSG_t	dll_CSNDDSG;
	CSNDPKD_t	dll_CSNDPKD;
};

#define CCA_KEYWORD_SIZE		8
#define CCA_KEY_ID_SIZE			64

struct cca_ec_key_pair_value_struct {
	uint8_t		curve_type;
	uint8_t		reserved;
	uint16_t	curve_length;
	uint16_t	priv_key_length;
	uint16_t	public_key_len;
} __packed;

struct cca_rsa_key_pair_value_struct {
	uint16_t	modulus_bit_length;
	uint16_t	modulus_length;
	uint16_t	public_exp_length;
	uint16_t	reserved;
	uint16_t	p_length;
	uint16_t	q_length;
	uint16_t	dp_length;
	uint16_t	dq_length;
	uint16_t	u_length;
	unsigned char	public_exponent[3];
} __packed;

struct cca_ec_pub_key_value_struct {
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
#define CCA_TOKEN_ID_EXTERNAL_PKA		0x1e
#define CCA_TOKEN_ID_INTERNAL_PKA		0x1f

/* Key token versions */
#define CCA_TOKEN_VERS1_V0			0x00

struct cca_section_header {
	uint8_t		section_identifier;
	uint8_t		section_version;
	uint16_t	section_length;
} __packed;

#define CCA_SECTION_ID_RSA_ME_1024_PRIV		0x02
#define CCA_SECTION_ID_RSA_PUBL			0x04
#define CCA_SECTION_ID_RSA_CRT_2048_PRIV	0x05
#define CCA_SECTION_ID_RSA_ME_1024_OPK_PRIV	0x06
#define CCA_SECTION_ID_RSA_CRT_4096_OPK_PRIV	0x08
#define CCA_SECTION_ID_RSA_ME_4096_PRIV		0x09
#define CCA_SECTION_ID_EC_PRIV			0x20
#define CCA_SECTION_ID_EC_PUBL			0x21
#define CCA_SECTION_ID_RSA_ME_1024_EOPK_PRIV	0x30
#define CCA_SECTION_ID_RSA_CRT_4096_EOPK_PRIV	0x31

struct cca_ec_pub_key_section {
	struct cca_section_header section_header;
	uint8_t		reserved1[4];
	uint8_t		curve_type;
	uint8_t		reserved2;
	uint16_t	prime_bits_length;
	uint16_t	pub_key_length; /* Incl. compression indication byte */
	/* Public key of length pub_key_length */
} __packed;

struct cca_rsa_pub_key_section {
	struct cca_section_header section_header;
	uint16_t	reserved1;
	uint16_t	pub_exp_length;
	uint16_t	modulus_bits_length;
	uint16_t	modulus_length; /* if 0 -> see priv key section */
	/* Public exponent of length pub_exp_length */
	/* Modulus of length modulus_length */
} __packed;

struct cca_rsa_crt_priv_key_section {
	struct cca_section_header section_header;
	uint16_t	assoc_data_length;
	uint16_t	payload_length;
	uint16_t	reserved1;
	uint8_t		assoc_data_version;
	uint8_t		key_format;
	uint8_t		key_source;
	uint8_t		reserved2;
	uint8_t		hash_type;
	uint8_t		hash[32];
	uint8_t		reserved3[3];
	uint8_t		key_usage;
	uint8_t		format_restriction;
	uint16_t	p_length;
	uint16_t	q_length;
	uint16_t	dp_length;
	uint16_t	dq_length;
	uint16_t	u_length;
	uint16_t	modulus_length;
	uint32_t	reserved4;
	uint8_t		opk[48];
	uint8_t		kvp[16];
	uint16_t	reserved6;
	/* Public modulus in length modulus_length */
	/* Encrypted payload (AESKW-wrapped key material) */
} __packed;

#define POINT_CONVERSION_ODD_EVEN	0x01

/**
 * Gets the CCA library function entry points from the library handle
 */
static int sk_cca_get_library_functions(const struct sk_ext_cca_lib *cca_lib,
					struct cca_lib *cca)
{
	if (cca_lib == NULL || cca == NULL)
		return -EINVAL;

	cca->dll_CSNDPKG = (CSNDPKG_t)dlsym(cca_lib->cca_lib, "CSNDPKG");
	cca->dll_CSNDPKB = (CSNDPKB_t)dlsym(cca_lib->cca_lib, "CSNDPKB");
	cca->dll_CSNDKTC = (CSNDKTC_t)dlsym(cca_lib->cca_lib, "CSNDKTC");
	cca->dll_CSNDDSG = (CSNDDSG_t)dlsym(cca_lib->cca_lib, "CSNDDSG");
	cca->dll_CSNDPKD = (CSNDPKD_t)dlsym(cca_lib->cca_lib, "CSNDPKD");

	if (cca->dll_CSNDPKG == NULL || cca->dll_CSNDPKB == NULL ||
	    cca->dll_CSNDKTC == NULL || cca->dll_CSNDDSG == NULL ||
	    cca->dll_CSNDPKD == NULL)
		return -EIO;

	return 0;
}

/**
 * Generates an CCA EC key of the specified curve type and length using the
 * CCA host library.
 *
 * @param cca_lib           the CCA library structure
 * @param curve_nid         the nid specifying the curve.
 * @param key_token         a buffer to store the generated key token
 * @param key_token_length  On entry: the size of the buffer
 *                          On return: the size of the key token
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_CCA_generate_ec_key_pair(const struct sk_ext_cca_lib *cca_lib,
				int curve_nid, unsigned char *key_token,
				size_t *key_token_length, bool debug)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0 };
	unsigned char key_skeleton[CCA_MAX_PKA_KEY_TOKEN_SIZE] = { 0 };
	long key_value_structure_length, private_key_name_length = 0;
	unsigned char regeneration_data[CCA_KEY_ID_SIZE] = { 0 };
	struct cca_ec_key_pair_value_struct key_value_structure;
	unsigned char private_key_name[CCA_KEY_ID_SIZE] = { 0 };
	unsigned char rule_array[3 * CCA_KEYWORD_SIZE] = { 0 };
	long regeneration_data_length = 0, key_skeleton_length;
	const struct sk_ec_curve_info *curve;
	unsigned char *exit_data = NULL;
	unsigned char *param2 = NULL;
	struct cca_lib cca;
	long token_length;
	long param1 = 0;
	int rc;

	if (cca_lib == NULL || key_token == NULL || key_token_length == NULL)
		return -EINVAL;

	if (key_token == NULL) {
		*key_token_length = CCA_MAX_PKA_KEY_TOKEN_SIZE;
		return 0;
	}

	sk_debug(debug, "curve_nid:  %d", curve_nid);

	rc = sk_cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get CCA functions from library");
		return rc;
	}

	memset(key_token, 0, *key_token_length);
	token_length = *key_token_length;

	memset(&key_value_structure, 0, sizeof(key_value_structure));
	curve = SK_UTIL_ec_get_curve_info(curve_nid);
	if (curve == NULL) {
		sk_debug(debug, "ERROR: Unsupported curve: %d", curve_nid);
		return -EINVAL;
	}
	switch (curve->type) {
	case SK_EC_TYPE_PRIME:
		key_value_structure.curve_type = CCA_PRIME_CURVE;
		break;
	case SK_EC_TYPE_BRAINPOOL:
		key_value_structure.curve_type = CCA_BRAINPOOL_CURVE;
		break;
	default:
		sk_debug(debug, "ERROR: Unknown curve type: %d", curve->type);
		return -EINVAL;
	}

	key_value_structure.curve_length = curve->prime_bits;
	key_value_structure_length = sizeof(key_value_structure);

	rule_array_count = 3;
	memcpy(rule_array, "ECC-PAIR", CCA_KEYWORD_SIZE);
	memcpy(rule_array + CCA_KEYWORD_SIZE, "KEY-MGMT", CCA_KEYWORD_SIZE);
	memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "ECC-VER1", CCA_KEYWORD_SIZE);

	key_skeleton_length = sizeof(key_skeleton);

	cca.dll_CSNDPKB(&return_code, &reason_code,
			&exit_data_len, exit_data,
			&rule_array_count, rule_array,
			&key_value_structure_length,
			(unsigned char *)&key_value_structure,
			&private_key_name_length, private_key_name,
			&param1, param2, &param1, param2,
			&param1, param2, &param1, param2,
			&param1, param2,
			&key_skeleton_length, key_skeleton);
	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDPKB (EC KEY TOKEN BUILD) "
			 "failed: return_code: %ld reason_code: %ld",
			 return_code, reason_code);
		return -EIO;
	}

	rule_array_count = 1;
	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "MASTER  ", (size_t)CCA_KEYWORD_SIZE);

	cca.dll_CSNDPKG(&return_code, &reason_code,
			NULL, NULL,
			&rule_array_count, rule_array,
			&regeneration_data_length, regeneration_data,
			&key_skeleton_length, key_skeleton,
			transport_key_identifier,
			&token_length, key_token);
	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDPKG (EC KEY GENERATE) failed: "
			 "return_code: %ld reason_code: %ld", return_code,
			 reason_code);
		return -EIO;
	}

	*key_token_length = token_length;

	return 0;
}

/**
 * Generates an CCA RSA key of the specified key size and optionally the
 * specified public exponent using the CCA host library.
 *
 * @param cca_lib           the CCA library structure
 * @param modulus_bits      the size of the key in bits (512, 1024, 2048, 4096)
 * @param pub_exp           the public exponent or zero. Possible values are:
 *                          3, 5, 17, 257, or 65537. Specify zero to choose the
 *                          exponent by random (only possible for modulus_bits
 *                          up to 2048).
 * @param key_token         a buffer to store the generated key token
 * @param key_token_length  On entry: the size of the buffer
 *                          On return: the size of the key token
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_CCA_generate_rsa_key_pair(const struct sk_ext_cca_lib *cca_lib,
				 size_t modulus_bits, unsigned int pub_exp,
				 unsigned char *key_token,
				 size_t *key_token_length, bool debug)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0 };
	unsigned char key_skeleton[CCA_MAX_PKA_KEY_TOKEN_SIZE] = { 0 };
	long key_value_structure_length, private_key_name_length = 0;
	unsigned char regeneration_data[CCA_KEY_ID_SIZE] = { 0 };
	struct cca_rsa_key_pair_value_struct key_value_structure;
	unsigned char private_key_name[CCA_KEY_ID_SIZE] = { 0 };
	unsigned char rule_array[2 * CCA_KEYWORD_SIZE] = { 0 };
	long regeneration_data_length = 0, key_skeleton_length;
	unsigned char *exit_data = NULL;
	unsigned char *param2 = NULL;
	struct cca_lib cca;
	long token_length;
	long param1 = 0;
	int rc;

	if (cca_lib == NULL || key_token == NULL || key_token_length == NULL)
		return -EINVAL;

	if (key_token == NULL) {
		*key_token_length = CCA_MAX_PKA_KEY_TOKEN_SIZE;
		return 0;
	}

	sk_debug(debug, "modulus_bits:  %lu pub_exp: %u", modulus_bits,
		 pub_exp);

	rc = sk_cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get CCA functions from library");
		return rc;
	}

	memset(key_token, 0, *key_token_length);
	token_length = *key_token_length;

	memset(&key_value_structure, 0, sizeof(key_value_structure));
	key_value_structure.modulus_bit_length = modulus_bits;
	switch (pub_exp) {
	case 0:
		if (modulus_bits > 2048) {
			sk_debug(debug, "ERROR: Cannot auto-generate public "
				 "exponent for keys > 2048");
			return -EINVAL;
		}
		key_value_structure.public_exp_length = 0;
		break;
	case 3:
		key_value_structure.public_exp_length = 1;
		key_value_structure.public_exponent[0] = 3;
		break;
	case 5:
		key_value_structure.public_exp_length = 1;
		key_value_structure.public_exponent[0] = 5;
		break;
	case 17:
		key_value_structure.public_exp_length = 1;
		key_value_structure.public_exponent[0] = 17;
		break;
	case 257:
		key_value_structure.public_exp_length = 2;
		key_value_structure.public_exponent[0] = 0x01;
		key_value_structure.public_exponent[0] = 0x01;
		break;
	case 65537:
		key_value_structure.public_exp_length = 3;
		key_value_structure.public_exponent[0] = 0x01;
		key_value_structure.public_exponent[1] = 0x00;
		key_value_structure.public_exponent[2] = 0x01;
		break;
	default:
		sk_debug(debug, "ERROR: Invalid public exponent: %d", pub_exp);
		return -EINVAL;
	}

	key_value_structure_length = sizeof(key_value_structure) +
				key_value_structure.public_exp_length;

	rule_array_count = 2;
	memcpy(rule_array, "RSA-AESC", CCA_KEYWORD_SIZE);
	memcpy(rule_array + CCA_KEYWORD_SIZE, "KEY-MGMT", CCA_KEYWORD_SIZE);

	key_skeleton_length = sizeof(key_skeleton);

	cca.dll_CSNDPKB(&return_code, &reason_code,
			&exit_data_len, exit_data,
			&rule_array_count, rule_array,
			&key_value_structure_length,
			(unsigned char *)&key_value_structure,
			&private_key_name_length, private_key_name,
			&param1, param2, &param1, param2,
			&param1, param2, &param1, param2,
			&param1, param2,
			&key_skeleton_length, key_skeleton);
	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDPKB (RSA KEY TOKEN BUILD) "
			 "failed: return_code: %ld reason_code: %ld",
			 return_code, reason_code);
		return -EIO;
	}

	rule_array_count = 1;
	memset(rule_array, 0, sizeof(rule_array));
	memcpy(rule_array, "MASTER  ", (size_t)CCA_KEYWORD_SIZE);

	cca.dll_CSNDPKG(&return_code, &reason_code,
			NULL, NULL,
			&rule_array_count, rule_array,
			&regeneration_data_length, regeneration_data,
			&key_skeleton_length, key_skeleton,
			transport_key_identifier,
			&token_length, key_token);
	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDPKG (RSA KEY GENERATE) failed: "
			 "return_code: %ld reason_code: %ld", return_code,
			 reason_code);
		return -EIO;
	}

	*key_token_length = token_length;

	return 0;
}

/**
 * Finds a specific section of a CCA internal PKA key token.
 */
static const void *sk_cca_get_pka_section(const unsigned char *key_token,
					  size_t key_token_length,
					  unsigned int section_id, bool debug)
{
	const struct cca_section_header *section_hdr;
	const struct cca_token_header *token_hdr;
	size_t ofs;

	if (key_token == NULL)
		return NULL;

	sk_debug(debug, "section_id: %x", section_id);

	if (key_token_length < sizeof(struct cca_token_header)) {
		sk_debug(debug, "ERROR: key token length too small");
		return NULL;
	}

	token_hdr = (struct cca_token_header *)key_token;
	if (token_hdr->token_length > key_token_length) {
		sk_debug(debug, "ERROR: key token length too small");
		return NULL;
	}
	if (token_hdr->token_identifier != CCA_TOKEN_ID_INTERNAL_PKA) {
		sk_debug(debug, "ERROR: not an internal PKA token");
		return NULL;
	}
	if (token_hdr->token_version1 != CCA_TOKEN_VERS1_V0) {
		sk_debug(debug, "ERROR: invalid token version");
		return NULL;
	}

	ofs = sizeof(struct cca_token_header);
	section_hdr = (struct cca_section_header *)&key_token[ofs];

	while (section_hdr->section_identifier != section_id) {
		ofs += section_hdr->section_length;
		if (ofs >= token_hdr->token_length) {
			sk_debug(debug, "ERROR: section %u not found",
				 section_id);
			return NULL;
		}
		section_hdr = (struct cca_section_header *)&key_token[ofs];
	}

	if (ofs + section_hdr->section_length > token_hdr->token_length) {
		sk_debug(debug, "ERROR: section exceed the token length");
		return NULL;
	}

	return section_hdr;
}

/**
 * Queries the PKEY type of the key token.
 *
 * @param key_token         the key token containing an CCA EC key
 * @param key_token_length  the size of the key token
 * @param pkey_type         On return: the PKEY type of the key token
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_CCA_get_key_type(const unsigned char *key_token, size_t key_token_length,
			int *pkey_type)
{
	if (key_token == NULL || pkey_type == NULL)
		return -EINVAL;

	if (sk_cca_get_pka_section(key_token, key_token_length,
				 CCA_SECTION_ID_EC_PUBL, false) != NULL)
		*pkey_type = EVP_PKEY_EC;
	else if (sk_cca_get_pka_section(key_token, key_token_length,
				      CCA_SECTION_ID_RSA_PUBL, false) != NULL)
		*pkey_type = EVP_PKEY_RSA;
	else
		return -EINVAL;

	return 0;
}

/**
 * Sign data using RSA.
 *
 * @param key_token         the RSA key token
 * @param key_token_length  the length of the key token
 * @param sig               a buffer to store the signature on return.
 * @param siglen            on input: the size if the signature buffer
 *                          on return: the size of the signature
 * @param tbs               the data to be signed.
 * @param tbslen            the size of the data to be signed
 * @param padding_type      the OpenSSL padding type (RSA_X931_PADDING or
 *                          RSA_PKCS1_PADDING)
 * @param digest_nid        the OpenSSL nid of the message digest used to
 *                          produce the data to be signed
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_cca_rsa_sign(const unsigned char *key_token,
			   size_t key_token_length,
			   unsigned char *sig, size_t *siglen,
			   const unsigned char *tbs, size_t tbslen,
			   int padding_type, int md_nid,
			   void *private, bool debug)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	long token_length, hash_length, sign_bit_length, sign_length;
	unsigned char rule_array[4 * CCA_KEYWORD_SIZE] = { 0 };
	const struct sk_ext_cca_lib *cca_lib = private;
	unsigned char *hash = NULL, *buf = NULL;
	const struct sk_digest_info *digest;
	unsigned char *exit_data = NULL;
	struct cca_lib cca;
	int rc;

	if (cca_lib == NULL || key_token == NULL || sig == NULL ||
	    siglen == NULL || tbs == NULL)
		return -EINVAL;

	sk_debug(debug, "tbslen: %lu siglen: %lu padding_type: %d md_nid: %d",
		 tbslen, *siglen, padding_type, md_nid);

	rc = sk_cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get CCA functions from library");
		return rc;
	}

	digest = SK_UTIL_get_digest_info(md_nid);
	if (digest == NULL) {
		sk_debug(debug, "ERROR: Invalid digest nid: %d", md_nid);
		return -EINVAL;
	}

	if (tbslen != digest->digest_size) {
		sk_debug(debug, "ERROR: Invalid data length: %lu", tbslen);
		return -EINVAL;
	}

	rule_array_count = 2;
	memcpy(rule_array, "RSA     ", CCA_KEYWORD_SIZE);
	memcpy(rule_array + CCA_KEYWORD_SIZE, "HASH    ", CCA_KEYWORD_SIZE);

	switch (padding_type) {
	case RSA_X931_PADDING:
		hash = (unsigned char *)tbs;
		hash_length = tbslen;

		memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "X9.31   ",
		       CCA_KEYWORD_SIZE);
		memcpy(rule_array + 3 * CCA_KEYWORD_SIZE, digest->cca_keyword,
		       CCA_KEYWORD_SIZE);
		rule_array_count = 4;
		break;

	case RSA_PKCS1_PADDING:
		hash_length = digest->der_size + tbslen;
		buf = (unsigned char *)malloc(hash_length);
		if (buf == NULL) {
			sk_debug(debug, "ERROR: malloc failed");
			return -ENOMEM;
		}

		memcpy(buf, digest->der, digest->der_size);
		memcpy(buf + digest->der_size, tbs, tbslen);
		hash = buf;

		memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "PKCS-1.1",
		       CCA_KEYWORD_SIZE);
		rule_array_count = 3;
		break;

	default:
		sk_debug(debug, "ERROR: Invalid padding type: %d",
			 padding_type);
		return -EINVAL;
	}

	token_length = key_token_length;
	sign_length = *siglen;

	cca.dll_CSNDDSG(&return_code, &reason_code,
			&exit_data_len, exit_data,
			&rule_array_count, rule_array,
			&token_length, (unsigned char *)key_token,
			&hash_length, hash,
			&sign_length, &sign_bit_length, sig);

	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDDSG (DIG. SIGNATURE CREATE, "
			 "RSA) failed: return_code: %ld reason_code: %ld",
			  return_code, reason_code);
		rc = -EIO;
		goto out;
	}

	*siglen = sign_length;
	rc = 0;

	sk_debug(debug, "siglen: %lu", *siglen);

out:
	if (buf != NULL)
		free(buf);

	return rc;
}

/**
 * Sign data using RSA-PSS.
 *
 * @param key_token         the RSA key token
 * @param key_token_length  the length of the key token
 * @param sig               a buffer to store the signature on return.
 * @param siglen            on input: the size if the signature buffer
 *                          on return: the size of the signature
 * @param tbs               the data to be signed.
 * @param tbslen            the size of the data to be signed
 * @param digest_nid        the OpenSSL nid of the message digest used to
 *                          produce the data to be signed
 * @param mgf_digest_nid    the OpenSSL nid of the mask generation function for
 *                          PSS padding
 * @param saltlen           the length of the salt for PSS
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_cca_rsa_pss_sign(const unsigned char *key_token,
			       size_t key_token_length,
			       unsigned char *sig, size_t *siglen,
			       const unsigned char *tbs, size_t tbslen,
			       int digest_nid, int mgf_digest_nid, int saltlen,
			       void *private, bool debug)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	long token_length, hash_length, sign_bit_length, sign_length;
	unsigned char rule_array[4 * CCA_KEYWORD_SIZE] = { 0 };
	const struct sk_ext_cca_lib *cca_lib = private;
	const struct sk_digest_info *digest;
	unsigned char *exit_data = NULL;
	unsigned char *buf = NULL;
	struct cca_lib cca;
	uint32_t salt_len;
	int rc;

	if (cca_lib == NULL || key_token == NULL || sig == NULL ||
	    siglen == NULL || tbs == NULL)
		return -EINVAL;

	sk_debug(debug, "tbslen: %lu siglen: %lu digest_nid: %d "
		 "mgf_digest_nid: %d saltlen: %d",
		 tbslen, *siglen, digest_nid, mgf_digest_nid, saltlen);

	rc = sk_cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get CCA functions from library");
		return rc;
	}

	if (mgf_digest_nid != digest_nid) {
		sk_debug(debug, "ERROR: Mgf nid must be the same as the "
			 "message digest nid");
		return -EINVAL;
	}

	digest = SK_UTIL_get_digest_info(digest_nid);
	if (digest == NULL || digest->cca_keyword == NULL) {
		sk_debug(debug, "ERROR: Invalid digest nid: %d", digest_nid);
		return -EINVAL;
	}

	if (tbslen != digest->digest_size) {
		sk_debug(debug, "ERROR: Invalid data length: %lu", tbslen);
		return -EINVAL;
	}

	rule_array_count = 4;
	memcpy(rule_array, "RSA     ", CCA_KEYWORD_SIZE);
	memcpy(rule_array + CCA_KEYWORD_SIZE, "PKCS-PSS", CCA_KEYWORD_SIZE);
	memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "HASH    ", CCA_KEYWORD_SIZE);
	memcpy(rule_array + 3 * CCA_KEYWORD_SIZE, digest->cca_keyword,
	       CCA_KEYWORD_SIZE);

	hash_length = sizeof(uint32_t) + tbslen;
	buf = (unsigned char *)malloc(hash_length);
	if (buf == NULL) {
		sk_debug(debug, "ERROR: malloc failed");
		return -ENOMEM;
	}

	salt_len = saltlen;
	memcpy(buf, &salt_len, sizeof(uint32_t));
	memcpy(buf + sizeof(uint32_t), tbs, tbslen);

	token_length = key_token_length;
	sign_length = *siglen;

	cca.dll_CSNDDSG(&return_code, &reason_code,
			&exit_data_len, exit_data,
			&rule_array_count, rule_array,
			&token_length, (unsigned char *)key_token,
			&hash_length, buf,
			&sign_length, &sign_bit_length, sig);

	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDDSG (DIG. SIGNATURE CREATE, "
			   "RSA-PSS) failed: return_code: %ld reason_code: %ld",
			   return_code, reason_code);
		rc = -EIO;
		goto out;
	}

	*siglen = sign_length;
	rc = 0;

	sk_debug(debug, "siglen: %lu", *siglen);

out:
	free(buf);

	return rc;
}

/**
 * Decrypt data using RSA.
 *
 * @param key_token         the RSA key token
 * @param key_token_length  the length of the key token
 * @param to                a buffer to store the decrypted data on return.
 * @param tolen             on input: the size if the to buffer
 *                          on return: the size of the decrypted data
 * @param from              the data to be decrypted.
 * @param fromlen           the size of the data to be decrypted
 * @param padding_type      the OpenSSL padding type
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_cca_rsa_decrypt(const unsigned char *key_token,
			      size_t key_token_length,
			      unsigned char *to, size_t *tolen,
			      const unsigned char *from, size_t fromlen,
			      int padding_type, void *private, bool debug)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	long token_length, from_length, to_length, data_struct_len = 0;
	unsigned char rule_array[3 * CCA_KEYWORD_SIZE] = { 0 };
	const struct sk_ext_cca_lib *cca_lib = private;
	unsigned char *data_struct = NULL;
	unsigned char *exit_data = NULL;
	struct cca_lib cca;
	int rc;

	if (cca_lib == NULL || key_token == NULL || to == NULL ||
	    tolen == NULL || from == NULL)
		return -EINVAL;

	sk_debug(debug, "fromlen: %lu tolen: %lu padding_type: %d",
		 fromlen, *tolen, padding_type);

	rc = sk_cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get CCA functions from library");
		return rc;
	}

	rule_array_count = 1;

	switch (padding_type) {
	case RSA_PKCS1_PADDING:
		memcpy(rule_array, "PKCS-1.2", CCA_KEYWORD_SIZE);
		break;

	default:
		sk_debug(debug, "ERROR: Invalid padding type: %d",
			 padding_type);
		return -EINVAL;
	}

	token_length = key_token_length;
	from_length = fromlen;
	to_length = *tolen;
	if (to_length > from_length)
		to_length = from_length;

	cca.dll_CSNDPKD(&return_code, &reason_code,
			&exit_data_len, exit_data,
			&rule_array_count, rule_array,
			&from_length, (unsigned char *)from,
			&data_struct_len, data_struct,
			&token_length, (unsigned char *)key_token,
			&to_length, to);

	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDPKD (PKA DECRYPT) "
			  "failed: return_code: %ld reason_code: %ld",
			  return_code, reason_code);
		rc = -EIO;
		goto out;
	}

	*tolen = to_length;
	rc = 0;

	sk_debug(debug, "tolen: %lu", *tolen);

out:
	return rc;
}

/**
 * Decrypt data using RSA OAEP.
 *
 * @param key_token         the RSA key token
 * @param key_token_length  the length of the key token
 * @param to                a buffer to store the decrypted data on return.
 * @param tolen             on input: the size if the to buffer
 *                          on return: the size of the decrypted data
 * @param from              the data to be decrypted.
 * @param fromlen           the size of the data to be decrypted
 * @param oaep_md_nid       the OpenSSL nid of the OAEP hashing algorithm
 * @param mgfmd_nid         the OpenSSL nid of the mask generation function
 * @param label             the label for OAEP
 * @param label_len         the length of the label for OAEP
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_cca_rsa_decrypt_oaep(const unsigned char *key_token,
				   size_t key_token_length,
				   unsigned char *to, size_t *tolen,
				   const unsigned char *from, size_t fromlen,
				   int oaep_md_nid, int mgfmd_nid,
				   unsigned char *UNUSED(label),
				   int label_len, void *private, bool debug)
{

	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	long token_length, from_length, to_length, data_struct_len = 0;
	unsigned char rule_array[3 * CCA_KEYWORD_SIZE] = { 0 };
	const struct sk_ext_cca_lib *cca_lib = private;
	unsigned char *data_struct = NULL;
	const struct sk_digest_info *digest;
	unsigned char *exit_data = NULL;
	struct cca_lib cca;
	int rc;

	if (cca_lib == NULL || key_token == NULL || to == NULL ||
	    tolen == NULL || from == NULL)
		return -EINVAL;

	sk_debug(debug, "fromlen: %lu tolen: %lu oaep_md_nid: %d mgfmd_nid: %d",
		 fromlen, *tolen, oaep_md_nid, mgfmd_nid);

	rc = sk_cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get CCA functions from library");
		return rc;
	}

	if (label_len != 0) {
		sk_debug(debug, "ERROR: CCA does not support non-empty OAEP "
			 "label");
		return -EINVAL;
	}

	if (oaep_md_nid != mgfmd_nid) {
		sk_debug(debug, "ERROR: Mgf nid must be the same as the oaep "
			   "nid");
		return -EINVAL;
	}

	digest = SK_UTIL_get_digest_info(mgfmd_nid);
	if (digest == NULL || digest->cca_keyword == NULL) {
		sk_debug(debug, "ERROR: Invalid mgf nid: %d", mgfmd_nid);
		return -EINVAL;
	}

	rule_array_count = 2;
	memcpy(rule_array, "PKCSOAEP", CCA_KEYWORD_SIZE);
	memcpy(rule_array + CCA_KEYWORD_SIZE, digest->cca_keyword,
	       CCA_KEYWORD_SIZE);

	token_length = key_token_length;
	from_length = fromlen;
	to_length = *tolen;
	if (to_length > from_length)
		to_length = from_length;

	cca.dll_CSNDPKD(&return_code, &reason_code,
			&exit_data_len, exit_data,
			&rule_array_count, rule_array,
			&from_length, (unsigned char *)from,
			&data_struct_len, data_struct,
			&token_length, (unsigned char *)key_token,
			&to_length, to);

	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDPKD (PKA DECRYPT) "
			  "failed: return_code: %ld reason_code: %ld",
			  return_code, reason_code);
		rc = -EIO;
		goto out;
	}

	*tolen = to_length;
	rc = 0;

	sk_debug(debug, "tolen: %lu", *tolen);

out:
	return rc;
}

/**
 * Sign data using ECDSA.
 *
 * @param key_token         the RSA key token
 * @param key_token_length  the length of the key token
 * @param sig               a buffer to store the signature on return.
 * @param siglen            on input: the size if the signature buffer
 *                          on return: the size of the signature
 * @param tbs               the data to be signed.
 * @param tbslen            the size of the data to be signed
 * @param digest_nid        the OpenSSL nid of the message digest used to
 *                          produce the data to be signed
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_cca_ecdsa_sign(const unsigned char *key_token,
			     size_t key_token_length,
			     unsigned char *sig, size_t *siglen,
			     const unsigned char *tbs, size_t tbslen,
			     int digest_nid, void *private,
			     bool debug)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	long token_length, hash_length, sign_bit_length, sign_length;
	unsigned char rule_array[2 * CCA_KEYWORD_SIZE] = { 0 };
	const struct sk_ext_cca_lib *cca_lib = private;
	unsigned char *exit_data = NULL;
	struct cca_lib cca;
	int rc;

	if (cca_lib == NULL || key_token == NULL || sig == NULL ||
	    siglen == NULL || tbs == NULL)
		return -EINVAL;

	sk_debug(debug, "tbslen: %lu siglen: %lu digest_nid: %d",
		 tbslen, *siglen, digest_nid);

	rc = sk_cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get CCA functions from library");
		return rc;
	}

	rule_array_count = 2;
	memcpy(rule_array, "ECDSA   ", CCA_KEYWORD_SIZE);
	memcpy(rule_array + CCA_KEYWORD_SIZE, "HASH    ", CCA_KEYWORD_SIZE);

	hash_length = tbslen;
	token_length = key_token_length;
	sign_length = *siglen;

	cca.dll_CSNDDSG(&return_code, &reason_code,
			&exit_data_len, exit_data,
			&rule_array_count, rule_array,
			&token_length, (unsigned char *)key_token,
			&hash_length, (unsigned char *)tbs,
			&sign_length, &sign_bit_length, sig);

	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDDSG (DIG. SIGNATURE CREATE, "
			 "ECDSA) failed: return_code: %ld reason_code: %ld",
			   return_code, reason_code);
		return -EIO;
	}

	rc = SK_UTIL_build_ecdsa_signature(sig, sign_length, sig, siglen);
	if (rc != 0) {
		sk_debug(debug, "ERROR: build_ecdsa_signature failed");
		return -EIO;
	}

	sk_debug(debug, "siglen: %lu", *siglen);

	return 0;
}

static const struct sk_funcs sk_cca_funcs = {
	.rsa_sign = sk_cca_rsa_sign,
	.rsa_pss_sign = sk_cca_rsa_pss_sign,
	.rsa_decrypt = sk_cca_rsa_decrypt,
	.rsa_decrypt_oaep = sk_cca_rsa_decrypt_oaep,
	.ecdsa_sign = sk_cca_ecdsa_sign,
};

struct pub_key_cb_data {
	const struct sk_ext_cca_lib *cca_lib;
	const unsigned char *key_token;
	size_t key_token_length;
	bool rsa_pss;
	EVP_PKEY *pkey;
	bool debug;
};

/*
 * Callback for generating an PKEY from a secure key
 */
static int sk_cca_get_secure_key_as_pkey_cb(
			const struct sk_pub_key_info *pub_key, void *private)
{
	struct pub_key_cb_data *data = private;
	int rc;

	if (pub_key == NULL || data == NULL)
		return -EINVAL;

	rc = SK_OPENSSL_get_pkey(data->key_token, data->key_token_length,
				 pub_key, data->rsa_pss, &sk_cca_funcs,
				 data->cca_lib, &data->pkey, data->debug);
	if (rc != 0) {
		sk_debug(data->debug,
			 "ERROR: SK_OPENSSL_get_pkey failed");
		return rc;
	}

	sk_debug(data->debug, "pkey: %p", data->pkey);

	return 0;
}

/**
 * Extracts the public key from a CCA internal RSA or EC key token, and returns
 * it as OpenSSL PKEY.
 *
 * @param cca_lib           the CCA library structure
 * @param key_token         the key token containing an CCA secure key
 * @param key_token_length  the size of the key token
 * @param rsa_pss           For RSA public keys: create a RSA-PSS type PKEY
 * @param pkey              On return: a PKEY containing the public key
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_CCA_get_secure_key_as_pkey(const struct sk_ext_cca_lib *cca_lib,
				  const unsigned char *key_token,
				  size_t key_token_length,
				  bool rsa_pss, EVP_PKEY **pkey, bool debug)
{
	struct pub_key_cb_data data;
	int rc;

	sk_debug(debug, "rsa_pss: %d", rsa_pss);

	data.cca_lib = cca_lib;
	data.key_token = key_token;
	data.key_token_length = key_token_length;
	data.rsa_pss = rsa_pss;
	data.pkey = NULL;
	data.debug = debug;

	rc = SK_CCA_get_public_from_secure_key(key_token, key_token_length,
					       sk_cca_get_secure_key_as_pkey_cb,
					       &data, debug);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: SK_CCA_get_public_from_secure_key failed");
		return rc;
	}

	sk_debug(debug, "pkey: %p", data.pkey);

	*pkey = data.pkey;
	return 0;
}

/**
 * Extracts the public key from a CCA internal RSA or EC key token, and calls
 * the specified callback function with the public key information.
 *
 * @param key_token         the key token containing an CCA secure key
 * @param key_token_length  the size of the key token
 * @param pub_key_cb        the callback function to call with the public key
 * @param private           a private pointer passed as is to the callback
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_cca_get_public_from_ec_key(const unsigned char *key_token,
					 size_t key_token_length,
					 sk_pub_key_func_t pub_key_cb,
					 void *private, bool debug)
{
	struct cca_ec_pub_key_section *ec_pub_section;
	struct sk_pub_key_info pub_key = { 0 };
	const struct sk_ec_curve_info *curve;
	const unsigned char *ec_pub_key;
	unsigned char *buf = NULL;
	int y_bit = 0;
	int rc = 0;

	if (key_token == NULL || pub_key_cb == NULL)
		return -EINVAL;

	pub_key.type = SK_KEY_TYPE_EC;

	ec_pub_section = (struct cca_ec_pub_key_section *)
			sk_cca_get_pka_section(key_token, key_token_length,
					     CCA_SECTION_ID_EC_PUBL, debug);
	if (ec_pub_section == NULL)
		return -EINVAL;
	if (ec_pub_section->section_header.section_version != 0x00) {
		sk_debug(debug, "ERROR: invalid EC public key section version");
		return -EINVAL;
	}
	if (ec_pub_section->section_header.section_length <
				sizeof(struct cca_ec_pub_key_section)) {
		sk_debug(debug, "ERROR: invalid EC public key section length");
		return -EINVAL;
	}

	ec_pub_key = ((unsigned char *)ec_pub_section) +
				sizeof(struct cca_ec_pub_key_section);

	sk_debug(debug, "CCA curve_type: %u", ec_pub_section->curve_type);

	if (ec_pub_section->curve_type == CCA_PRIME_CURVE)
		pub_key.ec.curve_nid =
			SK_UTIL_ec_get_prime_curve_by_prime_bits(
					ec_pub_section->prime_bits_length);
	else if (ec_pub_section->curve_type == CCA_BRAINPOOL_CURVE)
		pub_key.ec.curve_nid =
			SK_UTIL_ec_get_brainpool_curve_by_prime_bits(
					ec_pub_section->prime_bits_length);
	else
		pub_key.ec.curve_nid = 0;

	sk_debug(debug, "curve_nid: %d", pub_key.ec.curve_nid);
	curve = SK_UTIL_ec_get_curve_info(pub_key.ec.curve_nid);
	if (pub_key.ec.curve_nid == 0 || curve == NULL) {
		sk_debug(debug, "ERROR: unsupported curve: %d",
			 pub_key.ec.curve_nid);
		rc = -EIO;
		goto out;
	}

	pub_key.ec.prime_len = curve->prime_len;
	sk_debug(debug, "prime_len: %lu", pub_key.ec.prime_len);

	if (ec_pub_section->pub_key_length != 2 * pub_key.ec.prime_len + 1) {
		sk_debug(debug, "ERROR: invalid public key length");
		return -EINVAL;
	}

	pub_key.ec.x = ec_pub_key + 1;

	/* First byte of public key contains indication of key compression */
	switch (ec_pub_key[0]) {
	case POINT_CONVERSION_COMPRESSED:
	case POINT_CONVERSION_COMPRESSED + POINT_CONVERSION_ODD_EVEN:
		/* Compressed form, only x is available */
		y_bit = (ec_pub_key[0] & POINT_CONVERSION_ODD_EVEN) ? 1 : 0;

		buf = malloc(pub_key.ec.prime_len);
		if (buf == NULL) {
			sk_debug(debug, "ERROR: malloc failed");
			rc = -ENOMEM;
			goto out;
		}

		rc = SK_UTIL_ec_calculate_y_coordinate(pub_key.ec.curve_nid,
						       pub_key.ec.prime_len,
						       pub_key.ec.x, y_bit,
						       buf);
		if (rc != 0) {
			sk_debug(debug, "ERROR: ec_calculate_y_coordinate "
				 "failed");
			goto out;
		}

		pub_key.ec.y = buf;
		break;

	case POINT_CONVERSION_UNCOMPRESSED:
	case POINT_CONVERSION_HYBRID:
	case POINT_CONVERSION_HYBRID + POINT_CONVERSION_ODD_EVEN:
		/* Uncompressed or hybrid, x and y are available */
		pub_key.ec.y = pub_key.ec.x + pub_key.ec.prime_len;
		break;

	default:
		sk_debug(debug, "ERROR: invalid compression indication");
		rc = -EIO;
		goto out;
	}

	rc = pub_key_cb(&pub_key, private);
	if (rc != 0) {
		sk_debug(debug, "ERROR: pub_key_cb failed");
		goto out;
	}

out:
	if (buf != NULL)
		free(buf);

	return rc;
}

/**
 * Extracts the public key from a CCA internal RSA or EC key token, and calls
 * the specified callback function with the public key information.
 *
 * @param key_token         the key token containing an CCA secure key
 * @param key_token_length  the size of the key token
 * @param pub_key_cb        the callback function to call with the public key
 * @param private           a private pointer passed as is to the callback
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_cca_get_public_from_rsa_key(const unsigned char *key_token,
					  size_t key_token_length,
					  sk_pub_key_func_t pub_key_cb,
					  void *private,
					  bool debug)
{
	const struct cca_rsa_crt_priv_key_section *rsa_priv_section;
	const struct cca_rsa_pub_key_section *rsa_pub_section;
	struct sk_pub_key_info pub_key = { 0 };
	int rc = 0;

	if (key_token == NULL || pub_key_cb == NULL)
		return -EINVAL;

	pub_key.type = SK_KEY_TYPE_RSA;

	rsa_pub_section = (struct cca_rsa_pub_key_section *)
			sk_cca_get_pka_section(key_token, key_token_length,
				CCA_SECTION_ID_RSA_PUBL, debug);
	if (rsa_pub_section == NULL)
		return -EINVAL;
	if (rsa_pub_section->section_header.section_version != 0x00) {
		sk_debug(debug,
			 "ERROR: invalid RSA public key section version");
		return -EINVAL;
	}
	if (rsa_pub_section->section_header.section_length <
				sizeof(struct cca_ec_pub_key_section)) {
		sk_debug(debug, "ERROR: invalid RSA public key section length");
		return -EINVAL;
	}

	pub_key.rsa.pub_exp = ((unsigned char *)rsa_pub_section) +
				sizeof(struct cca_rsa_pub_key_section);
	pub_key.rsa.pub_exp_len = rsa_pub_section->pub_exp_length;
	pub_key.rsa.modulus = pub_key.rsa.pub_exp +
					rsa_pub_section->pub_exp_length;
	pub_key.rsa.modulus_len = rsa_pub_section->modulus_length;

	/*
	 * The public key section may have a modulus_length of zero, need to
	 * get the modulus from the private key section instead.
	 */
	if (rsa_pub_section->modulus_length == 0) {
		rsa_priv_section = (struct cca_rsa_crt_priv_key_section *)
			sk_cca_get_pka_section(key_token, key_token_length,
				CCA_SECTION_ID_RSA_CRT_4096_EOPK_PRIV, debug);

		if (rsa_priv_section == NULL)
			return -EINVAL;
		if (rsa_priv_section->section_header.section_version != 0x00) {
			sk_debug(debug, "ERROR: invalid RSA private key "
				 "section version");
			return -EINVAL;
		}
		if (rsa_priv_section->section_header.section_length <
				sizeof(struct cca_rsa_crt_priv_key_section)) {
			sk_debug(debug, "ERROR: invalid RSA private key "
				 "section length");
			return -EINVAL;
		}

		pub_key.rsa.modulus =  ((unsigned char *)rsa_priv_section) +
				sizeof(struct cca_rsa_crt_priv_key_section);
		pub_key.rsa.modulus_len = rsa_priv_section->modulus_length;
	}

	rc = pub_key_cb(&pub_key, private);
	if (rc != 0) {
		sk_debug(debug, "ERROR: pub_key_cb failed");
		goto out;
	}

out:
	return rc;

}

/**
 * Extracts the public key from a CCA internal RSA or EC key token, and calls
 * the specified callback function with the public key information.
 *
 * @param key_token         the key token containing an CCA secure key
 * @param key_token_length  the size of the key token
 * @param pub_key_cb        the callback function to call with the public key
 * @param private           a private pointer passed as is to the callback
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_CCA_get_public_from_secure_key(const unsigned char *key_token,
				      size_t key_token_length,
				      sk_pub_key_func_t pub_key_cb,
				      void *private, bool debug)
{
	int rc, pkey_type;

	rc = SK_CCA_get_key_type(key_token, key_token_length, &pkey_type);
	if (rc != 0) {
		sk_debug(debug, "ERROR: Failed to get the CCA key type: %s",
			 strerror(-rc));
		return rc;
	}

	sk_debug(debug, "pkey_type: %d", pkey_type);

	switch (pkey_type) {
	case EVP_PKEY_EC:
		rc = sk_cca_get_public_from_ec_key(key_token, key_token_length,
						   pub_key_cb, private, debug);
		if (rc != 0) {
			sk_debug(debug,
				 "ERROR: sk_cca_get_public_from_ec_key failed");
			return rc;
		}
		break;
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		rc = sk_cca_get_public_from_rsa_key(key_token, key_token_length,
						    pub_key_cb, private, debug);
		if (rc != 0) {
			sk_debug(debug,
				"ERROR: sk_cca_get_public_from_rsa_key failed");
			return rc;
		}
		break;
	default:
		sk_debug(debug, "ERROR: Invalid key type: %d", pkey_type);
		return -EIO;
	}

	return 0;
}

/**
 * Reenciphers a CCA secure key with a new CCA master key
 *
 * @param cca_lib           the CCA library structure
 * @param key_token         the key token containing an CCA secure key
 * @param key_token_length  the size of the key token
 * @param to_new            if true, reencipher with the MK in then NEW register
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_CCA_reencipher_key(const struct sk_ext_cca_lib *cca_lib,
			  unsigned char *key_token, size_t key_token_length,
			  bool to_new, bool debug)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char rule_array[2 * CCA_KEYWORD_SIZE] = { 0 };
	unsigned char *exit_data = NULL;
	struct cca_lib cca;
	long token_length;
	int rc, type;

	if (cca_lib == NULL || key_token == NULL)
		return -EINVAL;

	sk_debug(debug, "to_new: %d", to_new);

	rc = sk_cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get CCA functions from library");
		return rc;
	}

	rc = SK_CCA_get_key_type(key_token, key_token_length, &type);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to determine the key token type");
		return rc;
	}

	rule_array_count = 2;
	switch (type) {
	case EVP_PKEY_EC:
		memcpy(rule_array, "ECC     ", CCA_KEYWORD_SIZE);
		break;
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		memcpy(rule_array, "RSA     ", CCA_KEYWORD_SIZE);
		break;
	default:
		sk_debug(debug, "ERROR: Invalid key token type: %d", type);
		return -EINVAL;
	}

	if (to_new)
		memcpy(rule_array + CCA_KEYWORD_SIZE, "RTNMK   ",
		       CCA_KEYWORD_SIZE);
	else
		memcpy(rule_array + CCA_KEYWORD_SIZE, "RTCMK   ",
		       CCA_KEYWORD_SIZE);

	token_length = key_token_length;

	cca.dll_CSNDKTC(&return_code, &reason_code,
			&exit_data_len, exit_data,
			&rule_array_count, rule_array,
			&token_length, key_token);

	if (return_code != 0) {
		sk_debug(debug, "ERROR: CCA CSNDKTC (PKA KEY TOKEN CHANGE) "
			 "failed: return_code: %ld reason_code: %ld",
			 return_code, reason_code);

		if (return_code == 12 && reason_code == 764) {
			sk_debug(debug,
				 "ERROR: The master keys are not loaded");
			return -ENODEV;
		}

		return -EIO;
	}

	return 0;
}

