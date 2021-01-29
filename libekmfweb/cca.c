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

struct cca_ecc_key_pair_value_struct {
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
#define CCA_SECTION_ID_ECC_PRIV			0x20
#define CCA_SECTION_ID_ECC_PUBL			0x21
#define CCA_SECTION_ID_RSA_ME_1024_EOPK_PRIV	0x30
#define CCA_SECTION_ID_RSA_CRT_4096_EOPK_PRIV	0x31

struct cca_ecc_pub_key_section {
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

#define POINT_CONVERSION_COMPRESSED	0x02
#define POINT_CONVERSION_UNCOMPRESSED	0x04
#define POINT_CONVERSION_HYBRID		0x06
#define POINT_CONVERSION_ODD_EVEN	0x01

/**
 * Gets the CCA library function entry points from the library handle
 */
static int _cca_get_library_functions(const struct ekmf_cca_lib *cca_lib,
				      struct cca_lib *cca)
{
	if (cca_lib == NULL || cca == NULL)
		return -EINVAL;

	cca->dll_CSNDPKB = (CSNDPKB_t)dlsym(cca_lib->cca_lib, "CSNDPKB");
	cca->dll_CSNDPKG = (CSNDPKG_t)dlsym(cca_lib->cca_lib, "CSNDPKG");
	cca->dll_CSNDKTC = (CSNDKTC_t)dlsym(cca_lib->cca_lib, "CSNDKTC");
	cca->dll_CSNDDSG = (CSNDDSG_t)dlsym(cca_lib->cca_lib, "CSNDDSG");
	cca->dll_CSNBKTB2 = (CSNBKTB2_t)dlsym(cca_lib->cca_lib, "CSNBKTB2");
	cca->dll_CSNDEDH = (CSNDEDH_t)dlsym(cca_lib->cca_lib, "CSNDEDH");
	cca->dll_CSNDSYI2 = (CSNDSYI2_t)dlsym(cca_lib->cca_lib, "CSNDSYI2");

	if (cca->dll_CSNDPKB == NULL || cca->dll_CSNDPKG == NULL ||
	    cca->dll_CSNDKTC == NULL || cca->dll_CSNDDSG == NULL ||
	    cca->dll_CSNBKTB2 == NULL || cca->dll_CSNDEDH == NULL ||
	    cca->dll_CSNDSYI2 == NULL)
		return -EIO;

	return 0;
}

/**
 * Generates an CCA ECC key of the specified curve type and length using the
 * CCA host library.
 *
 * @param cca_lib           the CCA library structure
 * @param curve_nid         the nid specifying the curve.
 * @param key_token         a buffer to store the generated key token
 * @param key_token_length  On entry: the size of the buffer
 *                          On return: the size of the key token
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_generate_ecc_key_pair(const struct ekmf_cca_lib *cca_lib,
			      int curve_nid, unsigned char *key_token,
			      size_t *key_token_length, bool verbose)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char key_skeleton[CCA_MAX_PKA_KEY_TOKEN_SIZE] = { 0, };
	long key_value_structure_length, private_key_name_length = 0;
	unsigned char regeneration_data[CCA_KEY_ID_SIZE] = { 0, };
	struct cca_ecc_key_pair_value_struct key_value_structure;
	unsigned char private_key_name[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char rule_array[3 * CCA_KEYWORD_SIZE] = { 0, };
	long regeneration_data_length = 0, key_skeleton_length;
	unsigned char *exit_data = NULL;
	unsigned char *param2 = NULL;
	struct cca_lib cca;
	long token_length;
	long param1 = 0;
	int rc;

	if (cca_lib == NULL || key_token == NULL || key_token_length == NULL)
		return -EINVAL;

	rc = _cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CCA functions from library");
		return rc;
	}

	memset(key_token, 0, *key_token_length);
	token_length = *key_token_length;

	memset(&key_value_structure, 0, sizeof(key_value_structure));
	if (ecc_is_prime_curve(curve_nid)) {
		key_value_structure.curve_type = CCA_PRIME_CURVE;
	} else if (ecc_is_brainpool_curve(curve_nid)) {
		key_value_structure.curve_type = CCA_BRAINPOOL_CURVE;
	} else {
		pr_verbose(verbose, "Unsupported curve: %d", curve_nid);
		return -EINVAL;
	}
	key_value_structure.curve_length = ecc_get_curve_prime_bits(curve_nid);
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
		pr_verbose(verbose, "CCA CSNDPKB (EC KEY TOKEN BUILD) failed: "
			  "return_code: %ld reason_code: %ld", return_code,
			  reason_code);
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
		pr_verbose(verbose, "CCA CSNDPKG (EC KEY GENERATE) failed: "
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
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_generate_rsa_key_pair(const struct ekmf_cca_lib *cca_lib,
			      size_t modulus_bits, unsigned int pub_exp,
			      unsigned char *key_token,
			      size_t *key_token_length, bool verbose)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char key_skeleton[CCA_MAX_PKA_KEY_TOKEN_SIZE] = { 0, };
	long key_value_structure_length, private_key_name_length = 0;
	unsigned char regeneration_data[CCA_KEY_ID_SIZE] = { 0, };
	struct cca_rsa_key_pair_value_struct key_value_structure;
	unsigned char private_key_name[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char rule_array[2 * CCA_KEYWORD_SIZE] = { 0, };
	long regeneration_data_length = 0, key_skeleton_length;
	unsigned char *exit_data = NULL;
	unsigned char *param2 = NULL;
	struct cca_lib cca;
	long token_length;
	long param1 = 0;
	int rc;

	if (cca_lib == NULL || key_token == NULL || key_token_length == NULL)
		return -EINVAL;

	rc = _cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CCA functions from library");
		return rc;
	}

	memset(key_token, 0, *key_token_length);
	token_length = *key_token_length;

	memset(&key_value_structure, 0, sizeof(key_value_structure));
	key_value_structure.modulus_bit_length = modulus_bits;
	switch (pub_exp) {
	case 0:
		if (modulus_bits > 2048) {
			pr_verbose(verbose, "cannot auto-generate public "
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
		pr_verbose(verbose, "Invalid public exponent: %d", pub_exp);
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
		pr_verbose(verbose, "CCA CSNDPKB (RSA KEY TOKEN BUILD) failed: "
			  "return_code: %ld reason_code: %ld", return_code,
			  reason_code);
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
		pr_verbose(verbose, "CCA CSNDPKG (RSA KEY GENERATE) failed: "
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
static const void *_cca_get_pka_section(const unsigned char *key_token,
					size_t key_token_length,
					unsigned int section_id, bool verbose)
{
	const struct cca_section_header *section_hdr;
	const struct cca_token_header *token_hdr;
	size_t ofs;

	if (key_token == NULL)
		return NULL;

	if (key_token_length < sizeof(struct cca_token_header)) {
		pr_verbose(verbose, "key token length too small");
		return NULL;
	}

	token_hdr = (struct cca_token_header *)key_token;
	if (token_hdr->token_length > key_token_length) {
		pr_verbose(verbose, "key token length too small");
		return NULL;
	}
	if (token_hdr->token_identifier != CCA_TOKEN_ID_INTERNAL_PKA) {
		pr_verbose(verbose, "not an internal PKA token");
		return NULL;
	}
	if (token_hdr->token_version1 != CCA_TOKEN_VERS1_V0) {
		pr_verbose(verbose, "invalid token version");
		return NULL;
	}

	ofs = sizeof(struct cca_token_header);
	section_hdr = (struct cca_section_header *)&key_token[ofs];

	while (section_hdr->section_identifier != section_id) {
		ofs += section_hdr->section_length;
		if (ofs >= token_hdr->token_length) {
			pr_verbose(verbose, "section %u not found", section_id);
			return NULL;
		}
		section_hdr = (struct cca_section_header *)&key_token[ofs];
	}

	if (ofs + section_hdr->section_length > token_hdr->token_length) {
		pr_verbose(verbose, "section exceed the token length");
		return NULL;
	}

	return section_hdr;
}

/**
 * Queries the PKEY type of the key token.
 *
 * @param key_token         the key token containing an CCA ECC key
 * @param key_token_length  the size of the key token
 * @param pkey_type         On return: the PKEY type of the key token
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_get_key_type(const unsigned char *key_token, size_t key_token_length,
		     int *pkey_type)
{
	if (key_token == NULL || pkey_type == NULL)
		return -EINVAL;

	if (_cca_get_pka_section(key_token, key_token_length,
				 CCA_SECTION_ID_ECC_PUBL, false) != NULL)
		*pkey_type = EVP_PKEY_EC;
	else if (_cca_get_pka_section(key_token, key_token_length,
				      CCA_SECTION_ID_RSA_PUBL, false) != NULL)
		*pkey_type = EVP_PKEY_RSA;
	else
		return -EINVAL;

	return 0;
}

/**
 * Extracts the ECC public key from an CCA internal ECC key token, and returns a
 * it a OpenSSL PKEY.
 *
 * @param key_token         the key token containing an CCA ECC key
 * @param key_token_length  the size of the key token
 * @param pkey              On return: a PKEY containing the public key
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_get_ecc_pub_key_as_pkey(const unsigned char *key_token,
				size_t key_token_length,
				EVP_PKEY **pkey, bool verbose)
{
	struct cca_ecc_pub_key_section *ecc_pub_section;
	const unsigned char *ecc_pub_key, *x, *y;
	unsigned char *buf = NULL;
	size_t prime_len;
	int nid, y_bit = 0;
	int rc = 0;

	if (key_token == NULL ||  pkey == NULL)
		return -EINVAL;

	ecc_pub_section = (struct cca_ecc_pub_key_section *)
			_cca_get_pka_section(key_token, key_token_length,
					     CCA_SECTION_ID_ECC_PUBL, verbose);
	if (ecc_pub_section == NULL)
		return -EINVAL;
	if (ecc_pub_section->section_header.section_version != 0x00) {
		pr_verbose(verbose, "invalid ECC public key section version");
		return -EINVAL;
	}
	if (ecc_pub_section->section_header.section_length <
				sizeof(struct cca_ecc_pub_key_section)) {
		pr_verbose(verbose, "invalid ECC public key section length");
		return -EINVAL;
	}

	ecc_pub_key = ((unsigned char *)ecc_pub_section) +
				sizeof(struct cca_ecc_pub_key_section);

	if (ecc_pub_section->curve_type == CCA_PRIME_CURVE)
		nid = ecc_get_prime_curve_by_prime_bits(
				ecc_pub_section->prime_bits_length);
	else if (ecc_pub_section->curve_type == CCA_BRAINPOOL_CURVE)
		nid = ecc_get_brainpool_curve_by_prime_bits(
				ecc_pub_section->prime_bits_length);
	else
		nid = 0;
	if (nid == 0) {
		pr_verbose(verbose, "unsupported curve");
		rc = -EIO;
		goto out;
	}
	prime_len = ecc_get_curve_prime_length(nid);

	x = ecc_pub_key + 1;

	/* First byte of public key contains indication of key compression */
	switch (ecc_pub_key[0]) {
	case POINT_CONVERSION_COMPRESSED:
	case POINT_CONVERSION_COMPRESSED + POINT_CONVERSION_ODD_EVEN:
		/* Compressed form, only x is available */
		y_bit = (ecc_pub_key[0] & POINT_CONVERSION_ODD_EVEN) ? 1 : 0;

		buf = malloc(prime_len);
		if (buf == NULL) {
			pr_verbose(verbose, "malloc failed");
			rc = -ENOMEM;
			goto out;
		}

		rc = ecc_calculate_y_coordinate(nid, prime_len, x, y_bit, buf);
		if (rc != 0) {
			pr_verbose(verbose, "ecc_calculate_y_coordinate "
				   "failed");
			goto out;
		}

		y = buf;
		break;

	case POINT_CONVERSION_UNCOMPRESSED:
	case POINT_CONVERSION_HYBRID:
	case POINT_CONVERSION_HYBRID + POINT_CONVERSION_ODD_EVEN:
		/* Uncompressed or hybrid, x and y are available */
		y = x + prime_len;
		break;

	default:
		pr_verbose(verbose, "invalid compression indication");
		rc = -EIO;
		goto out;
	}

	rc = ecc_pub_key_as_pkey(nid, prime_len, x, y, pkey);
	if (rc != 0) {
		pr_verbose(verbose, "ecc_pub_key_as_pkey failed");
		goto out;
	}

out:
	if (buf != NULL)
		free(buf);

	return rc;
}

/**
 * Extracts the ECC public key from an CCA internal ECC key token, and returns a
 * JSON object representing the public key as JSON Web Key (JWK, see RFC7517).
 * The returned JSON objects must be freed by the caller using json_object_put()
 * when no longer needed.
 *
 * @param key_token         the key token containing an CCA ECC key
 * @param key_token_length  the size of the key token
 * qparam jwk               the ECC public key as JWT JSON object
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_get_ecc_pub_key_as_json_web_key(const unsigned char *key_token,
					size_t key_token_length,
					json_object **jwk, bool verbose)
{
	const struct cca_ecc_pub_key_section *ecc_pub_section;
	const struct cca_section_header *section_hdr;
	const struct cca_token_header *token_hdr;
	const unsigned char *ecc_pub_key, *x, *y;
	json_object *jwk_obj = NULL;
	unsigned char *buf = NULL;
	size_t ofs, prime_len;
	int nid, y_bit = 0;
	int rc = 0;

	if (key_token == NULL ||  jwk == NULL)
		return -EINVAL;

	if (key_token_length < sizeof(struct cca_token_header)) {
		pr_verbose(verbose, "key token length too small");
		return -EINVAL;
	}

	token_hdr = (struct cca_token_header *)key_token;
	if (token_hdr->token_length > key_token_length) {
		pr_verbose(verbose, "key token length too small");
		return -EINVAL;
	}
	if (token_hdr->token_identifier != CCA_TOKEN_ID_INTERNAL_PKA) {
		pr_verbose(verbose, "not an internal PKA token");
		return -EINVAL;
	}
	if (token_hdr->token_version1 != CCA_TOKEN_VERS1_V0) {
		pr_verbose(verbose, "invalid token version");
		return -EINVAL;
	}

	ofs = sizeof(struct cca_token_header);
	section_hdr = (struct cca_section_header *)&key_token[ofs];

	while (section_hdr->section_identifier != CCA_SECTION_ID_ECC_PUBL) {
		ofs += section_hdr->section_length;
		if (ofs >= token_hdr->token_length) {
			pr_verbose(verbose, "no ECC public key section found");
			return -EINVAL;
		}
		section_hdr = (struct cca_section_header *)&key_token[ofs];
	}

	if (section_hdr->section_version != 0x00) {
		pr_verbose(verbose, "invalid ECC public key section version");
		return -EINVAL;
	}
	if (section_hdr->section_length <
				sizeof(struct cca_ecc_pub_key_section)) {
		pr_verbose(verbose, "invalid ECC public key section length");
		return -EINVAL;
	}

	ecc_pub_section = (struct cca_ecc_pub_key_section *)section_hdr;
	ofs += sizeof(struct cca_ecc_pub_key_section);
	ecc_pub_key = &key_token[ofs];

	if (ecc_pub_section->curve_type == CCA_PRIME_CURVE)
		nid = ecc_get_prime_curve_by_prime_bits(
				ecc_pub_section->prime_bits_length);
	else if (ecc_pub_section->curve_type == CCA_BRAINPOOL_CURVE)
		nid = ecc_get_brainpool_curve_by_prime_bits(
				ecc_pub_section->prime_bits_length);
	else
		nid = 0;
	if (nid == 0) {
		pr_verbose(verbose, "unsupported curve");
		rc = -EIO;
		goto out;
	}
	prime_len = ecc_get_curve_prime_length(nid);

	x = ecc_pub_key + 1;

	/* First byte of public key contains indication of key compression */
	switch (ecc_pub_key[0]) {
	case POINT_CONVERSION_COMPRESSED:
	case POINT_CONVERSION_COMPRESSED + POINT_CONVERSION_ODD_EVEN:
		/* Compressed form, only x is available */
		y_bit = (ecc_pub_key[0] & POINT_CONVERSION_ODD_EVEN) ? 1 : 0;

		buf = malloc(prime_len);
		if (buf == NULL) {
			pr_verbose(verbose, "malloc failed");
			rc = -ENOMEM;
			goto out;
		}

		rc = ecc_calculate_y_coordinate(nid, prime_len, x, y_bit, buf);
		if (rc != 0) {
			pr_verbose(verbose, "ecc_calculate_y_coordinate "
				   "failed");
			goto out;
		}

		y = buf;
		break;

	case POINT_CONVERSION_UNCOMPRESSED:
	case POINT_CONVERSION_HYBRID:
	case POINT_CONVERSION_HYBRID + POINT_CONVERSION_ODD_EVEN:
		/* Uncompressed or hybrid, x and y are available */
		y = x + prime_len;
		break;

	default:
		pr_verbose(verbose, "invalid compression indication");
		rc = -EIO;
		goto out;
	}

	/* construct the JWK */
	jwk_obj = json_object_new_object();
	if (jwk_obj == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	/*
	 * Note: The order of the fields is important, EKMFWeb expects it in
	 * exactly this order!
	 */
	rc = json_object_object_add_ex(jwk_obj, "kty",
				       json_object_new_string("EC"), 0);
	rc |= json_object_object_add_ex(jwk_obj, "crv", json_object_new_string(
					ecc_get_curve_id(nid)), 0);
	rc |= json_object_object_add_ex(jwk_obj, "x",
					json_object_new_base64url(x, prime_len),
					0);
	rc |= json_object_object_add_ex(jwk_obj, "y",
					json_object_new_base64url(y, prime_len),
					0);
	if (rc != 0) {
		rc = -EIO;
		goto out;
	}

	*jwk = jwk_obj;

out:
	if (buf != NULL)
		free(buf);
	if (rc != 0 && jwk_obj != NULL)
		json_object_put(jwk_obj);
	return rc;
}

/**
 * Extracts the RSA public key from an CCA internal RSA key token, and returns a
 * it a OpenSSL PKEY.
 *
 * @param key_token         the key token containing an CCA RSA key
 * @param key_token_length  the size of the key token
 * @param pkey_type         the PKEY type (EVP_PKEY_RSA or EVP_PKEY_RSA_PSS)*
 * @param pkey              On return: a PKEY containing the public key
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_get_rsa_pub_key_as_pkey(const unsigned char *key_token,
				size_t key_token_length,
				int pkey_type, EVP_PKEY **pkey, bool verbose)
{
	const struct cca_rsa_crt_priv_key_section *rsa_priv_section;
	const struct cca_rsa_pub_key_section *rsa_pub_section;
	const unsigned char *pub_exp, *modulus;
	size_t modulus_length;
	int rc = 0;

	if (key_token == NULL ||  pkey == NULL)
		return -EINVAL;

	rsa_pub_section = (struct cca_rsa_pub_key_section *)
			_cca_get_pka_section(key_token, key_token_length,
				CCA_SECTION_ID_RSA_PUBL, verbose);
	if (rsa_pub_section == NULL)
		return -EINVAL;
	if (rsa_pub_section->section_header.section_version != 0x00) {
		pr_verbose(verbose, "invalid RSA public key section version");
		return -EINVAL;
	}
	if (rsa_pub_section->section_header.section_length <
				sizeof(struct cca_ecc_pub_key_section)) {
		pr_verbose(verbose, "invalid RSA public key section length");
		return -EINVAL;
	}

	pub_exp = ((unsigned char *)rsa_pub_section) +
				sizeof(struct cca_rsa_pub_key_section);
	modulus = pub_exp + rsa_pub_section->pub_exp_length;
	modulus_length = rsa_pub_section->modulus_length;

	/*
	 * The public key section may have a modulus_length of zero, need to
	 * get the modulus from the private key section instead.
	 */
	if (rsa_pub_section->modulus_length == 0) {
		rsa_priv_section = (struct cca_rsa_crt_priv_key_section *)
			_cca_get_pka_section(key_token, key_token_length,
				CCA_SECTION_ID_RSA_CRT_4096_EOPK_PRIV, verbose);

		if (rsa_priv_section == NULL)
			return -EINVAL;
		if (rsa_priv_section->section_header.section_version != 0x00) {
			pr_verbose(verbose, "invalid RSA private key section "
				   "version");
			return -EINVAL;
		}
		if (rsa_priv_section->section_header.section_length <
				sizeof(struct cca_rsa_crt_priv_key_section)) {
			pr_verbose(verbose, "invalid RSA private key section "
				   "length");
			return -EINVAL;
		}

		modulus =  ((unsigned char *)rsa_priv_section) +
				sizeof(struct cca_rsa_crt_priv_key_section);
		modulus_length = rsa_priv_section->modulus_length;
	}

	rc = rsa_pub_key_as_pkey(modulus, modulus_length, pub_exp,
				 rsa_pub_section->pub_exp_length,
				 pkey_type, pkey);
	if (rc != 0) {
		pr_verbose(verbose, "rsa_pub_key_as_pkey failed");
		goto out;
	}

out:
	return rc;
}

/**
 * Re-enciphers a key token with a new CCA master key.
 *
 * @param cca_lib           the CCA library structure
 * @param key_token         the key token containing an CCA ECC or RSA key.
 *                          The re-enciphered key token is returned in the same
 *                          buffer. The size of the re-enciphered key token
 *                          remains the same.
 * @param key_token_length  the size of the key token
 * @param to_new            If true: the key token is re-enciphered from the
 *                          current to the new master key.
 *                          If false: the key token is re-enciphered from the
 *                          old to the current master key.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 * -ENODEV is returned if the master keys are not loaded.
 */
int cca_reencipher_key(const struct ekmf_cca_lib *cca_lib,
		       const unsigned char *key_token, size_t key_token_length,
		       bool to_new, bool verbose)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char rule_array[2 * CCA_KEYWORD_SIZE] = { 0, };
	unsigned char *exit_data = NULL;
	struct cca_lib cca;
	long token_length;
	int rc, type;

	if (cca_lib == NULL || key_token == NULL)
		return -EINVAL;

	rc = _cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CCA functions from library");
		return rc;
	}

	rc = cca_get_key_type(key_token, key_token_length, &type);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to determine the key token type");
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
		pr_verbose(verbose, "Invalid key token type: %d", type);
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
			&token_length, (unsigned char *)key_token);

	if (return_code != 0) {
		pr_verbose(verbose, "CCA CSNDKTC (PKA KEY TOKEN CHANGE) failed:"
			  " return_code: %ld reason_code: %ld", return_code,
			  reason_code);

		if (return_code == 12 && reason_code == 764) {
			pr_verbose(verbose, "The master keys are not loaded");
			return -ENODEV;
		}

		return -EIO;
	}

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

		nid = ecc_get_curve_by_id(crv);
		if (nid == 0) {
			pr_verbose(verbose, "curve '%s' not supported", crv);
			rc = -EIO;
			goto out;
		}

		prime_len = ecc_get_curve_prime_length(nid);
		if (prime_len == 0) {
			pr_verbose(verbose, "curve %d not supported", nid);
			rc = -EIO;
			goto out;
		}

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
		if (ecc_is_prime_curve(nid)) {
			key_value_struct->curve_type = CCA_PRIME_CURVE;
		} else if (ecc_is_brainpool_curve(nid)) {
			key_value_struct->curve_type = CCA_BRAINPOOL_CURVE;
		} else {
			pr_verbose(verbose, "Unsupported curve: %d", nid);
			rc = -EINVAL;
			goto out;
		}
		key_value_struct->curve_length = ecc_get_curve_prime_bits(nid);
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

static const unsigned char der_DigestInfo_SHA1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, };
static const unsigned char der_DigestInfo_SHA224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
	0x00, 0x04, 0x1C, };
static const unsigned char der_DigestInfo_SHA256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20, };
static const unsigned char der_DigestInfo_SHA384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	0x00, 0x04, 0x30, };
static const unsigned char der_DigestInfo_SHA512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
	0x00, 0x04, 0x40, };
static const unsigned char der_DigestInfo_SHA3_224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
	0x00, 0x04, 0x1C, };
static const unsigned char der_DigestInfo_SHA3_256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
	0x00, 0x04, 0x20, };
static const unsigned char der_DigestInfo_SHA3_384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
	0x00, 0x04, 0x30, };
static const unsigned char der_DigestInfo_SHA3_512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05,
	0x00, 0x04, 0x40, };

struct digest_info {
	int digest_nid;
	size_t digest_size;
	const char *cca_keyword;
	const unsigned char *der;
	size_t der_size;
};

static const struct digest_info digest_list[] = {
	{ .digest_nid = NID_sha1, .digest_size = SHA_DIGEST_LENGTH,
	  .cca_keyword = "SHA-1   ", .der = der_DigestInfo_SHA1,
	  .der_size = sizeof(der_DigestInfo_SHA1), },
	{ .digest_nid = NID_sha224, .digest_size = SHA224_DIGEST_LENGTH,
	  .cca_keyword = "SHA-224 ", .der = der_DigestInfo_SHA224,
	  .der_size = sizeof(der_DigestInfo_SHA224), },
	{ .digest_nid = NID_sha256, .digest_size = SHA256_DIGEST_LENGTH,
	  .cca_keyword = "SHA-256 ", .der = der_DigestInfo_SHA256,
	  .der_size = sizeof(der_DigestInfo_SHA256), },
	{ .digest_nid = NID_sha384, .digest_size = SHA384_DIGEST_LENGTH,
	  .cca_keyword = "SHA-384 ", .der = der_DigestInfo_SHA384,
	  .der_size = sizeof(der_DigestInfo_SHA384), },
	{ .digest_nid = NID_sha512, .digest_size = SHA512_DIGEST_LENGTH,
	  .cca_keyword = "SHA-512 ", .der = der_DigestInfo_SHA512,
	  .der_size = sizeof(der_DigestInfo_SHA512), },
	{ .digest_nid = NID_sha3_224, .digest_size = SHA224_DIGEST_LENGTH,
	  .cca_keyword = NULL, .der = der_DigestInfo_SHA3_224,
	  .der_size = sizeof(der_DigestInfo_SHA3_224), },
	{ .digest_nid = NID_sha3_256, .digest_size = SHA256_DIGEST_LENGTH,
	  .cca_keyword = NULL, .der = der_DigestInfo_SHA3_256,
	  .der_size = sizeof(der_DigestInfo_SHA3_256), },
	{ .digest_nid = NID_sha3_384, .digest_size = SHA384_DIGEST_LENGTH,
	  .cca_keyword = NULL, .der = der_DigestInfo_SHA3_384,
	  .der_size = sizeof(der_DigestInfo_SHA3_384), },
	{ .digest_nid = NID_sha3_512, .digest_size = SHA512_DIGEST_LENGTH,
	  .cca_keyword = NULL, .der = der_DigestInfo_SHA3_512,
	  .der_size = sizeof(der_DigestInfo_SHA3_512), },
};

static const int digest_list_num = sizeof(digest_list) /
						sizeof(struct digest_info);

static const struct digest_info *get_digest_info(int digest_nid)
{
	int i;

	for (i = 0; i < digest_list_num; i++) {
		if (digest_list[i].digest_nid == digest_nid)
			return &digest_list[i];
	}

	return NULL;
}

struct cca_private_data {
	CSNDDSG_t dll_CSNDDSG;
	bool verbose;
};

/**
 * Sign data using RSA.
 *
 * @param cca_lib           the CCA library structure
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
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_rsa_sign(const struct ekmf_cca_lib *cca_lib,
		 const unsigned char *key_token, size_t key_token_length,
		 unsigned char *sig, size_t *siglen,
		 const unsigned char *tbs, size_t tbslen,
		 int padding_type, int md_nid, bool verbose)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	long token_length, hash_length, sign_bit_length, sign_length;
	unsigned char rule_array[3 * CCA_KEYWORD_SIZE] = { 0, };
	unsigned char *hash = NULL, *buf = NULL;
	const struct digest_info *digest;
	unsigned char *exit_data = NULL;
	struct cca_lib cca;
	int rc;

	if (cca_lib == NULL || key_token == NULL || sig == NULL ||
	    siglen == NULL || tbs == NULL)
		return -EINVAL;

	rc = _cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CCA functions from library");
		return rc;
	}

	rule_array_count = 3;
	memcpy(rule_array, "RSA     ", CCA_KEYWORD_SIZE);
	memcpy(rule_array + CCA_KEYWORD_SIZE, "HASH    ", CCA_KEYWORD_SIZE);

	switch (padding_type) {
	case RSA_X931_PADDING:
		hash = (unsigned char *)tbs;
		hash_length = tbslen;

		memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "X9.31   ",
		       CCA_KEYWORD_SIZE);
		break;

	case RSA_PKCS1_PADDING:
		digest = get_digest_info(md_nid);
		if (digest == NULL) {
			pr_verbose(verbose, "Invalid digest nid: %d", md_nid);
			return -EINVAL;
		}

		if (tbslen != digest->digest_size) {
			pr_verbose(verbose, "Invalid data length: %lu", tbslen);
			return -EINVAL;
		}

		hash_length = digest->der_size + tbslen;
		buf = (unsigned char *)malloc(hash_length);
		if (buf == NULL) {
			pr_verbose(verbose, "malloc failed");
			return -ENOMEM;
		}

		memcpy(buf, digest->der, digest->der_size);
		memcpy(buf + digest->der_size, tbs, tbslen);
		hash = buf;

		memcpy(rule_array + 2 * CCA_KEYWORD_SIZE, "PKCS-1.1",
		       CCA_KEYWORD_SIZE);
		break;

	default:
		pr_verbose(verbose, "Invalid padding type: %d", padding_type);
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
		pr_verbose(verbose, "CCA CSNDDSG (DIG. SIGNATURE CREATE, RSA) "
			  "failed: return_code: %ld reason_code: %ld",
			  return_code, reason_code);
		rc = -EIO;
		goto out;
	}

	*siglen = sign_length;
	rc = 0;

out:
	if (buf != NULL)
		free(buf);

	return rc;
}

/**
 * Sign data using RSA-PSS.
 *
 * @param cca_lib           the CCA library structure
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
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_rsa_pss_sign(const struct ekmf_cca_lib *cca_lib,
		     const unsigned char *key_token, size_t key_token_length,
		     unsigned char *sig, size_t *siglen,
		     const unsigned char *tbs, size_t tbslen,
		     int digest_nid, int mgf_digest_nid, int saltlen,
		     bool verbose)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char rule_array[4 * CCA_KEYWORD_SIZE] = { 0, };
	long token_length, hash_length, sign_bit_length, sign_length;
	const struct digest_info *digest;
	unsigned char *exit_data = NULL;
	unsigned char *buf = NULL;
	struct cca_lib cca;
	uint32_t salt_len;
	int rc;

	if (cca_lib == NULL || key_token == NULL || sig == NULL ||
	    siglen == NULL || tbs == NULL)
		return -EINVAL;

	rc = _cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CCA functions from library");
		return rc;
	}

	if (mgf_digest_nid != digest_nid) {
		pr_verbose(verbose, "Mgf nid must be the same as the message "
			   "digest nid");
		return -EINVAL;
	}

	digest = get_digest_info(digest_nid);
	if (digest == NULL || digest->cca_keyword == NULL) {
		pr_verbose(verbose, "Invalid mgf nid: %d", digest_nid);
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
		pr_verbose(verbose, "malloc failed");
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
		pr_verbose(verbose, "CCA CSNDDSG (DIG. SIGNATURE CREATE, "
			   "RSA-PSS) failed: return_code: %ld reason_code: %ld",
			   return_code, reason_code);
		rc = -EIO;
		goto out;
	}

	*siglen = sign_length;
	rc = 0;

out:
	free(buf);

	return rc;
}

/**
 * Sign data using ECDSA.
 *
 * @param cca_lib           the CCA library structure
 * @param key_token         the RSA key token
 * @param key_token_length  the length of the key token
 * @param sig               a buffer to store the signature on return.
 * @param siglen            on input: the size if the signature buffer
 *                          on return: the size of the signature
 * @param tbs               the data to be signed.
 * @param tbslen            the size of the data to be signed
 * @param digest_nid        the OpenSSL nid of the message digest used to
 *                          produce the data to be signed
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int cca_ecdsa_sign(const struct ekmf_cca_lib *cca_lib,
		   const unsigned char *key_token, size_t key_token_length,
		   unsigned char *sig, size_t *siglen,
		   const unsigned char *tbs, size_t tbslen,
		   int UNUSED(digest_nid), bool verbose)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	long token_length, hash_length, sign_bit_length, sign_length;
	unsigned char rule_array[2 * CCA_KEYWORD_SIZE] = { 0, };
	unsigned char *exit_data = NULL;
	unsigned char *der = NULL;
	ECDSA_SIG *ec_sig = NULL;
	BIGNUM *bn_r = NULL;
	BIGNUM *bn_s = NULL;
	struct cca_lib cca;
	int rc, der_len;

	if (cca_lib == NULL || key_token == NULL || sig == NULL ||
	    siglen == NULL || tbs == NULL)
		return -EINVAL;

	rc = _cca_get_library_functions(cca_lib, &cca);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CCA functions from library");
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
		pr_verbose(verbose, "CCA CSNDDSG (DIG. SIGNATURE CREATE, ECDSA)"
			   " failed: return_code: %ld reason_code: %ld",
			   return_code, reason_code);
		return -EIO;
	}

	ec_sig = ECDSA_SIG_new();
	if (ec_sig == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	bn_r = BN_bin2bn(sig, sign_length / 2, NULL);
	bn_s = BN_bin2bn(sig + sign_length / 2, sign_length / 2, NULL);
	if (bn_r == NULL || bn_s == NULL) {
		rc = -EIO;
		goto out;
	}

	if (ECDSA_SIG_set0(ec_sig, bn_r, bn_s) != 1) {
		rc = -EIO;
		goto out;
	}
	bn_r = NULL;
	bn_s = NULL;

	der_len = i2d_ECDSA_SIG(ec_sig, NULL);
	if (der_len > (int)*siglen) {
		rc = -ERANGE;
		goto out;
	}

	memset(sig, 0, *siglen);
	der = sig;
	*siglen = i2d_ECDSA_SIG(ec_sig, &der);

	if (*siglen == 0) {
		rc = -EIO;
		goto out;
	}

	rc = 0;
out:
	if (ec_sig != NULL)
		ECDSA_SIG_free(ec_sig);
	if (bn_r != NULL)
		BN_free(bn_r);
	if (bn_s != NULL)
		BN_free(bn_s);

	return rc;
}

