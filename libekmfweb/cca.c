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

#define CCA_PRIME_CURVE			0x00
#define CCA_BRAINPOOL_CURVE		0x01

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

	if (cca->dll_CSNDPKB == NULL || cca->dll_CSNDPKG == NULL)
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
