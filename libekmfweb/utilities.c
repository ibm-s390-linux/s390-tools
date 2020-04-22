/*
 * libekmfweb - EKMFWeb client library
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "utilities.h"

/**
 * Decodes a Base64URL encoded string. Base64URL is like Base64, but using a
 * URL and Filename Safe Alphabet, not using characters like '+', '/', or '='.
 *
 * The function converts the Base64URL input into standard Base64 data and then
 * decodes it using OpenSSL EVP_DecodeBlock.
 *
 * @param output            a buffer to store the output. If NULL, then the
 *                          required size in bytes is returned in outlen and
 *                          no decoding is performed.
 * @param outlen            on entry: Size of the output buffer in bytes.
 *                          on exit: Size of the decoded data in bytes.
 * @param input             the Base64URL encoded data to decode
 * @param inlen             the size of the input data in bytes
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ERANGE: the output buffer size is too small. outlen contains the
 *                   required size on return.
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to decode the data
 */
int decode_base64url(unsigned char *output, size_t *outlen,
		     const char *input, size_t inlen)
{
	size_t raw_outlen, padded_outlen, padded_inlen;
	char *padded_input = NULL;
	char *padded_output;
	int len, rc = 0;
	size_t i;

	if (input == NULL || outlen == NULL)
		return -EINVAL;

	/* Base64URL might optionally include padding chars ('='), remove it */
	for (; inlen > 0 && input[inlen - 1] == '='; inlen--)
		;

	/* Might need to pad with standard base64 padding character '=' */
	padded_inlen = inlen;
	if ((inlen % 4) > 0)
		padded_inlen += 4 - (inlen % 4);

	/* Also the output will be padded while decoding */
	padded_outlen = (padded_inlen / 4) * 3;
	raw_outlen = (inlen / 4) * 3 + ((inlen % 4) >= 2 ? (inlen % 4) - 1 : 0);

	if (output == NULL) /* size query */
		goto out;
	if (*outlen < raw_outlen) {
		rc = -ERANGE;
		goto out;
	}

	padded_input = (char *)malloc(padded_inlen + padded_outlen);
	if (padded_input == NULL)
		return -ENOMEM;
	padded_output = padded_input + padded_inlen;

	memcpy(padded_input, input, inlen);
	memset(padded_input + inlen, '=', padded_inlen - inlen);

	/* Replace '-' by '+', and '_' by '/' */
	for (i = 0; i < inlen; i++) {
		if (padded_input[i] == '-')
			padded_input[i] = '+';
		else if (padded_input[i] == '_')
			padded_input[i] = '/';
	}

	len = EVP_DecodeBlock((unsigned char *)padded_output,
			      (unsigned char *)padded_input, padded_inlen);
	if (len != (int)padded_inlen * 3 / 4) {
		rc = -EIO;
		goto out;
	}

	memcpy(output, padded_output, raw_outlen);

out:
	*outlen = raw_outlen;

	if (padded_input != NULL)
		free(padded_input);

	return rc;
}

/**
 * Encodes a data using Base64URL. Base64URL is like Base64, but using a
 * URL and Filename Safe Alphabet, not using characters like '+', '/', or '='.
 *
 * The function encodes the data into standard Base64 data using OpenSSL
 * EVP_EncodeBlock and then converts it into Base64URL data
 *
 * @param output            a buffer to store the output. If NULL, then the
 *                          required size in bytes is returned in outlen and
 *                          no encoding is performed.
 *                          The NUL character is added to the output at the end
 *                          of the encoded data.
 * @param outlen            on entry: Size of the output buffer in bytes.
 *                          on exit: Size of the encoded data in bytes,
 *                                   including the NUL character.
 * @param input             the data to Base64URL-encode
 * @param inlen             the size of the input data in bytes
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ERANGE: the output buffer size is too small. outlen contains the
 *                   required size on return.
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to decode the data
 */
int encode_base64url(char *output, size_t *outlen,
		     const unsigned char *input, size_t inlen)
{
	size_t padded_outlen, raw_outlen, ofs = 0;
	char *padded_output = NULL;
	int len, rc = 0;

	if (input == NULL || outlen == NULL)
		return -EINVAL;

	padded_outlen = (inlen / 3) * 4;
	if (inlen % 3 > 0)
		padded_outlen += 4;

	raw_outlen = (inlen / 3) * 4 + ((inlen % 3) > 0 ? (inlen % 3) + 1 : 0);

	if (output == NULL)
		goto out;

	if (*outlen < raw_outlen + 1) {
		rc = -ERANGE;
		goto out;
	}

	padded_output = (char *)malloc(padded_outlen + 1);
	if (padded_output == NULL)
		return -ENOMEM;

	len = EVP_EncodeBlock((unsigned char *)padded_output,
			      (unsigned char *)input, inlen);
	if (len != (int)padded_outlen) {
		rc = -EIO;
		goto out;
	}

	/* Replace '+' by '-', and '/' by '_', and stop at first '=' */
	for (ofs = 0; ofs < padded_outlen; ofs++) {
		if (padded_output[ofs] == '+')
			padded_output[ofs] = '-';
		else if (padded_output[ofs] == '/')
			padded_output[ofs] = '_';
		else if (padded_output[ofs] == '=')
			break;
	}
	if (ofs != raw_outlen) {
		rc = -EIO;
		goto out;
	}

	memcpy(output, padded_output, raw_outlen);
	output[raw_outlen] = '\0';

out:
	*outlen = raw_outlen + 1;

	if (padded_output != NULL)
		free(padded_output);

	return rc;
}

/**
 * Parses a JSON Web Token (JWT) and extracts the header and payload parts as
 * parsed JSON object. The returned JSON objects must be freed by the caller
 * using json_object_put() when no longer needed. The returned signature must
 * also be freed by the caller when no longer needed.
 *
 * @param token             the JSON Web Tolken to parse
 * @param header_obj        if not NULL, the parsed JWT header as JSON Object
 * @param payload_obj       if not NULL, the parsed JWT payload as JSON Object
 * @param signature         if not NULL, a pointer to the decoded signature
 * @param signature_len     if not NULL, the size of the signature in bytes
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -EBADMSG: If the token could not be parsed into parts
 *          -ENOMEM: failed to allocate memory
 *          -EIO: Base64 parsing error
 */
int parse_json_web_token(const char *token, json_object **header_obj,
			 json_object **payload_obj, unsigned char **signature,
			 size_t *signature_len)
{
	json_object *hdr = NULL, *pld = NULL, *b64_obj = NULL;
	char *ch, *header, *payload, *json = NULL;
	size_t header_len, payload_len, json_len;
	bool b64 = true;
	int rc = 0;

	if (token == NULL)
		return -EINVAL;

	if (header_obj != NULL)
		*header_obj = NULL;
	if (payload_obj != NULL)
		*payload_obj = NULL;
	if (signature != NULL)
		*signature = NULL;
	if (signature_len != NULL)
		*signature_len = 0;

	/*
	 * A JSON Web Token consists of several parts, each part Base64URL
	 * encoded, and separated by a colon '.' from each other.
	 * The first part is the JOSE (JSON Object Signing and Encryption)
	 * Header. The second part is the JWS Payload containing the JWS claims,
	 * and the following parts (if any) are used for JWS Signature, or JWE
	 * Encryption (not considered here).
	 */
	header = (char *)token;

	ch = strchr(token, '.');
	if (ch == NULL) {
		rc = -EBADMSG;
		goto out;
	}
	header_len = ch - token;

	payload = ++ch;

	ch = strchr(ch, '.');
	if (ch == NULL) {
		rc = -EBADMSG;
		goto out;
	}

	payload_len = ch - payload;
	ch++;

	rc = decode_base64url(NULL, &json_len, header, header_len);
	if (rc != 0)
		goto out;

	json = malloc(json_len + 1);
	if (json == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = decode_base64url((unsigned char *)json, &json_len,
			      header, header_len);
	if (rc != 0)
		goto out;

	json[json_len] = '\0';

	hdr = json_tokener_parse(json);
	if (hdr == NULL) {
		rc = -EIO;
		goto out;
	}

	if (json_object_object_get_ex(hdr, "b64", &b64_obj) &&
	    json_object_is_type(b64_obj, json_type_boolean))
		b64 = json_object_get_boolean(b64_obj);

	free(json);
	json = NULL;

	if (payload_obj != NULL) {
		if (b64) {
			rc = decode_base64url(NULL, &json_len, payload,
					      payload_len);
			if (rc != 0)
				goto out;

			json = malloc(json_len + 1);
			if (json == NULL) {
				rc = -ENOMEM;
				goto out;
			}

			rc = decode_base64url((unsigned char *)json, &json_len,
					      payload, payload_len);
			if (rc != 0)
				goto out;

			json[json_len] = '\0';
		} else {
			json = strndup(payload, payload_len);
		}

		pld = json_tokener_parse(json);
		if (pld == NULL) {
			rc = -EIO;
			goto out;
		}

		free(json);
		json = NULL;
	}

	if (signature != NULL && signature_len != NULL) {
		rc = decode_base64url(NULL, signature_len, ch, strlen(ch));
		if (rc != 0)
			goto out;

		*signature = malloc(*signature_len);
		if (*signature == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		rc = decode_base64url(*signature, signature_len, ch,
				      strlen(ch));
		if (rc != 0)
			goto out;
	}

out:
	if (header_obj != NULL && rc == 0)
		*header_obj = hdr;
	else
		json_object_put(hdr);
	if (payload_obj != NULL && rc == 0)
		*payload_obj = pld;
	else
		json_object_put(pld);
	if (signature != NULL && rc != 0) {
		free(signature);
		signature = NULL;
		*signature_len = 0;
	}
	if (json != NULL)
		free(json);

	return rc;
}

struct ecc_curve_info {
	int curve_nid;
	enum {
		ECC_TYPE_PRIME = 0,
		ECC_TYPE_BRAINPOOL = 1,
	} type;
	size_t prime_bits;
	size_t prime_len;
	const char *curve_id;
};

static const struct ecc_curve_info ecc_curve_list[] = {
	{ .curve_nid = NID_X9_62_prime192v1, .type = ECC_TYPE_PRIME,
	  .prime_bits = 192, .prime_len = 24, .curve_id = "P-192" },
	{ .curve_nid = NID_secp224r1,        .type = ECC_TYPE_PRIME,
	  .prime_bits = 224, .prime_len = 28, .curve_id = "P-224" },
	{ .curve_nid = NID_X9_62_prime256v1, .type = ECC_TYPE_PRIME,
	  .prime_bits = 256, .prime_len = 32, .curve_id = "P-256" },
	{ .curve_nid = NID_secp384r1,        .type = ECC_TYPE_PRIME,
	  .prime_bits = 384, .prime_len = 48, .curve_id = "P-384" },
	{ .curve_nid = NID_secp521r1,        .type = ECC_TYPE_PRIME,
	  .prime_bits = 521, .prime_len = 66, .curve_id = "P-521" },
	{ .curve_nid = NID_brainpoolP160r1,  .type = ECC_TYPE_BRAINPOOL,
	  .prime_bits = 160, .prime_len = 20, .curve_id = "brainpoolP160r1" },
	{ .curve_nid = NID_brainpoolP192r1,  .type = ECC_TYPE_BRAINPOOL,
	  .prime_bits = 192, .prime_len = 24, .curve_id = "brainpoolP192r1" },
	{ .curve_nid = NID_brainpoolP224r1,  .type = ECC_TYPE_BRAINPOOL,
	  .prime_bits = 224, .prime_len = 28, .curve_id = "brainpoolP224r1" },
	{ .curve_nid = NID_brainpoolP256r1,  .type = ECC_TYPE_BRAINPOOL,
	  .prime_bits = 256, .prime_len = 32, .curve_id = "brainpoolP256r1" },
	{ .curve_nid = NID_brainpoolP320r1,  .type = ECC_TYPE_BRAINPOOL,
	  .prime_bits = 320, .prime_len = 40, .curve_id = "brainpoolP320r1" },
	{ .curve_nid = NID_brainpoolP384r1,  .type = ECC_TYPE_BRAINPOOL,
	  .prime_bits = 384, .prime_len = 48, .curve_id = "brainpoolP384r1" },
	{ .curve_nid = NID_brainpoolP512r1,  .type = ECC_TYPE_BRAINPOOL,
	  .prime_bits = 512, .prime_len = 64, .curve_id = "brainpoolP512r1" },
};

static const int ecc_curve_num =
		sizeof(ecc_curve_list) / sizeof(struct ecc_curve_info);

/**
 * Returns the prime bit length of the specified curve, or 0 if the curve
 * is not known.
 */
size_t ecc_get_curve_prime_bits(int curve_nid)
{
	int i;

	for (i = 0; i < ecc_curve_num; i++) {
		if (ecc_curve_list[i].curve_nid == curve_nid)
			return ecc_curve_list[i].prime_bits;
	}
	return 0;
}

/**
 * Returns the prime length in bytes of the specified curve, or 0 if the curve
 * is not known.
 */
size_t ecc_get_curve_prime_length(int curve_nid)
{
	int i;

	for (i = 0; i < ecc_curve_num; i++) {
		if (ecc_curve_list[i].curve_nid == curve_nid)
			return ecc_curve_list[i].prime_len;
	}
	return 0;
}

/**
 * Returns the textual curve ID of the specified curve, or NULL if the curve
 * is not known.
 */
const char *ecc_get_curve_id(int curve_nid)
{
	int i;

	for (i = 0; i < ecc_curve_num; i++) {
		if (ecc_curve_list[i].curve_nid == curve_nid)
			return ecc_curve_list[i].curve_id;
	}
	return NULL;
}

/**
 * Returns true if the specified curve is a Prime curve, false if not, or if
 * the curve is not known.
 */
bool ecc_is_prime_curve(int curve_nid)
{
	int i;

	for (i = 0; i < ecc_curve_num; i++) {
		if (ecc_curve_list[i].curve_nid == curve_nid)
			return ecc_curve_list[i].type == ECC_TYPE_PRIME;
	}
	return false;
}

/**
 * Returns true if the specified curve is a Brainpool curve, false if not, or if
 * the curve is not known.
 */
bool ecc_is_brainpool_curve(int curve_nid)
{
	int i;

	for (i = 0; i < ecc_curve_num; i++) {
		if (ecc_curve_list[i].curve_nid == curve_nid)
			return ecc_curve_list[i].type == ECC_TYPE_BRAINPOOL;
	}
	return false;
}

/**
 * Returns the nid of the curve of the specified curve ID, or 0 if the curve
 * is not known.
 */
int ecc_get_curve_by_id(const char *curve_id)
{
	int i;

	for (i = 0; i < ecc_curve_num; i++) {
		if (strcmp(ecc_curve_list[i].curve_id, curve_id) == 0)
			return ecc_curve_list[i].curve_nid;
	}
	return 0;
}

/**
 * Returns the nid of the Prime curve by its specified prime bit size, or 0
 * if the curve is not knwon.
 */
int ecc_get_prime_curve_by_prime_bits(size_t prime_bits)
{
	int i;

	for (i = 0; i < ecc_curve_num; i++) {
		if (ecc_curve_list[i].type == ECC_TYPE_PRIME &&
		    ecc_curve_list[i].prime_bits == prime_bits)
			return ecc_curve_list[i].curve_nid;
	}
	return 0;
}

/**
 * Returns the nid of the Brainpool curve by its specified prime bit size, or 0
 * if the curve is not knwon.
 */
int ecc_get_brainpool_curve_by_prime_bits(size_t prime_bits)
{
	int i;

	for (i = 0; i < ecc_curve_num; i++) {
		if (ecc_curve_list[i].type == ECC_TYPE_BRAINPOOL &&
		    ecc_curve_list[i].prime_bits == prime_bits)
			return ecc_curve_list[i].curve_nid;
	}
	return 0;
}

/**
 * Calculates the y coordinate of a point on an EC curve using the x coordinate
 * and the y bit. x and y must be supplied by the caller with prime_len bytes.
 * On return y contains the calculated y coordinate.
 *
 * @param nid               the OpenSSL nid of the ECC curve used
 * @param prime_len         the length of the prime in bytes. This is also the
 *                          length of the x and y coordinates.
 * @param x                 the x coordinate as big endian binary number in
 *                          prime_len size
 * @param y_bit             the y-bit to identify which of the two possible
 *                          values for y should be used
 * @param y                 buffer to store the y coordinate as big endian
 *                          binary number in prime_len size.
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to calculate the y coordinate
 *          -ENOENT: OpenSSL does not know/support the curve (nid)
 */
int ecc_calculate_y_coordinate(int nid, size_t prime_len,
			       const unsigned char *x, int y_bit,
			       unsigned char *y)
{
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BIGNUM *bn_x = NULL;
	BIGNUM *bn_y = NULL;
	BN_CTX *ctx = NULL;
	int rc = 0;

	if (x == NULL || y == NULL)
		return -EINVAL;

	bn_x = BN_bin2bn(x, prime_len, NULL);
	if (bn_x == NULL) {
		rc = -EIO;
		goto out;
	}

	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL) {
		rc = -ENOENT;
		goto out;
	}

	point = EC_POINT_new(group);
	if (point == NULL) {
		rc = -EIO;
		goto out;
	}

	bn_y = BN_new();
	if (bn_y == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	ctx = BN_CTX_new();
	if (ctx == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	if (!EC_POINT_set_compressed_coordinates(group, point, bn_x,
						 y_bit, ctx)) {
		rc = -EIO;
		goto out;
	}

	if (!EC_POINT_is_on_curve(group, point, ctx)) {
		rc = -EIO;
		goto out;
	}

	if (!EC_POINT_get_affine_coordinates(group, point, bn_x, bn_y,
					     ctx)) {
		rc = -EIO;
		goto out;
	}

	BN_bn2binpad(bn_y, y, prime_len);

out:
	if (ctx != NULL)
		BN_CTX_free(ctx);
	if (point != NULL)
		EC_POINT_free(point);
	if (group != NULL)
		EC_GROUP_free(group);
	if (bn_x != NULL)
		BN_free(bn_x);
	if (bn_y != NULL)
		BN_free(bn_y);

	return rc;
}

/**
 * Converts an ECC public key given by the nid and the x and y coordinates into
 * an OpenSSL PKEY.
 *
 * @param nid               the OpenSSL nid of the ECC curve used
 * @param prime_len         the length of the prime in bytes. This is also the
 *                          length of the x and y coordinates.
 * @param x                 the x coordinate as big endian binary number in
 *                          prime_len size
 * @param y                 the y coordinate as big endian binary number in
 *                          prime_len size
 * @param pkey              On return: A PKEY containing the ECC public key.
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to generate the PKEY
 *          -ENOENT: OpenSSL does not know/support the curve (nid)
 */
int ecc_pub_key_as_pkey(int nid, size_t prime_len, const unsigned char *x,
			const unsigned char *y, EVP_PKEY **pkey)
{
	BIGNUM *bn_x = NULL, *bn_y = NULL;
	EC_GROUP *group = NULL;
	EC_KEY *ec = NULL;
	int rc;

	if (pkey == NULL || x == NULL || y == NULL)
		return -EINVAL;

	*pkey = NULL;

	bn_x = BN_bin2bn(x, prime_len, NULL);
	bn_y = BN_bin2bn(y, prime_len, NULL);
	if (bn_x == NULL || bn_y == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL) {
		rc = -ENOENT;
		goto out;
	}

	ec = EC_KEY_new();
	if (ec == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = EC_KEY_set_group(ec, group);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	rc = EC_KEY_set_public_key_affine_coordinates(ec, bn_x, bn_y);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	*pkey = EVP_PKEY_new();
	if (*pkey == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = EVP_PKEY_assign_EC_KEY(*pkey, ec);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	rc = 0;
out:
	if (bn_x != NULL)
		BN_free(bn_x);
	if (bn_y != NULL)
		BN_free(bn_y);
	if (group != NULL)
		EC_GROUP_free(group);
	if (rc != 0 && *pkey != NULL) {
		EVP_PKEY_free(*pkey);
		*pkey = NULL;
	}
	return rc;
}

/**
 * Converts an RSA public key given by the modulus and public exponent into
 * an OpenSSL PKEY.
 *
 * @param modulus           the modulus as big endian number
 * @param modulus_length    the length of the modulus in bytes
 * @param pub_exp           the public exponent as big endian number
 * @param pub_exp_length    the length of the public exponent in bytes
 * @param pkey_type         the PKEY type (EVP_PKEY_RSA or EVP_PKEY_RSA_PSS)
 * @param pkey              On return: A PKEY containing the RSA public key.
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to generate the PKEY
 */
int rsa_pub_key_as_pkey(const unsigned char *modulus, size_t modulus_length,
			const unsigned char *pub_exp, size_t pub_exp_length,
			int pkey_type, EVP_PKEY **pkey)
{
	BIGNUM *bn_modulus = NULL, *bn_pub_exp = NULL;
	RSA *rsa;
	int rc;

	if (pkey == NULL || modulus == NULL || pub_exp == NULL)
		return -EINVAL;

	if (pkey_type != EVP_PKEY_RSA && pkey_type != EVP_PKEY_RSA_PSS)
		return -EINVAL;

	*pkey = NULL;

	bn_modulus = BN_bin2bn(modulus, modulus_length, NULL);
	bn_pub_exp = BN_bin2bn(pub_exp, pub_exp_length, NULL);
	if (bn_modulus == NULL || bn_pub_exp == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = RSA_set0_key(rsa, bn_modulus, bn_pub_exp, NULL);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	*pkey = EVP_PKEY_new();
	if (*pkey == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = EVP_PKEY_assign(*pkey, pkey_type, rsa);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	rc = 0;

out:
	if (rc != 0 && bn_modulus != NULL)
		BN_free(bn_modulus);
	if (rc != 0 && bn_pub_exp != NULL)
		BN_free(bn_pub_exp);

	return rc;
}

/**
 * Write a secure key blob to the specified file.
 *
 * @param filename           the name of the file to write to
 * @param key_blob           the key blob to write
 * @param key_blob_len       the size of the key blob in bytes
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EIO: error during writing out the key blob
 *          any other errno as returned by fopen
 */
int write_key_blob(const char *filename, unsigned char *key_blob,
		   size_t key_blob_len)
{
	size_t count;
	FILE *fp;

	if (filename == NULL || key_blob == NULL || key_blob_len == 0)
		return -EINVAL;

	fp = fopen(filename, "w");
	if (fp == NULL)
		return -errno;

	count = fwrite(key_blob, 1, key_blob_len, fp);
	if (count != key_blob_len) {
		fclose(fp);
		return -EIO;
	}

	fclose(fp);
	return 0;
}

/**
 * Read a secure key blob from the specified file.
 *
 * @param filename           the name of the file to write to
 * @param key_blob           a buffer to read the key blob to. If NULL, then
 *                           only the size of the key blob is returned in
 *                           key_blob_len.
 * @param key_blob_len       On entry: the size of the buffer in bytes
 *                           On return: the size of the key blob read
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -ERANGE: The supplied buffer is too short. key_blob_len is set to
 *                   the required size.
 *          -EIO: error during reading in the key blob
 *          any other errno as returned by stat or fopen
 */
int read_key_blob(const char *filename, unsigned char *key_blob,
		  size_t *key_blob_len)
{
	size_t count, size;
	struct stat sb;
	FILE *fp;

	if (filename == NULL || key_blob_len == NULL)
		return -EINVAL;

	if (stat(filename, &sb))
		return -errno;
	size = sb.st_size;

	if (key_blob == NULL) {
		*key_blob_len = size;
		return 0;
	}

	if (size > *key_blob_len) {
		*key_blob_len = size;
		return -ERANGE;
	}

	fp = fopen(filename, "r");
	if (fp == NULL)
		return -errno;

	count = fread(key_blob, 1, size, fp);
	if (count != size) {
		fclose(fp);
		return -EIO;
	}

	*key_blob_len = size;
	fclose(fp);
	return 0;
}

/**
 * Reads a X.509 certificate from the specified PEM file.
 *
 * @param pem_filename       the name of the PEM file to read
 * @param cert               on Return: the X.509 certificate object
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EIO: error during reading in the certificate
 *          any other errno as returned by fopen
 */
int read_x509_certificate(const char *pem_filename, X509 **cert)
{
	FILE *fp;

	if (pem_filename == NULL || cert == NULL)
		return -EINVAL;

	fp = fopen(pem_filename, "r");
	if (fp == NULL)
		return -errno;

	*cert = PEM_read_X509(fp, NULL, NULL, NULL);

	fclose(fp);

	if (*cert == NULL)
		return -EIO;

	return 0;
}

/**
 * Writes a X.509 certificate to the specified PEM file.
 *
 * @param pem_filename       the name of the PEM file to write to
 * @param cert               the X.509 certificate object to write
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EIO: error during writing out the certificate
 *          any other errno as returned by fopen
 */
int write_x509_certificate(const char *pem_filename, X509 *cert)
{
	FILE *fp;
	int rc;

	if (pem_filename == NULL || cert == NULL)
		return -EINVAL;

	fp = fopen(pem_filename, "w");
	if (fp == NULL)
		return -errno;

	rc = PEM_write_X509(fp, cert);

	fclose(fp);

	if (rc != 1)
		return -EIO;

	return 0;
}

/**
 * Writes a X.509 certificate signing request to the specified PEM file.
 *
 * @param pem_filename       the name of the PEM file to write to
 * @param req                the X.509 request object to write
 * @param new_hdr            if true, output "NEW" in the PEM header lines
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EIO: error during writing out the certificate
 *          any other errno as returned by fopen
 */
int write_x509_request(const char *pem_filename, X509_REQ *req, bool new_hdr)
{
	FILE *fp;
	int rc;

	if (pem_filename == NULL || req == NULL)
		return -EINVAL;

	fp = fopen(pem_filename, "w");
	if (fp == NULL)
		return -errno;

	if (new_hdr)
		rc = PEM_write_X509_REQ_NEW(fp, req);
	else
		rc = PEM_write_X509_REQ(fp, req);

	fclose(fp);

	if (rc != 1)
		return -EIO;

	return 0;
}

/* Secure key PKEY context control */
#define EVP_PKEY_CTRL_SK_KEY_BLOB		0x10000001
#define EVP_PKEY_CTRL_SK_SIGN_FUNCTIONS		0x10000002
#define EVP_PKEY_CTRL_SK_PRIVATE_DATA		0x10000003

/* Secure key PKEY context data */
struct sk_pkey_ctx {
	rsa_sign_t         rsa_sign;
	rsa_pss_sign_t     rsa_pss_sign;
	ecdsa_sign_t       ecdsa_sign;

	unsigned char      *key_blob;
	size_t             key_blob_length;

	const EVP_MD       *md;
	int                rsa_padding;
	int                rsa_pss_saltlen;
	const EVP_MD       *rsa_pss_mgfmd;

	void               *private;
};

/**
 * Initialize an secure key PKEY context
 *
 * @param ctx                the PKEY context to initialize
 *
 * @returns 1 for success, 0 in case of an error
 */
static int sk_pkey_meth_init(EVP_PKEY_CTX *ctx)
{
	struct sk_pkey_ctx *sk_ctx;
	EVP_PKEY *pkey;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey == NULL)
		return 0;

	sk_ctx = OPENSSL_zalloc(sizeof(struct sk_pkey_ctx));
	if (sk_ctx == NULL)
		return 0;

	if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA_PSS) {
		sk_ctx->rsa_pss_saltlen = RSA_PSS_SALTLEN_AUTO;
		sk_ctx->rsa_padding = RSA_PKCS1_PSS_PADDING;
	}
	if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA)
		sk_ctx->rsa_padding = RSA_PKCS1_PADDING;

	EVP_PKEY_CTX_set_data(ctx, sk_ctx);

	return 1;
}

/**
 * Cleanup an secure key PKEY context
 *
 * @param ctx                the PKEY context to to clean
 */
static void sk_pkey_meth_cleanup(EVP_PKEY_CTX *ctx)
{
	struct sk_pkey_ctx *sk_ctx;

	sk_ctx = EVP_PKEY_CTX_get_data(ctx);
	if (sk_ctx != NULL) {
		OPENSSL_free(sk_ctx);
		EVP_PKEY_CTX_set_data(ctx, NULL);
	}
}

/**
 * Copy an secure key PKEY context
 *
 * @param dst                the source PKEY context to copy from
 * @param src                the destinationPKEY context to copy to
 *
 * @returns 1 for success, 0 in case of an error
 */
static int sk_pkey_meth_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	struct sk_pkey_ctx *sk_ctx_src, *sk_ctx_dst;

	if (sk_pkey_meth_init(dst) != 1)
		return 0;

	sk_ctx_src = EVP_PKEY_CTX_get_data(src);
	if (sk_ctx_src == NULL)
		return 0;

	sk_ctx_dst = EVP_PKEY_CTX_get_data(dst);
	if (sk_ctx_dst == NULL)
		return 0;

	sk_ctx_dst->rsa_sign = sk_ctx_src->rsa_sign;
	sk_ctx_dst->rsa_pss_sign = sk_ctx_src->rsa_pss_sign;
	sk_ctx_dst->ecdsa_sign = sk_ctx_src->ecdsa_sign;
	sk_ctx_dst->key_blob = sk_ctx_src->key_blob;
	sk_ctx_dst->key_blob_length = sk_ctx_src->key_blob_length;
	sk_ctx_dst->md = sk_ctx_src->md;
	sk_ctx_dst->rsa_pss_saltlen = sk_ctx_src->rsa_pss_saltlen;
	sk_ctx_dst->rsa_padding = sk_ctx_src->rsa_padding;
	sk_ctx_dst->rsa_pss_mgfmd = sk_ctx_src->rsa_pss_mgfmd;
	sk_ctx_dst->private = sk_ctx_src->private;

	return 1;
}

/**
 * Perform a sign operation with the secure key PKEY context.
 * The data to be signed has already been hashed.
 *
 * The key to perform the sign operation with is available in the PKEY context.
 * For this secure key case, the pkey as well as the secure key blob is
 * available.
 *
 * @param ctx                the PKEY context to sign with
 * @param sig                the buffer to store the signature
 * @param siglen             On input: the size of the signature buffer
 *                           On return: the size of the signature
 * @param tbs                the data to be signed
 * @param tbslen             the size of the data to be signed
 *
 * @returns 1 for success, 0 in case of an error
 */
static int sk_pkey_meth_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
			     size_t *siglen, const unsigned char *tbs,
			     size_t tbslen)
{
	int rc, md_type, mgf_md_type, saltlen, max_saltlen, hlen;
	struct sk_pkey_ctx *sk_ctx;
	EVP_PKEY *pkey;

	sk_ctx = EVP_PKEY_CTX_get_data(ctx);
	if (sk_ctx == NULL)
		return 0;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey == NULL)
		return 0;

	md_type = sk_ctx->md != NULL ? EVP_MD_type(sk_ctx->md) : NID_sha1;

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA:
		if (sk_ctx->rsa_sign == NULL)
			return 0;
		rc = sk_ctx->rsa_sign(sk_ctx->key_blob, sk_ctx->key_blob_length,
				      sig, siglen, tbs, tbslen,
				      sk_ctx->rsa_padding, md_type,
				      sk_ctx->private);
		break;

	case EVP_PKEY_RSA_PSS:
		if (sk_ctx->rsa_pss_sign == NULL)
			return 0;

		if (sk_ctx->md != NULL)
			hlen = EVP_MD_size(sk_ctx->md);
		else
			hlen = SHA_DIGEST_LENGTH;

		if (sk_ctx->rsa_pss_mgfmd != NULL) {
			mgf_md_type = EVP_MD_type(sk_ctx->rsa_pss_mgfmd);
			hlen = EVP_MD_size(sk_ctx->rsa_pss_mgfmd);
		} else {
			mgf_md_type = md_type;
		}

		/*
		 * We should be using RSA_bits(EVP_PKEY_get0_RSA(pkey)) here,
		 * but EVP_PKEY_get0_RSA(pkey) does not work with PKEY/type
		 * EVP_PKEY_RSA_PSS on older OpenSSL versions, so we fall back
		 * on EVP_PKEY_bits in this case.
		 */
		max_saltlen = (EVP_PKEY_get0_RSA(pkey) != NULL ?
					RSA_bits(EVP_PKEY_get0_RSA(pkey)) :
					EVP_PKEY_bits(pkey)) / 8 - hlen - 2;

		switch (sk_ctx->rsa_pss_saltlen) {
		case RSA_PSS_SALTLEN_DIGEST:
			saltlen = hlen;
			break;
		case RSA_PSS_SALTLEN_AUTO:
		case RSA_PSS_SALTLEN_MAX:
			saltlen = max_saltlen;
			break;
		default:
			saltlen = sk_ctx->rsa_pss_saltlen;
			break;
		}

		if (saltlen > max_saltlen || saltlen < 0)
			return 0;

		rc = sk_ctx->rsa_pss_sign(sk_ctx->key_blob,
					  sk_ctx->key_blob_length,
					  sig, siglen, tbs, tbslen,
					  md_type, mgf_md_type, saltlen,
					  sk_ctx->private);
		break;

	case EVP_PKEY_EC:
		if (sk_ctx->ecdsa_sign == NULL)
			return 0;

		rc = sk_ctx->ecdsa_sign(sk_ctx->key_blob,
					sk_ctx->key_blob_length, sig, siglen,
					tbs, tbslen, md_type, sk_ctx->private);
		break;

	default:
		rc = -1;
	}

	return rc == 0 ? 1 : 0;
}

/**
 * Control options of the secure key PKEY context
 *
 * Besides some standard controls, the following secure key PKEY context
 * specific controls are available:
 *   EVP_PKEY_CTRL_SK_KEY_BLOB         set the secure key blob into the context
 *   EVP_PKEY_CTRL_SK_SIGN_FUNCTIONS   set the sign functions for the context
 *   EVP_PKEY_CTRL_SK_PRIVATE_DATA     set the private data to the context
 *
 * @param ctx                the PKEY context to control
 * @param type               the control type
 * @param p1                 an integer option
 * @param p2                 a pointer option
 *
 * @returns 1 for success, 0 in case of an error, -2 if the control is not
 * supported by the context
 */
static int sk_pkey_meth_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	struct sk_pkey_sign_func *func;
	struct sk_pkey_ctx *sk_ctx;
	EVP_PKEY *pkey;
	int md_type;

	sk_ctx = EVP_PKEY_CTX_get_data(ctx);
	if (sk_ctx == NULL)
		return 0;

	pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (pkey == NULL)
		return 0;

	switch (type) {
	case EVP_PKEY_CTRL_SK_KEY_BLOB:
		sk_ctx->key_blob = p2;
		sk_ctx->key_blob_length = p1;
		break;

	case EVP_PKEY_CTRL_SK_SIGN_FUNCTIONS:
		func = (struct sk_pkey_sign_func *)p2;
		sk_ctx->rsa_sign = func->rsa_sign;
		sk_ctx->rsa_pss_sign = func->rsa_pss_sign;
		sk_ctx->ecdsa_sign = func->ecdsa_sign;
		break;

	case EVP_PKEY_CTRL_SK_PRIVATE_DATA:
		sk_ctx->private = p2;
		break;

	case EVP_PKEY_CTRL_MD:
		md_type = EVP_MD_type((const EVP_MD *)p2);
		if (md_type != NID_sha1 &&
		    md_type != NID_ecdsa_with_SHA1 &&
		    md_type != NID_sha224 &&
		    md_type != NID_sha256 &&
		    md_type != NID_sha384 &&
		    md_type != NID_sha512 &&
		    md_type != NID_sha3_224 &&
		    md_type != NID_sha3_256 &&
		    md_type != NID_sha3_384 &&
		    md_type != NID_sha3_512)
			return 0;
		sk_ctx->md = p2;
		break;

	case EVP_PKEY_CTRL_GET_MD:
		*(const EVP_MD **)p2 = sk_ctx->md;
		break;

	case EVP_PKEY_CTRL_RSA_PADDING:
		switch (EVP_PKEY_id(pkey)) {
		case EVP_PKEY_EC:
			return -2;
		case EVP_PKEY_RSA:
			break;
		case EVP_PKEY_RSA_PSS:
			if (p1 != RSA_PKCS1_PSS_PADDING)
				return -2;
			break;
		}
		sk_ctx->rsa_padding = p1;
		break;

	case EVP_PKEY_CTRL_GET_RSA_PADDING:
		switch (EVP_PKEY_id(pkey)) {
		case EVP_PKEY_EC:
			return -1;
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA_PSS:
			*(int *)p2 = sk_ctx->rsa_padding;
			break;
		}
		break;

	case EVP_PKEY_CTRL_RSA_PSS_SALTLEN:
		if (sk_ctx->rsa_padding != RSA_PKCS1_PSS_PADDING)
			return -2;
		if (p1 < RSA_PSS_SALTLEN_MAX)
			return -2;
		if (p1 == RSA_PSS_SALTLEN_MAX)
			sk_ctx->rsa_pss_saltlen = RSA_PSS_SALTLEN_MAX_SIGN;
		else
			sk_ctx->rsa_pss_saltlen = p1;
		break;

	case EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN:
		if (sk_ctx->rsa_padding != RSA_PKCS1_PSS_PADDING)
			return -2;
		*(int *)p2 = sk_ctx->rsa_pss_saltlen;
		break;

	case EVP_PKEY_CTRL_RSA_MGF1_MD:
		if (sk_ctx->rsa_padding != RSA_PKCS1_PSS_PADDING)
			return -2;
		sk_ctx->rsa_pss_mgfmd = p2;
		break;

	case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:
		if (sk_ctx->rsa_padding != RSA_PKCS1_PSS_PADDING)
			return -2;
		*(const EVP_MD **)p2 = sk_ctx->rsa_pss_mgfmd != NULL ?
					sk_ctx->rsa_pss_mgfmd : sk_ctx->md;
		break;

	case EVP_PKEY_CTRL_DIGESTINIT:
	case EVP_PKEY_CTRL_PEER_KEY:
	case EVP_PKEY_CTRL_PKCS7_SIGN:
	case EVP_PKEY_CTRL_CMS_SIGN:
		break;

	default:
		return -2;
	}

	return 1;
}

/**
 * Sets up a secure key PKEY method to handle PKEY sign operations of the
 * specified PKEY id (type) using secure key functions, instead of the default
 * ones.
 *
 * Note: This should be done only right before the sign operation is used, and
 * should be cleaned up using cleanup_secure_key_pkey_method() right after the
 * sign operation is finished, to not interfere with other PKEY usage.
 *
 * @param pkey_id            the PKEY id (type) to setup special handling
 *                           for. Use EVP_PKEY_id() to get the id of an existing
 *                           pkey.
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to setup the method
 */
int setup_secure_key_pkey_method(int pkey_id)
{
	EVP_PKEY_METHOD *pkey_meth;

	pkey_meth = EVP_PKEY_meth_new(pkey_id, 0);
	if (pkey_meth == NULL)
		return -ENOMEM;

	EVP_PKEY_meth_set_init(pkey_meth, sk_pkey_meth_init);
	EVP_PKEY_meth_set_cleanup(pkey_meth, sk_pkey_meth_cleanup);
	EVP_PKEY_meth_set_copy(pkey_meth, sk_pkey_meth_copy);
	EVP_PKEY_meth_set_ctrl(pkey_meth, sk_pkey_meth_ctrl, NULL);
	EVP_PKEY_meth_set_sign(pkey_meth, NULL, sk_pkey_meth_sign);

	if (EVP_PKEY_meth_add0(pkey_meth) != 1)
		return -EIO;

	return 0;
}

/**
 * Cleans up the secure key PKEY method to handle PKEY sign operations of the
 * specified PKEY id (type) using secure key functions.
 *
 * Note: Only call this function of you have previously setup the PKEY method
 *       using setup_secure_key_pkey_method().
 *
 * @param pkey_id            the PKEY id (type) to setup special handling
 *                           for. Use EVP_PKEY_id() to get the id of an existing
 *                           pkey.
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -ENOENT: method not found
 *          -EIO: OpenSSL failed to cleanup the method
 */
int cleanup_secure_key_pkey_method(int pkey_id)
{
	const EVP_PKEY_METHOD *pkey_meth;

	pkey_meth = EVP_PKEY_meth_find(pkey_id);
	if (pkey_meth == NULL)
		return -ENOENT;

	if (EVP_PKEY_meth_remove(pkey_meth) != 1)
		return -EIO;

	EVP_PKEY_meth_free((EVP_PKEY_METHOD *)pkey_meth);

	return 0;
}

/**
 * Sets up a secure key PKEY context to handle PKEY sign operations using the
 * specified secure key blob, and secure key sign functions. The secure key blob
 * must match the PKEY that was used to create the context with. The pkey
 * contains the public key parts only, the secure key blob contains the
 * private (and possibly public) key parts of the same key.
 *
 * Note: Only call this function of you have previously setup the PKEY method
 *       using setup_secure_key_pkey_method().
 *
 * @param pkey_ctx           the PKEY context to setup special handling for
 * @param key_blob           the secure key blob to sign with
 * @param key_blob_len       the size of the key bob in bytes
 * @param sign_funcs         secure key specific sign functions
 * @param private            a pointer passed as is to the sign functions
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid argument
 *          -EIO: OpenSSL failed to setup the context
 */
int setup_secure_key_pkey_context(EVP_PKEY_CTX *pkey_ctx,
				  const unsigned char *key_blob,
				  size_t key_blob_len,
				  struct sk_pkey_sign_func *sign_funcs,
				  void *private)
{
	int rc;

	if (pkey_ctx == NULL || sign_funcs == NULL)
		return -EINVAL;

	rc = EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_SK_KEY_BLOB,
			       key_blob_len, (void *)key_blob);
	if (rc != 1)
		return -EIO;

	rc = EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1,
			       EVP_PKEY_CTRL_SK_SIGN_FUNCTIONS,
			       0, sign_funcs);
	if (rc != 1)
		return -EIO;

	rc = EVP_PKEY_CTX_ctrl(pkey_ctx, -1, -1, EVP_PKEY_CTRL_SK_PRIVATE_DATA,
			       0, private);
	if (rc != 1)
		return -EIO;

	return 0;
}

/**
 * Sets up a PKEY context with RSA-PSS parameters.
 *
 * @param pkey_ctx           the PKEY context to setup special handling for
 * @param rsa_pss_params     the RSA-PSS paramaters
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid argument
 *          -EIO: OpenSSL failed to setup the context
 */
int setup_rsa_pss_pkey_context(EVP_PKEY_CTX *pkey_ctx,
			       struct ekmf_rsa_pss_params *rsa_pss_params)
{
	const EVP_MD *mgf_md;
	int rc;

	if (pkey_ctx == NULL || rsa_pss_params == NULL)
		return -EINVAL;

	rc = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx,
					  RSA_PKCS1_PSS_PADDING);
	if (rc != 1)
		return -EIO;

	rc = EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx,
					      rsa_pss_params->salt_len);
	if (rc != 1)
		return -EIO;

	if (rsa_pss_params->mgf_digest_nid != 0) {
		mgf_md = EVP_get_digestbynid(
				rsa_pss_params->mgf_digest_nid);
		if (mgf_md == NULL)
			return -ENOENT;

		rc = EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, mgf_md);
		if (rc != 1)
			return -EIO;
	}

	return 0;
}

/**
 * Checks if an exact duplicate of the name entry is part of the name already.
 */
static bool is_duplicate_name_entry(X509_NAME *name, X509_NAME_ENTRY *entry)
{
	X509_NAME_ENTRY *ne;
	int count, i;

	count = X509_NAME_entry_count(name);
	for (i = 0; i < count; i++) {
		ne = X509_NAME_get_entry(name, i);
		if (ne == NULL)
			break;

		if (OBJ_cmp(X509_NAME_ENTRY_get_object(entry),
			    X509_NAME_ENTRY_get_object(ne)) == 0 &&
		    ASN1_STRING_cmp(X509_NAME_ENTRY_get_data(entry),
				    X509_NAME_ENTRY_get_data(ne)) == 0)
			return true;
	}

	return false;
}

/**
 * Parse an array of relative distinguished names and builds an X.509 subject
 * name. The RDNs are created with type MBSTRING_ASC, unless utf8 is requested,
 * then they are created with MBSTRING_UTF8.
 * To create a multiple-RDS name, prepend the RDS to add to the previous RDS
 * with a '+' character.
 *
 * @param name               the X.509 name created. If *name is not NULL, then
 *                           the RDNs are added to the existing X.509 name.
 * @param rdns               an array of strings, each string representing an
 *                           RDN in the form '[+]type=value'. If the type is
 *                           prepended with a '+', then this RDN is added to the
 *                           previous one.
 * @param num_rdns           number of elements in the array.
 * @param utf8               if true, RDNs of type MBSTRING_UTF8 are created,
 *                           otherwise type is MBSTRING_ASC is used.
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EBADMSG: an RDN is not formatted correctly
 *          -EIO: OpenSSL failed to create an X.509 name entry
 *          -EEXIST: if one of the name entries to add is a duplicate
 */
int build_subject_name(X509_NAME **name, const char *rdns[], size_t num_rdns,
		       bool utf8)
{
	char *rdn, *type, *value;
	X509_NAME_ENTRY *ne;
	X509_NAME *n;
	int rc = 0;
	bool multi;
	size_t i;

	if (name == NULL || rdns == NULL)
		return -EINVAL;

	if (*name != NULL)
		n = *name;
	else
		n = X509_NAME_new();
	if (n == NULL)
		return -ENOMEM;

	for (i = 0; i < num_rdns; i++) {
		if (rdns[i] == NULL) {
			rc = -EINVAL;
			break;
		}

		rdn = strdup(rdns[i]);
		if (rdn == NULL) {
			rc = -ENOMEM;
			break;
		}

		multi = (rdn[0] == '+');
		type = &rdn[multi ? 1 : 0];

		for (value = type; *value != '=' && *value != '\0'; value++)
			;
		if (*value != '=') {
			rc = -EBADMSG;
			free(rdn);
			break;
		}
		*value = '\0';
		value++;

		ne = X509_NAME_ENTRY_create_by_txt(NULL, type,
						   utf8 ? MBSTRING_UTF8 :
								MBSTRING_ASC,
						   (unsigned char *)value, -1);
		if (ne == NULL) {
			rc = -EBADMSG;
			free(rdn);
			break;
		}

		if (is_duplicate_name_entry(n, ne)) {
			rc = -EEXIST;
			X509_NAME_ENTRY_free(ne);
			free(rdn);
			break;
		}

		rc = X509_NAME_add_entry(n, ne, -1, multi ? -1 : 0);

		free(rdn);
		X509_NAME_ENTRY_free(ne);

		if (rc != 1) {
			rc = -EIO;
			break;
		}
		rc = 0;
	}

	if (rc == 0)
		*name = n;
	else if (*name == NULL)
		X509_NAME_free(n);

	return rc;
}

/**
 * Compares X509 Extensions by their nid
 */
static int X509_EXTENSION_compfunc(const X509_EXTENSION * const* a,
				   const X509_EXTENSION * const* b)
{

	return (OBJ_obj2nid(X509_EXTENSION_get_object((X509_EXTENSION *)a)) -
		OBJ_obj2nid(X509_EXTENSION_get_object((X509_EXTENSION *)b)));
}

/**
 * Parse an array of textual X.509 certificate extensions and adds them to
 * either an X.509 certificate signing request, or an X.509 certificate.
 *
 * When adding extensions, a check is performed if an extension with the same
 * nid is already added. If so, a duplicate extension is not added, even if
 * its value is different from the existing one.
 *
 * @param cert               the X.509 certificate to add the extensions to.
 *                           Either req or cert can be specified.
 * @param req                the X.509 certificate signing request to add the
 *                           extensions to. Either req or cert can be specified.
 * @param exts               an array of strings, each string representing an
 *                           certificate extension in the form 'type=value'.
 *                           can be NULL if num_exts is zero.
 * @param num_exts           number of elements in the array.
 * @param addl_exts          a stack of extensions to add (can be NULL)
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EBADMSG: an extension is not formatted correctly
 *          -EIO: OpenSSL failed to create an X.509 extension
 *          -EEXIST: if one of the extensions to add is a duplicate
 */
int build_certificate_extensions(X509 *cert, X509_REQ *req,
				 const char *exts[], size_t num_exts,
				 const STACK_OF(X509_EXTENSION) *addl_exts)
{
	STACK_OF(X509_EXTENSION) *sk_ext;
	char *ext, *type, *value;
	X509V3_CTX x509v3_ctx;
	int count, k, rc = 0;
	X509_EXTENSION *ex;
	size_t i;

	if (num_exts > 0 && exts == NULL)
		return -EINVAL;
	if (cert == NULL && req == NULL)
		return -EINVAL;
	if (cert != NULL && req != NULL)
		return -EINVAL;

	sk_ext = sk_X509_EXTENSION_new_null();
	if (sk_ext == NULL)
		return -ENOMEM;

	sk_X509_EXTENSION_set_cmp_func(sk_ext, X509_EXTENSION_compfunc);

	for (i = 0; exts != NULL && i < num_exts; i++) {
		if (exts[i] == NULL) {
			rc = -EINVAL;
			break;
		}

		ext = strdup(exts[i]);
		if (ext == NULL) {
			rc = -ENOMEM;
			break;
		}

		type = &ext[0];

		for (value = type; *value != '=' && *value != '\0'; value++)
			;
		if (*value != '=') {
			rc = -EBADMSG;
			free(ext);
			break;
		}
		*value = '\0';
		value++;

		rc = -EBADMSG;
		ex = X509V3_EXT_conf(NULL, NULL, type, value);
		if (ex != NULL) {
			if (sk_X509_EXTENSION_find(sk_ext, ex) >= 0) {
				rc = -EEXIST;
				free(ext);
				break;
			}

			rc = sk_X509_EXTENSION_push(sk_ext, ex);
			if (rc < 1) {
				rc = -EIO;
				free(ext);
				break;
			}
			rc = 0;
		}

		free(ext);
	}

	if (rc != 0)
		goto out;

	if (addl_exts != NULL) {
		count = sk_X509_EXTENSION_num(addl_exts);
		for (k = 0; k < count; k++) {
			ex = sk_X509_EXTENSION_value(addl_exts, k);
			if (ex != NULL) {
				if (sk_X509_EXTENSION_find(sk_ext, ex) >= 0) {
					rc = -EEXIST;
					break;
				}

				rc = sk_X509_EXTENSION_push(sk_ext,
						X509_EXTENSION_dup(ex));
				if (rc < 1) {
					rc = -EIO;
					break;
				}
				rc = 0;
			}
		}
	}

	if (rc != 0)
		goto out;

	if (req != NULL && sk_X509_EXTENSION_num(sk_ext) > 0) {
		if (X509_REQ_add_extensions(req, sk_ext) != 1)
			rc = -EIO;
		sk_X509_EXTENSION_pop_free(sk_ext, X509_EXTENSION_free);
		sk_ext = NULL;
		goto out;
	}

	if (cert != NULL && sk_X509_EXTENSION_num(sk_ext) > 0) {
		X509V3_set_ctx_nodb(&x509v3_ctx);
		X509V3_set_ctx(&x509v3_ctx, cert, cert, NULL, NULL, 0);

		rc = 0;
		while ((ex = sk_X509_EXTENSION_pop(sk_ext)) != NULL) {
			if (rc == 0) {
				if (X509_add_ext(cert, ex, -1) != 1)
					rc = -EIO;
			}
			X509_EXTENSION_free(ex);
		}
	}

out:
	if (sk_ext != NULL)
		sk_X509_EXTENSION_pop_free(sk_ext, X509_EXTENSION_free);
	return rc;
}

/**
 * Generates a serial number of a specified bit size by random and sets it
 * as serial number into the certificate.
 *
 * @param cert               the certificate to set the serial number for
 * @param sn_bit_size        the size of the serial number in bits
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EIO: error during serial number generation
 */
int generate_x509_serial_number(X509 *cert, size_t sn_bit_size)
{
	ASN1_INTEGER *ai = NULL;
	BIGNUM *bn = NULL;
	int rc;

	if (cert == NULL)
		return -EINVAL;

	bn =  BN_new();
	if (bn == NULL)
		return -ENOMEM;

	rc = BN_rand(bn, sn_bit_size, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	ai = X509_get_serialNumber(cert);
	if (ai == NULL) {
		rc = -EIO;
		goto out;
	}

	if (BN_to_ASN1_INTEGER(bn, ai) == NULL) {
		rc = -EIO;
		goto out;
	}

	rc = 0;

out:
	if (bn != NULL)
		BN_free(bn);

	return rc;
}

