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
