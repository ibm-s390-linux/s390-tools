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
