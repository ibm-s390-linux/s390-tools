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
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>

#include "lib/zt_common.h"

#include "utilities.h"

#ifndef JSON_C_TO_STRING_NOSLASHESCAPE
#define JSON_C_TO_STRING_NOSLASHESCAPE (1 << 4)
#endif

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
 * Creates a JSON Web Signature object with the specified parts and returns a
 * a character string containing the serialized JWS (see RFC 7515 for details)
 *
 * @param algorithm         the JWS algorithm (e.g. ES512) (in the JWS header)
 * @param b64               the b64 property of the JWS header. If b64 is true,
 *                          then the payload (if any) is base64url encoded,
 *                          if false, the payload (if any) is used as-is.
 * @param kid               the Key ID JWS header field (can be NULL)
 * @param payload           the JWS payload.
 * @param payload_len       the length of the payload in bytes
 * @param detached_payload  if true a JWS with detached payload is created (see
 *                          RFC 7515 Appendix F)
 * @param md_ctx            An OpenSSL MD that has been set up with the desired
 *                          digest and signing algorithm, options, and key
 * @param jws               On return: a C-string allocated by this function
 *                          containing the serialized JWS. The caller must
 *                          free the memory used by the returned string.
 *
 * @returns zero for success, a negative errno in case of an error
 */
int create_json_web_signature(const char *algorithm, bool b64, const char *kid,
			      const unsigned char *payload, size_t payload_len,
			      bool detached_payload, EVP_MD_CTX *md_ctx,
			      char **jws)
{
	unsigned char *signature = NULL;
	json_object *header_obj = NULL;
	json_object *crit_obj = NULL;
	size_t signature_b64_len = 0;
	size_t payload_b64_len = 0;
	char *signature_b64 = NULL;
	size_t header_b64_len = 0;
	size_t signature_len = 0;
	char *payload_b64 = NULL;
	ECDSA_SIG *ec_sig = NULL;
	char *header_b64 = NULL;
	const unsigned char *p;
	const char *header;
	size_t prime_len;
	EVP_PKEY *pkey;
	int rc;

	if (algorithm == NULL || payload == NULL || md_ctx == NULL ||
	    jws == NULL)
		return -EINVAL;

	pkey = EVP_PKEY_CTX_get0_pkey(EVP_MD_CTX_pkey_ctx(md_ctx));
	if (pkey == NULL) {
		rc = -EIO;
		goto out;
	}

	header_obj = json_object_new_object();
	if (header_obj == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	/*
	 * Note: The order of the fields is important, EKMFWeb expects it in
	 * exactly this order!
	 */
	rc = json_object_object_add_ex(header_obj, "alg",
				       json_object_new_string(algorithm), 0);
	if (kid != NULL)
		rc |= json_object_object_add_ex(header_obj, "kid",
						json_object_new_string(kid), 0);
	rc |= json_object_object_add_ex(header_obj, "b64",
					json_object_new_boolean(b64), 0);
	crit_obj = json_object_new_array();
	rc |= (crit_obj == NULL ? -1 : 0);
	rc |= json_object_array_add(crit_obj, json_object_new_string("b64"));
	rc |= json_object_object_add_ex(header_obj, "crit", crit_obj, 0);
	crit_obj = NULL;
	if (rc != 0) {
		rc = -EIO;
		goto out;
	}

	header = json_object_to_json_string_ext(header_obj,
						JSON_C_TO_STRING_PLAIN |
						JSON_C_TO_STRING_NOSLASHESCAPE);
	if (header == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = encode_base64url(NULL, &header_b64_len, (unsigned char *)header,
			      strlen(header));
	if (rc != 0)
		goto out;

	header_b64 = malloc(header_b64_len);
	if (header_b64 == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = encode_base64url(header_b64, &header_b64_len,
			      (unsigned char *)header, strlen(header));
	if (rc != 0)
		goto out;

	if (b64) {
		rc = encode_base64url(NULL, &payload_b64_len, payload,
				      payload_len);
		if (rc != 0)
			goto out;

		payload_b64 = malloc(payload_b64_len);
		if (payload_b64 == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		rc = encode_base64url(payload_b64, &payload_b64_len, payload,
				      payload_len);
		if (rc != 0)
			goto out;
	}

	/* Sign: BASE64URL(UTF8(JWSHeader)) | '.' | [BASE64URL](JWS Payload) */
	rc = EVP_DigestSignUpdate(md_ctx, header_b64, strlen(header_b64));
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	rc = EVP_DigestSignUpdate(md_ctx, ".", 1);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	if (b64)
		rc = EVP_DigestSignUpdate(md_ctx, payload_b64,
					  strlen(payload_b64));
	else
		rc = EVP_DigestSignUpdate(md_ctx, payload, payload_len);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	signature_len = EVP_PKEY_size(pkey);
	signature = malloc(signature_len);
	if (signature == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = EVP_DigestSignFinal(md_ctx, signature, &signature_len);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_EC:
		prime_len = ecc_get_curve_prime_length(EC_GROUP_get_curve_name(
				EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey))));

		p = signature;
		if (d2i_ECDSA_SIG(&ec_sig, &p, signature_len) == NULL) {
			rc = -EIO;
			goto out;
		}

		if (signature_len < 2 * prime_len) {
			rc = -EINVAL;
			goto out;
		}

		memset(signature, 0, signature_len);
		BN_bn2binpad(ECDSA_SIG_get0_r(ec_sig), signature, prime_len);
		BN_bn2binpad(ECDSA_SIG_get0_s(ec_sig), signature + prime_len,
			     prime_len);
		signature_len = 2 * prime_len;
		break;

	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		/* No signature encoding for RSA */
		break;

	default:
		rc = -EINVAL;
		goto out;
	}

	rc = encode_base64url(NULL, &signature_b64_len, signature,
			      signature_len);
	if (rc != 0)
		goto out;

	signature_b64 = malloc(signature_b64_len);
	if (signature_b64 == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = encode_base64url(signature_b64, &signature_b64_len, signature,
			      signature_len);
	if (rc != 0)
		goto out;

	if (detached_payload) {
		if (asprintf(jws, "%s..%s", header_b64, signature_b64) < 0) {
			rc = -ENOMEM;
			goto out;
		}
	} else if (b64) {
		if (asprintf(jws, "%s.%s.%s", header_b64, payload_b64,
			     signature_b64) < 0) {
			rc = -ENOMEM;
			goto out;
		}
	} else {
		if (asprintf(jws, "%s.%.*s.%s", header_b64, (int)payload_len,
			     payload, signature_b64) < 0) {
			rc = -ENOMEM;
			goto out;
		}
	}

	rc = 0;

out:
	if (header_obj != NULL)
		json_object_put(header_obj);
	if (header_b64 != NULL)
		free(header_b64);
	if (payload_b64 != NULL)
		free(payload_b64);
	if (signature != NULL)
		free(signature);
	if (signature_b64 != NULL)
		free(signature_b64);
	if (ec_sig != NULL)
		ECDSA_SIG_free(ec_sig);

	return rc;
}

/**
 * Verifies a JSON Web Signature object (see RFC 7515 for details).
 *
 * @param jws               the JWS string
 * @param payload           if not NULL: the detached JWS payload.
 * @param payload_len       the length of the detached payload in bytes
 * @param md_ctx            An OpenSSL MD that has been set up with the desired
 *                          digest and signing algorithm, options, and key
 *
 * @returns zero for success, a negative errno in case of an error
 */
int verify_json_web_signature(const char *jws, const unsigned char *payload,
			      size_t payload_len, EVP_PKEY *pkey)
{
	size_t header_len, hdr_pld_len, payload_b64_len, signature_len = 0;
	unsigned char *signature = NULL, *der = NULL, *sig = NULL;
	json_object *header_obj = NULL, *b64_obj = NULL;
	int der_len, rc, curve_nid = 0, digest_nid = 0;
	struct ekmf_rsa_pss_params rsa_pss_params;
	bool b64 = true, rsa_pss = false;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	ECDSA_SIG *ec_sig = NULL;
	char *payload_b64 = NULL;
	const EVP_MD *md = NULL;
	BIGNUM *bn_r = NULL;
	BIGNUM *bn_s = NULL;
	const char *alg;
	size_t sig_len;
	char *ch;

	if (jws == NULL || pkey == NULL)
		return -EINVAL;

	rc = parse_json_web_token(jws, &header_obj, NULL, &signature,
				  &signature_len);
	if (rc != 0)
		goto out;

	ch = strchr(jws, '.');
	if (ch == NULL) {
		rc = -EBADMSG;
		goto out;
	}
	header_len = ch - jws;

	ch = strchr(++ch, '.');
	if (ch == NULL) {
		rc = -EBADMSG;
		goto out;
	}
	hdr_pld_len = ch - jws;

	if (EVP_PKEY_id(pkey) == EVP_PKEY_EC) {
		curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(
						EVP_PKEY_get0_EC_KEY(pkey)));
	}

	alg = json_get_string(header_obj, "alg");
	if (alg == NULL) {
		rc = -EIO;
		goto out;
	}

	/*
	 * Only the following combinations are allowed per RFC7518 for JSON
	 * Web Signatures (JWS) using ECC or RSA signing keys:
	 *   alg=ES256: ECDSA using P-256 and SHA-256
	 *   alg=ES384: ECDSA using P-384 and SHA-384
	 *   alg=ES512: ECDSA using P-521 and SHA-512
	 *   alg=RS256: RSA-PKCS1 using SHA-256
	 *   alg=RS384: RSA-PKCS1 using SHA-384
	 *   alg=RS512: RSA-PKCS1 using SHA-512
	 *   alg=PS256: RSA-PSS using SHA-256, MGF1 with SHA-256, salt=digest
	 *   alg=PS384: RSA-PSS using SHA-384, MGF1 with SHA-384, salt=digest
	 *   alg=PS512: RSA-PSS using SHA-512, MGF1 with SHA-512, salt=digest
	 */
	if (strncmp(alg, "ES", 2) == 0) {
		if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
			rc = EINVAL;
			goto out;
		}
		if ((strncmp(alg + 2, "512", 3) == 0 &&
					curve_nid != NID_secp521r1) ||
		    (strncmp(alg + 2, "384", 3) == 0 &&
					curve_nid != NID_secp384r1) ||
		    (strncmp(alg + 2, "256", 3) == 0 &&
					curve_nid != NID_X9_62_prime256v1)) {
			rc = EINVAL;
			goto out;
		}
	} else if (strncmp(alg, "RS", 2) == 0) {
		if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
			rc = EINVAL;
			goto out;
		}
	} else if (strncmp(alg, "PS", 2) == 0) {
		if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA &&
		    EVP_PKEY_id(pkey) != EVP_PKEY_RSA_PSS) {
			rc = EINVAL;
			goto out;
		}
		rsa_pss = true;
	} else {
		rc = -ENOTSUP;
		goto out;
	}

	if (strncmp(alg + 2, "512", 3) == 0)
		digest_nid = NID_sha512;
	else if (strncmp(alg + 2, "384", 3) == 0)
		digest_nid = NID_sha384;
	else if (strncmp(alg + 2, "256", 3) == 0)
		digest_nid = NID_sha256;
	if (digest_nid == 0) {
		rc = -ENOTSUP;
		goto out;
	}

	md = EVP_get_digestbynid(digest_nid);
	if (md == NULL) {
		rc = -ENOTSUP;
		goto out;
	}

	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = EVP_DigestVerifyInit(md_ctx, &pctx, md, NULL, pkey);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	if (rsa_pss) {
		rsa_pss_params.mgf_digest_nid = digest_nid;
		rsa_pss_params.salt_len = RSA_PSS_SALTLEN_DIGEST;
		rc = setup_rsa_pss_pkey_context(pctx, &rsa_pss_params);
		if (rc != 0)
			goto out;
	}

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_EC:
		ec_sig = ECDSA_SIG_new();
		if (ec_sig == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		bn_r = BN_bin2bn(signature, signature_len / 2, NULL);
		bn_s = BN_bin2bn(signature + signature_len / 2,
				 signature_len / 2, NULL);
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

		der_len = i2d_ECDSA_SIG(ec_sig, &der);
		if (der_len <= 0) {
			rc = -EIO;
			goto out;
		}

		sig = der;
		sig_len = der_len;
		break;

	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		/* No signature encoding for RSA */
		sig = signature;
		sig_len = signature_len;
		break;

	default:
		rc = -EINVAL;
		goto out;
	}

	if (payload != NULL && payload_len > 0) {
		/* Detached payload */
		if (json_object_object_get_ex(header_obj, "b64", &b64_obj) &&
		    json_object_is_type(b64_obj, json_type_boolean))
			b64 = json_object_get_boolean(b64_obj);

		if (b64) {
			rc = encode_base64url(NULL, &payload_b64_len, payload,
					      payload_len);
			if (rc != 0)
				goto out;

			payload_b64 = malloc(payload_b64_len);
			if (payload_b64 == NULL) {
				rc = -ENOMEM;
				goto out;
			}

			rc = encode_base64url(payload_b64, &payload_b64_len,
					      payload, payload_len);
			if (rc != 0)
				goto out;
		}

		/* Take header plus '.' as is */
		rc = EVP_DigestVerifyUpdate(md_ctx, jws, header_len + 1);
		if (rc != 1) {
			rc = -EIO;
			goto out;
		}

		if (b64)
			rc = EVP_DigestVerifyUpdate(md_ctx, payload_b64,
						    payload_b64_len);
		else
			rc = EVP_DigestVerifyUpdate(md_ctx, payload,
						    payload_len);
		if (rc != 1) {
			rc = -EIO;
			goto out;
		}
	} else {
		/* Take header plus '.' plus payload as is */
		rc = EVP_DigestVerifyUpdate(md_ctx, jws, hdr_pld_len);
		if (rc != 1) {
			rc = -EIO;
			goto out;
		}
	}

	rc = EVP_DigestVerifyFinal(md_ctx, sig, sig_len);
	if (rc != 1) {
		rc = -EIO;
		goto out;
	}

	rc = 0;

out:
	if (header_obj != NULL)
		json_object_put(header_obj);
	if (signature != NULL)
		free(signature);
	if (payload_b64 != NULL)
		free(payload_b64);
	if (ec_sig != NULL)
		ECDSA_SIG_free(ec_sig);
	if (der != NULL)
		OPENSSL_free(der);
	if (bn_r != NULL)
		BN_free(bn_r);
	if (bn_s != NULL)
		BN_free(bn_s);
	if (md_ctx != NULL)
		EVP_MD_CTX_free(md_ctx);

	return rc;
}

/**
 * Builds a JSON Object containing a timestamp value in ISO 8601 format, e.g.
 * { "timestamp": "2020-04-27T10:02:18.123Z" }. The time is expressed in UTC,
 * regardless of the local time zone.
 *
 * @returns a JSON object containing the timestamp, or NULL in case of an error.
 */
json_object *get_json_timestamp(void)
{
	char timestamp[100];
	struct timeval tv;
	struct tm *tm;
	char temp[20];

	if (gettimeofday(&tv, NULL) != 0)
		return NULL;

	tm = gmtime(&tv.tv_sec);
	if (strftime(timestamp, sizeof(timestamp), "%FT%T", tm) == 0)
		return NULL;

	snprintf(temp, sizeof(temp), ".%06ldZ", tv.tv_usec);
	strcat(timestamp, temp);

	return json_object_new_string(timestamp);
}

/**
 * If copy is true, returns a copy of str (via strdup), else returns str itself.
 * If str is NULL, then NULL is returned.
 */
static char *cond_strdup(const char *str, bool copy)
{
	if (str == NULL)
		return NULL;

	if (copy)
		return strdup(str);
	else
		return (char *)str;
}

/**
 * Returns the start of the UUId part of a href link.
 * Returns NULL if href is NULL, or if the UUID is not found.
 * The returned pointer (if not NULL) is within the specified href string!
 */
static const char *get_uuid_from_href(const char *href)
{
	const char *ch;

	if (href == NULL)
		return NULL;

	ch = strrchr(href, '/');
	if (ch == NULL)
		return NULL;

	return ch + 1;
}

/**
 * Builds a list of tag definitions from a JSON array.
 *
 * @param array             a JSON array of tag definitions
 * @param tag_def_list      the tag definition list to build
 * @param copy              if true, the string values are copied (via strdup),
 *                          if false, the string values re-use the JSON object's
 *                          string buffer (see json_object_get_string).
 *
 * @returns zero for success, a negative errno in case of an error
 */
int json_build_tag_def_list(json_object *array,
			    struct ekmf_tag_def_list *tag_def_list,
			    bool copy)
{
	const char *descr;
	json_object *obj;
	int rc = 0;
	size_t i;

	if (array == NULL || tag_def_list == NULL ||
	    !json_object_is_type(array, json_type_array))
		return -EINVAL;

	tag_def_list->num_tag_defs = json_object_array_length(array);
	tag_def_list->tag_defs = calloc(tag_def_list->num_tag_defs,
					sizeof(struct ekmf_tag_definition));
	if (tag_def_list->tag_defs == NULL)
		return -ENOMEM;

	for (i = 0; i < tag_def_list->num_tag_defs; i++) {
		obj =  json_object_array_get_idx(array, i);
		if (obj == NULL) {
			rc = -EBADMSG;
			goto out;
		}

		tag_def_list->tag_defs[i].name = cond_strdup(
				json_get_string(obj, "name"), copy);
		if (tag_def_list->tag_defs[i].name == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		descr = json_get_string(obj, "description");
		if (descr != NULL) {
			tag_def_list->tag_defs[i].description =
						cond_strdup(descr, copy);
			if (tag_def_list->tag_defs[i].description == NULL) {
				rc = -ENOMEM;
				goto out;
			}
		}
	}

out:
	if (rc != 0)
		free_tag_def_list(tag_def_list, copy);

	return rc;
}

/**
 * Clones (copies) a tag definition list
 *
 * @param src               the source tag definition list
 * @param dest              the destination tag definition list
 *
 * @returns zero for success, a negative errno in case of an error
 */
int clone_tag_def_list(const struct ekmf_tag_def_list *src,
		       struct ekmf_tag_def_list *dest)
{
	int rc = 0;
	size_t i;

	if (src == NULL || dest == NULL)
		return -EINVAL;

	dest->num_tag_defs = src->num_tag_defs;
	dest->tag_defs = calloc(dest->num_tag_defs,
					sizeof(struct ekmf_tag_definition));
	if (dest->tag_defs == NULL)
		return -ENOMEM;

	for (i = 0; i < dest->num_tag_defs; i++) {
		dest->tag_defs[i].name = cond_strdup(src->tag_defs[i].name,
						     true);
		if (dest->tag_defs[i].name == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		if (src->tag_defs[i].description != NULL) {
			dest->tag_defs[i].description =
					strdup(src->tag_defs[i].description);
			if (dest->tag_defs[i].description != NULL) {
				rc = -ENOMEM;
				goto out;
			}
		}
	}

out:
	if (rc != 0)
		free_tag_def_list(dest, true);
	return rc;
}

/**
 * Free a tag definition list
 *
 * @param tag_def_list      the tag definition list to free
 * @param free_tags         if true, the tag name and description string s are
 *                          freed, otherwise only the array is freed.
 */
void free_tag_def_list(struct ekmf_tag_def_list *tag_def_list, bool free_tags)
{
	size_t i;

	if (tag_def_list == NULL || tag_def_list->tag_defs == NULL)
		return;

	for (i = 0; free_tags && i < tag_def_list->num_tag_defs; i++) {
		free((char *)tag_def_list->tag_defs[i].name);
		free((char *)tag_def_list->tag_defs[i].description);
	}

	free(tag_def_list->tag_defs);
	tag_def_list->tag_defs = NULL;
	tag_def_list->num_tag_defs = 0;
}

/**
 * Builds a template info structure from a JSON object.
 *
 * @param obj               a JSON object containing the template info
 * @param template          the template info struct build
 * @param copy              if true, the string values are copied (via strdup),
 *                          if false, the string values re-use the JSON object's
 *                          string buffer (see json_object_get_string).
 *
 * @returns zero for success, a negative errno in case of an error
 */
int json_build_template_info(json_object *obj,
			     struct ekmf_template_info *template,
			     bool copy)
{
	json_object *field, *label_tags = NULL;
	int rc;

	if (obj == NULL || template == NULL ||
	   !json_object_is_type(obj, json_type_object))
		return -EINVAL;

	template->name = cond_strdup(json_get_string(obj, "name"), copy);
	template->uuid = cond_strdup(json_get_string(obj, "templateId"), copy);
	template->key_type = cond_strdup(json_get_string(obj, "keyType"), copy);
	template->algorithm = cond_strdup(json_get_string(obj, "algorithm"),
					  copy);
	if (json_object_object_get_ex(obj, "keyLength", &field) &&
	    json_object_is_type(field, json_type_int))
		template->key_size = json_object_get_int(field);
	template->state = cond_strdup(json_get_string(obj, "templateState"),
				      copy);
	template->key_state = cond_strdup(json_get_string(obj, "keyState"),
					  copy);
	template->label_template = cond_strdup(json_get_string(obj,
							"labelTemplate"), copy);
	if (json_object_object_get_ex(obj, "exportAllowed", &field) &&
	    json_object_is_type(field, json_type_boolean))
		template->export_allowed = json_object_get_boolean(field);
	template->keystore_type = cond_strdup(json_get_string(obj,
							      "keystoreType"),
					      copy);
	template->curve = cond_strdup(json_get_string(obj, "curve"), copy);
	template->created_on = cond_strdup(json_get_string(obj, "createdOn"),
					   copy);
	template->updated_on = cond_strdup(json_get_string(obj, "updatedOn"),
					   copy);

	if (template->name == NULL || template->uuid == NULL ||
	    template->algorithm == NULL || template->label_template == NULL ||
	    template->state == NULL || template->key_state == NULL ||
	    template->keystore_type == NULL || template->created_on == NULL ||
	    template->updated_on == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	json_object_object_get_ex(obj, "labelTags", &label_tags);
	rc = json_build_tag_def_list(label_tags, &template->label_tags, copy);
	if (rc != 0)
		goto out;

out:
	if (rc != 0) {
		free_tag_def_list(&template->label_tags, copy);
		if (copy)
			free_template_info(template);
	}

	return rc;
}

/**
 * Clones (copies) a template info structure
 *
 * @param src               the source template info structure
 * @param dest              the destination template info structure
 *
 * @returns zero for success, a negative errno in case of an error
 */
int clone_template_info(const struct ekmf_template_info *src,
			struct ekmf_template_info *dest)
{
	int rc;

	if (src == NULL || dest == NULL)
		return -EINVAL;

	dest->name = cond_strdup(src->name, true);
	dest->uuid = cond_strdup(src->uuid, true);
	dest->key_type = cond_strdup(src->key_type, true);
	dest->algorithm = cond_strdup(src->algorithm, true);
	dest->key_size = src->key_size;
	dest->state = cond_strdup(src->state, true);
	dest->key_state = cond_strdup(src->key_state, true);
	dest->label_template = cond_strdup(src->label_template, true);
	dest->export_allowed = src->export_allowed;
	dest->keystore_type = cond_strdup(src->keystore_type, true);
	dest->curve = cond_strdup(src->curve, true);
	dest->created_on = cond_strdup(src->created_on, true);
	dest->updated_on = cond_strdup(src->updated_on, true);
	if (dest->name == NULL || dest->uuid == NULL ||
	    dest->algorithm == NULL || dest->state == NULL ||
	    dest->key_state == NULL || dest->label_template == NULL ||
	    dest->keystore_type == NULL || dest->created_on == NULL ||
	    dest->updated_on == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = clone_tag_def_list(&src->label_tags, &dest->label_tags);
	if (rc != 0)
		goto out;

out:
	if (rc != 0)
		free_template_info(dest);
	return rc;
}

/**
 * Free a template info structure
 *
 * @param template          the template to free
 */
void free_template_info(struct ekmf_template_info *template)
{
	if (template == NULL)
		return;

	free((char *)template->name);
	free((char *)template->uuid);
	free((char *)template->key_type);
	free((char *)template->algorithm);
	free((char *)template->state);
	free((char *)template->key_state);
	free((char *)template->label_template);
	free((char *)template->keystore_type);
	free((char *)template->curve);
	free((char *)template->created_on);
	free((char *)template->updated_on);

	free_tag_def_list(&template->label_tags, true);
}

/**
 * Builds a list of tags from a JSON array.
 *
 * @param array             a JSON array of tags
 * @param tag_list          the tag list to build
 * @param copy              if true, the string values are copied (via strdup),
 *                          if false, the string values re-use the JSON object's
 *                          string buffer (see json_object_get_string).
 *
 * @returns zero for success, a negative errno in case of an error
 */
int json_build_tag_list(json_object *array, struct ekmf_tag_list *tag_list,
			bool copy)
{
	json_object *obj;
	size_t i;
	int rc = 0;

	if (array == NULL || tag_list == NULL ||
	    !json_object_is_type(array, json_type_array))
		return -EINVAL;

	tag_list->num_tags = json_object_array_length(array);
	tag_list->tags = calloc(tag_list->num_tags, sizeof(struct ekmf_tag));
	if (tag_list->tags == NULL)
		return -ENOMEM;

	for (i = 0; i < tag_list->num_tags; i++) {
		obj =  json_object_array_get_idx(array, i);
		if (obj == NULL)
			return -EBADMSG;

		tag_list->tags[i].name = cond_strdup(
				json_get_string(obj, "name"), copy);
		tag_list->tags[i].value = cond_strdup(
				json_get_string(obj, "value"), copy);

		if (tag_list->tags[i].name == NULL ||
		    tag_list->tags[i].value == NULL) {
			rc = -ENOMEM;
			goto out;
		}
	}

out:
	if (rc != 0)
		free_tag_list(tag_list, copy);

	return rc;
}

/**
 * Builds an JSON array with tag objects from a list of tags.
 * The returned JSON object must be freed using json_object_put by the caller.
 */

/**
 * Builds an JSON array with tag objects from a list of tags.
 * The returned JSON object must be freed using json_object_put by the caller.
 *
 * @param tag_list          the tag list
 * @param tags_obj          On return: a JSOn array containig the tags
 *
 * @returns zero for success, a negative errno in case of an error
 */
int build_json_tag_list(const struct ekmf_tag_list *tag_list,
			json_object **tags_obj)
{
	json_object *tag_obj = NULL;
	int rc = 0;
	size_t i;

	if (tag_list == NULL || tags_obj == NULL)
		return -EINVAL;

	*tags_obj = json_object_new_array();
	if (*tags_obj == NULL)
		return -ENOMEM;

	for (i = 0; i < tag_list->num_tags; i++) {
		if (tag_list->tags[i].name == NULL ||
		    tag_list->tags[i].value == NULL) {
			rc = -EINVAL;
			goto out;
		}

		tag_obj = json_object_new_object();
		if (tag_obj == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		rc = json_object_object_add_ex(tag_obj, "name",
			json_object_new_string(tag_list->tags[i].name), 0);
		if (rc != 0) {
			rc = -ENOMEM;
			goto out;
		}

		rc = json_object_object_add_ex(tag_obj, "value",
			json_object_new_string(tag_list->tags[i].value), 0);
		if (rc != 0) {
			rc = -ENOMEM;
			goto out;
		}

		rc = json_object_array_add(*tags_obj, tag_obj);
		if (rc != 0) {
			rc = -ENOMEM;
			goto out;
		}

		tag_obj = NULL;
	}
	rc = 0;

out:
	if (rc != 0) {
		if (*tags_obj != NULL)
			json_object_put(*tags_obj);
		if (tag_obj != NULL)
			json_object_put(tag_obj);
	}

	return rc;
}

/**
 * Clones (copies) a tag list
 *
 * @param src               the source tag list
 * @param dest              the destination tag list
 *
 * @returns zero for success, a negative errno in case of an error
 */
int clone_tag_list(const struct ekmf_tag_list *src,
		   struct ekmf_tag_list *dest)
{
	size_t i;
	int rc = 0;

	if (src == NULL || dest == NULL)
		return -EINVAL;

	dest->num_tags = src->num_tags;
	if (dest->num_tags == 0) {
		dest->tags = NULL;
		return 0;
	}

	dest->tags = calloc(dest->num_tags, sizeof(struct ekmf_tag));
	if (dest->tags == NULL)
		return -ENOMEM;

	for (i = 0; i < dest->num_tags; i++) {
		dest->tags[i].name = cond_strdup(src->tags[i].name, true);
		if (dest->tags[i].name == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		dest->tags[i].value = cond_strdup(src->tags[i].value, true);
		if (dest->tags[i].value == NULL) {
			rc = -ENOMEM;
			goto out;
		}
	}

out:
	if (rc != 0)
		free_tag_list(dest, true);
	return rc;
}

/**
 * Free a tag list
 *
 * @param tag_list          the tag list to free
 * @param free_tags         if true, the tag name and value string s are
 *                          freed, otherwise only the array is freed.
 */
void free_tag_list(struct ekmf_tag_list *tag_list, bool free_tags)
{
	size_t i;

	if (tag_list == NULL || tag_list->tags == NULL)
		return;

	for (i = 0; free_tags && i < tag_list->num_tags; i++) {
		free((char *)tag_list->tags[i].name);
		free((char *)tag_list->tags[i].value);
	}

	free(tag_list->tags);
	tag_list->tags = NULL;
	tag_list->num_tags = 0;
}

/**
 * Builds the export control information from a JSON object.
 *
 * @param export_control    the JSON oibject
 * @param tag_def_list      the tag list to build
 * @param copy              if true, the string values are copied (via strdup),
 *                          if false, the string values re-use the JSON object's
 *                          string buffer (see json_object_get_string).
 *
 * @returns zero for success, a negative errno in case of an error
 */
int json_build_export_control(json_object *export_control,
			      struct ekmf_export_control *export_info,
			      bool copy)
{
	json_object *obj, *array;
	size_t i;
	int rc = 0;

	if (export_control == NULL || export_info == NULL ||
	    !json_object_is_type(export_control, json_type_object))
		return -EINVAL;

	if (!json_object_object_get_ex(export_control, "exportAllowed", &obj) ||
	    !json_object_is_type(obj, json_type_boolean))
		return -EINVAL;

	export_info->export_allowed = json_object_get_boolean(obj);

	if (!json_object_object_get_ex(export_control, "allowedKeys", &array) ||
	    !json_object_is_type(array, json_type_array))
		return -EINVAL;

	export_info->num_exporting_keys = json_object_array_length(array);
	export_info->exporting_keys = calloc(export_info->num_exporting_keys,
					     sizeof(struct ekmf_exporting_key));
	if (export_info->exporting_keys == NULL)
		return -ENOMEM;

	for (i = 0; i < export_info->num_exporting_keys; i++) {
		obj =  json_object_array_get_idx(array, i);
		if (obj == NULL)
			return -EBADMSG;

		export_info->exporting_keys[i].name = cond_strdup(
				json_get_string(obj, "title"), copy);
		export_info->exporting_keys[i].uuid = cond_strdup(
				get_uuid_from_href(
					json_get_string(obj, "href")), copy);

		if (export_info->exporting_keys[i].name == NULL ||
		    export_info->exporting_keys[i].uuid == NULL) {
			rc = -ENOMEM;
			goto out;
		}
	}

out:
	if (rc != 0)
		free_export_control(export_info, copy);

	return rc;
}

/**
 * Clones (copies) an export control info
 *
 * @param src               the source export control
 * @param dest              the destination export control
 *
 * @returns zero for success, a negative errno in case of an error
 */
int clone_export_control(const struct ekmf_export_control *src,
			 struct ekmf_export_control *dest)
{
	size_t i;
	int rc = 0;

	if (src == NULL || dest == NULL)
		return -EINVAL;

	dest->export_allowed = src->export_allowed;

	dest->num_exporting_keys = src->num_exporting_keys;
	if (dest->num_exporting_keys == 0) {
		dest->exporting_keys = NULL;
		return 0;
	}

	dest->exporting_keys = calloc(dest->num_exporting_keys,
				      sizeof(struct ekmf_exporting_key));
	if (dest->exporting_keys == NULL)
		return -ENOMEM;

	for (i = 0; i < dest->num_exporting_keys; i++) {
		dest->exporting_keys[i].name =
				cond_strdup(src->exporting_keys[i].name, true);
		if (dest->exporting_keys[i].name == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		dest->exporting_keys[i].uuid =
				cond_strdup(src->exporting_keys[i].uuid, true);
		if (dest->exporting_keys[i].uuid == NULL) {
			rc = -ENOMEM;
			goto out;
		}
	}

out:
	if (rc != 0)
		free_export_control(dest, true);
	return rc;
}

/**
 * Free export control infos
 *
 * @param export_control    the export control infos to free
 * @param free_tags         if true, the exporting keys name and uuid strings
 *                          are freed, otherwise only the array is freed.
 */
void free_export_control(struct ekmf_export_control *export_control,
			 bool free_keys)
{
	size_t i;

	if (export_control == NULL || export_control->exporting_keys == NULL)
		return;

	for (i = 0; free_keys && i < export_control->num_exporting_keys; i++) {
		free((char *)export_control->exporting_keys[i].name);
		free((char *)export_control->exporting_keys[i].uuid);
	}

	free(export_control->exporting_keys);
	export_control->exporting_keys = NULL;
	export_control->num_exporting_keys = 0;
}

/**
 * Builds a key info structure from a JSON object.
 *
 * @param obj               a JSON object containing the key info
 * @param custom_tags       a JSON array containing the custom tags
 * @param export_control    a JSON object containing the export_control infos
 * @param key               the key info struct to build
 * @param copy              if true, the string values are copied (via strdup),
 *                          if false, the string values re-use the JSON object's
 *                          string buffer (see json_object_get_string).
 *
 * @returns zero for success, a negative errno in case of an error
 */
int json_build_key_info(json_object *obj, json_object *custom_tags,
			json_object *export_control,
			struct ekmf_key_info *key, bool copy)
{
	json_object *field, *label_tags = NULL;
	int rc = 0;

	if (obj == NULL || custom_tags == NULL || key == NULL ||
	    !json_object_is_type(obj, json_type_object) ||
	    !json_object_is_type(custom_tags, json_type_array))
		return -EINVAL;

	key->label = cond_strdup(json_get_string(obj, "label"), copy);
	key->description = cond_strdup(json_get_string(obj, "description"),
				       copy);
	key->uuid = cond_strdup(json_get_string(obj, "keyId"), copy);
	key->key_type = cond_strdup(json_get_string(obj, "type"), copy);
	key->algorithm = cond_strdup(json_get_string(obj, "algorithm"), copy);
	if (json_object_object_get_ex(obj, "length", &field) &&
	    json_object_is_type(field, json_type_int))
		key->key_size = json_object_get_int(field);
	else
		rc = -EBADMSG;

	key->state = cond_strdup(json_get_string(obj, "state"), copy);
	key->keystore_type = cond_strdup(json_get_string(obj, "keystoreType"),
					 copy);
	if (json_object_object_get_ex(obj, "template", &field) &&
	    json_object_is_type(field, json_type_object)) {
		key->template = cond_strdup(json_get_string(field, "title"),
					    copy);
		key->template_uuid = cond_strdup(get_uuid_from_href(
					json_get_string(field, "href")), copy);
	} else {
		rc = -EBADMSG;
	}
	key->activate_on = cond_strdup(json_get_string(obj, "activationDate"),
				       copy);
	key->expires_on = cond_strdup(json_get_string(obj, "expirationDate"),
				      copy);
	key->created_on = cond_strdup(json_get_string(obj, "createdOn"), copy);
	key->updated_on = cond_strdup(json_get_string(obj, "updatedOn"), copy);

	if (rc != 0 || key->label == NULL || key->uuid == NULL ||
	    key->algorithm == NULL || key->state == NULL ||
	    key->keystore_type == NULL || key->template == NULL ||
	    key->template_uuid == NULL || key->activate_on == NULL ||
	    key->expires_on == NULL || key->created_on == NULL ||
	    key->updated_on == NULL) {
		rc = (rc != 0 ? rc : -ENOMEM);
		goto out;
	}

	json_object_object_get_ex(obj, "labelTags", &label_tags);
	rc = json_build_tag_list(label_tags, &key->label_tags, copy);
	if (rc != 0)
		goto out;

	rc = json_build_tag_list(custom_tags, &key->custom_tags, copy);
	if (rc != 0)
		goto out;

	rc = json_build_export_control(export_control, &key->export_control,
				       copy);
	if (rc != 0)
		goto out;

out:
	if (rc != 0) {
		free_tag_list(&key->label_tags, copy);
		free_tag_list(&key->custom_tags, copy);
		free_export_control(&key->export_control, copy);
		if (copy)
			free_key_info(key);
	}

	return rc;
}

/**
 * Clones (copies) a key info structure
 *
 * @param src               the source key info structure
 * @param dest              the destination key info structure
 *
 * @returns zero for success, a negative errno in case of an error
 */
int clone_key_info(const struct ekmf_key_info *src,
		   struct ekmf_key_info *dest)
{
	int rc;

	if (src == NULL || dest == NULL)
		return -EINVAL;

	dest->label = cond_strdup(src->label, true);
	dest->description = cond_strdup(src->description, true);
	dest->uuid = cond_strdup(src->uuid, true);
	dest->key_type = cond_strdup(src->key_type, true);
	dest->algorithm = cond_strdup(src->algorithm, true);
	dest->key_size = src->key_size;
	dest->state = cond_strdup(src->state, true);
	dest->keystore_type = cond_strdup(src->keystore_type, true);
	dest->template = cond_strdup(src->template, true);
	dest->template_uuid = cond_strdup(src->template_uuid, true);
	dest->activate_on = cond_strdup(src->activate_on, true);
	dest->expires_on = cond_strdup(src->expires_on, true);
	dest->created_on = cond_strdup(src->created_on, true);
	dest->updated_on = cond_strdup(src->updated_on, true);
	if (dest->label == NULL || dest->uuid == NULL ||
	    dest->algorithm == NULL || dest->state == NULL ||
	    dest->keystore_type == NULL || dest->template == NULL ||
	    dest->template_uuid == NULL || dest->activate_on == NULL ||
	    dest->expires_on == NULL || dest->created_on == NULL ||
	    dest->updated_on == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = clone_tag_list(&src->label_tags, &dest->label_tags);
	if (rc != 0)
		goto out;

	rc = clone_tag_list(&src->custom_tags, &dest->custom_tags);
	if (rc != 0)
		goto out;
out:
	if (rc != 0)
		free_key_info(dest);
	return rc;
}

/**
 * Free a key info structure
 *
 * @param key               the key info to free
 */
void free_key_info(struct ekmf_key_info *key)
{
	if (key == NULL)
		return;

	free((char *)key->label);
	free((char *)key->description);
	free((char *)key->uuid);
	free((char *)key->key_type);
	free((char *)key->algorithm);
	free((char *)key->state);
	free((char *)key->keystore_type);
	free((char *)key->template);
	free((char *)key->template_uuid);
	free((char *)key->activate_on);
	free((char *)key->expires_on);
	free((char *)key->created_on);
	free((char *)key->updated_on);

	free_tag_list(&key->label_tags, true);
	free_tag_list(&key->custom_tags, true);
	free_export_control(&key->export_control, true);
}

/**
 * Finds the specified HTTP header in the list of HTTP headers. Returns a newly
 * allocated string containing the header value. The caller must free the string
 * when no longer needed.
 *
 * @param headers           the list of HTTP headers
 * @param name              the name of the header to look for.
 *
 * @returns a newly allocated string, or NULL if the header is not found
 */
char *get_http_header_value(const struct curl_slist *headers, const char *name)
{
	const struct curl_slist *hdr
;
	char *ch;

	if (headers == NULL || name == NULL)
		return NULL;

	for (hdr = headers; hdr != NULL; hdr = hdr->next) {
		if (hdr->data == NULL)
			continue;

		ch = strchr(hdr->data, ':');
		if (ch == NULL)
			continue;
		if (strncasecmp(hdr->data, name, ch - hdr->data) != 0)
			continue;

		for (ch++; *ch == ' '; ch++)
			;
		return strdup(ch);
	}

	return NULL;
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
 * Converts a JSON Web Key (ECC or RSA) into a OpenSSL PKEY
 *
 * @param jwk               The JSON Web Key to convert
 * @param pkey_type         If the JWK contains an RSA key, then the pkey_type
 *                          can be EVP_PKEY_RSA or EVP_PKEY_RSA_PSS
 * @param pkey              On return: the OpenSSL PKEY
 *
 * @returns zero for success, a negative errno in case of an error
 */
int json_web_key_as_pkey(json_object *jwk, int pkey_type, EVP_PKEY **pkey)
{
	unsigned char *x = NULL, *y = NULL, *n = NULL, *e = NULL;
	size_t prime_len, len, n_len, e_len;
	const char *kty, *crv;
	int nid, rc = 0;

	if (jwk == NULL || pkey == NULL)
		return -EINVAL;

	*pkey = NULL;

	kty = json_get_string(jwk, "kty");
	if (kty == NULL) {
		rc = -EIO;
		goto out;
	}

	if (strcmp(kty, "EC") == 0) {
		crv = json_get_string(jwk, "crv");
		if (crv == NULL) {
			rc = -EIO;
			goto out;
		}

		nid = ecc_get_curve_by_id(crv);
		if (nid == 0) {
			rc = -EIO;
			goto out;
		}

		prime_len = ecc_get_curve_prime_length(nid);
		if (prime_len == 0) {
			rc = -EIO;
			goto out;
		}

		x = malloc(prime_len);
		y = malloc(prime_len);
		if (x == NULL || y == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		len = prime_len;
		rc = json_object_get_base64url(jwk, "x", x, &len);
		if (rc != 0)
			goto out;
		if (len != prime_len) {
			/* RFC 7517: Must be full size of a coordinate */
			rc = -EINVAL;
			goto out;
		}

		len = prime_len;
		rc = json_object_get_base64url(jwk, "y", y, &len);
		if (rc != 0)
			goto out;
		if (len != prime_len) {
			/* RFC 7517: Must be full size of a coordinate */
			rc = -EINVAL;
			goto out;
		}

		rc = ecc_pub_key_as_pkey(nid, prime_len, x, y, pkey);
		if (rc != 0)
			goto out;
	} else if (strcmp(kty, "RSA") == 0) {
		n_len = 0;
		rc = json_object_get_base64url(jwk, "n", NULL, &n_len);
		if (rc != 0)
			goto out;

		n = malloc(n_len);
		if (n == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		rc = json_object_get_base64url(jwk, "n", n, &n_len);
		if (rc != 0)
			goto out;

		e_len = 0;
		rc = json_object_get_base64url(jwk, "e", NULL, &e_len);
		if (rc != 0)
			goto out;

		e = malloc(e_len);
		if (e == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		rc = json_object_get_base64url(jwk, "e", e, &e_len);
		if (rc != 0)
			goto out;

		rc = rsa_pub_key_as_pkey(n, n_len, e, e_len, pkey_type, pkey);
		if (rc != 0)
			goto out;

	} else {
		return -EIO;
	}

out:
	if (x != NULL)
		free(x);
	if (y != NULL)
		free(y);
	if (n != NULL)
		free(n);
	if (e != NULL)
		free(e);
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

/**
 * Reads a public key from the specified PEM file.
 *
 * @param pem_filename       the name of the PEM file to read
 * @param pkey               on Return: the PKEY object
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EIO: error during reading in the certificate
 *          any other errno as returned by fopen
 */
int read_public_key(const char *pem_filename, EVP_PKEY **pkey)
{
	FILE *fp;

	if (pem_filename == NULL || pkey == NULL)
		return -EINVAL;

	fp = fopen(pem_filename, "r");
	if (fp == NULL)
		return -errno;

	*pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);

	fclose(fp);

	if (*pkey == NULL)
		return -EIO;

	return 0;
}

/**
 * Writes apublic key to the specified PEM file.
 *
 * @param pem_filename       the name of the PEM file to write to
 * @param pkey               the PKEY object to write
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EIO: error during writing out the certificate
 *          any other errno as returned by fopen
 */
int write_public_key(const char *pem_filename, EVP_PKEY *pkey)
{
	FILE *fp;
	int rc;

	if (pem_filename == NULL || pkey == NULL)
		return -EINVAL;

	fp = fopen(pem_filename, "w");
	if (fp == NULL)
		return -errno;

	rc = PEM_write_PUBKEY(fp, pkey);

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
static int X509_EXTENSION_compfunc(const X509_EXTENSION * const *a,
				   const X509_EXTENSION * const *b)
{

	return (OBJ_obj2nid(X509_EXTENSION_get_object((X509_EXTENSION *)*a)) -
		OBJ_obj2nid(X509_EXTENSION_get_object((X509_EXTENSION *)*b)));
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

/**
 * Gets a String field from a JSON object.
 *
 * @param obj                the JSON object
 * @param name               the name of the String field to get
 *
 * @returns the contents of the String field or NULL.
 * Note: The memory returned is owned by the JSON object, and must not be freed
 *       by the caller. It is valid until the JSON object is freed, which also
 *       frees the memory used for the string value.
 */
const char *json_get_string(json_object *obj, const char *name)
{
	json_object *field;

	if (!json_object_object_get_ex(obj, name, &field) ||
	    !json_object_is_type(field, json_type_string))
		return NULL;

	return json_object_get_string(field);
}

/**
 * Gets a base64url field form a JSON object, decodes it and returns the
 * decoded data.
 *
 * @param obj                the JSON object
 * @param name               the name of the String field to get
 * @param data               buffer to return the decoded data, or NULL to
 *                           return only the required buffer size
 * @param data_len           on entry: the size of tne buffer
 *                           on exit: the size of the decoded data
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to calculate the y coordinate
 */
int json_object_get_base64url(json_object *obj, const char *name,
			      unsigned char *data, size_t *data_len)
{
	const char *b64;

	b64 = json_get_string(obj, name);
	if (b64 == NULL)
		return -ENOENT;

	return decode_base64url(data, data_len, b64, strlen(b64));
}

/**
 * Base64URL encodes the data and creates a JSON string object of it
 *
 * @param data              the data to base64url encode
 * @param len               the length of the data

 * @returns a new JSON object, or NULL in case of an error
 */
json_object *json_object_new_base64url(const unsigned char *data, size_t len)
{
	json_object *ret = NULL;
	char *b64 = NULL;
	size_t b64len;
	int rc;

	rc = encode_base64url(NULL, &b64len, data, len);
	if (rc != 0)
		goto out;

	b64 = malloc(b64len);
	if (b64 == NULL)
		goto out;

	rc = encode_base64url(b64, &b64len, data, len);
	if (rc != 0)
		goto out;

	ret = json_object_new_string(b64);

out:
	if (b64 != NULL)
		free(b64);

	return ret;
}

#ifdef IMPLEMENT_LOCAL_JSON_OBJECT_OBJECT_ADD

/**
 * JSON-C of version 0.12 does not have json_object_object_add_ex(), and
 * json_object_object_add does not return a return code, so implement
 * json_object_object_add_ex here instead.
 */
int json_object_object_add_ex(struct json_object *obj, const char *const key,
			      struct json_object *const val,
			      const unsigned int UNUSED(opts))
{
	json_object_object_add(obj, key, val);
	return 0;
}
#endif
