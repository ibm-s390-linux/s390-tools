/*
 * libekmfweb - EKMFWeb client library
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UTILITIES_H
#define UTILITIES_H

#include <stddef.h>
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/obj_mac.h>

#include <json-c/json.h>

int decode_base64url(unsigned char *output, size_t *outlen,
		     const char *input, size_t inlen);

int encode_base64url(char *output, size_t *outlen,
		     const unsigned char *input, size_t inlen);

int parse_json_web_token(const char *token, json_object **header_obj,
			 json_object **payload_obj, unsigned char **signature,
			 size_t *signature_len);

size_t ecc_get_curve_prime_bits(int curve_nid);
size_t ecc_get_curve_prime_length(int curve_nid);
const char *ecc_get_curve_id(int curve_nid);
bool ecc_is_prime_curve(int curve_nid);
bool ecc_is_brainpool_curve(int curve_nid);
int ecc_get_curve_by_id(const char *curve_id);
int ecc_get_prime_curve_by_prime_bits(size_t prime_bits);
int ecc_get_brainpool_curve_by_prime_bits(size_t prime_bits);

int write_key_blob(const char *filename, unsigned char *key_blob,
		   size_t key_blob_len);

int read_key_blob(const char *filename, unsigned char *key_blob,
		  size_t *key_blob_len);

int read_x509_certificate(const char *pem_filename, X509 **cert);

#endif
