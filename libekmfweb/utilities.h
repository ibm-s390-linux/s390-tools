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

#include <json-c/json.h>

int decode_base64url(unsigned char *output, size_t *outlen,
		     const char *input, size_t inlen);

int encode_base64url(char *output, size_t *outlen,
		     const unsigned char *input, size_t inlen);

int parse_json_web_token(const char *token, json_object **header_obj,
			 json_object **payload_obj, unsigned char **signature,
			 size_t *signature_len);

int read_x509_certificate(const char *pem_filename, X509 **cert);

#endif
