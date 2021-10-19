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
#include <openssl/evp.h>

#include <json-c/json.h>
#include <curl/curl.h>

#include "ekmfweb/ekmfweb.h"

int decode_base64url(unsigned char *output, size_t *outlen,
		     const char *input, size_t inlen);

int encode_base64url(char *output, size_t *outlen,
		     const unsigned char *input, size_t inlen);

int parse_json_web_token(const char *token, json_object **header_obj,
			 json_object **payload_obj, unsigned char **signature,
			 size_t *signature_len);

int create_json_web_signature(const char *algorithm, bool b64, const char *kid,
			      const unsigned char *payload, size_t payload_len,
			      bool detached_payload, EVP_MD_CTX *md_ctx,
			      char **jws);

int verify_json_web_signature(const char *jws, const unsigned char *payload,
			      size_t payload_len, EVP_PKEY *pkey);

json_object *get_json_timestamp(void);

int json_build_tag_def_list(json_object *array,
			    struct ekmf_tag_def_list *tag_def_list,
			    bool copy);
int clone_tag_def_list(const struct ekmf_tag_def_list *src,
		       struct ekmf_tag_def_list *dest);
void free_tag_def_list(struct ekmf_tag_def_list *tag_def_list, bool free_tags);

int json_build_template_info(json_object *obj,
			     struct ekmf_template_info *template,
			     bool copy);
int clone_template_info(const struct ekmf_template_info *src,
			struct ekmf_template_info *dest);
void free_template_info(struct ekmf_template_info *template);

int json_build_tag_list(json_object *array, struct ekmf_tag_list *tag_list,
			bool copy);
int build_json_tag_list(const struct ekmf_tag_list *tag_list,
			json_object **tags_obj);
int clone_tag_list(const struct ekmf_tag_list *src,
		   struct ekmf_tag_list *dest);
void free_tag_list(struct ekmf_tag_list *tag_list, bool free_tags);

int json_build_export_control(json_object *export_control,
			      struct ekmf_export_control *export_info,
			      bool copy);
int clone_export_control(const struct ekmf_export_control *src,
			 struct ekmf_export_control *dest);
void free_export_control(struct ekmf_export_control *export_control,
			 bool free_keys);

int json_build_key_info(json_object *obj, json_object *custom_tags,
			json_object *export_control,
			struct ekmf_key_info *key, bool copy);
int clone_key_info(const struct ekmf_key_info *src,
		   struct ekmf_key_info *dest);
void free_key_info(struct ekmf_key_info *key);

char *get_http_header_value(const struct curl_slist *headers, const char *name);

int json_web_key_as_pkey(json_object *jwk, int pkey_type, EVP_PKEY **pkey);

int write_key_blob(const char *filename, unsigned char *key_blob,
		   size_t key_blob_len);

int read_key_blob(const char *filename, unsigned char *key_blob,
		  size_t *key_blob_len);

int read_x509_certificate(const char *pem_filename, X509 **cert);

int write_x509_certificate(const char *pem_filename, X509 *cert);

int write_x509_request(const char *pem_filename, X509_REQ *req, bool new_hdr);

int read_public_key(const char *pem_filename, EVP_PKEY **pkey);

int write_public_key(const char *pem_filename, EVP_PKEY *pkey);

int build_subject_name(X509_NAME **name, const char *rdns[], size_t num_rdns,
		       bool utf8);

int build_certificate_extensions(X509 *cert, X509_REQ *req,
				 const char *exts[], size_t num_exts,
				 const STACK_OF(X509_EXTENSION) *addl_exts);

int generate_x509_serial_number(X509 *cert, size_t sn_bit_size);

const char *json_get_string(json_object *obj, const char *name);

int json_object_get_base64url(json_object *obj, const char *name,
			      unsigned char *data, size_t *data_len);

json_object *json_object_new_base64url(const unsigned char *data, size_t len);

#ifndef JSON_C_OBJECT_ADD_KEY_IS_NEW
#define JSON_C_OBJECT_ADD_KEY_IS_NEW (1 << 1)
#define IMPLEMENT_LOCAL_JSON_OBJECT_OBJECT_ADD

int json_object_object_add_ex(struct json_object *obj, const char *const key,
			      struct json_object *const val,
			      const unsigned int opts);
#endif

#endif
