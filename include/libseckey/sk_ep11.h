/*
 * libseckey - Secure key library
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef SK_EP11_H
#define SK_EP11_H

#include <stddef.h>
#include <stdbool.h>

#include <openssl/evp.h>

#include "libseckey/sk_openssl.h"

#define EP11_MAX_KEY_TOKEN_SIZE		8192

int SK_EP11_generate_ec_key_pair(const struct sk_ext_ep11_lib *ep11_lib,
				 int curve_nid, unsigned char *key_token,
				 size_t *key_token_length, bool debug);

int SK_EP11_generate_rsa_key_pair(const struct sk_ext_ep11_lib *ep11_lib,
				  size_t modulus_bits, unsigned int pub_exp,
				  bool x9_31, unsigned char *key_token,
				  size_t *key_token_length, bool debug);

int SK_EP11_get_key_type(const unsigned char *key_token,
			 size_t key_token_length,
			 int *pkey_type);

const unsigned char *SK_EP11_get_key_blob(const unsigned char *key_token,
					  size_t key_token_length);

size_t SK_EP11_get_key_blob_size(const unsigned char *key_token,
				 size_t key_token_length);

int SK_EP11_get_secure_key_as_pkey(const struct sk_ext_ep11_lib *ep11_lib,
				   const unsigned char *key_token,
				   size_t key_token_length,
				   bool rsa_pss, EVP_PKEY **pkey, bool debug);

int SK_EP11_get_public_from_secure_key(const unsigned char *key_token,
				       size_t key_token_length,
				       sk_pub_key_func_t pub_key_cb,
				       void *private,
				       bool debug);

int SK_EP11_reencipher_key(const struct sk_ext_ep11_lib *ep11_lib,
			   unsigned char *key_token, size_t key_token_length,
			   bool debug);

/* PKCS#11 definitions */

#define CK_PTR *

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_CHAR;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef long CK_LONG;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;
typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;

typedef CK_BYTE CK_PTR CK_BYTE_PTR;
typedef CK_CHAR CK_PTR CK_CHAR_PTR;
typedef CK_UTF8CHAR CK_PTR CK_UTF8CHAR_PTR;
typedef CK_ULONG CK_PTR CK_ULONG_PTR;
typedef void CK_PTR CK_VOID_PTR;
typedef CK_SLOT_ID CK_PTR CK_SLOT_ID_PTR;
typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;
typedef CK_RSA_PKCS_MGF_TYPE CK_PTR CK_RSA_PKCS_MGF_TYPE_PTR;

typedef struct CK_MECHANISM {
	CK_MECHANISM_TYPE mechanism;
	CK_VOID_PTR pParameter;
	CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;

typedef struct CK_ATTRIBUTE {
	CK_ATTRIBUTE_TYPE type;
	CK_VOID_PTR pValue;
	CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;

typedef struct CK_RSA_PKCS_PSS_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_ULONG sLen;
} CK_RSA_PKCS_PSS_PARAMS;

typedef CK_RSA_PKCS_PSS_PARAMS CK_PTR CK_RSA_PKCS_PSS_PARAMS_PTR;

typedef struct CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
	CK_VOID_PTR pSourceData;
	CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

typedef CK_RSA_PKCS_OAEP_PARAMS CK_PTR CK_RSA_PKCS_OAEP_PARAMS_PTR;

#define CKZ_DATA_SPECIFIED		0x00000001

#define CKG_MGF1_SHA1			0x00000001
#define CKG_MGF1_SHA224			0x00000005
#define CKG_MGF1_SHA256			0x00000002
#define CKG_MGF1_SHA384			0x00000003
#define CKG_MGF1_SHA512			0x00000004

#define CKG_VENDOR_DEFINED		0x80000000UL
#define CKG_IBM_MGF1_SHA3_224		(CKG_VENDOR_DEFINED + 1)
#define CKG_IBM_MGF1_SHA3_256		(CKG_VENDOR_DEFINED + 2)
#define CKG_IBM_MGF1_SHA3_384		(CKG_VENDOR_DEFINED + 3)
#define CKG_IBM_MGF1_SHA3_512		(CKG_VENDOR_DEFINED + 4)

#define CKR_OK				0x00000000
#define CKR_VENDOR_DEFINED		0x80000000

#define CKO_PUBLIC_KEY			0x00000002
#define CKO_PRIVATE_KEY			0x00000003

#define CKK_EC				0x00000003

#define CKM_RSA_PKCS_KEY_PAIR_GEN	0x00000000
#define CKM_RSA_PKCS			0x00000001
#define CKM_RSA_PKCS_OAEP		0x00000009
#define CKM_RSA_X9_31_KEY_PAIR_GEN	0x0000000A
#define CKM_RSA_X9_31			0x0000000B
#define CKM_RSA_PKCS_PSS		0x0000000D
#define CKM_SHA_1			0x00000220
#define CKM_SHA256			0x00000250
#define CKM_SHA224			0x00000255
#define CKM_SHA384			0x00000260
#define CKM_SHA512			0x00000270
#define CKM_SHA512_224			0x00000048
#define CKM_SHA512_256			0x0000004C
#define CKM_EC_KEY_PAIR_GEN		0x00001040
#define CKM_ECDSA			0x00001041

#define CKM_VENDOR_DEFINED		0x80000000
#define CKM_IBM_SHA3_224		(CKM_VENDOR_DEFINED + 0x00010001)
#define CKM_IBM_SHA3_256		(CKM_VENDOR_DEFINED + 0x00010002)
#define CKM_IBM_SHA3_384		(CKM_VENDOR_DEFINED + 0x00010003)
#define CKM_IBM_SHA3_512		(CKM_VENDOR_DEFINED + 0x00010004)

#define CKA_CLASS			0x00000000
#define CKA_KEY_TYPE			0x00000100
#define CKA_SENSITIVE			0x00000103
#define CKA_ENCRYPT			0x00000104
#define CKA_DECRYPT			0x00000105
#define CKA_SIGN			0x00000108
#define CKA_VERIFY			0x0000010A
#define CKA_DERIVE			0x0000010C
#define CKA_DECRYPT			0x00000105
#define CKA_WRAP			0x00000106
#define CKA_UNWRAP			0x00000107
#define CKA_MODULUS_BITS		0x00000121
#define CKA_PUBLIC_EXPONENT		0x00000122
#define CKA_EC_PARAMS			0x00000180

#endif
