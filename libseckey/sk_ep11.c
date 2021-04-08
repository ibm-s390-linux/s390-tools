/*
 * libseckey - Secure key library
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#include "lib/zt_common.h"

#include "libseckey/sk_ep11.h"
#include "libseckey/sk_openssl.h"
#include "libseckey/sk_utilities.h"

/* EP11 library definitions */

#define XCP_SERIALNR_CHARS	8
#define XCP_ADMCTR_BYTES	((size_t) (128/8))
#define XCP_KEYCSUM_BYTES	(256/8)

#define XCP_ADM_REENCRYPT	25 /* transform blobs to next WK */


#define CKR_VENDOR_DEFINED	0x80000000
#define CKR_IBM_WKID_MISMATCH	(CKR_VENDOR_DEFINED + 0x10001)

typedef struct XCPadmresp {
	uint32_t	fn;
	uint32_t	domain;
	uint32_t	domainInst;

	/* module ID || module instance */
	unsigned char	module[XCP_SERIALNR_CHARS + XCP_SERIALNR_CHARS];
	unsigned char	modNr[XCP_SERIALNR_CHARS];
	unsigned char	modInst[XCP_SERIALNR_CHARS];

	unsigned char	tctr[XCP_ADMCTR_BYTES];  /* transaction counter */

	CK_RV		rv;
	uint32_t	reason;

	const unsigned char *payload;
	size_t		pllen;
} *XCPadmresp_t;

typedef struct CK_IBM_DOMAIN_INFO {
	CK_ULONG domain;
	CK_BYTE wk[XCP_KEYCSUM_BYTES];
	CK_BYTE nextwk[XCP_KEYCSUM_BYTES];
	CK_ULONG flags;
	CK_BYTE mode[8];
} CK_IBM_DOMAIN_INFO;

#define CK_IBM_DOM_COMMITTED_NWK	8

#define CK_IBM_XCPQ_DOMAIN		3

typedef CK_RV (*m_GenerateKeyPair_t)(CK_MECHANISM_PTR mech,
				     CK_ATTRIBUTE_PTR public,
				     CK_ULONG pubattrs,
				     CK_ATTRIBUTE_PTR private,
				     CK_ULONG prvattrs,
				     const unsigned char *pin, size_t pinlen,
				     unsigned char *key, size_t *klen,
				     unsigned char *pubkey, size_t *pklen,
				     target_t target);

typedef CK_RV (*m_SignSingle_t)(const unsigned char *key, size_t klen,
				CK_MECHANISM_PTR pmech,
				CK_BYTE_PTR data, CK_ULONG dlen,
				CK_BYTE_PTR sig, CK_ULONG_PTR slen,
				target_t target);

typedef CK_RV (*m_DecryptSingle_t)(const unsigned char *key, size_t klen,
				   CK_MECHANISM_PTR mech,
				   CK_BYTE_PTR cipher, CK_ULONG clen,
				   CK_BYTE_PTR plain, CK_ULONG_PTR plen,
				   target_t target);

typedef CK_RV (*m_get_xcp_info_t)(CK_VOID_PTR pinfo, CK_ULONG_PTR infbytes,
				  unsigned int query, unsigned int subquery,
				  target_t target);
typedef unsigned long (*m_admin_t)(unsigned char *resp1, size_t *r1len,
				   unsigned char *resp2, size_t *r2len,
				   const unsigned char *cmd, size_t clen,
				   const unsigned char *sigs, size_t slen,
				   target_t target);
typedef long (*xcpa_cmdblock_t)(unsigned char *blk, size_t blen,
				unsigned int fn, const struct XCPadmresp *minf,
				const unsigned char *tctr,
				const unsigned char *payload, size_t plen);
typedef long (*xcpa_internal_rv_t)(const unsigned char *rsp, size_t rlen,
				   struct XCPadmresp *rspblk, CK_RV *rv);

struct ep11_lib {
	m_GenerateKeyPair_t	dll_m_GenerateKeyPair;
	m_SignSingle_t		dll_m_SignSingle;
	m_DecryptSingle_t	dll_m_DecryptSingle;
	m_get_xcp_info_t	dll_m_get_xcp_info;
	m_admin_t		dll_m_admin;
	xcpa_cmdblock_t		dll_xcpa_cmdblock;
	xcpa_internal_rv_t	dll_xcpa_internal_rv;
};

#define TOKTYPE_NON_CCA			0

#define PKEY_TYPE_EP11_ECC		6
#define PKEY_TYPE_EP11_RSA		7

#define PKEY_TYPE_EP11_HVER		0

#define PKEY_TYPE_EP11_FLAG_X9_31	0x01

/*
 * EP11 secure key blobs of type PKEY_TYPE_EP11_ECC and PKEY_TYPE_EP11_RSA
 * are EP11 blobs prepended by this header (aligned with definition in kernel
 * header arch/s390/include/uapi/asm/pkey.h):
 */
struct ep11kblob_header {
	uint8_t  type; /* always 0x00 (TOKTYPE_NON_CCA) */
	uint8_t  hver; /* header version,  currently needs to be 0x00 */
	uint16_t len;  /* total length in bytes (including this header) */
	uint8_t  version; /* PKEY_TYPE_EP11_ECC or PKEY_TYPE_EP11_RSA */
	uint8_t  flags; /* Flags, see PKEY_TYPE_EP11_FLAG */
	uint16_t bitlen; /* clear key bit len, 0 for unknown */
	uint8_t  res0[8];
} __packed;
/* Followed by len - sizeof(struct ep11kblob_header) bytes EP11 key blob */
/* Followed by secure key size - len bytes SPKI (public key) */

#define POINT_CONVERSION_ODD_EVEN	0x01

/**
 * Gets the Ep11 library function entry points from the library handle
 */
static int sk_ep11_get_library_functions(const struct sk_ext_ep11_lib *ep11_lib,
					 struct ep11_lib *ep11)
{
	if (ep11_lib == NULL || ep11 == NULL)
		return -EINVAL;

	ep11->dll_m_GenerateKeyPair = (m_GenerateKeyPair_t)
			dlsym(ep11_lib->ep11_lib, "m_GenerateKeyPair");
	ep11->dll_m_SignSingle = (m_SignSingle_t)
				dlsym(ep11_lib->ep11_lib, "m_SignSingle");
	ep11->dll_m_DecryptSingle = (m_DecryptSingle_t)
				dlsym(ep11_lib->ep11_lib, "m_DecryptSingle");
	ep11->dll_m_get_xcp_info = (m_get_xcp_info_t)
				dlsym(ep11_lib->ep11_lib, "m_get_xcp_info");
	ep11->dll_m_admin = (m_admin_t)
				dlsym(ep11_lib->ep11_lib, "m_admin");
	ep11->dll_xcpa_cmdblock = (xcpa_cmdblock_t)
				dlsym(ep11_lib->ep11_lib, "xcpa_cmdblock");
	ep11->dll_xcpa_internal_rv = (xcpa_internal_rv_t)
				dlsym(ep11_lib->ep11_lib, "xcpa_internal_rv");

	if (ep11->dll_m_GenerateKeyPair == NULL ||
	    ep11->dll_m_SignSingle == NULL ||
	    ep11->dll_m_DecryptSingle == NULL ||
	    ep11->dll_m_get_xcp_info == NULL ||
	    ep11->dll_m_admin == NULL ||
	    ep11->dll_xcpa_cmdblock == NULL ||
	    ep11->dll_xcpa_internal_rv == NULL)
		return -EIO;

	return 0;
}

/**
 * Generates an EP11 asymmetric key using the specified key type, mechanism, and
 * templates.
 */
static int sk_ep11_generate_key_pair(const struct sk_ext_ep11_lib *ep11_lib,
				     CK_MECHANISM *mech, CK_ATTRIBUTE *pub_tmpl,
				     CK_ULONG pub_tmpl_num,
				     CK_ATTRIBUTE *priv_tmpl,
				     CK_ULONG priv_tmpl_num,
				     unsigned char *key_token,
				     size_t *key_token_length, bool debug)
{
	unsigned char spki[EP11_MAX_KEY_TOKEN_SIZE] = { 0 };
	struct ep11kblob_header *hdr;
	size_t blob_size, spki_size;
	struct ep11_lib ep11;
	unsigned char *blob;
	size_t tok_len;
	CK_RV rv;
	int rc;

	if (ep11_lib == NULL || key_token == NULL || key_token_length == NULL)
		return -EINVAL;

	if (key_token == NULL) {
		*key_token_length = EP11_MAX_KEY_TOKEN_SIZE;
		return 0;
	}
	if (*key_token_length <= sizeof(struct ep11kblob_header)) {
		sk_debug(debug, "ERROR: key token too short");
		return -EINVAL;
	}

	hdr = (struct ep11kblob_header *)key_token;
	memset(hdr, 0, sizeof(struct ep11kblob_header));
	hdr->type = TOKTYPE_NON_CCA;
	hdr->hver = PKEY_TYPE_EP11_HVER;

	blob_size = *key_token_length - sizeof(struct ep11kblob_header);
	spki_size = sizeof(spki);

	blob = key_token + sizeof(struct ep11kblob_header);

	rc = sk_ep11_get_library_functions(ep11_lib, &ep11);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get EP11 functions from library");
		return rc;
	}

	sk_debug(debug, "mech: 0x%x", mech->mechanism);

	rv = ep11.dll_m_GenerateKeyPair(mech, pub_tmpl, pub_tmpl_num,
					priv_tmpl, priv_tmpl_num,
					NULL, 0, blob, &blob_size,
					spki, &spki_size,
					ep11_lib->target);
	if (rv != CKR_OK) {
		sk_debug(debug, "ERROR: m_GenerateKeyPair failed: rc: 0x%x",
			 rv);
		return -EIO;
	}

	sk_debug(debug, "blob_size: %lu spki_len: %lu", blob_size, spki_size);

	hdr->len = sizeof(struct ep11kblob_header) + blob_size;

	tok_len = sizeof(struct ep11kblob_header) + blob_size + spki_size;
	sk_debug(debug, "tok_len: %lu", tok_len);

	if (tok_len > *key_token_length) {
		sk_debug(debug, "ERROR: key token too short");
		return -EINVAL;
	}

	memcpy(blob + blob_size, spki, spki_size);

	*key_token_length = tok_len;

	return 0;
}

/**
 * Generates an EP11 EC key of the specified curve type and length using the
 * Ep11 host library.
 *
 * @param ep11_lib          the Ep11 library structure
 * @param curve_nid         the nid specifying the curve.
 * @param key_token         a buffer to store the generated key token
 * @param key_token_length  On entry: the size of the buffer
 *                          On return: the size of the key token
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_EP11_generate_ec_key_pair(const struct sk_ext_ep11_lib *ep11_lib,
				 int curve_nid, unsigned char *key_token,
				 size_t *key_token_length, bool debug)
{
	CK_MECHANISM mech = { .mechanism = CKM_EC_KEY_PAIR_GEN,
			      .pParameter = NULL, .ulParameterLen = 0 };
	struct ep11kblob_header *hdr;
	CK_BBOOL _false = false;
	CK_BBOOL _true = true;
	CK_ATTRIBUTE pub_tmpl[] = {
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_VERIFY, &_true, sizeof(_true) },
	};
	CK_ULONG pub_tmpl_num = sizeof(pub_tmpl) / sizeof(CK_ATTRIBUTE);
	CK_ATTRIBUTE priv_tmpl[] = {
		{ CKA_SENSITIVE, &_true, sizeof(_true) },
		{ CKA_SIGN, &_true, sizeof(_true) },
		{ CKA_DERIVE, &_false, sizeof(_false) },
	};
	CK_ULONG priv_tmpl_num = sizeof(priv_tmpl) / sizeof(CK_ATTRIBUTE);
	const struct sk_ec_curve_info *curve;
	int rc;

	if (ep11_lib == NULL || key_token == NULL || key_token_length == NULL)
		return -EINVAL;

	sk_debug(debug, "curve_nid: %d", curve_nid);

	curve = SK_UTIL_ec_get_curve_info(curve_nid);
	if (curve == NULL) {
		sk_debug(debug, "ERROR: Curve %d not supported", curve_nid);
		return -EIO;
	}

	pub_tmpl[0].pValue = (void *)curve->der;
	pub_tmpl[0].ulValueLen = curve->der_size;

	rc = sk_ep11_generate_key_pair(ep11_lib, &mech, pub_tmpl, pub_tmpl_num,
				       priv_tmpl, priv_tmpl_num, key_token,
				       key_token_length, debug);
	if (rc != 0) {
		sk_debug(debug, "ERROR: sk_ep11_generate_key_pair failed");
		return -rc;
	}

	hdr = (struct ep11kblob_header *)key_token;
	hdr->version = PKEY_TYPE_EP11_ECC;
	hdr->bitlen = curve->prime_bits;

	return 0;
}

/**
 * Generates an EP11 RSA key of the specified key size and optionally the
 * specified public exponent using the EP11 host library.
 *
 * @param ep11_lib          the EP11 library structure
 * @param modulus_bits      the size of the key in bits (512, 1024, 2048, 4096)
 * @param pub_exp           the public exponent or zero. Possible values are:
 *                          3, 5, 17, 257, or 65537. Specify zero to choose the
 *                          exponent by random.
 * @param x9_31             if true, generate a X9.31 RSA key
 * @param key_token         a buffer to store the generated key token
 * @param key_token_length  On entry: the size of the buffer
 *                          On return: the size of the key token
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_EP11_generate_rsa_key_pair(const struct sk_ext_ep11_lib *ep11_lib,
				  size_t modulus_bits, unsigned int pub_exp,
				  bool x9_31, unsigned char *key_token,
				  size_t *key_token_length, bool debug)
{
	CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN,
			      .pParameter = NULL, .ulParameterLen = 0 };
	CK_ULONG mod_bits = modulus_bits;
	struct ep11kblob_header *hdr;
	CK_BBOOL _true = true;
	CK_ATTRIBUTE pub_tmpl[] = {
		{ CKA_MODULUS_BITS, &mod_bits, sizeof(mod_bits) },
		{ CKA_VERIFY, &_true, sizeof(_true) },
		{ CKA_ENCRYPT, &_true, sizeof(_true) },
		{ CKA_WRAP, &_true, sizeof(_true) },
		{ CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) },
	};
	CK_ULONG pub_tmpl_num = sizeof(pub_tmpl) / sizeof(CK_ATTRIBUTE);
	CK_ATTRIBUTE priv_tmpl[] = {
		{ CKA_SENSITIVE, &_true, sizeof(_true) },
		{ CKA_SIGN, &_true, sizeof(_true) },
		{ CKA_DECRYPT, &_true, sizeof(_true) },
		{ CKA_UNWRAP, &_true, sizeof(_true) },
	};
	CK_ULONG priv_tmpl_num = sizeof(priv_tmpl) / sizeof(CK_ATTRIBUTE);
	int rc;

	if (ep11_lib == NULL || key_token == NULL || key_token_length == NULL)
		return -EINVAL;

	sk_debug(debug, "modulus_bits: %lu pub_exp: %u x9_31: %d",
		 modulus_bits, pub_exp, x9_31);

	if (pub_exp == 0)
		pub_tmpl_num--;

	if (x9_31)
		mech.mechanism = CKM_RSA_X9_31_KEY_PAIR_GEN;

	rc = sk_ep11_generate_key_pair(ep11_lib, &mech, pub_tmpl, pub_tmpl_num,
				       priv_tmpl, priv_tmpl_num, key_token,
				       key_token_length, debug);
	if (rc != 0) {
		sk_debug(debug, "ERROR: sk_ep11_generate_key_pair failed");
		return -rc;
	}

	hdr = (struct ep11kblob_header *)key_token;
	hdr->version = PKEY_TYPE_EP11_RSA;
	if (x9_31)
		hdr->flags |= PKEY_TYPE_EP11_FLAG_X9_31;
	hdr->bitlen = modulus_bits;

	return 0;
}

/*
 * Parses a DER encoded tag, returns the tag id, and sets the tag length and
 * value length.
 */
static unsigned char sk_ep11_parse_der_tag(const unsigned char *data,
					   size_t data_len, size_t *tag_len,
					   const unsigned char **value,
					   size_t *value_len)
{
	size_t num, i;

	if (data == NULL || data_len < 2)
		return 0;

	if (data[1] & 0x80) {
		num = data[1] & 0x7f;
		if (num > sizeof(size_t))
			return 0;
		*value_len = data[2];
		for (i = 1; i < num; i++) {
			*value_len <<= 8;
			*value_len |= data[2 + i];
		}
		*value = &data[2 + num];
		*tag_len = 2 + num + *value_len;
	} else {
		*value_len = data[1] & 0x7f;
		*value = &data[2];
		*tag_len = 2 + *value_len;
	}

	if (*tag_len > data_len)
		return 0;

	return data[0];
}

/*
 * Extract data from an SPKI
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *     algorithm         AlgorithmIdentifier,
 *     subjectPublicKey  BIT STRING
 *   }
 *
 *   AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm   OBJECT IDENTIFIER,
 *     parameters  ANY DEFINED BY algorithm OPTIONAL
 *   }
 */
static int sk_ep11_parse_spki(const unsigned char *spki, size_t spki_len,
			      enum sk_key_type *keytype,
			      const unsigned char **params,
			      size_t *params_len, const unsigned char **pub_key,
			      size_t *pub_key_len)
{
	size_t tag_len, seq1_len, seq2_tag_len, seq2_len, oid_len;
	const unsigned char *seq1, *seq2, *oid;
	ASN1_OBJECT *obj = NULL;
	unsigned char tag;
	int algo_nid;

	/* Outer sequence */
	tag = sk_ep11_parse_der_tag(spki, spki_len, &tag_len, &seq1, &seq1_len);
	if (tag != 0x30) /* SEQUENCE */
		return -EINVAL;

	/* Inner sequence */
	tag = sk_ep11_parse_der_tag(seq1, seq1_len, &seq2_tag_len, &seq2,
				    &seq2_len);
	if (tag != 0x30) /* SEQUENCE */
		return -EINVAL;

	/* Algorithm OID */
	tag = sk_ep11_parse_der_tag(seq2, seq2_len, &tag_len, &oid, &oid_len);
	if (tag != 0x06) /* OID */
		return -EINVAL;

	oid = seq2;
	if (d2i_ASN1_OBJECT(&obj, &oid, tag_len) == NULL)
		return -EIO;
	algo_nid = OBJ_obj2nid(obj);
	ASN1_OBJECT_free(obj);

	switch (algo_nid) {
	case NID_rsaEncryption:
		*keytype = SK_KEY_TYPE_RSA;
		break;
	case NID_X9_62_id_ecPublicKey:
		*keytype = SK_KEY_TYPE_EC;
		break;
	default:
		return -EINVAL;
	}

	/* Parameters */
	*params = seq2 + tag_len;
	*params_len = seq2_len - tag_len;

	/* Public key */
	tag = sk_ep11_parse_der_tag(seq1 + seq2_tag_len,
				    seq1_len - seq2_tag_len, &tag_len,
				    pub_key, pub_key_len);
	if (tag != 0x03) /* BITSTRING */
		return -EINVAL;

	/* skip unsused-bits byte */
	(*pub_key)++;
	(*pub_key_len)--;

	return 0;
}

static bool sk_ep11_valid_ep11_blob(const unsigned char *key_token,
				    size_t key_token_length)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;

	if (key_token == NULL)
		return false;

	if (key_token_length <= sizeof(struct ep11kblob_header))
		return false;

	if (hdr->len > key_token_length ||
	    hdr->type != TOKTYPE_NON_CCA ||
	    hdr->hver != PKEY_TYPE_EP11_HVER ||
	    (hdr->version != PKEY_TYPE_EP11_ECC &&
	     hdr->version != PKEY_TYPE_EP11_RSA))
		return false;

	return true;
}

/**
 * Queries the PKEY type of the key token.
 *
 * @param key_token         the key token containing an Ep11 EC key
 * @param key_token_length  the size of the key token
 * @param pkey_type         On return: the PKEY type of the key token
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_EP11_get_key_type(const unsigned char *key_token,
			 size_t key_token_length,
			 int *pkey_type)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;
	size_t params_len, pub_key_len, spki_size;
	const unsigned char *params, *pub_key;
	enum sk_key_type type;
	int rc;

	if (key_token == NULL || pkey_type == NULL)
		return -EINVAL;

	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return -EINVAL;

	spki_size = key_token_length - hdr->len;
	if (spki_size <= 0)
		return -EINVAL;

	rc = sk_ep11_parse_spki(key_token + hdr->len, spki_size,
				&type, &params, &params_len, &pub_key,
				&pub_key_len);
	if (rc != 0)
		return rc;

	switch (type) {
	case SK_KEY_TYPE_RSA:
		*pkey_type = EVP_PKEY_RSA;
		break;
	case SK_KEY_TYPE_EC:
		*pkey_type = EVP_PKEY_EC;
		break;
	default:
		*pkey_type = -1;
		return -EINVAL;
	}

	return 0;
}

/**
 * Returns the EP11 private key blob of the key token.
 *
 * @param key_token         the key token containing an Ep11 EC key
 * @param key_token_length  the size of the key token
 *
 * @returns the address of the EP11 key blob, or NULL in case of an error
 */
const unsigned char *SK_EP11_get_key_blob(const unsigned char *key_token,
					  size_t key_token_length)
{
	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return NULL;

	return key_token + sizeof(struct ep11kblob_header);
}

/**
 * Returns the EP11 private key blob size of the key token.
 *
 * @param key_token         the key token containing an Ep11 EC key
 * @param key_token_length  the size of the key token
 *
 * @returns the size of the EP11 key blob, or 0 in case of an error
 */
size_t SK_EP11_get_key_blob_size(const unsigned char *key_token,
				 size_t key_token_length)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;

	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return 0;

	return hdr->len - sizeof(struct ep11kblob_header);
}

/**
 * Sign data using RSA.
 *
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
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_ep11_rsa_sign(const unsigned char *key_token,
			    size_t key_token_length,
			    unsigned char *sig, size_t *siglen,
			    const unsigned char *tbs, size_t tbslen,
			    int padding_type, int md_nid,
			    void *private, bool debug)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;
	const unsigned char *blob = key_token +
					sizeof(struct ep11kblob_header);
	CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS,
			      .pParameter = NULL, .ulParameterLen = 0 };
	const struct sk_ext_ep11_lib *ep11_lib = private;
	const struct sk_digest_info *digest;
	unsigned char *msg = NULL;
	struct ep11_lib ep11;
	size_t msg_len;
	CK_RV rv;
	int rc;

	if (ep11_lib == NULL || key_token == NULL || sig == NULL ||
	    siglen == NULL || tbs == NULL)
		return -EINVAL;

	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return -EINVAL;

	sk_debug(debug, "tbslen: %lu siglen: %lu padding_type: %d md_nid: %d",
		 tbslen, *siglen, padding_type, md_nid);

	rc = sk_ep11_get_library_functions(ep11_lib, &ep11);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get EP11 functions from library");
		return rc;
	}

	digest = SK_UTIL_get_digest_info(md_nid);
	if (digest == NULL) {
		sk_debug(debug, "ERROR: Invalid digest nid: %d", md_nid);
		return -EINVAL;
	}

	if (tbslen != digest->digest_size) {
		sk_debug(debug, "ERROR: Invalid data length: %lu", tbslen);
		return -EINVAL;
	}

	switch (padding_type) {
	case RSA_PKCS1_PADDING:
		msg_len = digest->der_size + tbslen;
		msg = (unsigned char *)malloc(msg_len);
		if (msg == NULL) {
			sk_debug(debug, "ERROR: malloc failed");
			return -ENOMEM;
		}

		memcpy(msg, digest->der, digest->der_size);
		memcpy(msg + digest->der_size, tbs, tbslen);
		tbs = msg;
		tbslen = msg_len;
		break;

	case RSA_X931_PADDING:
		mech.mechanism = CKM_RSA_X9_31;

		if ((hdr->flags && PKEY_TYPE_EP11_FLAG_X9_31) == 0) {
			sk_debug(debug, "ERROR: no RSA X9.31 key");
			return -EINVAL;
		}

		msg_len = tbslen + 2;
		msg = (unsigned char *)malloc(msg_len);
		if (msg == NULL) {
			sk_debug(debug, "ERROR: malloc failed");
			return -ENOMEM;
		}

		memcpy(msg, tbs, tbslen);
		msg[tbslen] = digest->x9_31_md;
		msg[tbslen + 1] = 0xcc;

		tbs = msg;
		tbslen = msg_len;
		break;

	default:
		sk_debug(debug, "ERROR: Invalid padding type: %d",
			 padding_type);
		return -EINVAL;
	}

	rv = ep11.dll_m_SignSingle(blob, hdr->len - sizeof(*hdr), &mech,
				   (CK_BYTE_PTR)tbs, tbslen,
				   sig, siglen, ep11_lib->target);
	if (rv != CKR_OK) {
		sk_debug(debug, "ERROR: m_SignSingle failed: rc: 0x%x", rv);
		rc = -EIO;
		goto out;
	}

	rc = 0;

	sk_debug(debug, "siglen: %lu", *siglen);

out:
	if (msg != NULL)
		free(msg);

	return rc;
}

/**
 * Sign data using RSA-PSS.
 *
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
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_ep11_rsa_pss_sign(const unsigned char *key_token,
				size_t key_token_length,
				unsigned char *sig, size_t *siglen,
				const unsigned char *tbs, size_t tbslen,
				int digest_nid, int mgf_digest_nid, int saltlen,
				void *private, bool debug)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;
	const unsigned char *blob = key_token +
					sizeof(struct ep11kblob_header);

	CK_RSA_PKCS_PSS_PARAMS pss_params;
	CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS_PSS,
			      .pParameter = &pss_params,
			      .ulParameterLen = sizeof(pss_params) };
	const struct sk_ext_ep11_lib *ep11_lib = private;
	const struct sk_digest_info *digest;
	struct ep11_lib ep11;
	CK_RV rv;
	int rc;

	if (ep11_lib == NULL || key_token == NULL || sig == NULL ||
	    siglen == NULL || tbs == NULL)
		return -EINVAL;

	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return -EINVAL;

	sk_debug(debug, "tbslen: %lu siglen: %lu digest_nid: %d "
		 "mgf_digest_nid: %d saltlen: %d",
		 tbslen, *siglen, digest_nid, mgf_digest_nid, saltlen);

	rc = sk_ep11_get_library_functions(ep11_lib, &ep11);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get EP11 functions from library");
		return rc;
	}

	if (mgf_digest_nid != digest_nid) {
		sk_debug(debug, "ERROR: Mgf nid must be the same as the "
			 "message digest nid");
		return -EINVAL;
	}

	digest = SK_UTIL_get_digest_info(digest_nid);
	if (digest == NULL || digest->pkcs11_mech == 0 ||
	    digest->pkcs11_mgf == 0) {
		sk_debug(debug, "ERROR: Invalid digest nid: %d", digest_nid);
		return -EINVAL;
	}

	if (tbslen != digest->digest_size) {
		sk_debug(debug, "ERROR: Invalid data length: %lu", tbslen);
		return -EINVAL;
	}

	if (saltlen != (int)digest->digest_size) {
		sk_debug(debug, "ERROR: saltlen must be size of digest");
		return -EINVAL;
	}

	pss_params.hashAlg = digest->pkcs11_mech;
	pss_params.mgf = digest->pkcs11_mgf;
	pss_params.sLen = saltlen;

	sk_debug(debug, "pss_params.hashAlg: 0x%x", pss_params.hashAlg);
	sk_debug(debug, "pss_params.mgf: 0x%x", pss_params.mgf);

	rv = ep11.dll_m_SignSingle(blob, hdr->len - sizeof(*hdr), &mech,
				   (CK_BYTE_PTR)tbs, tbslen,
				   sig, siglen, ep11_lib->target);
	if (rv != CKR_OK) {
		sk_debug(debug, "ERROR: m_SignSingle failed: rc: 0x%x", rv);
		return -EIO;
	}

	sk_debug(debug, "siglen: %lu", *siglen);

	return 0;
}

/**
 * Decrypt data using RSA.
 *
 * @param key_token         the RSA key token
 * @param key_token_length  the length of the key token
 * @param to                a buffer to store the decrypted data on return.
 * @param tolen             on input: the size if the to buffer
 *                          on return: the size of the decrypted data
 * @param from              the data to be decrypted.
 * @param fromlen           the size of the data to be decrypted
 * @param padding_type      the OpenSSL padding type
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_ep11_rsa_decrypt(const unsigned char *key_token,
			       size_t key_token_length,
			       unsigned char *to, size_t *tolen,
			       const unsigned char *from, size_t fromlen,
			       int padding_type, void *private, bool debug)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;
	const unsigned char *blob = key_token +
					sizeof(struct ep11kblob_header);
	CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS,
			      .pParameter = NULL, .ulParameterLen = 0 };
	const struct sk_ext_ep11_lib *ep11_lib = private;
	struct ep11_lib ep11;
	CK_RV rv;
	int rc;

	if (ep11_lib == NULL || key_token == NULL || to == NULL ||
	    tolen == NULL || from == NULL)
		return -EINVAL;

	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return -EINVAL;

	sk_debug(debug, "fromlen: %lu tolen: %lu padding_type: %d",
		 fromlen, *tolen, padding_type);

	rc = sk_ep11_get_library_functions(ep11_lib, &ep11);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get EP11 functions from library");
		return rc;
	}

	switch (padding_type) {
	case RSA_PKCS1_PADDING:
		break;

	default:
		sk_debug(debug, "ERROR: Invalid padding type: %d",
			 padding_type);
		return -EINVAL;
	}

	rv = ep11.dll_m_DecryptSingle(blob, hdr->len - sizeof(*hdr), &mech,
				   (CK_BYTE_PTR)from, fromlen,
				   to, tolen, ep11_lib->target);
	if (rv != CKR_OK) {
		sk_debug(debug, "ERROR: m_DecryptSingle failed: rc: 0x%x", rv);
		return -EIO;
	}

	sk_debug(debug, "tolen: %lu", *tolen);

	return 0;
}

/**
 * Decrypt data using RSA OAEP.
 *
 * @param key_token         the RSA key token
 * @param key_token_length  the length of the key token
 * @param to                a buffer to store the decrypted data on return.
 * @param tolen             on input: the size if the to buffer
 *                          on return: the size of the decrypted data
 * @param from              the data to be decrypted.
 * @param fromlen           the size of the data to be decrypted
 * @param oaep_md_nid       the OpenSSL nid of the OAEP hashing algorithm
 * @param mgfmd_nid         the OpenSSL nid of the mask generation function
 * @param label             the label for OAEP
 * @param label_len         the length of the label for OAEP
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_ep11_rsa_decrypt_oaep(const unsigned char *key_token,
				    size_t key_token_length,
				    unsigned char *to, size_t *tolen,
				    const unsigned char *from, size_t fromlen,
				    int oaep_md_nid, int mgfmd_nid,
				    unsigned char *label,
				    int label_len,
				    void *private, bool debug)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;
	const unsigned char *blob = key_token +
					sizeof(struct ep11kblob_header);
	CK_RSA_PKCS_OAEP_PARAMS oaep_params;
	CK_MECHANISM mech = { .mechanism = CKM_RSA_PKCS_OAEP,
			      .pParameter = &oaep_params,
			      .ulParameterLen = sizeof(oaep_params) };
	const struct sk_ext_ep11_lib *ep11_lib = private;
	const struct sk_digest_info *digest;
	struct ep11_lib ep11;
	CK_RV rv;
	int rc;

	if (ep11_lib == NULL || key_token == NULL || to == NULL ||
	    tolen == NULL || from == NULL)
		return -EINVAL;

	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return -EINVAL;

	sk_debug(debug, "fromlen: %lu tolen: %lu oaep_md_nid: %d mgfmd_nid: %d",
		 fromlen, *tolen, oaep_md_nid, mgfmd_nid);

	rc = sk_ep11_get_library_functions(ep11_lib, &ep11);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get EP11 functions from library");
		return rc;
	}

	if (mgfmd_nid != oaep_md_nid) {
		sk_debug(debug, "ERROR: Mgf nid must be the same as the "
			 "OAEP digest nid");
		return -EINVAL;
	}

	digest = SK_UTIL_get_digest_info(oaep_md_nid);
	if (digest == NULL || digest->pkcs11_mech == 0  ||
	    digest->pkcs11_mgf == 0) {
		sk_debug(debug, "ERROR: Invalid digest nid: %d", oaep_md_nid);
		return -EINVAL;
	}

	oaep_params.hashAlg = digest->pkcs11_mech;
	oaep_params.mgf = digest->pkcs11_mgf;
	oaep_params.source = label_len > 0 ? CKZ_DATA_SPECIFIED : 0;
	oaep_params.pSourceData = label_len > 0 ? label : NULL;
	oaep_params.ulSourceDataLen = label_len;

	sk_debug(debug, "oaep_params.hashAlg: 0x%x", oaep_params.hashAlg);
	sk_debug(debug, "oaep_params.mgf: 0x%x", oaep_params.mgf);
	sk_debug(debug, "oaep_params.source: 0x%x", oaep_params.source);
	sk_debug(debug, "oaep_params.ulSourceDataLen: %lu",
		 oaep_params.ulSourceDataLen);

	rv = ep11.dll_m_DecryptSingle(blob, hdr->len - sizeof(*hdr), &mech,
				   (CK_BYTE_PTR)from, fromlen,
				   to, tolen, ep11_lib->target);
	if (rv != CKR_OK) {
		sk_debug(debug, "ERROR: m_DecryptSingle failed: rc: 0x%x", rv);
		return -EIO;
	}

	sk_debug(debug, "tolen: %lu", *tolen);

	return 0;
}

/**
 * Sign data using ECDSA.
 *
 * @param key_token         the RSA key token
 * @param key_token_length  the length of the key token
 * @param sig               a buffer to store the signature on return.
 * @param siglen            on input: the size if the signature buffer
 *                          on return: the size of the signature
 * @param tbs               the data to be signed.
 * @param tbslen            the size of the data to be signed
 * @param digest_nid        the OpenSSL nid of the message digest used to
 *                          produce the data to be signed
 * @param private           the CCA library structure
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
static int sk_ep11_ecdsa_sign(const unsigned char *key_token,
			      size_t key_token_length,
			      unsigned char *sig, size_t *siglen,
			      const unsigned char *tbs, size_t tbslen,
			      int digest_nid, void *private,
			      bool debug)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;
	const unsigned char *blob = key_token +
					sizeof(struct ep11kblob_header);
	CK_MECHANISM mech = { .mechanism = CKM_ECDSA,
			      .pParameter = NULL, .ulParameterLen = 0 };
	const struct sk_ext_ep11_lib *ep11_lib = private;
	struct ep11_lib ep11;
	CK_ULONG sig_len;
	CK_RV rv;
	int rc;

	if (ep11_lib == NULL || key_token == NULL || sig == NULL ||
	    siglen == NULL || tbs == NULL)
		return -EINVAL;

	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return -EINVAL;

	sk_debug(debug, "tbslen: %lu siglen: %lu digest_nid: %d",
		 tbslen, *siglen, digest_nid);

	rc = sk_ep11_get_library_functions(ep11_lib, &ep11);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get EP11 functions from library");
		return rc;
	}

	sig_len = *siglen;
	rv = ep11.dll_m_SignSingle(blob, hdr->len - sizeof(*hdr), &mech,
				   (CK_BYTE_PTR)tbs, tbslen,
				   sig, &sig_len, ep11_lib->target);
	if (rv != CKR_OK) {
		sk_debug(debug, "ERROR: m_SignSingle failed: rc: 0x%x", rv);
		return -EIO;
	}

	rc = SK_UTIL_build_ecdsa_signature(sig, sig_len, sig, siglen);
	if (rc != 0) {
		sk_debug(debug, "ERROR: build_ecdsa_signature failed");
		return -EIO;
	}

	sk_debug(debug, "siglen: %lu", *siglen);

	return 0;
}

static const struct sk_funcs sk_ep11_funcs = {
	.rsa_sign = sk_ep11_rsa_sign,
	.rsa_pss_sign = sk_ep11_rsa_pss_sign,
	.rsa_decrypt = sk_ep11_rsa_decrypt,
	.rsa_decrypt_oaep = sk_ep11_rsa_decrypt_oaep,
	.ecdsa_sign = sk_ep11_ecdsa_sign,
};

struct pub_key_cb_data {
	const struct sk_ext_ep11_lib *ep11_lib;
	const unsigned char *key_token;
	size_t key_token_length;
	bool rsa_pss;
	EVP_PKEY *pkey;
	bool debug;
};

/*
 * Callback for generating an PKEY from a secure key
 */
static int sk_ep11_get_secure_key_as_pkey_cb(
			const struct sk_pub_key_info *pub_key, void *private)
{
	struct pub_key_cb_data *data = private;
	int rc;

	if (pub_key == NULL || data == NULL)
		return -EINVAL;

	rc = SK_OPENSSL_get_pkey(data->key_token, data->key_token_length,
				 pub_key, data->rsa_pss, &sk_ep11_funcs,
				 data->ep11_lib, &data->pkey, data->debug);
	if (rc != 0) {
		sk_debug(data->debug,
			 "ERROR: SK_OPENSSL_get_pkey failed");
		return rc;
	}

	sk_debug(data->debug, "pkey: %p", data->pkey);

	return 0;
}

/**
 * Extracts the public key from a Ep11 RSA or EC key token, and returns
 * it as OpenSSL PKEY.
 *
 * @param ep11_lib          the EP11 library structure
 * @param key_token         the key token containing an EP11 secure key
 * @param key_token_length  the size of the key token
 * @param rsa_pss           For RSA public keys: create a RSA-PSS type PKEY
 * @param pkey              On return: a PKEY containing the public key
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_EP11_get_secure_key_as_pkey(const struct sk_ext_ep11_lib *ep11_lib,
				   const unsigned char *key_token,
				   size_t key_token_length,
				   bool rsa_pss, EVP_PKEY **pkey, bool debug)
{
	struct pub_key_cb_data data;
	int rc;

	sk_debug(debug, "rsa_pss: %d", rsa_pss);

	data.ep11_lib = ep11_lib;
	data.key_token = key_token;
	data.key_token_length = key_token_length;
	data.rsa_pss = rsa_pss;
	data.pkey = NULL;
	data.debug = debug;

	rc = SK_EP11_get_public_from_secure_key(key_token, key_token_length,
					sk_ep11_get_secure_key_as_pkey_cb,
						&data, debug);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: SK_EP11_get_public_from_secure_key failed");
		return rc;
	}

	sk_debug(debug, "pkey: %p", data.pkey);

	*pkey = data.pkey;
	return 0;
}

static int sk_ep11_get_public_from_ec_key(const unsigned char *pub_key,
					  size_t pub_key_len,
					  const unsigned char *params,
					  size_t params_len,
					  sk_pub_key_func_t pub_key_cb,
					  void *private,
					  bool debug)
{
	struct sk_pub_key_info pub_key_info = { 0 };
	const struct sk_ec_curve_info *curve;
	unsigned char *buf = NULL;
	ASN1_OBJECT *obj = NULL;
	int y_bit = 0;
	int rc = 0;

	/*
	 * ECParameters ::= CHOICE {
	 *   namedCurve         OBJECT IDENTIFIER
	 *   -- implicitCurve   NULL
	 *   -- specifiedCurve  SpecifiedECDomain
	 * }
	 *
	 * EC PublicKey         ECPoint
	 */
	if (d2i_ASN1_OBJECT(&obj, &params, params_len) == NULL) {
		sk_debug(debug, "ERROR: d2i_ASN1_OBJECT failed");
		return -EIO;
	}
	pub_key_info.ec.curve_nid = OBJ_obj2nid(obj);
	ASN1_OBJECT_free(obj);

	sk_debug(debug, "curve_nid: %d", pub_key_info.ec.curve_nid);
	curve = SK_UTIL_ec_get_curve_info(pub_key_info.ec.curve_nid);
	if (curve == NULL) {
		sk_debug(debug, "ERROR: unsupported curve");
		return -EIO;
	}
	pub_key_info.ec.prime_len = curve->prime_len;
	sk_debug(debug, "prime_len: %lu", pub_key_info.ec.prime_len);

	if (pub_key_len != 2 * pub_key_info.ec.prime_len + 1) {
		sk_debug(debug, "ERROR: invalid public key length");
		return -EINVAL;
	}

	pub_key_info.ec.x = pub_key + 1;

	/* First byte of public key contains indication of key compression */
	switch (pub_key[0]) {
	case POINT_CONVERSION_COMPRESSED:
	case POINT_CONVERSION_COMPRESSED + POINT_CONVERSION_ODD_EVEN:
		/* Compressed form, only x is available */
		y_bit = (pub_key[0] & POINT_CONVERSION_ODD_EVEN) ? 1 : 0;

		buf = malloc(pub_key_info.ec.prime_len);
		if (buf == NULL) {
			sk_debug(debug, "ERROR: malloc failed");
			rc = -ENOMEM;
			goto out;
		}

		rc = SK_UTIL_ec_calculate_y_coordinate(
						pub_key_info.ec.curve_nid,
						pub_key_info.ec.prime_len,
						pub_key_info.ec.x, y_bit,
						buf);
		if (rc != 0) {
			sk_debug(debug, "ERROR: ec_calculate_y_coordinate "
				 "failed");
			goto out;
		}

		pub_key_info.ec.y = buf;
		break;

	case POINT_CONVERSION_UNCOMPRESSED:
	case POINT_CONVERSION_HYBRID:
	case POINT_CONVERSION_HYBRID + POINT_CONVERSION_ODD_EVEN:
		/* Uncompressed or hybrid, x and y are available */
		pub_key_info.ec.y = pub_key_info.ec.x +
						pub_key_info.ec.prime_len;
		break;

	default:
		sk_debug(debug, "ERROR: invalid compression indication");
		rc = -EIO;
		goto out;
	}

	pub_key_info.type = SK_KEY_TYPE_EC;

	rc = pub_key_cb(&pub_key_info, private);
	if (rc != 0) {
		sk_debug(debug, "ERROR: pub_key_cb failed");
		goto out;
	}

out:
	if (buf != NULL)
		free(buf);

	return rc;
}

/*
 * Extracts the public key from a EP11 RSA key blob, and calls
 * the specified callback function with the public key information.
 */
static int sk_ep11_get_public_from_rsa_key(const unsigned char *pub_key,
					   size_t pub_key_len,
					   sk_pub_key_func_t pub_key_cb,
					   void *private,
					   bool debug)
{
	struct sk_pub_key_info pub_key_info = { 0 };
	const unsigned char *seq;
	size_t tag_len, seq_len;
	unsigned char tag;
	int rc;

	/*
	 * RSAPublicKey ::= SEQUENCE {
	 *   modulus           INTEGER,  -- n
	 *   publicExponent    INTEGER   -- e
	 * }
	 */
	tag = sk_ep11_parse_der_tag(pub_key, pub_key_len, &tag_len, &seq,
				    &seq_len);
	if (tag != 0x30) { /* SEQUENCE */
		sk_debug(debug, "ERROR: failed to parse SEQUENCE");
		return -EINVAL;
	}

	tag = sk_ep11_parse_der_tag(seq, seq_len, &tag_len,
				    &pub_key_info.rsa.modulus,
				    &pub_key_info.rsa.modulus_len);
	if (tag != 0x02) { /* INTEGER */
		sk_debug(debug, "ERROR: failed to parse INTEGER (modulus)");
		return -EINVAL;
	}

	tag = sk_ep11_parse_der_tag(seq + tag_len, seq_len - tag_len, &tag_len,
				    &pub_key_info.rsa.pub_exp,
				    &pub_key_info.rsa.pub_exp_len);
	if (tag != 0x02) { /* INTEGER */
		sk_debug(debug, "ERROR: failed to parse INTEGER (pub-exp)");
		return -EINVAL;
	}

	pub_key_info.type = SK_KEY_TYPE_RSA;

	rc = pub_key_cb(&pub_key_info, private);
	if (rc != 0) {
		sk_debug(debug, "ERROR: pub_key_cb failed");
		return rc;
	}

	return 0;
}


/**
 * Extracts the public key from a EP11 RSA or EC key blob, and calls
 * the specified callback function with the public key information.
 *
 * @param key_token         the key token containing an EP11 secure key
 * @param key_token_length  the size of the key token
 * @param pub_key_cb        the callback function to call with the public key
 * @param private           a private pointer passed as is to the callback
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_EP11_get_public_from_secure_key(const unsigned char *key_token,
				       size_t key_token_length,
				       sk_pub_key_func_t pub_key_cb,
				       void *private,
				       bool debug)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;
	size_t params_len, pub_key_len, spki_size;
	const unsigned char *params, *pub_key;
	enum sk_key_type type;
	int rc;

	if (key_token == NULL || pub_key_cb == NULL)
		return -EINVAL;

	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return -EINVAL;

	spki_size = key_token_length - hdr->len;
	if (spki_size <= 0)
		return -EINVAL;

	rc = sk_ep11_parse_spki(key_token + hdr->len, spki_size,
				&type, &params, &params_len, &pub_key,
				&pub_key_len);
	if (rc != 0) {
		sk_debug(debug, "ERROR: sk_ep11_parse_spki failed");
		return rc;
	}

	sk_debug(debug, "type: %d", type);

	switch (type) {
	case SK_KEY_TYPE_EC:
		rc = sk_ep11_get_public_from_ec_key(pub_key, pub_key_len,
						    params, params_len,
						    pub_key_cb,
						    private, debug);
		if (rc != 0) {
			sk_debug(debug,
				"ERROR: sk_ep11_get_public_from_ec_key failed");
			return rc;
		}
		break;
	case SK_KEY_TYPE_RSA:
		rc = sk_ep11_get_public_from_rsa_key(pub_key, pub_key_len,
						     pub_key_cb,
						     private, debug);
		if (rc != 0) {
			sk_debug(debug,
			    "ERROR: sk_ep11_get_public_from_rsa_key failed");
			return rc;
		}
		break;
	default:
		sk_debug(debug, "ERROR: Invalid key type: %d", type);
		return -EIO;
	}

	return 0;
}

/*
 * Checks that the specified target is a single APQN target, and extracts the
 * card and domain from it.
 */
static int sk_ep11_target_get_apqn(target_t target, unsigned short *card,
				   unsigned short *domain)
{
	if ((target & 0x8000000000000000L) != 0)
		return -ENODEV;

	*card = (target & 0x0000FFFF00000000) >> 32;
	*domain = target & 0x00000000000FFFF;
	return 0;
}

/**
 * Reenciphers an EP11 secure key with a new EP11 master key.
 * The target passed in via ep11_lib must be a single APQN target, and the
 * domain and card numbers must be specified.
 *
 * @param ep11_lib          the EP11 library structure
 * @param key_token         the key token containing an EP11 secure key
 * @param key_token_length  the size of the key token
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_EP11_reencipher_key(const struct sk_ext_ep11_lib *ep11_lib,
			   unsigned char *key_token, size_t key_token_length,
			   bool debug)
{
	const struct ep11kblob_header *hdr =
					(struct ep11kblob_header *)key_token;
	unsigned char *blob = key_token + sizeof(struct ep11kblob_header);
	CK_BYTE resp[EP11_MAX_KEY_TOKEN_SIZE];
	CK_BYTE req[EP11_MAX_KEY_TOKEN_SIZE];
	unsigned short card, domain;
	CK_IBM_DOMAIN_INFO dinf;
	struct XCPadmresp lrb;
	struct XCPadmresp rb;
	struct ep11_lib ep11;
	CK_ULONG dinf_len;
	size_t resp_len;
	long req_len;
	CK_RV rv;
	int rc;

	if (ep11_lib == NULL || key_token == NULL)
		return -EINVAL;

	if (!sk_ep11_valid_ep11_blob(key_token, key_token_length))
		return -EINVAL;

	rc = sk_ep11_target_get_apqn(ep11_lib->target, &card, &domain);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Need a single-APQN target for reencipher");
		return rc;
	}

	rc = sk_ep11_get_library_functions(ep11_lib, &ep11);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to get EP11 functions from library");
		return rc;
	}

	dinf_len = sizeof(dinf);
	rv = ep11.dll_m_get_xcp_info(&dinf, &dinf_len, CK_IBM_XCPQ_DOMAIN, 0,
				     ep11_lib->target);
	if (rv != CKR_OK) {
		sk_debug(debug, "Failed to query domain information for "
			 "APQN %02X.%04X: m_get_xcp_info rc: 0x%lx",
			 card, domain, rv);
		return -EIO;
	}

	if ((dinf.flags & CK_IBM_DOM_COMMITTED_NWK) == 0) {
		sk_debug(debug, "The NEW master key register of APQN %02X.%04X "
			 "is not in COMMITTED state", card, domain);
		return -ENODEV;
	}

	rb.domain = domain;
	lrb.domain = domain;

	resp_len = sizeof(resp);
	req_len = ep11.dll_xcpa_cmdblock(req, sizeof(req), XCP_ADM_REENCRYPT,
					 &rb, NULL, blob,
					 hdr->len - sizeof(*hdr));
	if (req_len < 0) {
		sk_debug(debug, "Failed to build XCP command block");
		return -EIO;
	}

	rv = ep11.dll_m_admin(resp, &resp_len, NULL, NULL, req, req_len, NULL,
			      0, ep11_lib->target);
	if (rv != CKR_OK || resp_len == 0) {
		sk_debug(debug, "Command XCP_ADM_REENCRYPT failed. "
			 "rc = 0x%lx, resp_len = %ld", rv, resp_len);
		return -EIO;
	}

	rc = ep11.dll_xcpa_internal_rv(resp, resp_len, &lrb, &rv);
	if (rc != 0) {
		sk_debug(debug, "Failed to parse response. rc = %d", rc);
		return -EIO;
	}

	if (rv != CKR_OK) {
		sk_debug(debug, "Failed to re-encrypt the EP11 secure key. "
			 "rc = 0x%lx", rv);
		switch (rv) {
		case CKR_IBM_WKID_MISMATCH:
			sk_debug(debug, "The EP11 secure key is currently "
				 "encrypted under a different master that does "
				 "not match the master key in the CURRENT "
				 "master key register of APQN %02X.%04X",
				 card, domain);
			break;
		}
		return -EIO;
	}

	if (hdr->len - sizeof(*hdr) != lrb.pllen) {
		sk_debug(debug, "Re-encrypted EP11 secure key size has "
			 "changed: org-len: %lu, new-len: %lu",
			 hdr->len - sizeof(*hdr), lrb.pllen);
		return -EIO;
	}

	return 0;
}


