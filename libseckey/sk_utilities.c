/*
 * libseckey - Secure key library
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "lib/zt_common.h"

#include "libseckey/sk_utilities.h"
#include "libseckey/sk_ep11.h"

void SK_UTIL_warnx(const char *func, const char *fmt, ...)
{
	char tmp_fmt[200];
	va_list ap;

	if (snprintf(tmp_fmt, sizeof(tmp_fmt), "DBG: %s: %s", func, fmt) >
							(int)sizeof(tmp_fmt))
		return;

	va_start(ap, fmt);
	vwarnx(tmp_fmt, ap);
	va_end(ap);
}

static const unsigned char der_prime192v1[] = {
	0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01
};
static const unsigned char der_secp224r1[] = {
	0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21
};
static const unsigned char der_prime256v1[] = {
	0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
};
static const unsigned char der_secp384r1[] = {
	0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22
};
static const unsigned char der_secp521r1[] = {
	0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23
};
static const unsigned char der_brainpoolP160r1[] = {
	0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01
};
static const unsigned char der_brainpoolP192r1[] = {
	0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03
};
static const unsigned char der_brainpoolP224r1[] = {
	0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05
};
static const unsigned char der_brainpoolP256r1[] = {
	0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07
};
static const unsigned char der_brainpoolP320r1[] = {
	0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09
};
static const unsigned char der_brainpoolP384r1[] = {
	0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B
};
static const unsigned char der_brainpoolP512r1[] = {
	0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D
};

static const struct sk_ec_curve_info ec_curve_list[] = {
	{ .curve_nid = NID_X9_62_prime192v1, .type = SK_EC_TYPE_PRIME,
	  .prime_bits = 192, .prime_len = 24, .der = der_prime192v1,
	  .der_size = sizeof(der_prime192v1) },
	{ .curve_nid = NID_secp224r1,        .type = SK_EC_TYPE_PRIME,
	  .prime_bits = 224, .prime_len = 28, .der = der_secp224r1,
	  .der_size = sizeof(der_secp224r1)},
	{ .curve_nid = NID_X9_62_prime256v1, .type = SK_EC_TYPE_PRIME,
	  .prime_bits = 256, .prime_len = 32, .der = der_prime256v1,
	  .der_size = sizeof(der_prime256v1)},
	{ .curve_nid = NID_secp384r1,        .type = SK_EC_TYPE_PRIME,
	  .prime_bits = 384, .prime_len = 48, .der = der_secp384r1,
	  .der_size = sizeof(der_secp384r1)},
	{ .curve_nid = NID_secp521r1,        .type = SK_EC_TYPE_PRIME,
	  .prime_bits = 521, .prime_len = 66, .der = der_secp521r1,
	  .der_size = sizeof(der_secp521r1)},
	{ .curve_nid = NID_brainpoolP160r1,  .type = SK_EC_TYPE_BRAINPOOL,
	  .prime_bits = 160, .prime_len = 20, .der = der_brainpoolP160r1,
	  .der_size = sizeof(der_brainpoolP160r1)},
	{ .curve_nid = NID_brainpoolP192r1,  .type = SK_EC_TYPE_BRAINPOOL,
	  .prime_bits = 192, .prime_len = 24, .der = der_brainpoolP192r1,
	  .der_size = sizeof(der_brainpoolP192r1)},
	{ .curve_nid = NID_brainpoolP224r1,  .type = SK_EC_TYPE_BRAINPOOL,
	  .prime_bits = 224, .prime_len = 28, .der = der_brainpoolP224r1,
	  .der_size = sizeof(der_brainpoolP224r1)},
	{ .curve_nid = NID_brainpoolP256r1,  .type = SK_EC_TYPE_BRAINPOOL,
	  .prime_bits = 256, .prime_len = 32, .der = der_brainpoolP256r1,
	  .der_size = sizeof(der_brainpoolP256r1)},
	{ .curve_nid = NID_brainpoolP320r1,  .type = SK_EC_TYPE_BRAINPOOL,
	  .prime_bits = 320, .prime_len = 40, .der = der_brainpoolP320r1,
	  .der_size = sizeof(der_brainpoolP320r1)},
	{ .curve_nid = NID_brainpoolP384r1,  .type = SK_EC_TYPE_BRAINPOOL,
	  .prime_bits = 384, .prime_len = 48, .der = der_brainpoolP384r1,
	  .der_size = sizeof(der_brainpoolP384r1)},
	{ .curve_nid = NID_brainpoolP512r1,  .type = SK_EC_TYPE_BRAINPOOL,
	  .prime_bits = 512, .prime_len = 64, .der = der_brainpoolP512r1,
	  .der_size = sizeof(der_brainpoolP512r1)},
};

static const int ec_curve_num =
		sizeof(ec_curve_list) / sizeof(struct sk_ec_curve_info);

/**
 * Returns the curve info of the specified curve, or NULL if the curve
 * is not known.
 *
 * @param nid               the OpenSSL nid of the EC curve
 *
 * @returns the address of the curve info or NULL if the curve was not found
 */
const struct sk_ec_curve_info *SK_UTIL_ec_get_curve_info(int curve_nid)
{
	int i;

	for (i = 0; i < ec_curve_num; i++) {
		if (ec_curve_list[i].curve_nid == curve_nid)
			return &ec_curve_list[i];
	}
	return NULL;
}

/**
 * Returns the nid of the Prime curve by its specified prime bit size, or 0
 * if the curve is not known.
 *
 * @param prime_bits        the prime bit size of the curve to search for
 *
 * @returns the OpenSSL nid of the EC curve or 0 if the curve was not found
 */
int SK_UTIL_ec_get_prime_curve_by_prime_bits(size_t prime_bits)
{
	int i;

	for (i = 0; i < ec_curve_num; i++) {
		if (ec_curve_list[i].type == SK_EC_TYPE_PRIME &&
		    ec_curve_list[i].prime_bits == prime_bits)
			return ec_curve_list[i].curve_nid;
	}
	return 0;
}

/**
 * Returns the nid of the Brainpool curve by its specified prime bit size, or 0
 * if the curve is not known.
 *
 * @param prime_bits        the prime bit size of the curve to search for
 *
 * @returns the OpenSSL nid of the EC curve or 0 if the curve was not found
 */
int SK_UTIL_ec_get_brainpool_curve_by_prime_bits(size_t prime_bits)
{
	int i;

	for (i = 0; i < ec_curve_num; i++) {
		if (ec_curve_list[i].type == SK_EC_TYPE_BRAINPOOL &&
		    ec_curve_list[i].prime_bits == prime_bits)
			return ec_curve_list[i].curve_nid;
	}
	return 0;
}

/**
 * Calculates the y coordinate of a point on an EC curve using the x coordinate
 * and the y bit. x and y must be supplied by the caller with prime_len bytes.
 * On return y contains the calculated y coordinate.
 *
 * @param nid               the OpenSSL nid of the EC curve used
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
int SK_UTIL_ec_calculate_y_coordinate(int nid, size_t prime_len,
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

	if (BN_bn2binpad(bn_y, y, prime_len) <= 0) {
		rc = -EIO;
		goto out;
	}

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

static const unsigned char der_DigestInfo_SHA1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, };
static const unsigned char der_DigestInfo_SHA224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
	0x00, 0x04, 0x1C, };
static const unsigned char der_DigestInfo_SHA256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20, };
static const unsigned char der_DigestInfo_SHA384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	0x00, 0x04, 0x30, };
static const unsigned char der_DigestInfo_SHA512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
	0x00, 0x04, 0x40, };
static const unsigned char der_DigestInfo_SHA3_224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05,
	0x00, 0x04, 0x1C, };
static const unsigned char der_DigestInfo_SHA3_256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
	0x00, 0x04, 0x20, };
static const unsigned char der_DigestInfo_SHA3_384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05,
	0x00, 0x04, 0x30, };
static const unsigned char der_DigestInfo_SHA3_512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05,
	0x00, 0x04, 0x40, };

static const struct sk_digest_info digest_list[] = {
	{ .digest_nid = NID_sha1, .digest_size = SHA_DIGEST_LENGTH,
	  .cca_keyword = "SHA-1   ", .der = der_DigestInfo_SHA1,
	  .der_size = sizeof(der_DigestInfo_SHA1),
	  .pkcs11_mech = CKM_SHA_1, .pkcs11_mgf = CKG_MGF1_SHA1,
	  .x9_31_md = 0x33, },
	{ .digest_nid = NID_sha224, .digest_size = SHA224_DIGEST_LENGTH,
	  .cca_keyword = "SHA-224 ", .der = der_DigestInfo_SHA224,
	  .der_size = sizeof(der_DigestInfo_SHA224),
	  .pkcs11_mech = CKM_SHA224, .pkcs11_mgf = CKG_MGF1_SHA224,
	  .x9_31_md = 0, },
	{ .digest_nid = NID_sha256, .digest_size = SHA256_DIGEST_LENGTH,
	  .cca_keyword = "SHA-256 ", .der = der_DigestInfo_SHA256,
	  .der_size = sizeof(der_DigestInfo_SHA256),
	  .pkcs11_mech = CKM_SHA256, .pkcs11_mgf = CKG_MGF1_SHA256,
	  .x9_31_md = 0x34, },
	{ .digest_nid = NID_sha384, .digest_size = SHA384_DIGEST_LENGTH,
	  .cca_keyword = "SHA-384 ", .der = der_DigestInfo_SHA384,
	  .der_size = sizeof(der_DigestInfo_SHA384),
	  .pkcs11_mech = CKM_SHA384, .pkcs11_mgf = CKG_MGF1_SHA384,
	  .x9_31_md = 0x36, },
	{ .digest_nid = NID_sha512, .digest_size = SHA512_DIGEST_LENGTH,
	  .cca_keyword = "SHA-512 ", .der = der_DigestInfo_SHA512,
	  .der_size = sizeof(der_DigestInfo_SHA512),
	  .pkcs11_mech = CKM_SHA512, .pkcs11_mgf = CKG_MGF1_SHA512,
	  .x9_31_md = 0x35, },
	{ .digest_nid = NID_sha3_224, .digest_size = SHA224_DIGEST_LENGTH,
	  .cca_keyword = NULL, .der = der_DigestInfo_SHA3_224,
	  .der_size = sizeof(der_DigestInfo_SHA3_224),
	  .pkcs11_mech = CKM_IBM_SHA3_224, .pkcs11_mgf = CKG_IBM_MGF1_SHA3_224,
	  .x9_31_md = 0, },
	{ .digest_nid = NID_sha3_256, .digest_size = SHA256_DIGEST_LENGTH,
	  .cca_keyword = NULL, .der = der_DigestInfo_SHA3_256,
	  .der_size = sizeof(der_DigestInfo_SHA3_256),
	  .pkcs11_mech = CKM_IBM_SHA3_256, .pkcs11_mgf = CKG_IBM_MGF1_SHA3_256,
	  .x9_31_md = 0, },
	{ .digest_nid = NID_sha3_384, .digest_size = SHA384_DIGEST_LENGTH,
	  .cca_keyword = NULL, .der = der_DigestInfo_SHA3_384,
	  .der_size = sizeof(der_DigestInfo_SHA3_384),
	  .pkcs11_mech = CKM_IBM_SHA3_384, .pkcs11_mgf = CKG_IBM_MGF1_SHA3_384,
	  .x9_31_md = 0, },
	{ .digest_nid = NID_sha3_512, .digest_size = SHA512_DIGEST_LENGTH,
	  .cca_keyword = NULL, .der = der_DigestInfo_SHA3_512,
	  .der_size = sizeof(der_DigestInfo_SHA3_512),
	  .pkcs11_mech = CKM_IBM_SHA3_512, .pkcs11_mgf = CKG_IBM_MGF1_SHA3_512,
	  .x9_31_md = 0, },
};

static const int digest_list_num = sizeof(digest_list) /
						sizeof(struct sk_digest_info);

/**
 * Returns the digest info of the specified digest nid, or NULL if the digest
 * is not known.
 *
 * @param nid               the OpenSSL nid of the digest
 *
 * @returns the address of the digest info or NULL if the digest was not found
 */
const struct sk_digest_info *SK_UTIL_get_digest_info(int digest_nid)
{
	int i;

	for (i = 0; i < digest_list_num; i++) {
		if (digest_list[i].digest_nid == digest_nid)
			return &digest_list[i];
	}

	return NULL;
}



/**
 * Checks if an exact duplicate of the name entry is part of the name already.
 */
static bool SK_UTILS_is_duplicate_name_entry(const X509_NAME *name,
					     const X509_NAME_ENTRY *entry)
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
int SK_UTIL_build_subject_name(X509_NAME **name, const char *rdns[],
			       size_t num_rdns, bool utf8)
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

		if (SK_UTILS_is_duplicate_name_entry(n, ne)) {
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
int SK_UTIL_build_certificate_extensions(X509 *cert, X509_REQ *req,
					 const char *exts[], size_t num_exts,
					 const STACK_OF(X509_EXTENSION)
								*addl_exts)
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
				X509_EXTENSION_free(ex);
				free(ext);
				break;
			}

			rc = sk_X509_EXTENSION_push(sk_ext, ex);
			if (rc < 1) {
				rc = -EIO;
				X509_EXTENSION_free(ex);
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
int SK_UTIL_generate_x509_serial_number(X509 *cert, size_t sn_bit_size)
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
 * Builds an DER encoded signature from a raw signature.
 *
 * @param raw_sig            the raw signature to encode
 * @param raw_sig_len        the size of the raw signature (2 times prime len)
 * @param sig                a buffer for storing he encoded signature. If
 *                           NULL, then required size is returend in sig_len.
 * @param sig_len            On entry: the size of the buffer in sig.
 *                           On exit: the size of the encoded sigature.
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -ERANGE: signature buffer is too small
 *          -EIO: error during signature encoding
 */
int SK_UTIL_build_ecdsa_signature(const unsigned char *raw_sig,
				  size_t raw_sig_len,
				  unsigned char *sig, size_t *sig_len)
{
	unsigned char *der = NULL;
	ECDSA_SIG *ec_sig = NULL;
	BIGNUM *bn_r = NULL;
	BIGNUM *bn_s = NULL;
	int rc = 0, der_len;

	ec_sig = ECDSA_SIG_new();
	if (ec_sig == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	bn_r = BN_bin2bn(raw_sig, raw_sig_len / 2, NULL);
	bn_s = BN_bin2bn(raw_sig + raw_sig_len / 2, raw_sig_len / 2, NULL);
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

	der_len = i2d_ECDSA_SIG(ec_sig, NULL);
	if (der_len <= 0) {
		rc = -EIO;
		goto out;
	}

	if (sig == NULL) {
		*sig_len = der_len;
		goto out;
	}
	if (der_len > (int)*sig_len) {
		rc = -ERANGE;
		goto out;
	}

	memset(sig, 0, *sig_len);
	der = sig;
	der_len = i2d_ECDSA_SIG(ec_sig, &der);
	if (der_len <= 0) {
		rc = -EIO;
		goto out;
	}

	*sig_len = der_len;

out:
	if (ec_sig != NULL)
		ECDSA_SIG_free(ec_sig);
	if (bn_r != NULL)
		BN_free(bn_r);
	if (bn_s != NULL)
		BN_free(bn_s);

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
int SK_UTIL_read_x509_certificate(const char *pem_filename, X509 **cert)
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
int SK_UTIL_write_x509_certificate(const char *pem_filename, X509 *cert)
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
int SK_UTIL_write_x509_request(const char *pem_filename, X509_REQ *req,
			       bool new_hdr)
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
 * Reads a secure key from the specified file.
 *
 * @param filename           the name of the file to read
 * @param key_blob           on Return: the key blob
 * @param key_blob_len       on Entry: the size of the buffer,
 *                           on Return: the size of the key blob read
 *
 * @returns zero for success, a negative errno in case of an error
 */
int SK_UTIL_read_key_blob(const char *filename, unsigned char *key_blob,
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
 * Writes a secure key to the specified file.
 *
 * @param filename           the name of the file to write
 * @param key_blob           the key blob
 * @param key_blob_len       the size of the key blob
 *
 * @returns zero for success, a negative errno in case of an error
 */
int SK_UTIL_write_key_blob(const char *filename, unsigned char *key_blob,
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
int SK_UTIL_read_public_key(const char *pem_filename, EVP_PKEY **pkey)
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
 * Writes a public key to the specified PEM file.
 *
 * @param pem_filename       the name of the PEM file to write to
 * @param pkey               the PKEY object to write
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: invalid parameter
 *          -EIO: error during writing out the certificate
 *          any other errno as returned by fopen
 */
int SK_UTIL_write_public_key(const char *pem_filename, EVP_PKEY *pkey)
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

