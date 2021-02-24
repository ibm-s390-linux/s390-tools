/*
 * General cryptography helper functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <glib.h>
#include <glib/gtypes.h>
#include <limits.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "boot/s390.h"
#include "common.h"
#include "include/pv_crypto_def.h"
#include "pv/pv_error.h"

#include "buffer.h"
#include "curl.h"
#include "crypto.h"

#define DEFINE_GSLIST_MAP(t2, t1)					\
	typedef t1 *(*g_slist_map_func_##t2##_##t1)(const t2 *x,	\
						     GError **err);	\
	G_GNUC_UNUSED static GSList *g_slist_map_##t2##_##t1(const GSList *list, \
							     g_slist_map_func_##t2##_##t1 func, \
							     GError **err) \
	{								\
		g_autoslist(t1) ret = NULL;				\
		for (const GSList *iterator = list; iterator;		\
		     iterator = iterator->next) {			\
			const t2 *value = iterator->data;		\
			t1 *new_value = NULL;				\
			g_assert(value);				\
			new_value = func(value, err);			\
			if (!new_value)					\
				return NULL;				\
			ret = g_slist_append(ret, g_steal_pointer(&new_value)); \
		}							\
		return g_steal_pointer(&ret);				\
	}

#define DEFINE_GSLIST_TO_STACK(t1)					\
	G_GNUC_UNUSED static STACK_OF(t1) *g_slist_to_stack_of_##t1(GSList **list) \
	{								\
		g_assert(list);						\
		g_autoptr(STACK_OF_##t1) ret = sk_##t1##_new_null();	\
		if (!ret)						\
			g_abort();					\
		for (GSList *iterator = *list; iterator;		\
		     iterator = iterator->next) {			\
			if (sk_##t1##_push(ret, g_steal_pointer(&iterator->data)) == 0) \
				g_abort();				\
		}							\
		g_clear_pointer(list, g_slist_free);			\
		return g_steal_pointer(&ret);				\
	}

DEFINE_GSLIST_MAP(x509_with_path, X509)
DEFINE_GSLIST_TO_STACK(X509)

EVP_MD_CTX *digest_ctx_new(const EVP_MD *md, GError **err)
{
	g_autoptr(EVP_MD_CTX) ctx = EVP_MD_CTX_new();

	if (!ctx)
		g_abort();

	if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_DigestInit_ex failed"));
		return NULL;
	}

	return g_steal_pointer(&ctx);
}

PvBuffer *digest_ctx_finalize(EVP_MD_CTX *ctx, GError **err)
{
	gint md_size = EVP_MD_size(EVP_MD_CTX_md(ctx));
	g_autoptr(PvBuffer) ret = NULL;
	guint digest_size;

	g_assert(md_size > 0);

	ret = pv_buffer_alloc((guint)md_size);
	if (EVP_DigestFinal_ex(ctx, ret->data, &digest_size) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_DigestFinal_ex failed"));
		return NULL;
	}

	g_assert(digest_size == (guint)md_size);
	g_assert(digest_size == ret->size);
	return g_steal_pointer(&ret);
}

/* Returns the digest of @buf using the hash algorithm @md */
static PvBuffer *digest_buffer(const EVP_MD *md, const PvBuffer *buf, GError **err)
{
	g_autoptr(EVP_MD_CTX) md_ctx = NULL;
	g_autoptr(PvBuffer) ret = NULL;
	g_assert(buf);

	md_ctx = digest_ctx_new(md, err);
	if (!md_ctx)
		return NULL;

	if (EVP_DigestUpdate(md_ctx, buf->data, buf->size) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_DigestUpdate failed"));
		return NULL;
	}

	ret = digest_ctx_finalize(md_ctx, err);
	if (!ret)
		return NULL;

	return g_steal_pointer(&ret);
}

/* Returns the SHA256 digest of @buf */
PvBuffer *sha256_buffer(const PvBuffer *buf, GError **err)
{
	g_autoptr(PvBuffer) ret = NULL;

	ret = digest_buffer(EVP_sha256(), buf, err);
	if (!ret)
		return NULL;

	g_assert(ret->size == SHA256_DIGEST_LENGTH);
	return g_steal_pointer(&ret);
}

/* Convert a EVP_PKEY to the key format used in the PV header */
union ecdh_pub_key *evp_pkey_to_ecdh_pub_key(EVP_PKEY *key, GError **err)
{
	g_autofree union ecdh_pub_key *ret = g_new0(union ecdh_pub_key, 1);
	g_autoptr(BIGNUM) pub_x_big = NULL;
	g_autoptr(BIGNUM) pub_y_big = NULL;
	g_autoptr(EC_KEY) ec_key = NULL;
	const EC_POINT *pub_key;
	const EC_GROUP *grp;

	ec_key = EVP_PKEY_get1_EC_KEY(key);
	if (!ec_key) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Key has the wrong type"));
		return NULL;
	}

	pub_key = EC_KEY_get0_public_key(ec_key);
	if (!pub_key) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to get public key"));
		return NULL;
	}

	grp = EC_KEY_get0_group(ec_key);
	if (!grp) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to get EC group"));
		return NULL;
	}

	pub_x_big = BN_new();
	if (!pub_x_big)
		g_abort();

	pub_y_big = BN_new();
	if (!pub_y_big)
		g_abort();

	if (EC_POINT_get_affine_coordinates_GFp(grp, pub_key, pub_x_big,
						pub_y_big, NULL) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Cannot convert key to internal format"));
		return NULL;
	}

	if (BN_bn2binpad(pub_x_big, ret->x, sizeof(ret->x)) < 0) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Cannot convert key to internal format"));
		return NULL;
	}

	if (BN_bn2binpad(pub_y_big, ret->y, sizeof(ret->y)) < 0) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Cannot convert key to internal format"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

static PvBuffer *derive_key(EVP_PKEY *cust, EVP_PKEY *host, GError **err)
{
	g_autoptr(EVP_PKEY_CTX) ctx = NULL;
	g_autoptr(PvBuffer) ret = NULL;
	gsize key_size;

	ctx = EVP_PKEY_CTX_new(cust, NULL);
	if (!ctx)
		g_abort();

	if (EVP_PKEY_derive_init(ctx) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Key derivation failed"));
		return NULL;
	}

	if (EVP_PKEY_derive_set_peer(ctx, host) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Key derivation failed"));
		return NULL;
	}

	/* Determine buffer length */
	if (EVP_PKEY_derive(ctx, NULL, &key_size) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_DERIVE,
			    _("Key derivation failed"));
		return NULL;
	}

	ret = pv_buffer_alloc(key_size);
	if (EVP_PKEY_derive(ctx, ret->data, &key_size) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_DERIVE,
			    _("Key derivation failed"));
		return NULL;
	}

	g_assert(ret->size == key_size);
	return g_steal_pointer(&ret);
}

PvBuffer *compute_exchange_key(EVP_PKEY *cust, EVP_PKEY *host, GError **err)
{
	g_autoptr(PvBuffer) raw = pv_buffer_alloc(70);
	g_autoptr(PvBuffer) ret = NULL;
	g_autoptr(PvBuffer) key = NULL;
	guchar *data;

	key = derive_key(cust, host, err);
	if (!key)
		return NULL;

	g_assert(key->size == 66);
	g_assert(key->size < raw->size);

	/* ANSI X.9.63-2011: 66 bytes x with leading 7 bits and
	 * concatenate 32 bit int '1'
	 */
	memcpy(raw->data, key->data, key->size);
	data = raw->data;
	data[66] = 0x00;
	data[67] = 0x00;
	data[68] = 0x00;
	data[69] = 0x01;

	ret = sha256_buffer(raw, err);
	if (!ret)
		return NULL;

	return g_steal_pointer(&ret);
}

gint generate_tweak(union tweak *tweak, uint16_t i, GError **err)
{
	tweak->cmp_idx.idx = GUINT16_TO_BE(i);
	if (RAND_bytes(tweak->cmp_idx.rand, sizeof(tweak->cmp_idx.rand)) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_RANDOMIZATION,
			    _("Generating a tweak failed because the required amount of random data is not available"));
		return -1;
	}

	return 0;
}

static PvBuffer *generate_rand_data(guint size, const gchar *err_msg,
				    GError **err)
{
	g_autoptr(PvBuffer) buf = pv_buffer_alloc(size);

	g_assert(size <= INT_MAX);

	if (RAND_bytes(buf->data, (int)size) != 1) {
		g_set_error_literal(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_RANDOMIZATION,
				    err_msg);
		return NULL;
	}

	return g_steal_pointer(&buf);
}

PvBuffer *generate_aes_iv(guint size, GError **err)
{
	return generate_rand_data(size,
				  _("Generating a IV failed because the required amount of random data is not available"),
				  err);
}

PvBuffer *generate_aes_key(guint size, GError **err)
{
	return generate_rand_data(size,
				  _("Generating a key failed because the required amount of random data is not available"),
				  err);
}

EVP_PKEY *generate_ec_key(gint nid, GError **err)
{
	g_autoptr(EVP_PKEY_CTX) ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	g_autoptr(EVP_PKEY) ret = NULL;

	if (!ctx)
		g_abort();

	if (EVP_PKEY_keygen_init(ctx) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_KEYGENERATION,
			    _("EC key could not be auto-generated"));
		return NULL;
	}

	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_KEYGENERATION,
			    _("EC key could not be auto-generated"));
		return NULL;
	}

	if (EVP_PKEY_keygen(ctx, &ret) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_KEYGENERATION,
			    _("EC key could not be auto-generated"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

static gboolean certificate_uses_correct_curve(EVP_PKEY *key, gint nid,
					       GError **err)
{
	g_autoptr(EC_KEY) ec = NULL;
	gint rc;

	g_assert(key);

	if (EVP_PKEY_id(key) != EVP_PKEY_EC) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INVALID_PARM,
			    _("No EC key found"));
		return FALSE;
	}

	ec = EVP_PKEY_get1_EC_KEY(key);
	if (!ec) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INVALID_PARM,
			    _("No EC key found"));
		return FALSE;
	}

	if (EC_KEY_check_key(ec) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INVALID_PARM,
			    _("Invalid EC key"));
		return FALSE;
	}

	rc = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
	if (rc != nid) {
		/* maybe the NID is unset */
		if (rc == 0) {
			g_autoptr(EC_GROUP) grp = EC_GROUP_new_by_curve_name(nid);
			const EC_POINT *pub = EC_KEY_get0_public_key(ec);
			g_autoptr(BN_CTX) ctx = BN_CTX_new();

			if (EC_POINT_is_on_curve(grp, pub, ctx) != 1) {
				g_set_error_literal(err, PV_CRYPTO_ERROR,
						    PV_CRYPTO_ERROR_INVALID_PARM,
						    _("Invalid EC curve"));
				return FALSE;
			}
		} else {
			/* NID was set but doesn't match with the expected NID
			 */
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INVALID_PARM,
				    _("Wrong NID used: '%d'"),
				    EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)));
			return FALSE;
		}
	}

	return TRUE;
}

/* Verify that the used public key algorithm matches the subject signature
 * algorithm
 */
static int check_signature_algo_match(const EVP_PKEY *pkey, const X509 *subject,
				      GError **err)
{
	gint pkey_nid;

	if (!pkey) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_NO_PUBLIC_KEY,
			    _("no public key"));
		return -1;
	}

	if (OBJ_find_sigid_algs(X509_get_signature_nid(subject), NULL,
				&pkey_nid) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_INVALID_SIGNATURE_ALGORITHM,
			    _("unsupported signature algorithm"));
		return -1;
	}

	if (EVP_PKEY_type(pkey_nid) != EVP_PKEY_base_id(pkey)) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_SIGNATURE_ALGORITHM_MISMATCH,
			    _("signature algorithm mismatch"));
		return -1;
	}

	return 0;
}

static X509_CRL *load_crl_from_bio(BIO *bio)
{
	g_autoptr(X509_CRL) crl = PEM_read_bio_X509_CRL(bio, NULL, 0, NULL);
	if (crl)
		return g_steal_pointer(&crl);
	ERR_clear_error();
	BIO_reset(bio);

	/* maybe the CRL is stored in DER format */
	crl = d2i_X509_CRL_bio(bio, NULL);
	if (crl)
		return g_steal_pointer(&crl);
	return NULL;
}

static X509_CRL *GByteArray_to_X509_CRL(const GByteArray *data)
{
	g_autoptr(X509_CRL) ret = NULL;
	g_autoptr(BIO) bio = NULL;

	g_assert(data);

	if (data->len > INT_MAX)
		return NULL;

	bio = BIO_new_mem_buf(data->data, (int)data->len);
	if (!bio)
		g_abort();

	ret = load_crl_from_bio(bio);
	if (!ret)
		return NULL;

	return g_steal_pointer(&ret);
}

static gint load_crl_from_web(const gchar *url, X509_CRL **crl, GError **err)
{
	g_autoptr(X509_CRL) tmp_crl = NULL;
	g_autoptr(GByteArray) data = NULL;
	g_assert(crl);

	data = curl_download(url, CRL_DOWNLOAD_TIMEOUT_MS,
			     CRL_DOWNLOAD_MAX_SIZE, err);
	if (!data) {
		g_prefix_error(err, _("unable to download CRL: "));
		return -1;
	}
	tmp_crl = GByteArray_to_X509_CRL(data);
	if (!tmp_crl) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_CRL_DOWNLOAD_FAILED,
			    _("unable to load CRL from '%s'"), url);
		return -1;
	}
	*crl = g_steal_pointer(&tmp_crl);
	return 0;
}

static BIO *bio_read_from_file(const char *path)
{
	g_autoptr(BIO) bio = BIO_new_file(path, "r");

	if (!bio)
		return NULL;

	return g_steal_pointer(&bio);
}

/* This function reads in only the first certificate and ignores all other. This
 * is only relevant for the PEM file format. For the host-key document and the
 * root CA this behavior is expected.
 */
X509 *load_cert_from_file(const char *path, GError **err)
{
	g_autoptr(BIO) bio = bio_read_from_file(path);
	g_autoptr(X509) cert = NULL;

	if (!bio) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_READ_CERTIFICATE,
			    _("unable to read certificate: '%s'"), path);
		return NULL;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert)
		return g_steal_pointer(&cert);
	ERR_clear_error();
	BIO_reset(bio);

	/* maybe the certificate is stored in DER format */
	cert = d2i_X509_bio(bio, NULL);
	if (cert)
		return g_steal_pointer(&cert);

	g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_READ_CERTIFICATE,
		    _("unable to load certificate: '%s'"), path);
	return NULL;
}

/* @crl_paths is allowed to be NULL */
static int load_crls_to_store(X509_STORE *store, const gchar *const *crl_paths,
			      gboolean err_out_empty_crls, GError **err)
{
	for (const gchar *const *iterator = crl_paths;
	     iterator != NULL && *iterator != NULL; iterator++) {
		const gchar *crl_path = *iterator;
		X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
		int count;

		g_assert(crl_path);

		if (!lookup) {
			g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    _("X509 store initialization failed"));
			return -1;
		}

		/* support *.pem files containing multiple CRLs */
		count = X509_load_crl_file(lookup, crl_path, X509_FILETYPE_PEM);
		if (count > 0)
			continue;

		count = X509_load_crl_file(lookup, crl_path, X509_FILETYPE_ASN1);
		if (count == 1)
			continue;

		if (err_out_empty_crls) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_LOAD_CRL,
				    _("unable to load CRL from: '%s'"), crl_path);
			return -1;
		}
	}

	return 0;
}

/* returns
 *   0 when the certificate is valid,
 *  -1 when not yet valid,
 *   1 when expired
 */
static int check_validity_period(const ASN1_TIME *not_before, const ASN1_TIME *not_after)
{
	if (X509_cmp_current_time(not_before) != -1)
		return -1;

	if (X509_cmp_current_time(not_after) != 1)
		return 1;

	return 0;
}

static gint x509_name_entry_get_data0(X509_NAME_ENTRY *entry, const guchar **data,
				      gsize *data_len)
{
	const ASN1_STRING *asn1_str;
	gint tmp_data_len;

	g_assert(data);
	g_assert(data_len);

	asn1_str = X509_NAME_ENTRY_get_data(entry);
	if (!asn1_str)
		return -1;

	tmp_data_len = ASN1_STRING_length(asn1_str);
	if (tmp_data_len < 0)
		return -1;

	*data = ASN1_STRING_get0_data(asn1_str);
	*data_len = (gsize)tmp_data_len;
	return 0;
}

/* The caller must not free *data! */
static gint x509_name_get_data0_by_NID(X509_NAME *name, gint nid,
				       const guchar **data, gsize *data_len)
{

	X509_NAME_ENTRY *entry = NULL;
	gint lastpos = -1;

	lastpos = X509_NAME_get_index_by_NID(name, nid, lastpos);
	if (lastpos == -1)
		return -1;

	entry = X509_NAME_get_entry(name, lastpos);
	if (!entry)
		return -1;

	if (x509_name_entry_get_data0(entry, data, data_len) < 0)
		return -1;

	return 0;
}

/* @y must be a NULL-terminated string */
static gboolean x509_name_data_by_nid_equal(X509_NAME *name, gint nid,
					    const gchar *y)
{
	const guchar *data = NULL;
	gsize y_len = strlen(y);
	gsize data_len;

	if (x509_name_get_data0_by_NID(name, nid, &data, &data_len) < 0)
		return FALSE;

	if (data_len != y_len)
		return FALSE;

	return memcmp(data, y, data_len) == 0;
}

static gboolean own_X509_NAME_ENTRY_equal(const X509_NAME_ENTRY *x,
					  const X509_NAME_ENTRY *y)
{
	const ASN1_OBJECT *x_obj = X509_NAME_ENTRY_get_object(x);
	const ASN1_STRING *x_data = X509_NAME_ENTRY_get_data(x);
	const ASN1_OBJECT *y_obj = X509_NAME_ENTRY_get_object(y);
	const ASN1_STRING *y_data = X509_NAME_ENTRY_get_data(y);
	gint x_len = ASN1_STRING_length(x_data);
	gint y_len = ASN1_STRING_length(y_data);

	if (x_len < 0 || x_len != y_len)
		return FALSE;

	/* ASN1_STRING_cmp(x_data, y_data) == 0 doesn't work because it also
	 * compares the type, which is sometimes different.
	 */
	return OBJ_cmp(x_obj, y_obj) == 0 &&
		memcmp(ASN1_STRING_get0_data(x_data),
		       ASN1_STRING_get0_data(y_data),
		       (unsigned long)x_len) == 0;
}

static gboolean own_X509_NAME_equal(const X509_NAME *x, const X509_NAME *y)
{
	gint x_count = X509_NAME_entry_count(x);
	gint y_count = X509_NAME_entry_count(y);

	if (x != y && (!x || !y))
		return FALSE;

	if (x_count != y_count)
		return FALSE;

	for (gint i = 0; i < x_count; i++) {
		const X509_NAME_ENTRY *entry_i = X509_NAME_get_entry(x, i);
		gboolean entry_found = FALSE;

		for (gint j = 0; j < y_count; j++) {
			const X509_NAME_ENTRY *entry_j =
				X509_NAME_get_entry(y, j);

			if (own_X509_NAME_ENTRY_equal(entry_i, entry_j)) {
				entry_found = TRUE;
				break;
			}
		}

		if (!entry_found)
			return FALSE;
	}
	return TRUE;
}

/* Checks whether the subject of @cert is a IBM signing key subject. For this we
 * must check that the subject is equal to: 'C = US, ST = New York, L =
 * Poughkeepsie, O = International Business Machines Corporation, CN =
 * International Business Machines Corporation' and the organization unit (OUT)
 * must end with the suffix ' Key Signing Service'.
 */
static gboolean has_ibm_signing_subject(X509 *cert)
{
	X509_NAME *subject = X509_get_subject_name(cert);
	/* X509_NAME_entry_count is safe to be used with NULL */
	gint entry_count = X509_NAME_entry_count(subject);
	g_autofree gchar *data_str = NULL;
	const guchar *data;
	gsize data_len;

	if (entry_count != PV_IMB_Z_SUBJECT_ENTRY_COUNT)
		return FALSE;

	if (!x509_name_data_by_nid_equal(subject, NID_countryName,
					 PV_IBM_Z_SUBJECT_COUNTRY_NAME))
		return FALSE;

	if (!x509_name_data_by_nid_equal(subject, NID_stateOrProvinceName,
					 PV_IBM_Z_SUBJECT_STATE))
		return FALSE;

	if (!x509_name_data_by_nid_equal(subject, NID_localityName,
					 PV_IBM_Z_SUBJECT_LOCALITY_NAME))
		return FALSE;

	if (!x509_name_data_by_nid_equal(subject, NID_organizationName,
					 PV_IBM_Z_SUBJECT_ORGANIZATION_NAME))
		return FALSE;

	if (!x509_name_data_by_nid_equal(subject, NID_commonName,
					 PV_IBM_Z_SUBJECT_COMMON_NAME))
		return FALSE;

	if (x509_name_get_data0_by_NID(subject, NID_organizationalUnitName,
				       &data, &data_len) < 0)
		return FALSE;

	/* Make sure that data_str is null-terminated as in general it cannot be
	 * assumed that @data is null-terminated.
	 */
	data_str = g_strndup((const gchar *)data, data_len);
	if (!g_str_has_suffix(data_str,
			      PV_IBM_Z_SUBJECT_ORGANIZATIONONAL_UNIT_NAME_SUFFIX))
		return FALSE;

	return TRUE;
}

static X509_NAME *x509_name_reorder_attributes(const X509_NAME *name, const gint nids[],
					       gsize nids_len)
{
	gint entry_count = X509_NAME_entry_count(name);
	g_autoptr(X509_NAME) ret = NULL;

	if (entry_count < 0)
		return NULL;

	if (nids_len != (gsize) entry_count)
		return NULL;

	ret = X509_NAME_new();
	if (!ret)
		g_abort();

	for (gsize i = 0; i < nids_len; i++) {
		const X509_NAME_ENTRY *entry = NULL;
		gint nid = nids[i];
		gint lastpos = -1;

		lastpos = X509_NAME_get_index_by_NID((X509_NAME *)name, nid, lastpos);
		if (lastpos == -1)
			return NULL;

		entry = X509_NAME_get_entry(name, lastpos);
		if (!entry)
			return NULL;

		if (X509_NAME_add_entry(ret, entry, -1, 0) != 1)
			return NULL;
	}

	return g_steal_pointer(&ret);
}

/* In RFC 5280 the attributes of a (subject/issuer) name is not mandatory
 * ordered. The problem is that our certificates are not consistent in the order
 * (see https://tools.ietf.org/html/rfc5280#section-4.1.2.4 for details).
 *
 * This function converts a correct X509_NAME into the broken one. The caller is
 * responsible to free the returned value.
 */
X509_NAME *c2b_name(const X509_NAME *name)
{
	gint nids[] = { NID_countryName, NID_organizationName, NID_organizationalUnitName,
		NID_localityName, NID_stateOrProvinceName, NID_commonName };
	g_autoptr(X509_NAME) broken_name = NULL;

	g_assert(name);

	/* Try to reorder the attributes */
	broken_name = x509_name_reorder_attributes(name, nids, G_N_ELEMENTS(nids));
	if (broken_name)
		return g_steal_pointer(&broken_name);
	return X509_NAME_dup((X509_NAME *)name);
}

/* Verify that: subject(issuer) == issuer(crl) and SKID(issuer) == AKID(crl) */
static gint check_crl_issuer(X509_CRL *crl, X509 *issuer, GError **err)
{
	const X509_NAME *crl_issuer = X509_CRL_get_issuer(crl);
	const X509_NAME *issuer_subject = X509_get_subject_name(issuer);
	AUTHORITY_KEYID *akid = NULL;

	if (!own_X509_NAME_equal(issuer_subject, crl_issuer)) {
		g_autofree char *issuer_subject_str = X509_NAME_oneline(issuer_subject,
									NULL, 0);
		g_autofree char *crl_issuer_str = X509_NAME_oneline(crl_issuer, NULL, 0);

		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_CRL_SUBJECT_ISSUER_MISMATCH,
			    _("issuer mismatch:\n%s\n%s"),
			    issuer_subject_str, crl_issuer_str);
		return -1;
	}

	/* If AKID(@crl) is specified it must match with SKID(@issuer) */
	akid = X509_CRL_get_ext_d2i(crl, NID_authority_key_identifier, NULL, NULL);
	if (akid && X509_check_akid(issuer, akid) != X509_V_OK) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_SKID_AKID_MISMATCH,
			    _("AKID mismatch"));
		return -1;
	}

	return 0;
}

/* Verify whether a revocation list @crl is valid and is issued by @cert. For
 * this multiple steps must be done:
 *
 * 1. verify issuer of the CRL matches with the suject name of @cert
 * 2. verify the validity period of the CRL
 * 3. verify the signature of the CRL
 *
 * Important: This function doesn't verify whether @cert is allowed to issue a
 * CRL. Returns 0 if @crl is valid and issued by @cert, otherwise -1.
 */
gint check_crl_valid_for_cert(X509_CRL *crl, X509 *cert,
			      gint verify_flags, GError **err)
{
	EVP_PKEY *pkey = X509_get0_pubkey(cert);

	g_assert(crl);

	if (!pkey) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("failed to retrieve public key from the certificate"));
		return -1;
	}

	/* check that the @crl issuer matches with the subject name of @cert*/
	if (check_crl_issuer(crl, cert, err) < 0)
		return -1;

	/* verify the validity period of the CRL */
	if (!(verify_flags & X509_V_FLAG_NO_CHECK_TIME)) {
		const ASN1_TIME *last = X509_CRL_get0_lastUpdate(crl);
		const ASN1_TIME *next = X509_CRL_get0_nextUpdate(crl);

		if (!last || !next || check_validity_period(last, next)) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INVALID_VALIDITY_PERIOD,
				    _("validity period is not valid"));
			return -1;
		}
	} else {
		verify_flags &= ~X509_V_FLAG_NO_CHECK_TIME;
	}

	/* verify the signature */
	if (X509_CRL_verify(crl, pkey) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_CRL_SIGNATURE_INVALID,
			    _("signature is not valid"));
		return -1;
	}
	g_assert(verify_flags == 0);
	return 0;
}

/* Given a certificate @cert try to find valid revocation lists in @ctx. If no
 * valid CRL was found NULL is returned.
 */
STACK_OF_X509_CRL *store_ctx_find_valid_crls(X509_STORE_CTX *ctx, X509 *cert,
					     GError **err)
{
	g_autoptr(STACK_OF_X509_CRL) ret = NULL;
	const gint verify_flags = 0;
	X509_NAME *subject = NULL;

	subject = X509_get_subject_name(cert);
	if (!subject) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_MALFORMED_CERTIFICATE,
			    _("certificate is malformed"));
		return NULL;
	}

	ret = X509_STORE_CTX_get1_crls(ctx, subject);
	if (!ret) {
		/* Workaround to fix the mismatch between issuer name of the
		 * IBM Z signing CRLs and the IBM Z signing key subject name.
		 */
		g_autoptr(X509_NAME) broken_subject = c2b_name(subject);

		ret = X509_STORE_CTX_get1_crls(ctx, broken_subject);
		if (!ret) {
			g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_NO_CRL,
				    _("no CRL found"));
			return NULL;
		}
	}

	/* Filter out non-valid CRLs for @cert */
	for (gint i = 0; i < sk_X509_CRL_num(ret); i++) {
		X509_CRL *crl = sk_X509_CRL_value(ret, i);

		g_assert(crl);

		/* If @crl is not valid remove it from the array and log a
		 * warning.
		 */
		if (check_crl_valid_for_cert(crl, cert, verify_flags, err) < 0) {
			g_assert(err);
			g_warning(_("CRL is not valid: %s"), (*err)->message);
			g_clear_error(err);

			/* Remove this certificate from the list and change i-- as the
			 * array has changed - this is not beautfiul, but right now the
			 * easiest solution I came up with
			 */
			if (sk_X509_CRL_delete(ret, i--) != crl)
				g_abort();

			g_clear_pointer(&crl, X509_CRL_free);
		}
	}

	if (sk_X509_CRL_num(ret) < 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_NO_CRL,
			    _("no valid CRL found"));
		return NULL;
	}
	return g_steal_pointer(&ret);
}

/* Return a list of all IBM Z signing key certificates in @certs and remove them
 * from the chain. Return empty stack if no IBM Z signing key is found.
 */
STACK_OF_X509 *delete_ibm_signing_certs(STACK_OF_X509 *certs)
{
	g_autoptr(STACK_OF_X509) ret = sk_X509_new_null();

	for (gint i = 0; i < sk_X509_num(certs); i++) {
		X509 *cert = sk_X509_value(certs, i);

		g_assert(cert);

		if (!has_ibm_signing_subject(cert))
			continue;

		/* Remove this certificate from the list and change i-- as the
		 * array has changed - this is not beautfiul, but right now the
		 * easiest solution I came up with.
		 */
		if (sk_X509_delete(certs, i--) != cert)
			g_abort();

		if (sk_X509_push(ret, g_steal_pointer(&cert)) == 0)
			g_abort();
	}

	return g_steal_pointer(&ret);
}

X509_STORE *store_setup(const gchar *root_ca_path, const gchar * const *crl_paths,
			GError **err)
{
	g_autoptr(X509_STORE) store = X509_STORE_new();

	g_assert(store);

	/* if @root_ca_path != NULL use the specified root CA only, otherwise use the
	 * default root CAs found on the system
	 */
	if (root_ca_path) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
		int count;

		if (!lookup) {
			g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    _("X509 store initialization failed"));
			return NULL;
		}

		count = X509_load_cert_file(lookup, root_ca_path, X509_FILETYPE_PEM);
		if (count > 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_LOAD_ROOT_CA,
				    _("multiple certificates in one PEM file is not supported: '%s'"),
				    root_ca_path);
			return NULL;
		} else if (count < 1) {
			count = X509_load_cert_file(lookup, root_ca_path,
						    X509_FILETYPE_ASN1);
			if (count != 1) {
				g_set_error(err, PV_CRYPTO_ERROR,
					    PV_CRYPTO_ERROR_LOAD_ROOT_CA,
					    _("failed to load root certificate from '%s'"),
					    root_ca_path);
				return NULL;
			}
		}
	} else {
		/* Load certificates into @store from the hardcoded OpenSSL
		 * default paths
		 */
		if (X509_STORE_set_default_paths(store) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_LOAD_DEFAULT_CA,
				    _("failed to load system root certificates"));
			return NULL;
		}
	}

	/* Error out if a CRL file was provided that has not at least one CRL*/
	if (load_crls_to_store(store, crl_paths, TRUE, err) < 0)
		return NULL;

	return g_steal_pointer(&store);
}

int store_set_verify_param(X509_STORE *store, GError **err)
{
	g_autoptr(X509_VERIFY_PARAM) param = NULL;
	unsigned long flags = X509_V_FLAG_CRL_CHECK |
			      X509_V_FLAG_CRL_CHECK_ALL |
			      X509_V_FLAG_TRUSTED_FIRST |
			      X509_V_FLAG_CHECK_SS_SIGNATURE |
			      X509_V_FLAG_X509_STRICT |
			      X509_V_FLAG_POLICY_CHECK;

	/* Create a X509_VERIFY_PARAM structure, which specifies which checks
	 * should be done by the certificate verification operation
	 */
	param = X509_VERIFY_PARAM_new();
	if (!param)
		g_abort();

	/* The maximum depth level of the chain of trust for the verification of
	 * the IBM Z signing key is 2, i.e. IBM Z signing key -> (DigiCert)
	 * intermediate CA -> (DigiCert) root CA
	 */
	X509_VERIFY_PARAM_set_depth(param, 2);

	/* Set minimum allowed security level to at least 112 bits. */
	X509_VERIFY_PARAM_set_auth_level(param, PV_CERTS_SECURITY_LEVEL);

	/* Set verification purpose to 'Any Purpose' and specify that the
	 * associated trust setting of the default purpose should be used.
	 */
	if (X509_VERIFY_PARAM_set_purpose(param,
					  X509_PURPOSE_ANY | X509_TRUST_DEFAULT) != 1)
		goto error;

	/* Each certificate from the chain of trust must be checked against a
	 * CRL to see if it has been revoked. In addition, use trusted
	 * certificates first mode, check signature of the last certificate,
	 * strict mode, and verify the policies.
	 */
	if (X509_VERIFY_PARAM_set_flags(param, flags) != 1)
		goto error;

	if (X509_STORE_set1_param(store, param) != 1)
		goto error;

	return 0;

error:
	g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
		    _("X509 store initialization failed"));
	return -1;
}

/* @cert_paths must contain at least one element, otherwise an error is
 * reported.
 */
GSList *load_certificates(const gchar *const *cert_paths, GError **err)
{
	g_autoslist(x509_with_path) ret = NULL;

	for (const gchar *const *iterator = cert_paths;
	     iterator != NULL && *iterator != NULL; iterator++) {
		const gchar *cert_path = *iterator;
		g_autoptr(X509) cert = NULL;

		g_assert(cert_path);

		cert = load_cert_from_file(cert_path, err);
		if (!cert)
			return NULL;

		ret = g_slist_append(ret, x509_with_path_new(cert, cert_path));
	}
	if (!ret) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_READ_CERTIFICATE,
			    _("no certificates specified"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

static X509 *get_cert(const x509_with_path *cert_with_path, G_GNUC_UNUSED GError **err)
{
	g_autoptr(X509) cert = NULL;

	g_assert(cert_with_path && cert_with_path->cert);

	cert = cert_with_path->cert;
	if (X509_up_ref(cert) != 1)
		g_abort();
	return g_steal_pointer(&cert);
}

STACK_OF_X509 *get_x509_stack(const GSList *x509_with_path_list)
{
	g_autoslist(X509) certs = NULL;
	g_autoptr(GError) err = NULL;

	certs = g_slist_map_x509_with_path_X509(x509_with_path_list,
						get_cert, &err);
	g_assert_null(err);
	return g_slist_to_stack_of_X509(&certs);
}

x509_with_path *x509_with_path_new(X509 *cert, const gchar *path)
{
	g_autoptr(x509_with_path) ret = g_new(x509_with_path, 1);

	g_assert(cert && path);

	if (X509_up_ref(cert) != 1)
		g_abort();
	ret->cert = cert;
	ret->path = g_strdup(path);
	return g_steal_pointer(&ret);
}

void x509_with_path_free(x509_with_path *cert)
{
	if (!cert)
		return;

	X509_free(cert->cert);
	g_free((gchar *)cert->path);
	g_free(cert);
}

x509_pair *x509_pair_new(X509 **cert, STACK_OF_X509_CRL **crls)
{
	g_autoptr(x509_pair) ret = g_new0(x509_pair, 1);

	g_assert(cert);
	g_assert(crls);

	ret->cert = g_steal_pointer(cert);
	ret->crls = g_steal_pointer(crls);
	return g_steal_pointer(&ret);
}

void x509_pair_free(x509_pair *pair)
{
	if (!pair)
		return;

	sk_X509_CRL_pop_free(pair->crls, X509_CRL_free);
	X509_free(pair->cert);
	g_free(pair);
}

X509_STORE_CTX *create_store_ctx(X509_STORE *trusted, STACK_OF_X509 *chain,
				 GError **err)
{
	g_autoptr(X509_STORE_CTX) ctx = X509_STORE_CTX_new();

	if (!ctx || !X509_STORE_CTX_init(ctx, trusted, NULL, chain)) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("X509 store initialization failed: %s"),
			    X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
		return NULL;
	}

	return g_steal_pointer(&ctx);
}

gint verify_cert(X509 *cert, X509_STORE_CTX *ctx, GError **err)
{
	gint rc;

	X509_STORE_CTX_set_cert(ctx, cert);
	rc = X509_verify_cert(ctx);
	if (rc != 1) {
		X509 *tmp_cert = NULL;

		tmp_cert = X509_STORE_CTX_get_current_cert(ctx);
		if (tmp_cert) {
			g_autofree char *subj_name = X509_NAME_oneline(
				X509_get_subject_name(tmp_cert), NULL, 0);
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("failed to verify certificate '%s': %s"),
				    subj_name,
				    X509_verify_cert_error_string(
					    X509_STORE_CTX_get_error(ctx)));
		} else {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("failed to verify certificate: %s"),
				    X509_verify_cert_error_string(
					    X509_STORE_CTX_get_error(ctx)));
		}

		return -1;
	}

	return 0;
}

static int security_level_to_bits(int level)
{
	static int security_bits[] = { 0, 80, 112, 128, 192, 256 };

	g_assert(level > 0 && level < (int)G_N_ELEMENTS(security_bits));

	return security_bits[level];
}

static ASN1_OCTET_STRING *digicert_assured_id_root_ca;

const ASN1_OCTET_STRING *get_digicert_assured_id_root_ca_skid(void)
{
	pv_crypto_init();
	return digicert_assured_id_root_ca;
}

/* Used for the caching of the downloaded CRLs */
static GHashTable *cached_crls;

void pv_crypto_init(void)
{
	if (digicert_assured_id_root_ca)
		return;

	cached_crls = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
					    (GDestroyNotify)X509_CRL_free);
	digicert_assured_id_root_ca = s2i_ASN1_OCTET_STRING(
		NULL, NULL, DIGICERT_ASSURED_ID_ROOT_CA_SKID);
}

void pv_crypto_cleanup(void)
{
	if (!digicert_assured_id_root_ca)
		return;
	g_clear_pointer(&cached_crls, g_hash_table_destroy);
	g_clear_pointer(&digicert_assured_id_root_ca, ASN1_OCTET_STRING_free);
}

gint check_chain_parameters(const STACK_OF_X509 *chain,
			    const ASN1_OCTET_STRING *skid, GError **err)
{
	const ASN1_OCTET_STRING *ca_skid = NULL;
	gint len = sk_X509_num(chain);
	X509 *ca = NULL;

	g_assert(skid);
	/* at least one root and one leaf certificate must be defined */
	g_assert(len >= 2);

	/* get the root certificate of the chain of trust */
	ca = sk_X509_value(chain, len - 1);
	if (!ca) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("no root certificate found"));
		return -1;
	}

	ca_skid = X509_get0_subject_key_id(ca);
	if (!ca_skid) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_MALFORMED_ROOT_CA,
			    _("malformed root certificate"));
		return -1;
	}

	if (ASN1_STRING_cmp(ca_skid, skid) != 0) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_WRONG_CA_USED,
			    _("expecting DigiCert root CA to be used"));
		return -1;
	}

	return 0;
}

/* It's almost the same as X509_check_issed from OpenSSL does except that we
 * don't check the key usage of the potential issuer. This means we check:
 * 1. issuer_name(cert) == subject_name(issuer)
 * 2. Check whether the akid(cert) (if available) matches the issuer skid
 * 3. Check that the cert algrithm matches the subject algorithm
 * 4. Verify the signature of certificate @cert is using the public key of
 *    @issuer.
 */
static gint check_host_key_issued(X509 *cert, X509 *issuer, GError **err)
{
	const X509_NAME *issuer_subject = X509_get_subject_name(issuer);
	const X509_NAME *cert_issuer = X509_get_issuer_name(cert);
	AUTHORITY_KEYID *akid = NULL;

	/* We cannot use X509_NAME_cmp() because it considers the order of the
	 * X509_NAME_Entries.
	 */
	if (!own_X509_NAME_equal(issuer_subject, cert_issuer)) {
		g_autofree char *issuer_subject_str =
			X509_NAME_oneline(issuer_subject, NULL, 0);
		g_autofree char *cert_issuer_str =
			X509_NAME_oneline(cert_issuer, NULL, 0);
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_CERT_SUBJECT_ISSUER_MISMATCH,
			    _("Subject issuer mismatch:\n'%s'\n'%s'"),
			    issuer_subject_str, cert_issuer_str);
		return -1;
	}

	akid = X509_get_ext_d2i(cert, NID_authority_key_identifier, NULL, NULL);
	if (akid && X509_check_akid(issuer, akid) != X509_V_OK) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_SKID_AKID_MISMATCH,
			    _("AKID mismatch"));
		return -1;
	}

	if (check_signature_algo_match(X509_get0_pubkey(issuer), cert, err) < 0)
		return -1;

	if (X509_verify(cert, X509_get0_pubkey(issuer)) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_CERT_SIGNATURE_INVALID,
			    _("Signature verification failed"));
		return -1;
	}

	return 0;
}

static gboolean is_cert_revoked(X509 *cert, X509_CRL *crl)
{
	X509_REVOKED *revoked = NULL;
	gint rc;

	if (!cert || !crl)
		g_abort();

	rc = X509_CRL_get0_by_serial(crl, &revoked,
				     (ASN1_INTEGER *)X509_get0_serialNumber(cert));
	if (rc == 0)
		return FALSE;

	if (revoked)
		return TRUE;

	return FALSE;
}

/* Get the first http[s] URL from a DIST_POINT */
static const char *get_first_dp_url(DIST_POINT *dp)
{
	GENERAL_NAMES *general_names;

	g_assert(dp);

	if (!dp->distpoint || dp->distpoint->type != 0)
		return NULL;

	general_names = dp->distpoint->name.fullname;
	for (gint i = 0; i < sk_GENERAL_NAME_num(general_names); i++) {
		GENERAL_NAME *name = sk_GENERAL_NAME_value(general_names, i);
		g_autofree const gchar *uri_str = NULL;
		ASN1_STRING *uri_asn1;
		const gchar *uri_data;
		gint uri_data_len;
		gint type;

		uri_asn1 = GENERAL_NAME_get0_value(name, &type);
		if (type != GEN_URI)
			continue;
		uri_data_len = ASN1_STRING_length(uri_asn1);
		if (uri_data_len < 0)
			continue;
		uri_data = (const gchar *)ASN1_STRING_get0_data(uri_asn1);
		/* Make sure that uri_str is null-terminated as in general it
		 * cannot be assumed that @uri_data is null-terminated.
		 */
		uri_str = g_strndup(uri_data,
				    (gsize)uri_data_len);
		if (g_str_has_prefix(uri_str, "http://"))
			return uri_data;
		if (g_str_has_prefix(uri_str, "https://"))
			return uri_data;
	}
	return NULL;
}

static gboolean insert_crl(X509_NAME *name, X509_CRL *crl)
{
	g_autofree gchar *key = NULL;

	g_assert(name);

	key = X509_NAME_oneline(name, NULL, 0);
	if (!key)
		g_abort();
	if (X509_CRL_up_ref(crl) != 1)
		g_abort();
	return g_hash_table_insert(cached_crls, g_steal_pointer(&key), crl);
}

/* Caller is responsible for free'ing */
static X509_CRL *lookup_crl(X509_NAME *name)
{
	g_autoptr(X509_CRL) crl = NULL;
	g_autofree gchar *key = NULL;

	g_assert(name);

	key = X509_NAME_oneline(name, NULL, 0);
	if (!key)
		g_abort();
	crl = g_hash_table_lookup(cached_crls, key);
	if (crl) {
		if (X509_CRL_up_ref(crl) != 1)
			g_abort();
		return g_steal_pointer(&crl);
	}
	return NULL;
}

/* Returns empty stack if no CRL downloaded. */
static STACK_OF_X509_CRL *crls_download_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
	g_autoptr(STACK_OF_X509_CRL) crls = NULL;
	g_autoptr(X509_CRL) crl = NULL;
	/* must not be free'd */
	X509 *cert = NULL;

	crls = sk_X509_CRL_new_null();
	if (!crls)
		g_abort();
	cert = X509_STORE_CTX_get_current_cert(ctx);
	if (!cert)
		return g_steal_pointer(&crls);
	g_assert(X509_NAME_cmp(X509_get_issuer_name(cert), nm) == 0);
	crl = lookup_crl(nm);
	if (!crl) {
		/* ignore error */
		crl = load_crl_by_cert(cert, NULL);
		if (!crl)
			return g_steal_pointer(&crls);
		g_assert_true(insert_crl(nm, crl));
	}
	if (sk_X509_CRL_push(crls, g_steal_pointer(&crl)) == 0)
		g_abort();
	return g_steal_pointer(&crls);
}

void STACK_OF_DIST_POINT_free(STACK_OF_DIST_POINT *stack)
{
	if (!stack)
		return;

	sk_DIST_POINT_pop_free(stack, DIST_POINT_free);
}

void STACK_OF_X509_free(STACK_OF_X509 *stack)
{
	if (!stack)
		return;

	sk_X509_pop_free(stack, X509_free);
}

void STACK_OF_X509_CRL_free(STACK_OF_X509_CRL *stack)
{
	if (!stack)
		return;

	sk_X509_CRL_pop_free(stack, X509_CRL_free);
}

/* Downloaded CRLs have a higher precedence than the CRLs specified on the
 * command line.
 */
static STACK_OF_X509_CRL *crls_cb(X509_STORE_CTX *ctx, X509_NAME *nm)
{
	g_autoptr(STACK_OF_X509_CRL) crls = crls_download_cb(ctx, nm);

	if (sk_X509_CRL_num(crls) > 0)
		return g_steal_pointer(&crls);
	return X509_STORE_CTX_get1_crls(ctx, nm);
}

/* Set up CRL lookup with download support */
void store_setup_crl_download(X509_STORE *st)
{
	X509_STORE_set_lookup_crls(st, crls_cb);
}

/* Download a CRL using the URI specified in the distribution @crldp */
static X509_CRL *load_crl_by_dist_point(DIST_POINT *crldp, GError **err)
{
	const gchar *uri = get_first_dp_url(crldp);
	g_autoptr(X509_CRL) crl = NULL;

	if (!uri) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("no valid URL specified in distribution point"));
		return NULL;
	}

	if (load_crl_from_web(uri, &crl, err) < 0)
		return NULL;

	return g_steal_pointer(&crl);
}

/* This function returns the first X509_CRL found from the CRL distribution
 * points specified in @cert. This function could be optimized by filtering
 * duplicate certificates and/or filtering duplicated URIs.
 */
X509_CRL *load_crl_by_cert(X509 *cert, GError **err)
{
	g_autoptr(STACK_OF_DIST_POINT) crldps = NULL;
	g_autoptr(X509_CRL) ret = NULL;

	g_assert(cert);

	crldps = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
	if (!crldps || sk_DIST_POINT_num(crldps) == 0) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_NO_CRLDP,
			    _("no distribution point found"));
		return NULL;
	}

	for (int i = 0; i < sk_DIST_POINT_num(crldps); i++) {
		DIST_POINT *crldp = sk_DIST_POINT_value(crldps, i);

		g_assert(crldp);

		/* ignore error */
		ret = load_crl_by_dist_point(crldp, NULL);
		if (ret)
			return g_steal_pointer(&ret);
	}

	g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_FAILED_DOWNLOAD_CRL,
		    _("failed to download CRL"));
	return NULL;
}

STACK_OF_X509_CRL *try_load_crls_by_certs(GSList *certs_with_path)
{
	g_autoptr(STACK_OF_X509_CRL) ret = sk_X509_CRL_new_null();
	if (!ret)
		g_abort();

	for (GSList *iterator = certs_with_path; iterator;
	     iterator = iterator->next) {
		x509_with_path *cert_with_path = iterator->data;
		X509 *cert = cert_with_path->cert;
		g_autoptr(X509_CRL) crl = NULL;

		g_assert(cert);

		/* ignore error */
		crl = load_crl_by_cert(cert, NULL);
		if (!crl)
			continue;

		if (sk_X509_CRL_push(ret, g_steal_pointer(&crl)) == 0)
			g_abort();
	}

	return g_steal_pointer(&ret);
}

/* Assumptions are that the issuer_crt and issuer_crl is a trusted IBM Z
 * signing certificate/revocation list. This function verifies a host-key
 * document. To do so multiple steps are required:
 *
 * 1. issuer(host_key) == subject(issuer_crt)
 * 2. Signature verification
 * 3. @host_key must not be expired
 * 4. @host_key must not be revoked
 */
gint verify_host_key(X509 *host_key, GSList *issuer_pairs,
		     gint verify_flags, int level, GError **err)
{
	g_assert(host_key);

	const gint exp_security_bits = security_level_to_bits(level);
	EVP_PKEY *pkey = X509_get0_pubkey(host_key);
	gboolean successfully_checked = FALSE;
	gint pkey_security_bits;

	if (!pkey) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("failed to retrieve public key"));
		return -1;
	}

	/* check key level, if necessary */
	pkey_security_bits = EVP_PKEY_security_bits(pkey);
	if (exp_security_bits > 0 && pkey_security_bits < exp_security_bits) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_VERIFICATION,
			    _("not enough bits of security (%d, %d expected)"),
			    pkey_security_bits, exp_security_bits);
		return -1;
	}

	if (!(verify_flags & X509_V_FLAG_NO_CHECK_TIME)) {
		const ASN1_TIME *last = X509_get_notBefore(host_key);
		const ASN1_TIME *next = X509_get_notAfter(host_key);

		if (!last || !next || check_validity_period(last, next)) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INVALID_VALIDITY_PERIOD,
				    _("validity period is not valid"));
			return -1;
		}
	} else {
		verify_flags &= ~X509_V_FLAG_NO_CHECK_TIME;
	}

	/* Verify that the host_key was issued by a certificate and that it
	 * wasn't revoked.
	 */
	for (GSList *iterator = issuer_pairs; iterator;
	     iterator = iterator->next) {
		const x509_pair *pair = iterator->data;
		STACK_OF_X509_CRL *issuer_crls = NULL;
		X509 *issuer_cert = NULL;

		g_assert(pair);

		issuer_cert = pair->cert;
		issuer_crls = pair->crls;

		g_assert(issuer_cert);

		/* Verify that the issuer(host_key) == subject(issuer_cert) and
		 * that the signature is valid
		 */
		if (check_host_key_issued(host_key, issuer_cert, NULL) < 0)
			continue;

		/* Check against CRL */
		if (verify_flags & X509_V_FLAG_CRL_CHECK) {
			gboolean crl_checked = FALSE;

			verify_flags &= ~X509_V_FLAG_CRL_CHECK;
			for (gint i = 0; i < sk_X509_CRL_num(issuer_crls); i++) {
				X509_CRL *issuer_crl =
					sk_X509_CRL_value(issuer_crls, i);

				g_assert(issuer_crl);

				if (is_cert_revoked(host_key, issuer_crl)) {
					g_set_error(err, PV_CRYPTO_ERROR,
						    PV_CRYPTO_ERROR_CERT_REVOKED,
						    _("certificate revoked"));
					return -1;
				}

				crl_checked = TRUE;
			}

			if (!crl_checked) {
				g_set_error(err, PV_CRYPTO_ERROR,
					    PV_CRYPTO_ERROR_INTERNAL,
					    _("no valid CRL found"));
				return -1;
			}
			successfully_checked = TRUE;
			break;
		}
	}

	if (!successfully_checked) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_NO_ISSUER_IBM_Z_FOUND,
			    _("no IBM Z signing key that issued this host-key document found"));
		return -1;
	}

	/* were some unsupported flags specified? */
	g_assert(verify_flags == 0);
	return 0;
}

EVP_PKEY *read_ec_pubkey_cert(X509 *cert, gint nid,
			      GError **err)
{
	g_autoptr(EVP_PKEY) ret = NULL;

	ret = X509_get_pubkey(cert);
	if (!ret) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INVALID_PARM,
			    _("Failed to get public key from host-key document"));
		return NULL;
	}

	if (!certificate_uses_correct_curve(ret, nid, err)) {
		g_prefix_error(err,
			       _("Host-key document doesn\'t use correct EC curve"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

static gint __encrypt_decrypt_bio(const struct cipher_parms *parms, BIO *b_in,
				  BIO *b_out, gsize *size_in, gsize *size_out,
				  gboolean encrypt, GError **err)
{
	gint num_bytes_read, num_bytes_written;
	g_autoptr(EVP_CIPHER_CTX) ctx = NULL;
	g_autoptr(BIGNUM) tweak_num = NULL;
	const EVP_CIPHER *cipher = parms->cipher;
	gint cipher_block_size = EVP_CIPHER_block_size(cipher);
	guchar in_buf[PAGE_SIZE],
		out_buf[PAGE_SIZE + (guint)cipher_block_size];
	const PvBuffer *key = parms->key;
	const PvBuffer *tweak = parms->iv_or_tweak;
	g_autofree guchar *tmp_tweak = NULL;
	gint out_len, tweak_size;
	gsize tmp_size_in = 0, tmp_size_out = 0;

	g_assert(cipher_block_size > 0);
	g_assert(key);
	g_assert(tweak);
	g_assert(tweak->size <= INT_MAX);

	/* copy the value for leaving the original value untouched */
	tmp_tweak = g_malloc0(tweak->size);
	memcpy(tmp_tweak, tweak->data, tweak->size);
	tweak_size = (int)tweak->size;
	tweak_num = BN_bin2bn(tmp_tweak, tweak_size, NULL);
	if (!tweak_num) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("BN_bin2bn failed"));
		return -1;
	}

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		g_abort();

	/* don't set the key or tweak right away as we want to check
	 * lengths before
	 */
	if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encrypt) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CipherInit_ex failed"));
		return -1;
	}

	/* Now we can set the key and tweak */
	if (EVP_CipherInit_ex(ctx, NULL, NULL, key->data, tmp_tweak, encrypt) !=
	    1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CipherInit_ex failed"));
		return -1;
	}

	do {
		memset(in_buf, 0, sizeof(in_buf));
		/* Read in data in 4096 bytes blocks. Update the ciphering
		 * with each read.
		 */
		num_bytes_read = BIO_read(b_in, in_buf, (int)PAGE_SIZE);
		if (num_bytes_read < 0) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("Failed to read"));
			return -1;
		}
		tmp_size_in += (guint)num_bytes_read;

		/* in case we reached the end and it's not the special
		 * case of an empty component we can break here
		 */
		if (num_bytes_read == 0 && tmp_size_in != 0)
			break;

		if (EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf,
				     sizeof(in_buf)) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_CipherUpdate failed"));
			return -1;
		}
		g_assert(out_len >= 0);

		num_bytes_written = BIO_write(b_out, out_buf, out_len);
		if (num_bytes_written < 0) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("Failed to write"));
			return -1;
		}
		g_assert(num_bytes_written == out_len);

		tmp_size_out += (guint)num_bytes_written;

		/* Set new tweak value. Please keep in mind that the
		 * tweaks are stored in big-endian form. Therefore we
		 * must use the correct OpenSSL functions
		 */
		if (BN_add_word(tweak_num, PAGE_SIZE) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("BN_add_word failed"));
		}
		g_assert(BN_num_bytes(tweak_num) > 0);
		g_assert(BN_num_bytes(tweak_num) <= tweak_size);

		if (BN_bn2binpad(tweak_num, tmp_tweak, tweak_size) < 0) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("BN_bn2binpad failed"));
		};

		/* set new tweak */
		if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, tmp_tweak,
				      encrypt) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_CipherInit_ex failed"));
			return -1;
		}
	} while (num_bytes_read == PAGE_SIZE);

	/* Now cipher the final block and write it out to file */
	if (EVP_CipherFinal_ex(ctx, out_buf, &out_len) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CipherFinal_ex failed"));
		return -1;
	}
	g_assert(out_len >= 0);

	num_bytes_written = BIO_write(b_out, out_buf, out_len);
	if (num_bytes_written < 0) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to write"));
		return -1;
	}
	g_assert(out_len == num_bytes_written);
	tmp_size_out += (guint)out_len;

	if (BIO_flush(b_out) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to flush"));
		return -1;
	}

	*size_in = tmp_size_in;
	*size_out = tmp_size_out;
	return 0;
}

static PvBuffer *__encrypt_decrypt_buffer(const struct cipher_parms *parms,
					  const PvBuffer *in, gboolean encrypt,
					  GError **err)
{
	g_autoptr(PvBuffer) ret = NULL;
	g_autoptr(BIO) b_out = NULL;
	g_autoptr(BIO) b_in = NULL;
	gsize in_size, out_size;
	gchar *data = NULL;
	long data_size;

	g_assert(in->size <= INT_MAX);

	b_in = BIO_new_mem_buf(in->data, (int)in->size);
	if (!b_in)
		g_abort();

	b_out = BIO_new(BIO_s_mem());
	if (!b_out)
		g_abort();

	if (__encrypt_decrypt_bio(parms, b_in, b_out, &in_size, &out_size,
				  encrypt, err) < 0)
		return NULL;

	data_size = BIO_get_mem_data(b_out, &data);
	if (data_size < 0) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Could not read buffer"));
		return NULL;
	}

	ret = pv_buffer_alloc((unsigned long)data_size);
	memcpy(ret->data, data, ret->size);
	return g_steal_pointer(&ret);
}

PvBuffer *encrypt_buf(const struct cipher_parms *parms, const PvBuffer *in,
		      GError **err)
{
	return __encrypt_decrypt_buffer(parms, in, TRUE, err);
}

PvBuffer *decrypt_buf(const struct cipher_parms *parms, const PvBuffer *in,
		      GError **err)
{
	return __encrypt_decrypt_buffer(parms, in, FALSE, err);
}

static gint __encrypt_decrypt_file(const struct cipher_parms *parms,
				   const gchar *path_in, const gchar *path_out,
				   gsize *size_in, gsize *size_out, gboolean encrypt,
				   GError **err)
{
	g_autoptr(BIO) b_out = NULL;
	g_autoptr(BIO) b_in = NULL;

	b_in = BIO_new_file(path_in, "rb");
	if (!b_in) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_READ_CERTIFICATE,
			    _("Failed to read file '%s'"), path_in);
		return -1;
	}

	b_out = BIO_new_file(path_out, "wb");
	if (!b_out) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_READ_CERTIFICATE,
			    _("Failed to write file '%s'"), path_out);
		return -1;
	}

	if (__encrypt_decrypt_bio(parms, b_in, b_out, size_in, size_out,
				  encrypt, err) < 0)
		return -1;

	return 0;
}

gint encrypt_file(const struct cipher_parms *parms, const gchar *path_in,
		  const gchar *path_out, gsize *in_size, gsize *out_size,
		  GError **err)
{
	return __encrypt_decrypt_file(parms, path_in, path_out, in_size,
				      out_size, TRUE, err);
}

G_GNUC_UNUSED static gint decrypt_file(const struct cipher_parms *parms,
				       const gchar *path_in, const gchar *path_out,
				       gsize *in_size, gsize *out_size,
				       GError **err)
{
	return __encrypt_decrypt_file(parms, path_in, path_out, in_size,
				      out_size, FALSE, err);
}

/* GCM mode uses (zero-)padding */
static int64_t gcm_encrypt_decrypt(const PvBuffer *in, const PvBuffer *aad,
				   const struct cipher_parms *parms,
				   PvBuffer *out, PvBuffer *tag,
				   enum PvCryptoMode mode, GError **err)
{
	g_autoptr(EVP_CIPHER_CTX) ctx = NULL;
	const EVP_CIPHER *cipher = parms->cipher;
	const PvBuffer *iv = parms->iv_or_tweak;
	gboolean encrypt = mode == PV_ENCRYPT;
	const PvBuffer *key = parms->key;
	int64_t ret = -1;
	gint len = -1;

	g_assert(cipher);
	g_assert(key);
	g_assert(iv);
	/* Checks for later casts */
	g_assert(aad->size <= INT_MAX);
	g_assert(in->size <= INT_MAX);
	g_assert(tag->size <= INT_MAX);
	g_assert(iv->size <= INT_MAX);
	g_assert(out->size == in->size);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		g_abort();

	/* First, set the cipher algorithm so we can verify our key/IV lengths
	 */
	if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encrypt) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CIPHER_CTX_new failed"));
		return -1;
	}

	/* Set IV length */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv->size, NULL) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CIPHER_CTX_ex failed"));
		return -1;
	}

	/* Initialise key and IV */
	if (EVP_CipherInit_ex(ctx, NULL, NULL, key->data, iv->data, encrypt) !=
	    1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CipherInit_ex failed"));
		return -1;
	}

	if (aad->size > 0) {
		/* Provide any AAD data */
		if (EVP_CipherUpdate(ctx, NULL, &len, aad->data,
				     (int)aad->size) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_CipherUpdate failed"));
			return -1;
		}
		g_assert(len == (int)aad->size);
	}

	/* Provide data to be en/decrypted */
	if (EVP_CipherUpdate(ctx, out->data, &len, in->data, (int)in->size) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CipherUpdate failed"));
		return -1;
	}
	ret = len;

	if (!encrypt) {
		/* Set expected tag value */
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
					(int)tag->size, tag->data) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("Setting the GCM tag failed"));
			return -1;
		}
	}

	/* Finalize the en/decryption */
	if (EVP_CipherFinal_ex(ctx, (guchar *)out->data + len, &len) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("EVP_CipherFinal_ex failed"));
		return -1;
	}
	ret += len;

	if (encrypt) {
		/* Get the tag */
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
					(int)tag->size, tag->data) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("Getting the GCM tag failed"));
			return -1;
		}
	}

	g_assert(ret == (int)in->size);
	return ret;
}

int64_t gcm_encrypt(const PvBuffer *in, const PvBuffer *aad,
		    const struct cipher_parms *parms, PvBuffer *out, PvBuffer *tag,
		    GError **err)
{
	return gcm_encrypt_decrypt(in, aad, parms, out, tag, PV_ENCRYPT, err);
}
