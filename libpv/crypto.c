/*
 * Cryptography functions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#include "lib/zt_common.h"
#include "libpv/crypto.h"
#include "libpv/glib-helper.h"
#include "libpv/hash.h"

const char *pv_get_openssl_error(void)
{
	const char *ret;
	BIO *bio;
	char *buf;
	long len;

	bio = BIO_new(BIO_s_mem());
	ERR_print_errors(bio);
	len = BIO_get_mem_data(bio, &buf);
	if (len < 0)
		ret = "Cannot receive OpenSSL error message.";
	else
		ret = g_strndup(buf, (size_t)len);
	BIO_free(bio);
	return ret;
}

int pv_BIO_reset(BIO *b)
{
	int rc = BIO_reset(b);

	if (rc != 1 && (BIO_method_type(b) == BIO_TYPE_FILE && rc != 0))
		return -1;
	return 1;
}

GBytes *pv_generate_rand_data(size_t size, GError **error)
{
	g_autofree uint8_t *data = NULL;

	if (size > INT_MAX) {
		g_set_error_literal(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_RANDOMIZATION,
				    "Too many random data requested. Split it up");
		OPENSSL_clear_free(data, size);
		return NULL;
	}

	data = g_malloc(size);
	if (RAND_bytes(data, (int)size) != 1) {
		g_set_error_literal(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_RANDOMIZATION,
				    "The required amount of random data is not available");
		return NULL;
	}

	return pv_sec_gbytes_new_take(g_steal_pointer(&data), size);
}

GBytes *pv_generate_key(const EVP_CIPHER *cipher, GError **error)
{
	int size;

	pv_wrapped_g_assert(cipher);

	size = EVP_CIPHER_key_length(cipher);
	if (size <= 0) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_KEYGENERATION,
			    "Unknown cipher");
		return NULL;
	}

	return pv_generate_rand_data((guint)size, error);
}

GBytes *pv_generate_iv(const EVP_CIPHER *cipher, GError **error)
{
	int size;

	pv_wrapped_g_assert(cipher);

	size = EVP_CIPHER_iv_length(cipher);
	if (size <= 0) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_KEYGENERATION,
			    "Unknown cipher");
		return NULL;
	}

	return pv_generate_rand_data((guint)size, error);
}

static int64_t pv_gcm_encrypt_decrypt(GBytes *input, GBytes *aad, const PvCipherParms *parms,
				      GBytes **output, GBytes **tagp, enum PvCryptoMode mode,
				      GError **error)
{
	const uint8_t *in_data, *aad_data = NULL, *iv_data, *key_data;
	size_t in_size, aad_size = 0, iv_size, key_size, out_size;
	const EVP_CIPHER *cipher = parms->cipher;
	const size_t tag_size = parms->tag_size;
	gboolean encrypt = mode == PV_ENCRYPT;
	g_autoptr(EVP_CIPHER_CTX) ctx = NULL;
	g_autofree uint8_t *out_data = NULL;
	g_autofree uint8_t *tag_data = NULL;
	const GBytes *key = parms->key;
	const GBytes *iv = parms->iv;
	int cipher_block_size;
	int64_t ret = -1;
	int len = -1;
	GBytes *tag;

	g_assert(tagp);
	g_assert(cipher);
	g_assert(key);
	g_assert(iv);

	tag = *tagp;
	in_data = g_bytes_get_data((GBytes *)input, &in_size);
	if (aad)
		aad_data = g_bytes_get_data((GBytes *)aad, &aad_size);
	iv_data = g_bytes_get_data((GBytes *)iv, &iv_size);
	key_data = g_bytes_get_data((GBytes *)key, &key_size);
	out_size = in_size;
	cipher_block_size = EVP_CIPHER_block_size(cipher);

	/* Checks for later casts */
	g_assert(aad_size <= INT_MAX);
	g_assert(in_size <= INT_MAX);
	g_assert(iv_size <= INT_MAX);
	g_assert(cipher_block_size > 0);

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		g_abort();

	if (tag_size == 0 || (tag_size % (size_t)cipher_block_size != 0)) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "Passed tag size is incorrect");
		return -1;
	}

	/* Has the passed key the correct size? */
	if (EVP_CIPHER_key_length(cipher) != (int)key_size) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "Passed key has incorrect size: %ld != %d", key_size,
			    EVP_CIPHER_key_length(cipher));
		return -1;
	}

	/* First, set the cipher algorithm so we can verify our key/IV lengths
	 */
	if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, encrypt) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "EVP_CIPHER_CTX_new failed");
		return -1;
	}

	/* Set IV length */
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_size, NULL) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "EVP_CIPHER_CTX_ex failed");
		return -1;
	}

	/* Initialise key and IV */
	if (EVP_CipherInit_ex(ctx, NULL, NULL, key_data, iv_data, encrypt) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "EVP_CipherInit_ex failed");
		return -1;
	}

	/* Allocate output data */
	out_data = g_malloc0(out_size);
	if (encrypt)
		tag_data = g_malloc0(tag_size);

	if (aad_size > 0) {
		/* Provide any AAD data */
		if (EVP_CipherUpdate(ctx, NULL, &len, aad_data, (int)aad_size) != 1) {
			g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    "EVP_CipherUpdate failed");
			return -1;
		}
		g_assert(len == (int)aad_size);
	}

	/* Provide data to be en/decrypted */
	if (EVP_CipherUpdate(ctx, out_data, &len, in_data, (int)in_size) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    "EVP_CipherUpdate failed");
		return -1;
	}
	ret = len;

	if (!encrypt) {
		const uint8_t *tmp_tag_data = NULL;
		size_t tmp_tag_size = 0;

		if (tag)
			tmp_tag_data = g_bytes_get_data(tag, &tmp_tag_size);
		if (tag_size != tmp_tag_size) {
			g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    "Getting the GCM tag failed");
			return -1;
		}

		/* Set expected tag value */
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tmp_tag_size,
					(uint8_t *)tmp_tag_data) != 1) {
			g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    "Setting the GCM tag failed");
			return -1;
		}
	}

	/* Finalize the en/decryption */
	if (EVP_CipherFinal_ex(ctx, (uint8_t *)out_data + len, &len) != 1) {
		if (encrypt)
			g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    "Encrypting failed (EVP_CipherFinal_ex)");
		else
			g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_NO_MATCH_TAG,
				    "Verifying the GCM tag failed");
		return -1;
	}
	ret += len;

	if (encrypt) {
		/* Get the tag */
		if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_size, tag_data) != 1) {
			g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
				    "Getting the GCM tag failed");
			return -1;
		}

		g_assert(!*tagp);
		*tagp = g_bytes_new_take(g_steal_pointer(&tag_data), tag_size);
	}
	g_assert(ret == (int)out_size);
	g_assert(out_size == in_size);

	g_assert(!*output);
	*output = pv_sec_gbytes_new_take(g_steal_pointer(&out_data), out_size);
	return ret;
}

int64_t pv_gcm_encrypt(GBytes *plain, GBytes *aad, const PvCipherParms *parms, GBytes **cipher,
		       GBytes **tag, GError **error)
{
	pv_wrapped_g_assert(plain);
	pv_wrapped_g_assert(parms);
	pv_wrapped_g_assert(cipher);
	pv_wrapped_g_assert(tag);

	return pv_gcm_encrypt_decrypt(plain, aad, parms, cipher, tag, PV_ENCRYPT, error);
}

int64_t pv_gcm_decrypt(GBytes *cipher, GBytes *aad, GBytes *tag, const PvCipherParms *parms,
		       GBytes **plain, GError **error)
{
	pv_wrapped_g_assert(cipher);
	pv_wrapped_g_assert(tag);
	pv_wrapped_g_assert(parms);
	pv_wrapped_g_assert(plain);

	return pv_gcm_encrypt_decrypt(cipher, aad, parms, plain, &tag, PV_DECRYPT, error);
}

GBytes *pv_hkdf_extract_and_expand(size_t derived_key_len, GBytes *key, GBytes *salt, GBytes *info,
				   const EVP_MD *md, G_GNUC_UNUSED GError **error)
{
	const unsigned char *salt_data, *key_data, *info_data;
	g_autoptr(EVP_PKEY_CTX) ctx = NULL;
	size_t salt_len, key_len, info_len;
	g_autofree unsigned char *derived_key = NULL;

	g_assert(derived_key_len > 0);
	pv_wrapped_g_assert(key);
	pv_wrapped_g_assert(salt);
	pv_wrapped_g_assert(info);
	pv_wrapped_g_assert(md);

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (!ctx)
		g_abort();

	if (EVP_PKEY_derive_init(ctx) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	salt_data = g_bytes_get_data(salt, &salt_len);
	if (salt_len > INT_MAX) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt_data, (int)salt_len) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	key_data = g_bytes_get_data(key, &key_len);
	if (key_len > INT_MAX) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key_data, (int)key_len) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	info_data = g_bytes_get_data(info, &info_len);
	if (info_len > INT_MAX) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, (unsigned char *)info_data, (int)info_len) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		return NULL;
	}

	derived_key = g_malloc0(derived_key_len);
	if (EVP_PKEY_derive(ctx, derived_key, &derived_key_len) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_HKDF_FAIL,
			    "FAILED to derive key via HKDF");
		printf("%s\n", pv_get_openssl_error());
		return NULL;
	}

	return pv_sec_gbytes_new_take(g_steal_pointer(&derived_key), derived_key_len);
}

EVP_PKEY *pv_generate_ec_key(int nid, GError **error)
{
	g_autoptr(EVP_PKEY_CTX) ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	g_autoptr(EVP_PKEY) ret = NULL;

	g_assert(ctx);

	if (EVP_PKEY_keygen_init(ctx) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_KEYGENERATION,
			    _("EC key could not be auto-generated"));
		return NULL;
	}

	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_KEYGENERATION,
			    _("EC key could not be auto-generated"));
		return NULL;
	}

	if (EVP_PKEY_keygen(ctx, &ret) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_KEYGENERATION,
			    _("EC key could not be auto-generated"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

/* Convert a EVP_PKEY to the key format used in the PV header */
PvEcdhPubKey *pv_evp_pkey_to_ecdh_pub_key(EVP_PKEY *key, GError **error)
{
	g_autofree PvEcdhPubKey *ret = g_new0(PvEcdhPubKey, 1);
	g_autoptr(BIGNUM) pub_x_big = NULL, pub_y_big = NULL;
	g_autoptr(EC_KEY) ec_key = NULL;
	const EC_POINT *pub_key;
	const EC_GROUP *grp;

	pv_wrapped_g_assert(key);

	ec_key = EVP_PKEY_get1_EC_KEY(key);
	if (!ec_key) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Key has the wrong type"));
		return NULL;
	}

	pub_key = EC_KEY_get0_public_key(ec_key);
	if (!pub_key) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to get public key"));
		return NULL;
	}

	grp = EC_KEY_get0_group(ec_key);
	if (!grp) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Failed to get EC group"));
		return NULL;
	}

	pub_x_big = BN_new();
	if (!pub_x_big)
		g_abort();

	pub_y_big = BN_new();
	if (!pub_y_big)
		g_abort();

	if (EC_POINT_get_affine_coordinates_GFp(grp, pub_key, pub_x_big, pub_y_big, NULL) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Cannot convert key to internal format"));
		return NULL;
	}

	if (BN_bn2binpad(pub_x_big, ret->x, sizeof(ret->x)) < 0) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Cannot convert key to internal format"));
		return NULL;
	}

	if (BN_bn2binpad(pub_y_big, ret->y, sizeof(ret->y)) < 0) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Cannot convert key to internal format"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

static GBytes *derive_key(EVP_PKEY *key1, EVP_PKEY *key2, GError **error)
{
	g_autoptr(EVP_PKEY_CTX) ctx = NULL;
	uint8_t *data = NULL;
	size_t data_size, key_size;

	ctx = EVP_PKEY_CTX_new(key1, NULL);
	if (!ctx)
		g_abort();

	if (EVP_PKEY_derive_init(ctx) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Key derivation failed"));
		return NULL;
	}

	if (EVP_PKEY_derive_set_peer(ctx, key2) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INTERNAL,
			    _("Key derivation failed"));
		return NULL;
	}

	/* Determine buffer length */
	if (EVP_PKEY_derive(ctx, NULL, &key_size) != 1) {
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_DERIVE,
			    _("Key derivation failed"));
		return NULL;
	}

	data_size = key_size;
	data = OPENSSL_malloc(data_size);
	if (!data)
		g_abort();
	if (EVP_PKEY_derive(ctx, data, &data_size) != 1) {
		OPENSSL_clear_free(data, data_size);
		g_set_error(error, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_DERIVE,
			    _("Key derivation failed"));
		return NULL;
	}

	g_assert(data_size == key_size);
	return pv_sec_gbytes_new_take(g_steal_pointer(&data), data_size);
}

GBytes *pv_derive_exchange_key(EVP_PKEY *cust, EVP_PKEY *host, GError **error)
{
	const guint8 append[] = { 0x00, 0x00, 0x00, 0x01 };
	g_autoptr(GBytes) derived_key = NULL, ret = NULL;
	g_autoptr(GByteArray) der_key_ga = NULL;
	g_autofree uint8_t *raw = NULL;
	size_t raw_len;

	pv_wrapped_g_assert(cust);
	pv_wrapped_g_assert(host);

	derived_key = derive_key(cust, host, error);
	if (!derived_key)
		return NULL;

	der_key_ga = g_bytes_unref_to_array(g_steal_pointer(&derived_key));
	/* ANSI X.9.63-2011: 66 bytes x with leading 7 bits and
	 * concatenate 32 bit int '1'
	 */
	der_key_ga = g_byte_array_append(der_key_ga, append, sizeof(append));
	/* free GBytesArray and get underlying data */
	raw_len = der_key_ga->len;
	raw = g_byte_array_free(g_steal_pointer(&der_key_ga), FALSE);

	ret = pv_sha256_hash(raw, raw_len, error);
	OPENSSL_cleanse(raw, raw_len);
	return g_steal_pointer(&ret);
}

GQuark pv_crypto_error_quark(void)
{
	return g_quark_from_static_string("pv-crypto-error-quark");
}
