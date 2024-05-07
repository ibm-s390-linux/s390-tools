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

char *pv_get_openssl_errors(void)
{
	char *ret;
	char *buf;
	BIO *bio;
	long len;

	bio = BIO_new(BIO_s_mem());
	ERR_print_errors(bio);
	len = BIO_get_mem_data(bio, &buf);
	if (len <= 0 || !buf)
		ret = g_strdup("Cannot receive OpenSSL error message.");
	else
		ret = g_strndup(buf, (size_t)len);
	BIO_free(bio);
	return ret;
}

int pv_BIO_reset(BIO *b)
{
	int rc = BIO_reset(b);

	if (rc != 1 && !(BIO_method_type(b) == BIO_TYPE_FILE && rc == 0))
		return -1;
	return 1;
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
				   const EVP_MD *md, GError **error)
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
		return NULL;
	}

	return pv_sec_gbytes_new_take(g_steal_pointer(&derived_key), derived_key_len);
}

GQuark pv_crypto_error_quark(void)
{
	return g_quark_from_static_string("pv-crypto-error-quark");
}
