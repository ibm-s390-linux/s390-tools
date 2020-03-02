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
#include <stdint.h>
#include <string.h>

#include "boot/s390.h"
#include "common.h"
#include "include/pv_crypto_def.h"
#include "pv/pv_error.h"

#include "buffer.h"
#include "crypto.h"

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

Buffer *digest_ctx_finalize(EVP_MD_CTX *ctx, GError **err)
{
	gint md_size = EVP_MD_size(EVP_MD_CTX_md(ctx));
	g_autoptr(Buffer) ret = NULL;
	guint digest_size;

	g_assert(md_size > 0);

	ret = buffer_alloc((guint)md_size);
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
static Buffer *digest_buffer(const EVP_MD *md, const Buffer *buf, GError **err)
{
	g_autoptr(EVP_MD_CTX) md_ctx = NULL;
	g_autoptr(Buffer) ret = NULL;
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
Buffer *sha256_buffer(const Buffer *buf, GError **err)
{
	g_autoptr(Buffer) ret = NULL;

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

static Buffer *derive_key(EVP_PKEY *cust, EVP_PKEY *host, GError **err)
{
	g_autoptr(EVP_PKEY_CTX) ctx = NULL;
	g_autoptr(Buffer) ret = NULL;
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

	ret = buffer_alloc(key_size);
	if (EVP_PKEY_derive(ctx, ret->data, &key_size) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_DERIVE,
			    _("Key derivation failed"));
		return NULL;
	}

	g_assert(ret->size == key_size);
	return g_steal_pointer(&ret);
}

Buffer *compute_exchange_key(EVP_PKEY *cust, EVP_PKEY *host, GError **err)
{
	g_autoptr(Buffer) raw = buffer_alloc(70);
	g_autoptr(Buffer) ret = NULL;
	g_autoptr(Buffer) key = NULL;
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

static Buffer *generate_rand_data(guint size, const gchar *err_msg,
				  GError **err)
{
	g_autoptr(Buffer) buf = buffer_alloc(size);

	g_assert(size <= INT_MAX);

	if (RAND_bytes(buf->data, (int)size) != 1) {
		g_set_error_literal(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_RANDOMIZATION,
				    err_msg);
		return NULL;
	}

	return g_steal_pointer(&buf);
}

Buffer *generate_aes_iv(guint size, GError **err)
{
	return generate_rand_data(size,
				  _("Generating a IV failed because the required amount of random data is not available"),
				  err);
}

Buffer *generate_aes_key(guint size, GError **err)
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

static gboolean verify_certificate(X509_STORE *store, X509 *cert, GError **err)
{
	g_autoptr(X509_STORE_CTX) csc = X509_STORE_CTX_new();
	if (!csc)
		g_abort();

	if (X509_STORE_CTX_init(csc, store, cert, NULL) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INIT,
			    _("Failed to initialize X.509 store"));
		return FALSE;
	}

	if (X509_verify_cert(csc) != 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_VERIFICATION,
			    _("Failed to verify host-key document"));
		return FALSE;
	}

	return TRUE;
}

static X509 *load_certificate(const gchar *path, GError **err)
{
	g_autoptr(X509) ret = NULL;
	g_autoptr(BIO) bio = BIO_new_file(path, "rb");

	if (!bio) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_READ_CERTIFICATE,
			    _("Failed to read host-key document: '%s'"), path);
		return NULL;
	}

	ret = PEM_read_bio_X509(bio, NULL, 0, NULL);
	if (!ret) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_READ_CERTIFICATE,
			    _("Failed to load host-key document: '%s'"), path);
		return NULL;
	}

	return g_steal_pointer(&ret);
}

EVP_PKEY *read_ec_pubkey_cert(X509_STORE *store, gint nid, const gchar *path,
			      GError **err)
{
	g_autoptr(EVP_PKEY) ret = NULL;
	g_autoptr(X509) cert = NULL;

	cert = load_certificate(path, err);
	if (!cert)
		return NULL;

	if (store && !verify_certificate(store, cert, err)) {
		g_prefix_error(err,
			       _("Failed to load host-key document: '%s': "),
			       path);
		return NULL;
	}

	ret = X509_get_pubkey(cert);
	if (!ret) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_INVALID_PARM,
			    _("Failed to get public key from host-key document: '%s'"),
			    path);
		return NULL;
	}

	if (!certificate_uses_correct_curve(ret, nid, err)) {
		g_prefix_error(err,
			       _("Failed to load host-key document: '%s': "),
			       path);
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
	const Buffer *key = parms->key;
	const Buffer *tweak = parms->iv_or_tweak;
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

static Buffer *__encrypt_decrypt_buffer(const struct cipher_parms *parms,
					const Buffer *in, gboolean encrypt,
					GError **err)
{
	g_autoptr(Buffer) ret = NULL;
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

	ret = buffer_alloc((unsigned long)data_size);
	memcpy(ret->data, data, ret->size);
	return g_steal_pointer(&ret);
}

Buffer *encrypt_buf(const struct cipher_parms *parms, const Buffer *in,
		    GError **err)
{
	return __encrypt_decrypt_buffer(parms, in, TRUE, err);
}

Buffer *decrypt_buf(const struct cipher_parms *parms, const Buffer *in,
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
static int64_t gcm_encrypt_decrypt(const Buffer *in, const Buffer *aad,
				   const struct cipher_parms *parms,
				   Buffer *out, Buffer *tag,
				   enum PvCryptoMode mode, GError **err)
{
	g_autoptr(EVP_CIPHER_CTX) ctx = NULL;
	const EVP_CIPHER *cipher = parms->cipher;
	const Buffer *iv = parms->iv_or_tweak;
	gboolean encrypt = mode == PV_ENCRYPT;
	const Buffer *key = parms->key;
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

int64_t gcm_encrypt(const Buffer *in, const Buffer *aad,
		    const struct cipher_parms *parms, Buffer *out, Buffer *tag,
		    GError **err)
{
	return gcm_encrypt_decrypt(in, aad, parms, out, tag, PV_ENCRYPT, err);
}
