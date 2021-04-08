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
#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

#include "lib/zt_common.h"

#include "libseckey/sk_openssl.h"
#include "libseckey/sk_utilities.h"

/*
 * This source file is only used with OpenSSL < 3.0.
 * PKEY method functions are deprecated since OpenSSL 3.0
 */
#if !OPENSSL_VERSION_PREREQ(3, 0)

static int sk_pkey_data_ec_index = -1;
static int sk_pkey_data_rsa_index = -1;

static const EVP_PKEY_METHOD *sk_pkey_meth_default_method_ec;
static const EVP_PKEY_METHOD *sk_pkey_meth_default_method_rsa;
static const EVP_PKEY_METHOD *sk_pkey_meth_default_method_rsa_pss;

static int sk_pkey_meth_lib = -1;

int sk_openssl_get_pkey_ec(const unsigned char *secure_key,
			   size_t secure_key_size, int nid, size_t prime_len,
			   const unsigned char *x, const unsigned char *y,
			   const struct sk_funcs *sk_funcs, const void *private,
			   EVP_PKEY **pkey, bool debug);

int sk_openssl_get_pkey_rsa(const unsigned char *secure_key,
			    size_t secure_key_size,
			    const unsigned char *modulus, size_t modulus_length,
			    const unsigned char *pub_exp, size_t pub_exp_length,
			    int pkey_type, const struct sk_funcs *sk_funcs,
			    const void *private, EVP_PKEY **pkey, bool debug);

#define sk_debug_data(data, fmt...)	sk_debug(data->debug, fmt)

static void sk_pkey_meth_put_error(int err, const char *file, int line,
				   char *fmt, ...)
{
	char text[200];
	va_list ap;

	va_start(ap, fmt);
	ERR_put_error(sk_pkey_meth_lib, 0, err, file, line);
	vsnprintf(text, sizeof(text), fmt, ap);
	ERR_add_error_data(1, text);
	va_end(ap);
}

#define put_error_data(data, err, fmt...)				\
		do {							\
			sk_debug_data(data, "ERROR: "fmt);		\
			sk_pkey_meth_put_error(err, __FILE__, __LINE__,	\
					       fmt);			\
		} while (0)


/* Secure key PKEY extra data */
struct sk_pkey_data {
	unsigned char *key_blob;
	size_t key_blob_size;
	struct sk_funcs *funcs;
	void *private;
	bool debug;
};

/*
 * Free secure key PKEY data attached to a PKEY
 */
static void sk_pkey_data_free(void *UNUSED(parent), void *ptr,
			      CRYPTO_EX_DATA *UNUSED(ad), int UNUSED(idx),
			      long UNUSED(argl), void *UNUSED(argp))
{
	struct sk_pkey_data *data = ptr;

	if (data == NULL)
		return;

	sk_debug_data(data, "data: %p", data);

	if (data != NULL) {
		if (data->key_blob != NULL)
			OPENSSL_free(data->key_blob);
		OPENSSL_free(data);
	}
}

/*
 * Duplicate secure key PKEY data attached to a PKEY
 */
static int sk_pkey_data_dup(CRYPTO_EX_DATA *UNUSED(to),
			    const CRYPTO_EX_DATA *UNUSED(from),
			    void *from_d, int UNUSED(idx), long UNUSED(argl),
			    void *UNUSED(argp))
{
	struct sk_pkey_data *from_data;
	struct sk_pkey_data *data;
	void **pptr = from_d;

	from_data = *pptr;

	sk_debug_data(from_data, "from_data: %p", from_data);

	data = OPENSSL_zalloc(sizeof(struct sk_pkey_data));
	if (data == NULL) {
		put_error_data(from_data, ERR_R_MALLOC_FAILURE,
			       "OPENSSL_malloc failed");
		return 0;
	}
	memcpy(data, from_data, sizeof(struct sk_pkey_data));

	data->key_blob = OPENSSL_malloc(data->key_blob_size);
	if (data->key_blob == NULL) {
		put_error_data(from_data, ERR_R_MALLOC_FAILURE,
			       "OPENSSL_malloc failed");
		OPENSSL_free(data);
		return 0;
	}
	memcpy(data->key_blob, from_data->key_blob, data->key_blob_size);

	*pptr = data;
	sk_debug_data(from_data, "data: %p", data);
	return 1;
}

/*
 * Get the default PKEY method for a POKEY id
 */
static const EVP_PKEY_METHOD *sk_pkey_meth_get_default_method(int pkey_id)
{
	switch (pkey_id) {
	case EVP_PKEY_EC:
		return sk_pkey_meth_default_method_ec;
	case EVP_PKEY_RSA:
		return sk_pkey_meth_default_method_rsa;
	case EVP_PKEY_RSA_PSS:
		return sk_pkey_meth_default_method_rsa_pss;
	default:
		return NULL;
	}
}

static int sk_pkey_meth_get_pkey_data(EVP_PKEY_CTX *ctx, EVP_PKEY **pkey,
				      struct sk_pkey_data **sk_data)
{
	*pkey = EVP_PKEY_CTX_get0_pkey(ctx);
	if (*pkey == NULL)
		return 0;

	switch (EVP_PKEY_id(*pkey)) {
	case EVP_PKEY_EC:
		*sk_data = EC_KEY_get_ex_data(EVP_PKEY_get0_EC_KEY(*pkey),
					     sk_pkey_data_ec_index);
		break;
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		*sk_data = RSA_get_ex_data(EVP_PKEY_get0_RSA(*pkey),
					  sk_pkey_data_rsa_index);
		break;
	default:
		return 0;
	}

	return 1;
}

static int sk_pkey_meth_sign_init(EVP_PKEY_CTX *ctx)
{
	int (*sign_init)(EVP_PKEY_CTX *ctx);
	const EVP_PKEY_METHOD *default_meth;
	struct sk_pkey_data *sk_data;
	EVP_PKEY *pkey;

	if (!sk_pkey_meth_get_pkey_data(ctx, &pkey, &sk_data))
		return 0;

	if (sk_data == NULL) {
		/* If no secure key is attached, call default implementation */
		default_meth = sk_pkey_meth_get_default_method(
							EVP_PKEY_id(pkey));
		if (default_meth == NULL)
			return 0;

		EVP_PKEY_meth_get_sign(default_meth, &sign_init, NULL);
		if (sign_init == NULL)
			return 1;

		return sign_init(ctx);
	}

	sk_debug_data(sk_data, "sk_data: %p pkey: %p type: %d", sk_data, pkey,
		      EVP_PKEY_id(pkey));
	return 1;
}

static int sk_pkey_meth_sign(EVP_PKEY_CTX *ctx, unsigned char *sig,
			     size_t *siglen, const unsigned char *tbs,
			     size_t tbslen)
{
	int (*sign)(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
		    const unsigned char *tbs, size_t tbslen);
	int sig_sz, pad_mode, hlen, saltlen, max_saltlen;
	const EVP_PKEY_METHOD *default_meth;
	struct sk_pkey_data *sk_data;
	int rc, md_type, mgf_md_type;
	const EVP_MD *sigmd, *mgf1md;
	const EC_KEY *ec;
	EVP_PKEY *pkey;

	if (!sk_pkey_meth_get_pkey_data(ctx, &pkey, &sk_data))
		return 0;

	if (sk_data == NULL) {
		/* If no secure key is attached, call default implementation */
		default_meth = sk_pkey_meth_get_default_method(
							EVP_PKEY_id(pkey));
		if (default_meth == NULL)
			return 0;

		EVP_PKEY_meth_get_sign(default_meth, NULL, &sign);
		if (sign == NULL)
			return 0;

		return sign(ctx, sig, siglen, tbs, tbslen);
	}

	/* A secure key is attached, implement secure key sign */
	sk_debug_data(sk_data, "sk_data: %p pkey: %p type: %d", sk_data, pkey,
		      EVP_PKEY_id(pkey));

	if (sig == NULL) {
		*siglen = EVP_PKEY_size(pkey);
		sk_debug_data(sk_data, "siglen: %lu", *siglen);
		return 1;
	}

	if (*siglen < (size_t)EVP_PKEY_size(pkey)) {
		put_error_data(sk_data, ERR_R_PASSED_INVALID_ARGUMENT,
			       "signature buffer too small");
		return 0;
	}

	*siglen = EVP_PKEY_size(pkey);

	if (sk_data->funcs == NULL) {
		put_error_data(sk_data, ERR_R_PASSED_NULL_PARAMETER,
			      "no secure key funcs");
		return 0;
	}

	if (EVP_PKEY_CTX_get_signature_md(ctx, &sigmd) != 1)
		return 0;
	md_type = sigmd != NULL ? EVP_MD_type(sigmd) : NID_sha1;

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA:
		if (sk_data->funcs->rsa_sign == NULL) {
			put_error_data(sk_data, ERR_R_PASSED_NULL_PARAMETER,
				       "no secure key sign function");
			return 0;
		}

		if (EVP_PKEY_CTX_get_rsa_padding(ctx, &pad_mode) != 1)
			return 0;

		rc = sk_data->funcs->rsa_sign(sk_data->key_blob,
					      sk_data->key_blob_size,
					      sig, siglen, tbs, tbslen,
					      pad_mode, md_type,
					      sk_data->private,
					      sk_data->debug);
		break;

	case EVP_PKEY_RSA_PSS:
		if (sk_data->funcs->rsa_pss_sign == NULL) {
			put_error_data(sk_data, ERR_R_PASSED_NULL_PARAMETER,
				       "no secure key sign function");
			return 0;
		}

		if (EVP_PKEY_CTX_get_rsa_padding(ctx, &pad_mode) != 1)
			return 0;
		if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1md) != 1)
			return 0;
		if (EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, &saltlen) != 1)
			return 0;

		hlen = sigmd != NULL ? EVP_MD_size(sigmd) : SHA_DIGEST_LENGTH;
		if (mgf1md != NULL) {
			mgf_md_type = EVP_MD_type(mgf1md);
			hlen = EVP_MD_size(mgf1md);
		} else {
			mgf_md_type = md_type;
		}

		/*
		 * We should be using RSA_bits(EVP_PKEY_get0_RSA(pkey)) here,
		 * but EVP_PKEY_get0_RSA(pkey) does not work with PKEY/type
		 * EVP_PKEY_RSA_PSS on older OpenSSL versions, so we fall back
		 * on EVP_PKEY_bits in this case.
		 */
		max_saltlen = (EVP_PKEY_get0_RSA(pkey) != NULL ?
					RSA_bits(EVP_PKEY_get0_RSA(pkey)) :
					EVP_PKEY_bits(pkey)) / 8 - hlen - 2;

		switch (saltlen) {
		case RSA_PSS_SALTLEN_DIGEST:
			saltlen = hlen;
			break;
		case RSA_PSS_SALTLEN_AUTO:
		case RSA_PSS_SALTLEN_MAX:
			saltlen = max_saltlen;
			break;
		default:
			break;
		}

		if (saltlen > max_saltlen || saltlen < 0) {
			put_error_data(sk_data, ERR_R_PASSED_INVALID_ARGUMENT,
				       "invalid salt length: %d", saltlen);
			return 0;
		}

		rc = sk_data->funcs->rsa_pss_sign(sk_data->key_blob,
						  sk_data->key_blob_size,
						  sig, siglen, tbs, tbslen,
						  md_type, mgf_md_type, saltlen,
						  sk_data->private,
						  sk_data->debug);
		break;

	case EVP_PKEY_EC:
		ec = EVP_PKEY_get0_EC_KEY(pkey);
		if (ec == NULL) {
			put_error_data(sk_data, ERR_R_INTERNAL_ERROR,
				       "EVP_PKEY_get0_EC_KEY failed");
			return 0;
		}

		sig_sz = ECDSA_size(ec);
		if (sig == NULL) {
			*siglen = (size_t)sig_sz;
			return 0;
		}
		if (*siglen < (size_t)sig_sz) {
			put_error_data(sk_data, ERR_R_PASSED_INVALID_ARGUMENT,
				       "siglen too small");
			return 0;
		}

		if (sk_data->funcs->ecdsa_sign == NULL) {
			put_error_data(sk_data, ERR_R_PASSED_NULL_PARAMETER,
				       "no secure key sign function");
			return 0;
		}

		rc = sk_data->funcs->ecdsa_sign(sk_data->key_blob,
						sk_data->key_blob_size,
						sig, siglen,
						tbs, tbslen, md_type,
						sk_data->private,
						sk_data->debug);
		break;

	default:
		rc = -1;
		put_error_data(sk_data, ERR_R_INTERNAL_ERROR,
			       "invalid PKEY type");
	}

	if (rc != 0) {
		put_error_data(sk_data, ERR_R_OPERATION_FAIL,
			       "secure key sign operation failed");
		return 0;
	}

	sk_debug_data(sk_data, "siglen: %lu", *siglen);

	return 1;
}

static int sk_pkey_meth_decrypt_init(EVP_PKEY_CTX *ctx)
{
	int (*decrypt_init)(EVP_PKEY_CTX *ctx);
	const EVP_PKEY_METHOD *default_meth;
	struct sk_pkey_data *sk_data;
	EVP_PKEY *pkey;

	if (!sk_pkey_meth_get_pkey_data(ctx, &pkey, &sk_data))
		return 0;

	if (sk_data == NULL) {
		/* If no secure key is attached, call default implementation */
		default_meth = sk_pkey_meth_get_default_method(
							EVP_PKEY_id(pkey));
		if (default_meth == NULL)
			return 0;

		EVP_PKEY_meth_get_decrypt(default_meth, &decrypt_init, NULL);
		if (decrypt_init == NULL)
			return 1;

		return decrypt_init(ctx);
	}

	sk_debug_data(sk_data, "sk_data: %p pkey: %p type: %d", sk_data, pkey,
		      EVP_PKEY_id(pkey));
	return 1;
}

static int sk_pkey_meth_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out,
				size_t *outlen, const unsigned char *in,
				size_t inlen)
{
	int (*decrypt)(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
		       const unsigned char *in, size_t inlen);
	int rc, pad_mode, label_len, md_type, mgfmd_type;
	const EVP_PKEY_METHOD *default_meth;
	struct sk_pkey_data *sk_data;
	const EVP_MD *md, *mgf1md;
	unsigned char *label;
	EVP_PKEY *pkey;

	if (!sk_pkey_meth_get_pkey_data(ctx, &pkey, &sk_data))
		return 0;

	if (sk_data == NULL) {
		/* If no secure key is attached, call default implementation */
		default_meth = sk_pkey_meth_get_default_method(
							EVP_PKEY_id(pkey));
		if (default_meth == NULL)
			return 0;

		EVP_PKEY_meth_get_decrypt(default_meth, NULL, &decrypt);
		if (decrypt == NULL)
			return 0;

		return decrypt(ctx, out, outlen, in, inlen);
	}

	/* A secure key is attached, implement secure key decrypt */
	sk_debug_data(sk_data, "sk_data: %p pkey: %p type: %d", sk_data, pkey,
		      EVP_PKEY_id(pkey));

	if (out == NULL) {
		*outlen = EVP_PKEY_size(pkey);
		sk_debug_data(sk_data, "outlen: %lu", *outlen);
		return 1;
	}

	if (*outlen < (size_t)EVP_PKEY_size(pkey)) {
		put_error_data(sk_data, ERR_R_PASSED_INVALID_ARGUMENT,
			       "output buffer too small");
		return 0;
	}

	*outlen = EVP_PKEY_size(pkey);

	if (sk_data->funcs == NULL) {
		put_error_data(sk_data, ERR_R_PASSED_NULL_PARAMETER,
			      "no secure key funcs");
		return 0;
	}

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_RSA:
		if (EVP_PKEY_CTX_get_rsa_padding(ctx, &pad_mode) != 1)
			return 0;

		switch (pad_mode) {
		case RSA_PKCS1_OAEP_PADDING:
			label_len = EVP_PKEY_CTX_get0_rsa_oaep_label(ctx,
								     &label);
			if (label_len < 0)
				return 0;
			if (EVP_PKEY_CTX_get_rsa_oaep_md(ctx, &md) != 1)
				return 0;
			if (EVP_PKEY_CTX_get_rsa_mgf1_md(ctx, &mgf1md) != 1)
				return 0;

			md_type = md != NULL ? EVP_MD_type(md) : NID_sha1;
			mgfmd_type = mgf1md != NULL ?
						EVP_MD_type(mgf1md) : md_type;

			if (sk_data->funcs->rsa_decrypt_oaep == NULL) {
				put_error_data(sk_data,
					       ERR_R_PASSED_NULL_PARAMETER,
					       "no secure key decrypt function");
				return 0;
			}

			rc = sk_data->funcs->rsa_decrypt_oaep(
							sk_data->key_blob,
							sk_data->key_blob_size,
							out, outlen, in, inlen,
							md_type, mgfmd_type,
							label, label_len,
							sk_data->private,
							sk_data->debug);
			break;

		default:
			if (sk_data->funcs->rsa_decrypt == NULL) {
				put_error_data(sk_data,
					       ERR_R_PASSED_NULL_PARAMETER,
					       "no secure key decrypt function");
				return 0;
			}

			rc = sk_data->funcs->rsa_decrypt(sk_data->key_blob,
							 sk_data->key_blob_size,
							 out, outlen, in, inlen,
							 pad_mode,
							 sk_data->private,
							 sk_data->debug);
			break;
		}
		break;

	case EVP_PKEY_RSA_PSS:
	case EVP_PKEY_EC:
	default:
		/* encrypt not supported */
		put_error_data(sk_data, ERR_R_INTERNAL_ERROR,
			       "invalid PKEY type");
		return 0;
	}

	if (rc != 0) {
		put_error_data(sk_data, ERR_R_OPERATION_FAIL,
			       "secure key decrypt operation failed");
		return 0;
	}

	sk_debug_data(sk_data, "outlen: %lu", *outlen);

	return 1;

}

static int sk_pkey_meth_derive_init(EVP_PKEY_CTX *ctx)
{
	int (*derive_init)(EVP_PKEY_CTX *ctx);
	const EVP_PKEY_METHOD *default_meth;
	struct sk_pkey_data *sk_data;
	EVP_PKEY *pkey;

	if (!sk_pkey_meth_get_pkey_data(ctx, &pkey, &sk_data))
		return 0;

	if (sk_data == NULL) {
		/* If no secure key is attached, call default implementation */
		default_meth = sk_pkey_meth_get_default_method(
							EVP_PKEY_id(pkey));
		if (default_meth == NULL)
			return 0;

		EVP_PKEY_meth_get_derive(default_meth, &derive_init, NULL);
		if (derive_init == NULL)
			return 1;

		return derive_init(ctx);
	}

	/* We can not derive with a secure key attached */
	put_error_data(sk_data, ERR_R_OPERATION_FAIL,
		       "secure key derive not supported");
	return 0;
}

static int sk_pkey_meth_derive(EVP_PKEY_CTX *ctx, unsigned char *key,
			       size_t *keylen)
{
	int (*derive)(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
	const EVP_PKEY_METHOD *default_meth;
	struct sk_pkey_data *sk_data;
	EVP_PKEY *pkey;

	if (!sk_pkey_meth_get_pkey_data(ctx, &pkey, &sk_data))
		return 0;

	if (sk_data == NULL) {
		/* If no secure key is attached, call default implementation */
		default_meth = sk_pkey_meth_get_default_method(
							EVP_PKEY_id(pkey));
		if (default_meth == NULL)
			return 0;

		EVP_PKEY_meth_get_derive(default_meth, NULL, &derive);
		if (derive == NULL)
			return 1;

		return derive(ctx, key, keylen);
	}

	/* We can not derive with a secure key attached */
	put_error_data(sk_data, ERR_R_OPERATION_FAIL,
		       "secure key derive not supported");
	return 0;
}

static int sk_pkey_meth_setup(int pkey_id, bool debug)
{
	const EVP_PKEY_METHOD *default_meth;
	EVP_PKEY_METHOD *pkey_meth;
	int flags = 0;

	sk_debug(debug, "pkey_id: %d", pkey_id);

	default_meth = sk_pkey_meth_get_default_method(pkey_id);
	if (default_meth == NULL) {
		sk_debug(debug, "ERROR: get_default_pkey_method failed");
		return -EIO;
	}

	EVP_PKEY_meth_get0_info(NULL, &flags, default_meth);
	pkey_meth = EVP_PKEY_meth_new(pkey_id, flags);
	if (pkey_meth == NULL) {
		sk_debug(debug, "ERROR: EVP_PKEY_meth_new failed");
		return -ENOMEM;
	}

	/* Inherit all functions from the default PKEY method */
	EVP_PKEY_meth_copy(pkey_meth, default_meth);

	/* Override private key operations */
	EVP_PKEY_meth_set_sign(pkey_meth, sk_pkey_meth_sign_init,
			       sk_pkey_meth_sign);
	EVP_PKEY_meth_set_decrypt(pkey_meth, sk_pkey_meth_decrypt_init,
				  sk_pkey_meth_decrypt);
	EVP_PKEY_meth_set_derive(pkey_meth, sk_pkey_meth_derive_init,
				 sk_pkey_meth_derive);

	/*
	 * Do not provide signctx and digestsign functions, even if the default
	 * method would support them. If not available, it will fall back to
	 * regular sign function usage, which we do override.
	 */
	EVP_PKEY_meth_set_signctx(pkey_meth, NULL, NULL);
	EVP_PKEY_meth_set_digestsign(pkey_meth, NULL);

	/* Add this as the preferred PKEY method */
	if (EVP_PKEY_meth_add0(pkey_meth) != 1) {
		sk_debug(debug, "ERROR: EVP_PKEY_meth_add0 failed");
		return -EIO;
	}

	return 0;
}

static int sk_pkey_meth_cleanup(int pkey_id)
{
	const EVP_PKEY_METHOD *pkey_meth;

	pkey_meth = EVP_PKEY_meth_find(pkey_id);
	if (pkey_meth == NULL)
		return -ENOENT;

	if (EVP_PKEY_meth_remove(pkey_meth) != 1)
		return -EIO;

	EVP_PKEY_meth_free((EVP_PKEY_METHOD *)pkey_meth);

	return 0;
}

static int sk_pkey_meth_setup_pkey(EVP_PKEY *pkey,
				   const unsigned char *secure_key,
				   size_t secure_key_size,
				   const struct sk_funcs *funcs,
				   const void *private, bool debug)
{
	struct sk_pkey_data *data;
	EC_KEY *ec;
	RSA *rsa;

	if (pkey == NULL || secure_key == NULL || secure_key_size == 0 ||
	    funcs == NULL)
		return -EINVAL;

	sk_debug(debug, "pkey: %p type: %d", pkey, EVP_PKEY_id(pkey));

	if (sk_pkey_data_ec_index < 0 || sk_pkey_data_rsa_index < 0) {
		sk_debug(debug, "sk_pkey_meth support not initialized");
		return -ENODEV;
	}

	data = OPENSSL_zalloc(sizeof(struct sk_pkey_data));
	if (data == NULL) {
		sk_debug(debug, "OPENSSL_zalloc failed");
		return -ENOMEM;
	}

	data->key_blob = OPENSSL_malloc(secure_key_size);
	if (data->key_blob == NULL) {
		sk_debug(debug, "OPENSSL_malloc failed");
		OPENSSL_free(data);
		return -ENOMEM;
	}
	memcpy(data->key_blob, secure_key, secure_key_size);
	data->key_blob_size = secure_key_size;
	data->funcs = (struct sk_funcs *)funcs;
	data->private = (void *)private;
	data->debug = debug;

	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_EC:
		ec = EVP_PKEY_get0_EC_KEY(pkey);
		if (ec == NULL) {
			sk_debug(debug, "EVP_PKEY_get0_EC_KEY failed");
			return -EIO;
		}

		if (!EC_KEY_set_ex_data(ec, sk_pkey_data_ec_index, data)) {
			sk_debug(debug, "EC_KEY_set_ex_data failed");
			return -EIO;
		}
		break;
	case EVP_PKEY_RSA:
	case EVP_PKEY_RSA_PSS:
		rsa = EVP_PKEY_get0_RSA(pkey);
		if (rsa == NULL) {
			sk_debug(debug, "EVP_PKEY_get0_RSA failed");
			return -EIO;
		}

		if (!RSA_set_ex_data(rsa, sk_pkey_data_rsa_index, data)) {
			sk_debug(debug, "RSA_set_ex_data failed");
			return -EIO;
		}
		break;
	}

	return 0;
}

/**
 * Initializes the secure key support for OpenSSL.
 *
 * @param debug             true to enable internal debugging
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed for various reasons
 */
int SK_OPENSSL_init(bool debug)
{
	int rc;

	if (sk_pkey_data_ec_index < 0)
		sk_pkey_data_ec_index = CRYPTO_get_ex_new_index(
				CRYPTO_EX_INDEX_EC_KEY, 0, NULL,
				NULL, sk_pkey_data_dup, sk_pkey_data_free);
	if (sk_pkey_data_ec_index < 0) {
		sk_debug(debug, "ERROR: CRYPTO_get_ex_new_index(EC) failed");
		return -EIO;
	}

	if (sk_pkey_data_rsa_index < 0)
		sk_pkey_data_rsa_index = CRYPTO_get_ex_new_index(
				CRYPTO_EX_INDEX_RSA, 0, NULL,
				NULL, sk_pkey_data_dup, sk_pkey_data_free);
	if (sk_pkey_data_rsa_index < 0) {
		sk_debug(debug, "ERROR: CRYPTO_get_ex_new_index(RSA) failed");
		return -EIO;
	}

	sk_pkey_meth_default_method_ec = EVP_PKEY_meth_find(EVP_PKEY_EC);
	if (sk_pkey_meth_default_method_ec == NULL) {
		sk_debug(debug, "ERROR: EVP_PKEY_meth_find(EC) failed");
		return -EIO;
	}
	sk_pkey_meth_default_method_rsa = EVP_PKEY_meth_find(EVP_PKEY_RSA);
	if (sk_pkey_meth_default_method_ec == NULL) {
		sk_debug(debug, "ERROR: EVP_PKEY_meth_find(RSA) failed");
	return -EIO;
	}
	sk_pkey_meth_default_method_rsa_pss =
					EVP_PKEY_meth_find(EVP_PKEY_RSA_PSS);
	if (sk_pkey_meth_default_method_ec == NULL) {
		sk_debug(debug, "ERROR: EVP_PKEY_meth_find(RSA-PSS) failed");
		return -EIO;
	}

	rc = sk_pkey_meth_setup(EVP_PKEY_EC, debug);
	if (rc != 0) {
		sk_debug(debug, "ERROR: sk_pkey_meth_setup(EC) "
			 "failed");
		return rc;
	}
	rc = sk_pkey_meth_setup(EVP_PKEY_RSA, debug);
	if (rc != 0) {
		sk_debug(debug, "ERROR: sk_pkey_meth_setup(RSA) "
			 "failed");
		return rc;
	}
	rc = sk_pkey_meth_setup(EVP_PKEY_RSA_PSS, debug);
	if (rc != 0) {
		sk_debug(debug, "ERROR: sk_pkey_meth_setup(RSA-PSS) "
			 "failed");
		return rc;
	}

	if (sk_pkey_meth_lib <= 0)
		sk_pkey_meth_lib = ERR_get_next_error_library();
	if (sk_pkey_meth_lib <= 0) {
		sk_debug(debug, "ERROR: ERR_get_next_error_library failed");
		return -EIO;
	}

	sk_debug(debug, "sk_pkey_meth support initialized");

	return 0;
}

/**
 * Terminate the secure key support for OpenSSL.
 */
void SK_OPENSSL_term(void)
{
	if (sk_pkey_data_ec_index >= 0)
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_EC_KEY,
				     sk_pkey_data_ec_index);
	sk_pkey_data_ec_index = -1;

	if (sk_pkey_data_rsa_index >= 0)
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA,
				sk_pkey_data_rsa_index);
	sk_pkey_data_rsa_index = -1;


	sk_pkey_meth_cleanup(EVP_PKEY_EC);
	sk_pkey_meth_cleanup(EVP_PKEY_RSA);
	sk_pkey_meth_cleanup(EVP_PKEY_RSA_PSS);

	sk_pkey_meth_default_method_ec = NULL;
	sk_pkey_meth_default_method_rsa = NULL;
	sk_pkey_meth_default_method_rsa_pss = NULL;

	sk_pkey_meth_lib = -1;
}

/**
 * Converts an EC key given by the nid and the x and y coordinates into an
 * OpenSSL PKEY and attaches the secure key together with secure key functions
 * and private pointer to it. If no secure key is provided, a public EC key
 * only PKEY is returned.
 *
 * @param secure_key        the secure key blob.
 *                          If NULL, a clear key PKEY is created.
 * @param secure_key_size   the size of the secure key blob (ignored if
 *                          secure_key is NULL)
 * @param nid               the OpenSSL nid of the EC curve used
 * @param prime_len         the length of the prime in bytes. This is also the
 *                          length of the x and y coordinates.
 * @param x                 the x coordinate as big endian binary number in
 *                          prime_len size
 * @param y                 the y coordinate as big endian binary number in
 *                          prime_len size
 * @param sk_funcs          the secure key functions to operate with the key.
 *                          Ignored if secure_key is NULL, required otherwise.
 * @param private           a private pointer that is passed to the secure key
 *                          functions (can be NULL)
 * @param pkey              On return: A PKEY containing the EC public key.
 * @param debug             true to enable internal debugging
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to generate the PKEY
 *          -ENOENT: OpenSSL does not know/support the curve (nid)
 */
int sk_openssl_get_pkey_ec(const unsigned char *secure_key,
			   size_t secure_key_size, int nid, size_t prime_len,
			   const unsigned char *x, const unsigned char *y,
			   const struct sk_funcs *sk_funcs, const void *private,
			   EVP_PKEY **pkey, bool debug)
{
	BIGNUM *bn_x = NULL, *bn_y = NULL;
	EC_GROUP *group = NULL;
	EC_KEY *ec = NULL;
	int rc;

	if (pkey == NULL || x == NULL || y == NULL)
		return -EINVAL;
	if (secure_key != NULL && (secure_key_size == 0 || sk_funcs == NULL))
		return -EINVAL;

	*pkey = NULL;

	bn_x = BN_bin2bn(x, prime_len, NULL);
	bn_y = BN_bin2bn(y, prime_len, NULL);
	if (bn_x == NULL || bn_y == NULL) {
		sk_debug(debug, "ERROR: BN_bin2bn failed");
		rc = -ENOMEM;
		goto out;
	}

	group = EC_GROUP_new_by_curve_name(nid);
	if (group == NULL) {
		sk_debug(debug, "ERROR: EC_GROUP_new_by_curve_name failed");
		rc = -ENOENT;
		goto out;
	}

	ec = EC_KEY_new();
	if (ec == NULL) {
		sk_debug(debug, "ERROR: EC_KEY_new failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = EC_KEY_set_group(ec, group);
	if (rc != 1) {
		sk_debug(debug, "ERROR: EC_KEY_set_group failed");
		rc = -EIO;
		goto out;
	}

	rc = EC_KEY_set_public_key_affine_coordinates(ec, bn_x, bn_y);
	if (rc != 1) {
		sk_debug(debug,
		    "ERROR: EC_KEY_set_public_key_affine_coordinates failed");
		rc = -EIO;
		goto out;
	}

	*pkey = EVP_PKEY_new();
	if (*pkey == NULL) {
		sk_debug(debug, "ERROR: EVP_PKEY_new failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = EVP_PKEY_assign_EC_KEY(*pkey, ec);
	if (rc != 1) {
		sk_debug(debug, "ERROR: EVP_PKEY_assign_EC_KEY failed");
		rc = -EIO;
		goto out;
	}

	if (secure_key != NULL) {
		rc = sk_pkey_meth_setup_pkey(*pkey, secure_key, secure_key_size,
					     sk_funcs, private, debug);
		if (rc != 0) {
			sk_debug(debug,
				 "ERROR: sk_pkey_meth_setup_pkey failed");
			goto out;
		}
	}

	rc = 0;
	sk_debug(debug, "pkey created: %p", *pkey);

out:
	if (bn_x != NULL)
		BN_free(bn_x);
	if (bn_y != NULL)
		BN_free(bn_y);
	if (group != NULL)
		EC_GROUP_free(group);
	if (rc != 0 && *pkey != NULL) {
		EVP_PKEY_free(*pkey);
		*pkey = NULL;
	}

	return rc;
}

/**
 * Converts an RSA key given by the modulus and public exponent into an
 * OpenSSL PKEY and attaches the secure key together with secure key functions
 * and private pointer to it. If no secure key is provided, a public RSA key
 * only PKEY is returned.
 *
 * @param secure_key        the secure key blob.
 *                          If NULL, a clear key PKEY is created.
 * @param secure_key_size   the size of the secure key blob (ignored if
 *                          secure_key is NULL)
 * @param modulus           the modulus as big endian number
 * @param modulus_length    the length of the modulus in bytes
 * @param pub_exp           the public exponent as big endian number
 * @param pub_exp_length    the length of the public exponent in bytes
 * @param pkey_type         the PKEY type (EVP_PKEY_RSA or EVP_PKEY_RSA_PSS)
 * @param sk_funcs          the secure key functions to operate with the key.
 *                          Ignored if secure_key is NULL, required otherwise.
 * @param private           a private pointer that is passed to the secure key
 *                          functions (can be NULL)
 * @param pkey              On return: A PKEY containing the RSA public key.
 * @param debug             true to enable internal debugging
 *
 * @returns zero for success, a negative errno in case of an error:
 *          -EINVAL: a function parameter is invalid
 *          -ENOMEM: failed to allocate memory
 *          -EIO: OpenSSL failed to generate the PKEY
 */
int sk_openssl_get_pkey_rsa(const unsigned char *secure_key,
			    size_t secure_key_size,
			    const unsigned char *modulus, size_t modulus_length,
			    const unsigned char *pub_exp, size_t pub_exp_length,
			    int pkey_type, const struct sk_funcs *sk_funcs,
			    const void *private, EVP_PKEY **pkey, bool debug)
{
	BIGNUM *bn_modulus = NULL, *bn_pub_exp = NULL;
	RSA *rsa;
	int rc;

	if (pkey == NULL || modulus == NULL || pub_exp == NULL)
		return -EINVAL;
	if (secure_key != NULL && (secure_key_size == 0 || sk_funcs == NULL))
		return -EINVAL;
	if (pkey_type != EVP_PKEY_RSA && pkey_type != EVP_PKEY_RSA_PSS)
		return -EINVAL;

	*pkey = NULL;

	bn_modulus = BN_bin2bn(modulus, modulus_length, NULL);
	bn_pub_exp = BN_bin2bn(pub_exp, pub_exp_length, NULL);
	if (bn_modulus == NULL || bn_pub_exp == NULL) {
		sk_debug(debug, "ERROR: BN_bin2bn failed");
		rc = -ENOMEM;
		goto out;
	}

	rsa = RSA_new();
	if (rsa == NULL) {
		sk_debug(debug, "ERROR: RSA_new failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = RSA_set0_key(rsa, bn_modulus, bn_pub_exp, NULL);
	if (rc != 1) {
		sk_debug(debug, "ERROR: RSA_set0_key failed");
		rc = -EIO;
		goto out;
	}

	*pkey = EVP_PKEY_new();
	if (*pkey == NULL) {
		sk_debug(debug, "ERROR: EVP_PKEY_new failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = EVP_PKEY_assign(*pkey, pkey_type, rsa);
	if (rc != 1) {
		sk_debug(debug, "ERROR: EVP_PKEY_assign failed");
		rc = -EIO;
		goto out;
	}

	if (secure_key != NULL) {
		rc = sk_pkey_meth_setup_pkey(*pkey, secure_key, secure_key_size,
					     sk_funcs, private, debug);
		if (rc != 0) {
			sk_debug(debug,
				 "ERROR: sk_pkey_meth_setup_pkey failed");
			goto out;
		}
	}

	rc = 0;
	sk_debug(debug, "pkey created: %p", *pkey);

out:
	if (rc != 0 && bn_modulus != NULL)
		BN_free(bn_modulus);
	if (rc != 0 && bn_pub_exp != NULL)
		BN_free(bn_pub_exp);
	return rc;
}

/**
 * Get the curve NID of the EC pkey
 */
int SK_OPENSSL_get_curve_from_ec_pkey(EVP_PKEY *pkey)
{
	if (EVP_PKEY_id(pkey) != EVP_PKEY_EC)
		return NID_undef;

	return EC_GROUP_get_curve_name(EC_KEY_get0_group(
					EVP_PKEY_get0_EC_KEY(pkey)));
}

#endif
