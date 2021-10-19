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

#include "lib/zt_common.h"

#include "libseckey/sk_openssl.h"
#include "libseckey/sk_utilities.h"
#include "libseckey/sk_cca.h"
#include "libseckey/sk_ep11.h"

#define SERIAL_NUMBER_BIT_SIZE		159

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

/**
 * Generate a secure key using the specified secure key crypto library.
 *
 * @param secure_key        A buffer where the secure key is stored to. If NULL,
 *                          the required buffer size is returned in
 *                          secure_key_size (size query).
 * @param secure_key_size   On entry, the size of the buffer specified with
 *                          secure_key (ignored if secure_key is NULL),
 *                          on exit the size of the secure key.
 * @param info              key generation info, such as key type (EC or RSA)
 *                          and key parameters.
 * @param ext_lib           External secure key crypto library to use
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_OPENSSL_generate_secure_key(unsigned char *secure_key,
				   size_t *secure_key_size,
				   const struct sk_key_gen_info *info,
				   const struct sk_ext_lib *ext_lib, bool debug)
{
	int rc;

	if (info == NULL || ext_lib == NULL || secure_key_size == NULL)
		return -EINVAL;

	sk_debug(debug, "ext-lib type: %d key type: %d", ext_lib->type,
		 info->type);

	switch (ext_lib->type) {
	case SK_EXT_LIB_CCA:
		switch (info->type) {
		case SK_KEY_TYPE_EC:
			rc = SK_CCA_generate_ec_key_pair(ext_lib->cca,
					info->ec.curve_nid,
					secure_key, secure_key_size,
					debug);
			break;
		case SK_KEY_TYPE_RSA:
			rc = SK_CCA_generate_rsa_key_pair(ext_lib->cca,
					info->rsa.modulus_bits,
					info->rsa.pub_exp,
					secure_key, secure_key_size,
					debug);
			break;
		default:
			sk_debug(debug, "ERROR: Invalid key type: %d",
				 info->type);
			return -EINVAL;
		}
		break;

	case SK_EXT_LIB_EP11:
		switch (info->type) {
		case SK_KEY_TYPE_EC:
			rc = SK_EP11_generate_ec_key_pair(ext_lib->ep11,
					info->ec.curve_nid,
					secure_key, secure_key_size,
					debug);
			break;
		case SK_KEY_TYPE_RSA:
			rc = SK_EP11_generate_rsa_key_pair(ext_lib->ep11,
					info->rsa.modulus_bits,
					info->rsa.pub_exp,
					info->rsa.x9_31,
					secure_key, secure_key_size,
					debug);
			break;
		default:
			sk_debug(debug, "ERROR: Invalid key type: %d",
				 info->type);
			return -EINVAL;
		}
		break;

	default:
		sk_debug(debug, "ERROR: Invalid ext-lib type: %d",
			 ext_lib->type);
		return -EINVAL;
	}

	if (rc != 0) {
		sk_debug(debug, "ERROR: Failed to generate a key: rc: %d - %s",
			 rc, strerror(-rc));
		return rc;
	}

	return 0;
}

/**
 * Reenciphers a secure key with a new master key using the specified secure
 * key crypto library.
 *
 * @param secure_key        the key token containing an secure key
 * @param secure_key_size   the size of the key token
 * @param to_new            if true, reencipher with the MK in then NEW register
 * @param ext_lib           External secure key crypto library to use
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_OPENSSL_reencipher_secure_key(unsigned char *secure_key,
				     size_t secure_key_size, bool to_new,
				     const struct sk_ext_lib *ext_lib,
				     bool debug)
{
	int rc;

	if (ext_lib == NULL || secure_key == NULL)
		return -EINVAL;

	sk_debug(debug, "ext-lib type: %d to_new: %d", ext_lib->type, to_new);

	switch (ext_lib->type) {
	case SK_EXT_LIB_CCA:
		rc = SK_CCA_reencipher_key(ext_lib->cca, secure_key,
					   secure_key_size, to_new, debug);
		break;

	case SK_EXT_LIB_EP11:
		rc = SK_EP11_reencipher_key(ext_lib->ep11, secure_key,
					    secure_key_size, debug);
		break;

	default:
		sk_debug(debug, "ERROR: Invalid ext lib type: %d",
			 ext_lib->type);
		return -EINVAL;
	}

	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: Failed to reencipher a key: rc: %d - %s",
			 rc, strerror(-rc));
		return rc;
	}

	return 0;
}

/**
 * Extracts the public key from a secure key, and returns it as OpenSSL PKEY.
 *
 * @param secure_key        the key token containing an secure key
 * @param secure_key_size   the size of the key token
 * @param rsa_pss           if the secure key is a RSA key, return a PKEY of
 *                          type EVP_PKEY_RSA_PSS
 * @param pkey              On return: a PKEY containing the public key
 * @param ext_lib           External secure key crypto library to use
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_OPENSSL_get_secure_key_as_pkey(const unsigned char *secure_key,
				      size_t secure_key_size, bool rsa_pss,
				      EVP_PKEY **pkey,
				      const struct sk_ext_lib *ext_lib,
				      bool debug)
{
	int rc;

	if (ext_lib == NULL || secure_key == NULL || pkey == NULL)
		return -EINVAL;

	sk_debug(debug, "ext-lib type: %d rsa_pss: %d", ext_lib->type, rsa_pss);

	switch (ext_lib->type) {
	case SK_EXT_LIB_CCA:
		rc = SK_CCA_get_secure_key_as_pkey(ext_lib->cca, secure_key,
						   secure_key_size, rsa_pss,
						   pkey, debug);
		break;

	case SK_EXT_LIB_EP11:
		rc = SK_EP11_get_secure_key_as_pkey(ext_lib->ep11, secure_key,
						    secure_key_size, rsa_pss,
						    pkey, debug);
		break;

	default:
		sk_debug(debug, "ERROR: Invalid ext lib type: %d",
			 ext_lib->type);
		return -EINVAL;
	}

	if (rc != 0) {
		sk_debug(debug, "ERROR: Failed to get PKEY: rc: %d - %s",
			 rc, strerror(-rc));
		return rc;
	}

	sk_debug(debug, "pkey: %p", *pkey);
	return 0;
}

/**
 * Extracts the public key from a secure key, and calls the specified callback
 * function with the public key information.
 *
 * @param secure_key        the key token containing an secure key
 * @param secure_key_size   the size of the key token
 * @param pub_key_cb        the callback function to call with the public key
 * @param private           a private pointer passed as is to the callback
 * @param ext_lib           External secure key crypto library to use
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_OPENSSL_get_public_from_secure_key(const unsigned char *secure_key,
					  size_t secure_key_size,
					  sk_pub_key_func_t pub_key_cb,
					  void *private,
					  const struct sk_ext_lib *ext_lib,
					  bool debug)
{
	int rc;

	if (ext_lib == NULL || secure_key == NULL || pub_key_cb == NULL)
		return -EINVAL;

	sk_debug(debug, "ext-lib type: %d", ext_lib->type);

	switch (ext_lib->type) {
	case SK_EXT_LIB_CCA:
		rc = SK_CCA_get_public_from_secure_key(secure_key,
						       secure_key_size,
						       pub_key_cb, private,
						       debug);
		break;

	case SK_EXT_LIB_EP11:
		rc = SK_EP11_get_public_from_secure_key(secure_key,
							secure_key_size,
							pub_key_cb, private,
							debug);
		break;

	default:
		sk_debug(debug, "ERROR: Invalid ext lib type: %d",
			 ext_lib->type);
		return -EINVAL;
	}

	if (rc != 0) {
		sk_debug(debug, "ERROR: Failed to get PKEY: rc: %d - %s",
			 rc, strerror(-rc));
		return rc;
	}

	return 0;
}

/**
 * Converts a key given by the public key infos into an OpenSSL PKEY and
 * attaches the secure key together with secure key functions and private
 * pointer to it. If no secure key is provided, a public key only PKEY is
 * returned.
 *
 * @param secure_key        the secure key blob.
 *                          If NULL, a clear key PKEY is created.
 * @param secure_key_size   the size of the secure key blob (ignored if
 *                          secure_key is NULL)
 * @param pub_key           the public key info
 * @param rsa_pss           For RSA public keys: create a RSA-PSS type PKEY
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
int SK_OPENSSL_get_pkey(const unsigned char *secure_key, size_t secure_key_size,
			const struct sk_pub_key_info *pub_key, bool rsa_pss,
			const struct sk_funcs *sk_funcs, const void *private,
			EVP_PKEY **pkey, bool debug)
{
	int rc;

	if (pub_key == NULL)
		return -EINVAL;

	sk_debug(debug, "key type: %d", pub_key->type);

	switch (pub_key->type) {
	case SK_KEY_TYPE_EC:
		rc = sk_openssl_get_pkey_ec(secure_key, secure_key_size,
					    pub_key->ec.curve_nid,
					    pub_key->ec.prime_len,
					    pub_key->ec.x, pub_key->ec.y,
					    sk_funcs, private,
					    pkey, debug);
		if (rc != 0) {
			sk_debug(debug,
				 "ERROR: SK_OPENSSL_get_pkey_ec failed");
			return rc;
		}
		break;
	case SK_KEY_TYPE_RSA:
		rc = sk_openssl_get_pkey_rsa(secure_key, secure_key_size,
					     pub_key->rsa.modulus,
					     pub_key->rsa.modulus_len,
					     pub_key->rsa.pub_exp,
					     pub_key->rsa.pub_exp_len,
					     rsa_pss ? EVP_PKEY_RSA_PSS :
							EVP_PKEY_RSA,
					     sk_funcs, private,
					     pkey, debug);
		if (rc != 0) {
			sk_debug(debug,
				 "ERROR: SK_OPENSSL_get_pkey_rsa failed");
			return rc;
		}
		break;
	default:
		sk_debug(debug, "ERROR: Invalid key type: %d",
			 pub_key->type);
		return -EINVAL;
	}

	sk_debug(debug, "pkey: %p", pkey);

	return 0;
}

/**
 * Sets up a digest sign context with the specified PKEY.
 *
 * @param pkey              the PKEY to use
 * @param verify            if true a verify context is created, otherwise a
 *                          sign context
 * @param digest_nid        the NID of the digest algorithm to use. If
 *                          NID_undef, then the PKEY's default digest is used.
 * @param rsa_pss_params    RSA-PSS parameters (if PKEY is a RSA-PSS key)
 * @param md_ctx            On return: the MD context that was set up
 * @param pkey_ctx          On return: the PKEY context that was set up.
 *                          Note: The PKEY context value returned must not be
 *                          freed by the application, it will be freed
 *                          automatically when the MD context is freed.
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int SK_OPENSSL_setup_sign_context(EVP_PKEY *pkey, bool verify, int digest_nid,
				  struct sk_rsa_pss_params *rsa_pss_params,
				  EVP_MD_CTX **md_ctx, EVP_PKEY_CTX **pkey_ctx,
				  bool debug)
{
	EVP_PKEY_CTX *pctx = NULL;
	const EVP_MD *md = NULL;
	int rc, default_nid;
	EVP_MD_CTX *ctx;

	sk_debug(debug, "pkey: %p verify: %d digest_nid: %d", pkey, verify,
		 digest_nid);

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		sk_debug(debug, "ERROR: Failed to allocate the digest context");
		rc = -ENOMEM;
		goto out;
	}

	if (digest_nid != NID_undef) {
		md = EVP_get_digestbynid(digest_nid);
		if (md == NULL) {
			sk_debug(debug,
				 "ERROR: Requested digest not supported");
			rc = -ENOTSUP;
			goto out;
		}

		if (EVP_PKEY_get_default_digest_nid(pkey, &default_nid) == 2 &&
		    default_nid == 0) {
			sk_debug(debug, "ERROR: The signing algorithm requires "
				 "there to be no digest");
			md = NULL;
		}
	}

	if (verify)
		rc = EVP_DigestVerifyInit(ctx, &pctx, md, NULL, pkey);
	else
		rc = EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey);
	if (rc != 1) {
		sk_debug(debug, "ERROR: Failed to initialize the signing "
			 "operation");
		rc = -EIO;
		goto out;
	}

	if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA_PSS && rsa_pss_params != NULL) {
		sk_debug(debug, "RSA-PSS: saltlen: %d mgf_digest_nid: %d",
			 rsa_pss_params->salt_len,
			 rsa_pss_params->mgf_digest_nid);

		rc = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING);
		if (rc != 1) {
			sk_debug(debug,
				 "ERROR: Failed to set the PSS padding mode");
			rc = -EIO;
			goto out;
		}

		rc = EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
						      rsa_pss_params->salt_len);
		if (rc != 1) {
			sk_debug(debug,
				 "ERROR: Failed to set the PSS salt length");
			rc = -EIO;
			goto out;
		}

		if (rsa_pss_params->mgf_digest_nid != 0) {
			md = EVP_get_digestbynid(
					rsa_pss_params->mgf_digest_nid);
			if (md == NULL) {
				sk_debug(debug,
					 "ERROR: Requested MGF digest not "
					 "supported");
				rc = -ENOENT;
				goto out;
			}

			rc = EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md);
			if (rc != 1) {
				sk_debug(debug,
					 "ERROR: Failed to set the MGF md");
				rc = -EIO;
				goto out;
			}
		}
	}

	rc = 0;
	*md_ctx = ctx;
	*pkey_ctx = pctx;

out:
	if (rc != 0 && ctx != NULL)
		EVP_MD_CTX_free(ctx);

	return rc;
}

/**
 * Generate a certificate signing request using the secure key with the
 * specified subject name, certificate extensions (if any), and writes the
 * CSR to the specified file in PEM format.
 *
 * To renew an existing certificate, specify the existing certificate file with
 * renew_cert_filename, and the subject name is extracted from it. Any specified
 * subject name RDNs are added to the CSR. Also, the extensions are taken from
 * the existing certificate, and any specified extensions are added to the CSR.
 *
 * The CSR is signed using the secure key with an signing algorithm matching
 * the secure key type (ECDSA, RSA-PKCS, or RSA-PSS if rsa_pss_params is not
 * NULL), and the specified digest. If the digest nid is NID_undef, then a
 * default digest is used.
 *
 * @param secure_key        the key token containing an secure key
 * @param secure_key_size   the size of the key token
 * @param subject_rdns      an array of strings, each string representing an
 *                          RDN in the form '[+]type=value'. If the type is
 *                          prepended with a '+', then this RDN is added to the
 *                          previous one.
 * @param num_subject_rdns  number of RDN elements in the array.
 * @param subject_utf8      if true, RDNs of type MBSTRING_UTF8 are created,
 *                          otherwise type is MBSTRING_ASC is used.
 * @param renew_cert        if not NULL, specifies the an existing certificate
 *                          that is renewed.
 * @param extensions        an array of strings, each string representing an
 *                          certificate extension in the form 'type=value'.
 * @param num_extensions    number of extension elements in the array.
 * @param digest_nid        the OpenSSL digest nid to use with the signature
 *                          algorithm, or NID_undef to use the default
 * @param rsa_pss_params    if not NULL and the secure key is an RSA key, then
 *                          the CSR is signed with RSA-PSS using the specified
 *                          PSS parameters. Ignored if the secure key is an EC
 *                          key
 * @param csr               On return: the generated CSR. Must be freed by the
 *                          caller using X509_REQ_free.
 * @param ext_lib           External secure key crypto library to use
 * @param debug             if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success:
 *          -EINVAL: invalid parameter
 *          -ENOMEM: Failed to allocate memory
 *          -EBADMSG: an RDN or extension is not formatted correctly
 *          -EIO: OpenSSL failed to create the CSR
 *          -EEXIST: if one of the RDN name entries or extensions to add is a
 *                   duplicate
 *          -ENOTSUP: the specified digest is not supported
 *          any other errno from file I/O routines
 */
int SK_OPENSSL_generate_csr(const unsigned char *secure_key,
			    size_t secure_key_size,
			    const char *subject_rdns[], size_t num_subject_rdns,
			    bool subject_utf8, const X509 *renew_cert,
			    const char *extensions[], size_t num_extensions,
			    int digest_nid,
			    struct sk_rsa_pss_params *rsa_pss_params,
			    X509_REQ **csr,
			    const struct sk_ext_lib *ext_lib, bool debug)
{
	const STACK_OF(X509_EXTENSION) *cert_exts = NULL;
	X509_NAME *subject_name = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY *pkey = NULL;
	X509_REQ *req = NULL;
	int rc;

	if (secure_key == NULL || ext_lib == NULL || csr == NULL)
		return -EINVAL;
	if (renew_cert == NULL &&
	    (subject_rdns == NULL || num_subject_rdns == 0))
		return -EINVAL;
	if (num_extensions != 0 && extensions == NULL)
		return -EINVAL;

	rc = SK_OPENSSL_get_secure_key_as_pkey(secure_key, secure_key_size,
					       rsa_pss_params != NULL, &pkey,
					       ext_lib, debug);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: SK_OPENSSL_get_secure_key_as_pkey failed");
		goto out;
	}

	req = X509_REQ_new();
	if (req == NULL) {
		sk_debug(debug, "ERROR: X509_REQ_new failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = X509_REQ_set_version(req, 0L);
	if (rc != 1) {
		sk_debug(debug, "ERROR: X509_REQ_set_version failed: rc: %d",
			 rc);
		rc = -EIO;
		goto out;
	}

	if (renew_cert != NULL) {
		subject_name = X509_NAME_dup(X509_get_subject_name(renew_cert));
		cert_exts = X509_get0_extensions(renew_cert);
	}

	if (subject_rdns != NULL && num_subject_rdns > 0) {
		rc = SK_UTIL_build_subject_name(&subject_name, subject_rdns,
						num_subject_rdns, subject_utf8);
		if (rc != 0) {
			sk_debug(debug, "ERROR: Failed to parse the subject "
				 "name RDNs: %s", strerror(-rc));
			goto out;
		}
	}

	if (subject_name == NULL) {
		rc = -EINVAL;
		sk_debug(debug, "ERROR: Subject name can not be empty");
		goto out;
	}

	rc = X509_REQ_set_subject_name(req, subject_name);
	if (rc != 1) {
		rc = -EIO;
		sk_debug(debug,
			 "ERROR: Failed to set subject name into request");
		goto out;
	}

	rc = SK_UTIL_build_certificate_extensions(NULL, req, extensions,
						  num_extensions, cert_exts);
	if (rc != 0) {
		sk_debug(debug, "ERROR: Failed to parse the extensions: "
			 "%s", strerror(-rc));
		goto out;
	}

	rc = X509_REQ_set_pubkey(req, pkey);
	if (rc != 1) {
		sk_debug(debug, "ERROR: Failed to set the public key");
		rc = -EIO;
		goto out;
	}

	rc = SK_OPENSSL_setup_sign_context(pkey, false, digest_nid,
					   rsa_pss_params, &md_ctx, &pkey_ctx,
					   debug);
	if (rc != 0) {
		sk_debug(debug, "ERROR: SK_OPENSSL_setup_sign_context failed");
		goto out;
	}

	rc = X509_REQ_sign_ctx(req, md_ctx);
	if (rc <= 0) {
		sk_debug(debug,
			 "ERROR: Failed to perform the signing operation");
		rc = -EIO;
		goto out;
	}

	if (debug) {
		sk_debug(debug, "Certificate Signing Request created:");
		X509_REQ_print_fp(stderr, req);
	}

	*csr = req;
	req = NULL;
	rc = 0;

out:
	if (md_ctx != NULL)
		EVP_MD_CTX_free(md_ctx);
	if (subject_name != NULL)
		X509_NAME_free(subject_name);
	if (req != NULL)
		X509_REQ_free(req);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return rc;
}

/**
 * Generate a self signed certificate using the secure key with the
 * specified subject name, certificate extensions (if any), and writes the
 * certificate to the specified file in PEM format.
 *
 * To renew an existing certificate, specify the existing certificate file with
 * renew_cert_filename, and the subject name is extracted from it. Any specified
 * subject name RDNs are added to the certificate. Also, the extensions are
 * taken from the existing certificate, and any specified extensions are added
 * to the certificate.
 *
 * The certificate is signed using the secure key with an signing algorithm
 * matching the secure key type (ECDSA, RSA-PKCS, or RSA-PSS if rsa_pss_params
 * is not NULL), and the specified digest. If the digest nid is NID_undef, then
 * a default digest is used.
 *
 * @param secure_key        the key token containing an secure key
 * @param secure_key_size   the size of the key token
 * @param subject_rdns      an array of strings, each string representing an
 *                          RDN in the form '[+]type=value'. If the type is
 *                          prepended with a '+', then this RDN is added to the
 *                          previous one.
 * @param num_subject_rdns  number of RDN elements in the array.
 * @param subject_utf8      if true, RDNs of type MBSTRING_UTF8 are created,
 *                          otherwise type is MBSTRING_ASC is used.
 * @param renew_cert        if not NULL, specifies an existing certificate that
 *                          is renewed
 * @param extensions        an array of strings, each string representing an
 *                          certificate extension in the form 'type=value'.
 * @param num_extensions    number of extension elements in the array.
 * @param validity_days     number if day from the current date how long the
 *                          certificate is valid.
 * @param digest_nid        the OpenSSL digest nid to use with the signature
 *                          algorithm, or NID_undef to use the default
 * @param rsa_pss_params    if not NULL and the secure key is an RSA key, then
 *                          the certificate is signed with RSA-PSS using the
 *                          specified PSS parameters. Ignored if the secure
 *                          key is an EC key
 * @param ss_cert           On return: The generated self signed certificate.
 *                          Must be freed by the caller using X509_free.
 * @param ext_lib           External secure key crypto library to use
 * @param debug            if true, debug messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 *          -EINVAL: invalid parameter
 *          -ENOMEM: Failed to allocate memory
 *          -EBADMSG: an RDN or extension is not formatted correctly
 *          -EIO: OpenSSL failed to create the certificate
 *          -EEXIST: if one of the RDN name entries or extensions to add is a
 *                   duplicate
 *          -ENOTSUP: the specified digest is not supported
 *          any other errno from file I/O routines
 */
int SK_OPENSSL_generate_ss_cert(const unsigned char *secure_key,
				size_t secure_key_size,
				const char *subject_rdns[],
				size_t num_subject_rdns, bool subject_utf8,
				const X509 *renew_cert,
				const char *extensions[], size_t num_extensions,
				int validity_days, int digest_nid,
				struct sk_rsa_pss_params *rsa_pss_params,
				X509 **ss_cert,
				const struct sk_ext_lib *ext_lib, bool debug)
{
	const STACK_OF(X509_EXTENSION) *cert_exts = NULL;
	X509_NAME *subject_name = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY *pkey = NULL;
	X509 *cert = NULL;
	int rc;

	if (ext_lib == NULL || ss_cert == NULL)
		return -EINVAL;
	if (secure_key == NULL)
		return -EINVAL;
	if (renew_cert == NULL &&
	    (subject_rdns == NULL || num_subject_rdns == 0))
		return -EINVAL;
	if (num_extensions != 0 && extensions == NULL)
		return -EINVAL;

	rc = SK_OPENSSL_get_secure_key_as_pkey(secure_key, secure_key_size,
					       rsa_pss_params != NULL, &pkey,
					       ext_lib, debug);
	if (rc != 0) {
		sk_debug(debug,
			 "ERROR: SK_OPENSSL_get_secure_key_as_pkey failed");
		goto out;
	}

	cert = X509_new();
	if (cert == NULL) {
		sk_debug(debug, "ERROR: X509_new failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = X509_set_version(cert, 2L);
	if (rc != 1) {
		sk_debug(debug, "ERROR: X509_set_version failed: rc: %d", rc);
		rc = -EIO;
		goto out;
	}

	rc = SK_UTIL_generate_x509_serial_number(cert, SERIAL_NUMBER_BIT_SIZE);
	if (rc != 0) {
		sk_debug(debug, "ERROR: Failed to set the serial number: %s",
			 strerror(-rc));
		goto out;
	}

	if (renew_cert != NULL) {
		subject_name = X509_NAME_dup(X509_get_subject_name(renew_cert));
		cert_exts = X509_get0_extensions(renew_cert);
	}


	if (subject_rdns != NULL && num_subject_rdns > 0) {
		rc = SK_UTIL_build_subject_name(&subject_name, subject_rdns,
						num_subject_rdns, subject_utf8);
		if (rc != 0) {
			sk_debug(debug, "ERROR: Failed to parse the subject "
				 "name RDNs: %s", strerror(-rc));
			goto out;
		}
	}

	if (subject_name == NULL) {
		rc = -EINVAL;
		sk_debug(debug, "ERROR: Subject name can not be empty");
		goto out;
	}

	rc = X509_set_subject_name(cert, subject_name);
	if (rc != 1) {
		rc = -EIO;
		sk_debug(debug, "ERROR: Failed to set subject name into cert");
		goto out;
	}

	rc = X509_set_issuer_name(cert, subject_name);
	if (rc != 1) {
		rc = -EIO;
		sk_debug(debug, "ERROR: Failed to set issuer name into cert");
		goto out;
	}

	rc = SK_UTIL_build_certificate_extensions(cert, NULL, extensions,
						  num_extensions, cert_exts);
	if (rc != 0) {
		sk_debug(debug, "ERROR: Failed to parse the extensions: "
			 "%s", strerror(-rc));
		goto out;
	}

	if (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL) {
		rc = -EIO;
		sk_debug(debug,
			 "ERROR: Failed to set notBefore time inti cert");
		goto out;
	}

	if (X509_time_adj_ex(X509_getm_notAfter(cert),
			     validity_days, 0, NULL) == NULL) {
		rc = -EIO;
		sk_debug(debug, "ERROR: Failed to set notAfter time into cert");
		goto out;
	}

	rc = X509_set_pubkey(cert, pkey);
	if (rc != 1) {
		sk_debug(debug, "ERROR: Failed to set the public key");
		rc = -EIO;
		goto out;
	}

	rc = SK_OPENSSL_setup_sign_context(pkey, false, digest_nid,
					   rsa_pss_params, &md_ctx, &pkey_ctx,
					   debug);
	if (rc != 0) {
		sk_debug(debug, "ERROR: SK_OPENSSL_setup_sign_context failed");
		goto out;
	}

	rc = X509_sign_ctx(cert, md_ctx);
	if (rc <= 0) {
		sk_debug(debug,
			 "ERROR: Failed to perform the signing operation");
		rc = -EIO;
		goto out;
	}

	if (debug) {
		sk_debug(debug, "Self-signed Certificate created:");
		X509_print_fp(stderr, cert);
	}

	*ss_cert = cert;
	cert = NULL;
	rc = 0;

out:
	if (md_ctx != NULL)
		EVP_MD_CTX_free(md_ctx);
	if (subject_name != NULL)
		X509_NAME_free(subject_name);
	if (cert != NULL)
		X509_free(cert);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return rc;
}

