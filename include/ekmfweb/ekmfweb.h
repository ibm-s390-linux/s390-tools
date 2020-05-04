/*
 * libekmfweb - EKMFWeb client library
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_EKMFWEB_H
#define LIB_EKMFWEB_H

#include <stddef.h>
#include <stdbool.h>

typedef void CURL;

struct ekmf_config {
	/** The base URL of the server. Should use https:// ! */
	const char *base_url;
	/** Optional: File name of the CA bundle PEM file, or a name of a
	 *  directory the multiple CA certificates. If this is NULL, then the
	 *  default system path for CA certificates is used */
	const char *tls_ca;
	/** Optional: File name of the client certificate PEM file */
	const char *tls_client_cert;
	/** Optional: File name of the clients key PEM file */
	const char *tls_client_key;
	/** Optional: Passphrase to read the clients key PEM file */
	const char *tls_client_key_passphrase;
	/** Optional: File name of a PEM file holding a CA certificate of the
	 *  issuer */
	const char *tls_issuer_cert;
	/** Optional: File name of a PEM file containing the servers pinned
	 *  public key. Public key pinning requires that verify_peer or
	 *  verify_host (or both) is true. */
	const char *tls_pinned_pubkey;
	/** Optional: File name of a PEM file containing the server's
	 *  certificate. This can be used to allow peer verification with
	 *  self-signed server certificates */
	const char *tls_server_cert;
	/** If true, the peer certificate is verified */
	bool tls_verify_peer;
	/** If true, that the server certificate is for the server it is known
	 *  as (i.e. the hostname in the url) */
	bool tls_verify_host;
	/** Maximum number of redirects to follow. Zero means that redirects are
	 *  not followed. -1 means to infinitely follow redirects. */
	long max_redirs;
	/** File name of the login token (JSON Web Token) used for the last
	 *  login. */
	const char *login_token;
	/** File name of a file containing the client identity secure key blob.
	 *  This key represents the client identity against EKMFWeb. Some
	 *  requests sent to EKMFWeb are signed with this (secure) key */
	const char *identity_secure_key;
	/** File name of a PEM file containing the EKMFWeb servers public key
	 *  used to sign key export responses. */
	const char *ekmf_server_pubkey;
};

struct ekmf_cca_lib {
	void *cca_lib; /* Handle of CCA host library loaded via dlopen */
};

enum ekmf_ext_lib_type {
	EKMF_EXT_LIB_CCA = 1,
};

struct ekmf_ext_lib {
	enum ekmf_ext_lib_type type;
	union {
		struct ekmf_cca_lib *cca; /* Used if type = EKMF_EXT_LIB_CCA */
	};
};

/**
 * Connects to the specified server url and obtains the servers certificate
 * and its chain of signing certificates and stores them in the specified
 * PEM files.
 *
 * @param config            the configuration structure. Only the base_url must
 *                          be specified, all others are optional.
 * @param server_cert_pem   Optional: name of a PEM file to store the servers
 *                          certificate
 * @param server_pubkey_pem Optional: name of a PEM file to store the servers
 *                          public key (can be used for public key pinning)
 * @param ca_bundle_pem     Optional: name of a PEM file to store the CA
 *                          certificate chain as a bundle
 * @param verified          On return: If the server 's certificate has been
 *                          verified using the CA specification from the config
 *                          (if ca = NULL: default system CAs, otherwise path
 *                          or file to CAs).
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 */
int ekmf_get_server_cert_chain(const struct ekmf_config *config,
			       const char *server_cert_pem,
			       const char *server_pubkey_pem,
			       const char *ca_bundle_pem,
			       bool *verified, char **error_msg, bool verbose);

/**
 * Print the certificate(s) contained in the specified PEM file.
 *
 * @param cert_pem          the file name of the PEM file to print
 * @param verbose           if true, verbose messages are printed
 *
 * @returns -EIO if the file could not be opened. -ENOENT if the PEM file
 *          does not contain any certificates. 0 if success.
 */
int ekmf_print_certificates(const char *cert_pem, bool verbose);

/**
 * Checks if the login token stored in the file denoted by field login_token
 * of the config structure is valid or not. The file (if existent) contains a
 * JSON Web Token (JWT, see RFC7519). It is valid if the current date and time
 * is before its expiration time ("exp" claim), and after or equal its
 * not-before time ("nbf" claim).
 * Note: The signature (if any) of the JWT is not checked, nor any other JWT
 * fields.
 *
 * @param config            the configuration structure
 * @param valid             On return: true if the token is valid, false if not
 * @param login_token       On return: If not NULL: the login token, if the
 *                          token is still valid. The returned string must
 *                          be freed by the caller when no longer needed.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int ekmf_check_login_token(const struct ekmf_config *config, bool *valid,
			   char **login_token, bool verbose);

enum ekmf_key_type {
	EKMF_KEY_TYPE_ECC = 1,
	EKMF_KEY_TYPE_RSA = 2,
};

struct ekmf_key_gen_info {
	enum ekmf_key_type type;
	union {
		struct {
			int curve_nid;
		} ecc;
		struct {
			size_t modulus_bits;
			unsigned int pub_exp;
		} rsa;
	} params;
};

/**
 * Generate a secure identity key used to identify the client to EKMFWeb.
 * The secure key blob is stored in a file specified in field
 * identity_secure_key of the config structure. If an secure key already exists
 * at that location, it is overwritten.
 *
 * @param config            the configuration structure. Only field
 *                          identity_secure_key must be specified, all others
 *                          are optional.
 * @param info              key generation info, such as key type (ECC or RSA)
 *                          and key parameters.
 * @param ext_lib           External secure key crypto library to use
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 */
int ekmf_generate_identity_key(const struct ekmf_config *config,
			       const struct ekmf_key_gen_info *info,
			       const struct ekmf_ext_lib *ext_lib,
			       bool verbose);

/**
 * Re-encipher the secure identity key (form field identity_secure_key in
 * config) used to identify the client to EKMFWeb.
 * The secure key blob is encrypted using the HSM master key. Whenever the HSM
 * master key is being changed, the secure identity key must be re-enciphered.
 * You can either pro-actively re-encipher a secure key once the new master key
 * has been prepared (but not yet made active): to_new = true; or you can
 * re-encipher a secure key when the HSM master key has already been changed:
 * to_new = false. This requires that the HSM still has the old master key.
 * Not all HSMs support this.
 *
 * For pro-active re-encipherment it is suggested to store the re-enciphered
 * secure key on a separate place, until the new HSM master key has been made
 * active. Specify a file name in reenc_secure_key to do so. For an in-place
 * re-encipherment, set reenc_secure_key = NULL.
 *
 * @param config            the configuration structure. Only field
 *                          identity_secure_key must be specified, all others
 *                          are optional.
 * @param to_new            If true: the identity key is re-enciphered from the
 *                          current to the new master key.
 *                          If false: the identity key is re-enciphered from the
 *                          old to the current master key.
 * @param reenc_secure_key  if not NULL, then the re-enciphered secure key is
 *                          stored into the filename specified here. Otherwise
 *                          the re-enciphered secure key replaces the original
 *                          secure identity key.
 * @param ext_lib           External secure key crypto library to use
 * @param verbose           if true, verbose messages are printed
 *
 * @returns a negative errno in case of an error, 0 if success.
 * A -ENODEV indicates that the master keys are not loaded.
 */
int ekmf_reencipher_identity_key(const struct ekmf_config *config,
				 bool to_new, const char *reenc_secure_key,
				 const struct ekmf_ext_lib *ext_lib,
				 bool verbose);

struct ekmf_rsa_pss_params {
	int salt_len;        /* salt length in bytes, or OpenSSL constants
				RSA_PSS_SALTLEN_DIGEST (-1),
				RSA_PSS_SALTLEN_AUTO (-2), or
				RSA_PSS_SALTLEN_MAX(-3) */
	int mgf_digest_nid;  /* OpenSSl digest nid, or zero to use the same
				digest algorithm as the signature algorithm */
};

/**
 * Generate a certificate signing request using the secure identity key (field
 * identity_secure_key in config structure) with the specified subject name,
 * certificate extensions (if any), and writes the CSR to the specified file
 * in PEM format.
 *
 * To renew an existing certificate, specify renew_cert = true. In this case
 * the existing certificate (field sign_certificate in config struct) is read,
 * and the subject name is extracted from it. Any specified subject name RDNs
 * are added to the CSR. Also, the extensions are taken from the existing
 * certificate, and any specified extensions are added to the CSR.
 *
 * The CSR is signed using the secure identity key (field identity_secure_key in
 * config structure) with an signing algorithm matching the identity key (ECDSA,
 * RSA-PKCS, or RSA-PSS if rsa_pss is true), and the specified digest. If the
 * digest nid is zero, then a default digest is used.
 *
 * @param config            the configuration structure. Only field
 *                          identity_secure_key must be specified, all others
 *                          are optional.
 * @param subject_rdns      an array of strings, each string representing an
 *                          RDN in the form '[+]type=value'. If the type is
 *                          prepended with a '+', then this RDN is added to the
 *                          previous one.
 * @param num_subject_rdns  number of RDN elements in the array.
 * @param subject_utf8      if true, RDNs of type MBSTRING_UTF8 are created,
 *                          otherwise type is MBSTRING_ASC is used.
 * @param renew_cert_filename if not NULL, specifies the file name of a PEM file
 *                          containing an existing certificate that is renewed
 * @param extensions        an array of strings, each string representing an
 *                          certificate extension in the form 'type=value'.
 * @param num_extensions    number of extension elements in the array.
 * @param digest_nid        the OpenSSL digest nid to use with the signature
 *                          algorithm, or 0 to use the default
 * @param rsa_pss_params    if not NULL and the identity key is an RSA key, then
 *                          the CSR is signed with RSA-PSS using the specified
 *                          PSS parameters. Ignored if the identity key is an EC
 *                          key
 * @param csr_pem_filename  the name of the PEM file to which the CSR is written
 * @param new_hdr           if true, output "NEW" in the PEM header lines
 * @param ext_lib           External secure key crypto library to use
 * @param verbose           if true, verbose messages are printed
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
int ekmf_generate_csr(const struct ekmf_config *config,
		      const char *subject_rdns[], size_t num_subject_rdns,
		      bool subject_utf8, const char *renew_cert_filename,
		      const char *extensions[], size_t num_extensions,
		      int digest_nid,
		      struct ekmf_rsa_pss_params *rsa_pss_params,
		      const char *csr_pem_filename, bool new_hdr,
		      const struct ekmf_ext_lib *ext_lib, bool verbose);

/**
 * Generate a self signed certificate using the secure identity key (field
 * identity_secure_key in config structure) with the specified subject name,
 * certificate extensions (if any), and writes the certificate the specified
 * file in PEM format.
 *
 * To renew an existing certificate, specify renew_cert = true. In this case
 * the existing certificate (field sign_certificate in config struct) is read,
 * and the subject name is extracted from it. Any specified subject name RDNs
 * are added to the certificate. Also, the extensions are taken from the
 * existing certificate, and any specified extensions are added to the new
 * certificate.
 *
 * The certificate is signed using the secure identity key (field
 * identity_secure_key in config structure) with an signing algorithm matching
 * the identity key (ECDSA, RSA-PKCS, or RSA-PSS if rsa_pss is true), and the
 * specified digest. If the digest nid is zero, then a default digest is used.
 *
 * @param config            the configuration structure. Only field
 *                          identity_secure_key must be specified, all others
 *                          are optional.
 * @param subject_rdns      an array of strings, each string representing an
 *                          RDN in the form '[+]type=value'. If the type is
 *                          prepended with a '+', then this RDN is added to the
 *                          previous one.
 * @param num_subject_rdns  number of RDN elements in the array.
 * @param subject_utf8      if true, RDNs of type MBSTRING_UTF8 are created,
 *                          otherwise type is MBSTRING_ASC is used.
 * @param renew_cert_filename if not NULL, specifies the file name of a PEM file
 *                          containing an existing certificate that is renewed
 * @param extensions        an array of strings, each string representing an
 *                          certificate extension in the form 'type=value'.
 * @param num_extensions    number of extension elements in the array.
 * @param validity_days     number if day from the current date how long the
 *                          certificate is valid.
 * @param digest_nid        the OpenSSL digest nid to use with the signature
 *                          algorithm, or 0 to use the default
 * @param rsa_pss_params    if not NULL and the identity key is an RSA key, then
 *                          the certificate is signed with RSA-PSS using the
 *                          specified PSS parameters. Ignored if the identity
 *                          key is an EC key
 * @param cert_pem_filename the name of the PEM file to which the Certificate
 *                          is written
 * @param ext_lib           External secure key crypto library to use
 * @param verbose           if true, verbose messages are printed
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
int ekmf_generate_ss_cert(const struct ekmf_config *config,
			  const char *subject_rdns[], size_t num_subject_rdns,
			  bool subject_utf8, const char *renew_cert_filename,
			  const char *extensions[], size_t num_extensions,
			  int validity_days, int digest_nid,
			  struct ekmf_rsa_pss_params *rsa_pss_params,
			  const char *cert_pem_filename,
			  const struct ekmf_ext_lib *ext_lib, bool verbose);

/**
 * Request the EKMFWeb server's public signing key and store it into PEM file
 * specified in field server_pubkey of the config structure.
 *
 * To perform a single request, set curl_handle to NULL. This will cause the
 * function to initialize a new CURL handle, use it, and destroy it.
 * If you plan to perform multiple requests to the same host, supply the address
 * of a CURL pointer that is initially NULL. This function will then initialize
 * a new CURL handle on the first call. On subsequent calls, pass in the address
 * of the same CURL pointer so that the CURL handle is reused. After the last
 * request, the CURL handle must be destroyed by calling ekmf_curl_destroy).
 *
 * @param config            the configuration structure
 * @param curl_handle       address of a CURL handle used for reusing the same
 *                          CURL handle with multiple requests.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 */
int ekmf_get_public_key(const struct ekmf_config *config, CURL **curl_handle,
			char **error_msg, bool verbose);

/**
 * Requests a key to be retrieved from EKMFweb and imported under the current
 * HSM's master key.
 *
 * To perform a single request, set curl_handle to NULL. This will cause the
 * function to initialize a new CURL handle, use it, and destroy it.
 * If you plan to perform multiple requests to the same host, supply the address
 * of a CURL pointer that is initially NULL. This function will then initialize
 * a new CURL handle on the first call. On subsequent calls, pass in the address
 * of the same CURL pointer so that the CURL handle is reused. After the last
 * request, the CURL handle must be destroyed by calling ekmf_curl_destroy).
 *
 * @param config            the configuration structure
 * @param curl_handle       address of a CURL handle used for reusing the same
 *                          CURL handle with multiple requests.
 * @param key_uuid          the UUID of the key to retrieve
 * @param sess_ec_curve_nid The OpenSSL nid of the EC curve used for the session
 *                          ECC key. If 0, then the default curve is used.
 * @param sign_rsa_digest_nid The OpenSSL nid of a digest used to sign the
 *                          request with if the identity key is an RSA-type key.
 *                          If 0, then the default digest is used.
 *                          Ignored for ECC-type identity keys.
 * @param use_rsa_pss       If true, and the identity key is an RSA-type key,
 *                          use RSA-PSS to sign the request.
 * @param signature_kid     the Key ID for the signature of the request
 * @param key_blob          a buffer to store the retrieved key blob to
 * @param key_blob_length   On entry: the size ofthe buffer
 *                          On return: the size of the key blob retrieved
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param ext_lib           External secure key crypto library to use
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          retrieve the key
 */
int ekmf_retrieve_key(const struct ekmf_config *config, CURL **curl_handle,
		      const char *key_uuid, int sess_ec_curve_nid,
		      int sign_rsa_digest_nid, bool use_rsa_pss,
		      const char *signature_kid, unsigned char *key_blob,
		      size_t *key_blob_length, char **error_msg,
		      const struct ekmf_ext_lib *ext_lib, bool verbose);

/**
 * Close the connection to the EKMFWeb server by destroying the CURL handle.
 *
 * @param curl_handle       the CURL handle to destroy
 */
void ekmf_curl_destroy(CURL *curl_handle);

#endif
