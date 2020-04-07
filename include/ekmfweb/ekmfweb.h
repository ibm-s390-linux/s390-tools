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

#endif
