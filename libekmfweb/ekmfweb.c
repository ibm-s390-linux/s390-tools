/*
 * libekmfweb - EKMFWeb client library
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <time.h>

#include <curl/curl.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <json-c/json.h>
#ifndef JSON_C_TO_STRING_NOSLASHESCAPE
#define JSON_C_TO_STRING_NOSLASHESCAPE (1 << 4)
#endif

#include "lib/zt_common.h"

#include "ekmfweb/ekmfweb.h"
#include "utilities.h"
#include "cca.h"

#define MAX_KEY_BLOB_SIZE		CCA_MAX_PKA_KEY_TOKEN_SIZE

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

#define CURL_ERROR_CHECK(rc, text, verbose, label)			\
		do {							\
			if (rc != CURLE_OK) {				\
				pr_verbose(verbose, "%s: %s", text,	\
					   curl_easy_strerror(rc));	\
				goto label;				\
			}						\
		} while (0)

struct curl_header_cb_data {
	struct curl_slist **headers;
	bool error;
	bool verbose;
};

struct curl_write_cb_data {
	json_tokener *tok;
	json_object *obj;
	bool error;
	bool verbose;
};

struct curl_sslctx_cb_data {
	const char *tls_server_cert;
	bool error;
	bool verbose;
};

#define CURL_CERTINFO_CERT	"Cert:"
#define HTTP_HDR_CONTENT_TYPE	"Content-Type:"

const char *accepted_content_types[] = { "application/json",
					 "text/x-json",
					 NULL};

/**
 * Extract the public key from a certificate in PEM format and store it into a
 * PEM file
 */
static int _ekmf_extract_pubkey(const char *cert, const char *pub_key_pem,
				bool verbose)
{
	EVP_PKEY *pkey = NULL;
	X509 *x509 = NULL;
	FILE *fp = NULL;
	BIO *b = NULL;
	int rc;

	b = BIO_new_mem_buf(cert, -1);
	if (b == NULL) {
		pr_verbose(verbose, "BIO_new_mem_buf failed");
		return -ENOMEM;
	}

	x509 = PEM_read_bio_X509(b, NULL, NULL, NULL);
	if (x509 == NULL) {
		pr_verbose(verbose, "PEM_read_bio_X509 failed");
		rc = -EIO;
		goto out;
	}

	pkey = X509_get0_pubkey(x509);
	if (pkey == NULL) {
		pr_verbose(verbose, "PEM_read_bio_X509 failed");
		rc = -EIO;
		goto out;
	}

	fp = fopen(pub_key_pem, "w");
	if (fp == NULL) {
		rc = -errno;
		pr_verbose(verbose, "File '%s': %s", pub_key_pem,
			   strerror(-rc));
		goto out;
	}

	if (!PEM_write_PUBKEY(fp, pkey)) {
		pr_verbose(verbose, "PEM_write_PUBKEY failed");
		rc = -EIO;
		goto out;
	}

out:
	if (fp != NULL)
		fclose(fp);
	if (x509 != NULL)
		X509_free(x509);
	if (b != NULL)
		BIO_free(b);
	return 0;
}

/**
 * Process the attributes of a certificate supplied by curl and writes the
 * PEM-format certificate attribute into the specified file pointer.
 */
static int _ekmf_process_certificate(FILE *fp, struct curl_slist *slist,
				     const char *pub_key_pem, bool verbose)
{
	char *cert;
	int rc;

	for (; slist != NULL; slist = slist->next) {
		pr_verbose(verbose, "%s", slist->data);

		if (strncmp(slist->data, CURL_CERTINFO_CERT,
					  strlen(CURL_CERTINFO_CERT)) == 0) {
			cert = slist->data + strlen(CURL_CERTINFO_CERT);

			if (fp != NULL) {
				if (fwrite(cert, strlen(cert), 1, fp) != 1) {
					rc = -errno;
					pr_verbose(verbose, "fwrite failed: %s",
						   strerror(-rc));
					return rc;
				}
			}

			if (pub_key_pem != NULL) {
				rc = _ekmf_extract_pubkey(cert, pub_key_pem,
							  verbose);
				if (rc != 0)
					return rc;
			}
		}
	}

	return 0;
}

/**
 * Callback called during curl_easy_perform() to handle received data.
 * Parse the (potentially partial) JSON data.
 */
static size_t _ekmf_dummy_write_cb(void *UNUSED(contents), size_t size,
				   size_t nmemb, void *UNUSED(userp))
{
	return size * nmemb;
}

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
			       bool *verified, char **error_msg, bool verbose)
{
	char error_str[CURL_ERROR_SIZE] = { 0 };
	struct curl_certinfo *ci;
	long do_verify = 1;
	FILE *fp = NULL;
	struct stat sb;
	int i, rc = 0;

	CURL *curl;

	if (config == NULL)
		return -EINVAL;

	if (error_msg != NULL)
		*error_msg = NULL;

	pr_verbose(verbose, "Getting certificate chain for '%s'",
		   config->base_url);

	curl = curl_easy_init();
	if (curl == NULL) {
		pr_verbose(verbose, "curl_easy_init failed");
		return CURLE_FAILED_INIT;
	}

	rc = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_str);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_ERRORBUFFER", verbose,
			 out);

	rc = curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose ? 1 : 0);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_VERBOSE", verbose, out);

	rc = curl_easy_setopt(curl, CURLOPT_URL, config->base_url);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_URL", verbose, out);

	if (config->tls_ca != NULL) {
		if (stat(config->tls_ca, &sb) != 0) {
			rc = -errno;
			pr_verbose(verbose, "stat failed on '%s': %s",
				   config->tls_ca, strerror(-rc));
			goto out;
		}

		if (S_ISDIR(sb.st_mode)) {
			rc = curl_easy_setopt(curl, CURLOPT_CAPATH,
					      config->tls_ca);
			CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CAPATH",
					 verbose, out);
		} else {
			rc = curl_easy_setopt(curl, CURLOPT_CAINFO,
					      config->tls_ca);
			CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CAINFO",
					 verbose, out);
		}
	}

	rc = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_FOLLOWLOCATION",
			 verbose, out);

	if (config->tls_client_cert != NULL) {
		rc = curl_easy_setopt(curl, CURLOPT_SSLCERT,
				      config->tls_client_cert);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSLCERT",
				 verbose, out);
		rc = curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSLCERTTYPE",
				 verbose, out);
	}

	if (config->tls_client_key != NULL) {
		rc = curl_easy_setopt(curl, CURLOPT_SSLKEY,
				      config->tls_client_key);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSLKEY", verbose,
				 out);
		rc = curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSLKEYTYPE",
				 verbose, out);

		if (config->tls_client_key_passphrase != NULL) {
			rc = curl_easy_setopt(curl, CURLOPT_KEYPASSWD,
					 config->tls_client_key_passphrase);
			CURL_ERROR_CHECK(rc,
					 "curl_easy_setopt CURLOPT_KEYPASSWD",
					 verbose, out);
		}
	}

retry:
	rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, do_verify);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSL_VERIFYPEER", verbose,
			 out);
	rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSL_VERIFYHOST", verbose,
			 out);

	rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			      _ekmf_dummy_write_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_WRITEFUNCTION", verbose,
			 out);

	rc = curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CERTINFO", verbose, out);

	rc = curl_easy_perform(curl);
	if (rc == CURLE_SSL_CACERT && do_verify != 0) {
		do_verify = 0;
		goto retry;
	}

	CURL_ERROR_CHECK(rc, "curl_easy_perform", verbose, out);

	/*
	 * If the first try worked, the server certificate could be verified
	 * with the specified or default CA.
	 */
	if (verified != NULL)
		*verified = do_verify != 0;

	rc = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &ci);
	CURL_ERROR_CHECK(rc, "curl_easy_getinfo CURLINFO_CERTINFO", verbose,
			 out);

	if (server_cert_pem != NULL) {
		fp = fopen(server_cert_pem, "w");
		if (fp == NULL) {
			rc = -errno;
			pr_verbose(verbose, "File '%s': %s", server_cert_pem,
				   strerror(-rc));
			goto out;
		}
	}

	pr_verbose(verbose, "%d certificates", ci->num_of_certs);

	/*
	 * Process all certificates in the list.
	 * First one is the server certificate, all following are
	 * CA certificates
	 */
	for (i = 0; i < ci->num_of_certs; i++) {
		pr_verbose(verbose, "Certificate %d:", i);

		rc = _ekmf_process_certificate(fp, ci->certinfo[i], i == 0 ?
						     server_pubkey_pem : NULL,
					       verbose);
		if (rc != 0)
			break;

		if (i == 0) {
			if (fp != NULL)
				fclose(fp);
			fp = NULL;

			/*
			 * Save CA-chain if requested, but only if the
			 * server certificate wasn't verified by the specified
			 * or default CA.
			 */
			if (ci->num_of_certs > 1 && ca_bundle_pem != NULL &&
			    do_verify == 0) {
				fp = fopen(ca_bundle_pem, "w");
				if (fp == NULL) {
					rc = -errno;
					pr_verbose(verbose, "File '%s': %s",
						   ca_bundle_pem,
						   strerror(-rc));
					break;
				}
			}
		}
	}

out:
	if (fp != NULL)
		fclose(fp);

	if (rc > 0 && error_msg != NULL && *error_msg == NULL) {
		pr_verbose(verbose, "Error: %s", error_str);
		if (asprintf(error_msg, "CURL: %s", strlen(error_str) > 0 ?
				error_str : curl_easy_strerror(rc)) < 0) {
			pr_verbose(verbose, "asprintf failed");
			rc = -ENOMEM;
		}
	}

	curl_easy_cleanup(curl);

	if (rc > 0)
		rc = -EIO;
	return rc;
}

/**
 * Callback called during curl_easy_perform() to handle received headers.
 * Check for the expected response content type.
 */
static size_t _ekmf_header_cb(void *contents, size_t size, size_t nmemb,
			     void *userp)
{
	struct curl_header_cb_data *cb = (struct curl_header_cb_data *)userp;
	size_t num = size * nmemb;
	size_t ofs;
	char *hdr = contents;
	char *val, *str;
	int i;

	if (num < 2)
		return num;

	if (cb->headers != NULL) {
		str = strndup((char *)contents, num - 2);
		if (str == NULL) {
			pr_verbose(cb->verbose, "strndup failed");
			return 0;
		}
		*cb->headers = curl_slist_append(*cb->headers, str);
		free(str);
		if (*cb->headers == NULL) {
			pr_verbose(cb->verbose, "curl_slist_append failed");
			return 0;
		}
	}

	if (num < strlen(HTTP_HDR_CONTENT_TYPE))
		goto out;

	if (strncasecmp(hdr, HTTP_HDR_CONTENT_TYPE,
			strlen(HTTP_HDR_CONTENT_TYPE)) != 0)
		goto out;

	ofs = strlen(HTTP_HDR_CONTENT_TYPE);
	val = hdr + ofs;
	while (*val == ' ' && ofs < num) {
		ofs++;
		val++;
	}
	if (ofs >= num)
		goto out;

	for (i = 0; accepted_content_types[i] != NULL; i++) {
		if (num - ofs >= strlen(accepted_content_types[i]) &&
		    strncasecmp(val, accepted_content_types[i],
				strlen(accepted_content_types[i])) == 0)
			goto out;
	}

	cb->error = true;
	pr_verbose(cb->verbose, "Unexpected response Content-Type: %.*s",
		   (int)(num - ofs), val);
	return 0;

out:
	return num;
}

/**
 * Callback called during curl_easy_perform() to handle received data.
 * Parse the (potentially partial) JSON data.
 */
static size_t _ekmf_write_cb(void *contents, size_t size, size_t nmemb,
			    void *userp)
{
	struct curl_write_cb_data *cb = (struct curl_write_cb_data *)userp;
	enum json_tokener_error jerr;
	size_t num = size * nmemb;

	pr_verbose(cb->verbose, "Response Data: ->%.*s<-", (int)num,
		   (char *)contents);

	if (cb->obj != NULL) {
		pr_verbose(cb->verbose, "JSON data already complete, but "
			   "additional data received");
		cb->error = true;
		return 0;
	}

	cb->obj = json_tokener_parse_ex(cb->tok, (const char *)contents, num);

	if (cb->obj == NULL) {
		jerr = json_tokener_get_error(cb->tok);
		if (jerr == json_tokener_continue)
			goto out;

		cb->error = true;
		pr_verbose(cb->verbose, "json_tokener_parse_ex failed: %s",
			   json_tokener_error_desc(jerr));
		return 0;
	}

out:
	return num;
}

/**
 * Extracts the EKMFWeb API error information form the response object.
 */
static int _ekmf_get_api_error(json_object *response_obj, char **error_msg)
{
	json_object *field;
	int code;

	if (response_obj == NULL || error_msg == NULL)
		return -EINVAL;

	if (!json_object_is_type(response_obj, json_type_object))
		return -EBADMSG;

	if (!json_object_object_get_ex(response_obj, "code", &field))
		return -EBADMSG;
	if (!json_object_is_type(field, json_type_int))
		return -EBADMSG;
	code = json_object_get_int(field);

	if (!json_object_object_get_ex(response_obj, "message", &field))
		return -EBADMSG;
	if (!json_object_is_type(field, json_type_string))
		return -EBADMSG;

	if (asprintf(error_msg, "EKMFWeb: %d: %s", code,
		     json_object_get_string(field)) < 0)
		return -ENOMEM;

	return 0;
}

/**
 * This callback called before the SSL handshake is performed.
 * It adds a pinned server certificate to the SSL certificate store, so
 * that it is treated as trusted, although it might be self-signed.
 */
static CURLcode _ekmf_sslctx_cb(CURL *UNUSED(curl), void *sslctx, void *parm)
{
	struct curl_sslctx_cb_data *sslctx_cb = parm;
	SSL_CTX *ssl_ctx = (SSL_CTX *)sslctx;
	X509_STORE *store;
	X509 *cert = NULL;
	int rc;

	if (ssl_ctx == NULL || sslctx_cb == NULL)
		return CURLE_ABORTED_BY_CALLBACK;

	if (sslctx_cb->tls_server_cert == NULL)
		return CURLE_OK;

	store = SSL_CTX_get_cert_store(ssl_ctx);
	if (store == NULL) {
		pr_verbose(sslctx_cb->verbose, "Failed to get SSL Store");
		return CURLE_ABORTED_BY_CALLBACK;
	}

	rc = read_x509_certificate(sslctx_cb->tls_server_cert, &cert);
	if (rc != 0) {
		pr_verbose(sslctx_cb->verbose, "Failed to read the server "
			   "certificate from file '%s'",
			   sslctx_cb->tls_server_cert);
		return CURLE_ABORTED_BY_CALLBACK;
	}

	rc = X509_STORE_add_cert(store, cert);
	if (rc != 1) {
		pr_verbose(sslctx_cb->verbose, "Failed to add server "
			   "certificate to SSL Store");
		X509_free(cert);
		return CURLE_ABORTED_BY_CALLBACK;
	}

	X509_free(cert);
	return CURLE_OK;
}

/**
 * Perform an HTTP request to the url constructed from the base_url in config
 * and th uri specified using the specified HTTP request.
 * The config structure contains information about TLS certificates.
 * If specified, it serializes the request data (JSON) and sends it to the
 * server. The response data (JSON) is parsed and returned in the response data.
 * If the response content type is not JSON, then an error is returned.
 * The HTTP status code is returned in status_code.
 *
 * @param config            the configuration structure
 * @param uri               the uri (and query parameters) to concatenate to the
 *                          base_url from the config structure.
 * @param request           the HTTP request to perform (e.g. GET, PUT, POST)
 * @param request_data      the JSON data to be sent with the request.
 * @param request_headers   a NULL terminated list of pointers to HTTP headers
 *                          to send along with the request. Can be NULL.
 * @param login_token       if not NULL, a Bearer token to authorize with
 * @param response_data     on return the JSON response data is returned. When
 *                          no longer needed, it must be released using
 *                          json_object_put()
 * @param response headers  address of a curl_slist to add response headers to,
 *                          or NULL to not return any headers.
 * @param status_code       on return the HTTP status code is returned
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param curl              a CURL handle to perform the request with.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno or a positive CURL error code in
 *          case of an error
 */
static int _ekmf_perform_request(const struct ekmf_config *config,
				 const char *uri, const char *request,
				 json_object *request_data,
				 char **request_headers,
				 const char *login_token,
				 json_object **response_data,
				 struct curl_slist **response_headers,
				 long *status_code, char **error_msg,
				 CURL *curl, bool verbose)
{
	struct curl_header_cb_data header_cb = { 0 };
	struct curl_sslctx_cb_data sslctx_cb = { 0 };
	struct curl_write_cb_data write_cb = { 0 };
	char error_str[CURL_ERROR_SIZE] = { 0 };
	struct curl_slist *list = NULL;
	char *url = NULL;
	const char *str;
	struct stat sb;
	char *auth_hdr;
	int i, rc;

	if (config == NULL || uri == NULL || request == NULL ||
	    status_code == NULL || curl == NULL)
		return -EINVAL;

	if (error_msg != NULL)
		*error_msg = NULL;

	if (asprintf(&url, "%s%s", config->base_url, uri) < 0) {
		pr_verbose(verbose, "asprintf failed");
		return -ENOMEM;
	}

	pr_verbose(verbose, "Performing request for '%s'", url);

	curl_easy_reset(curl);

	rc = curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose ? 1 : 0);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_VERBOSE", verbose, out);

	rc = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_str);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_ERRORBUFFER", verbose,
			 out);

	rc = curl_easy_setopt(curl, CURLOPT_URL, url);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_URL", verbose, out);

	rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
			 config->tls_verify_peer ? 1L : 0L);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSL_VERIFYPEER", verbose,
			 out);
	rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
			 config->tls_verify_host ? 2L : 0L);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSL_VERIFYHOST", verbose,
			 out);

	if (config->tls_ca != NULL) {
		if (stat(config->tls_ca, &sb) != 0) {
			rc = -errno;
			pr_verbose(verbose, "stat failed on '%s': %s",
				   config->tls_ca, strerror(-rc));
			goto out;
		}

		if (S_ISDIR(sb.st_mode)) {
			rc = curl_easy_setopt(curl, CURLOPT_CAPATH,
					      config->tls_ca);
			CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CAPATH",
					 verbose, out);
		} else {
			rc = curl_easy_setopt(curl, CURLOPT_CAINFO,
					      config->tls_ca);
			CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CAINFO",
					 verbose, out);
		}
	}

	if (config->tls_client_cert != NULL) {
		rc = curl_easy_setopt(curl, CURLOPT_SSLCERT,
				      config->tls_client_cert);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSLCERT",
				 verbose, out);
		rc = curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSLCERTTYPE",
				 verbose, out);
	}

	if (config->tls_client_key != NULL) {
		rc = curl_easy_setopt(curl, CURLOPT_SSLKEY,
				      config->tls_client_key);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSLKEY", verbose,
				 out);
		rc = curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSLKEYTYPE",
				 verbose, out);

		if (config->tls_client_key_passphrase != NULL) {
			rc = curl_easy_setopt(curl, CURLOPT_KEYPASSWD,
					 config->tls_client_key_passphrase);
			CURL_ERROR_CHECK(rc,
					 "curl_easy_setopt CURLOPT_KEYPASSWD",
					 verbose, out);
		}
	}

	if (config->tls_issuer_cert != NULL) {
		rc = curl_easy_setopt(curl, CURLOPT_ISSUERCERT,
				      config->tls_issuer_cert);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_ISSUERCERT",
				 verbose, out);
	}

	if (config->tls_pinned_pubkey != NULL) {
		rc = curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY,
				 config->tls_pinned_pubkey);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_PINNEDPUBLICKEY",
				 verbose, out);
	}

	if (config->max_redirs > 0) {
		rc = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_FOLLOWLOCATION",
				 verbose, out);
		rc = curl_easy_setopt(curl, CURLOPT_MAXREDIRS,
				      config->max_redirs);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_MAXREDIRS",
				 verbose, out);
		rc = curl_easy_setopt(curl, CURLOPT_POSTREDIR,
				      CURL_REDIR_POST_ALL);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_POSTREDIR",
				 verbose, out);
	} else {
		rc = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_FOLLOWLOCATION",
				 verbose, out);
	}

	if (strcmp(request, "GET") == 0) {
		rc = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, NULL);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CUSTOMREQUEST",
				 verbose, out);
		rc = curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_HTTPGET",
				 verbose, out);
	} else {
		rc = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST,
				      request);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_CUSTOMREQUEST",
				 verbose, out);

		if (request_data != NULL) {
			rc = curl_easy_setopt(curl, CURLOPT_POST, 1L);
			CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_POST",
					 verbose, out);

			list = curl_slist_append(list,
				"Content-Type: application/json;charset=UTF-8");
			if (list == NULL) {
				pr_verbose(verbose, "curl_slist_append failed");
				rc = -ENOMEM;
				goto out;
			}

			/*
			 * The memory returned by json_object_to_json_string_ext
			 * is freed when the JSON object is freed.
			 */
			str = json_object_to_json_string_ext(request_data,
						JSON_C_TO_STRING_PLAIN |
						JSON_C_TO_STRING_NOSLASHESCAPE);
			pr_verbose(verbose, "Request Data: ->%s<-", str);
			rc = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, str);
			CURL_ERROR_CHECK(rc,
					 "curl_easy_setopt CURLOPT_POSTFIELDS",
					 verbose, out);
		}
	}

	list = curl_slist_append(list, "Accept: application/json");
	if (list == NULL) {
		pr_verbose(verbose, "curl_slist_append failed");
		rc = -ENOMEM;
		goto out;
	}
	list = curl_slist_append(list, "Accept-Charset: UTF-8");
	if (list == NULL) {
		pr_verbose(verbose, "curl_slist_append failed");
		rc = -ENOMEM;
		goto out;
	}
	/* Disable "Expect: 100-continue" */
	list = curl_slist_append(list, "Expect:");
	if (list == NULL) {
		pr_verbose(verbose, "curl_slist_append failed");
		rc = -ENOMEM;
		goto out;
	}

	if (login_token != NULL) {
		/*
		 * Note: We could alternatively use CURLOPT_XOAUTH2_BEARER, with
		 * CURLOPT_HTTPAUTH using CURLAUTH_BEARER, but this seems to
		 * cause a memory leak in some curl versions.
		 */
		if (asprintf(&auth_hdr, "Authorization: Bearer %s",
			     login_token) < 0) {
			pr_verbose(verbose, "asprintf failed");
			rc = -ENOMEM;
			goto out;
		}
		list = curl_slist_append(list, auth_hdr);
		free(auth_hdr);
		if (list == NULL) {
			pr_verbose(verbose, "curl_slist_append failed");
			rc = -ENOMEM;
			goto out;
		}
	}

	for (i = 0; request_headers != NULL &&
		    request_headers[i] != NULL; i++) {
		list = curl_slist_append(list, request_headers[i]);
		if (list == NULL) {
			pr_verbose(verbose, "curl_slist_append failed");
			rc = -ENOMEM;
			goto out;
		}
	}

	rc = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_HTTPHEADER", verbose,
			 out);

	header_cb.headers = response_headers;
	header_cb.verbose = verbose;

	write_cb.verbose = verbose;
	write_cb.tok = json_tokener_new();
	if (write_cb.tok == NULL) {
		pr_verbose(verbose, "json_tokener_new failed");
		rc = -ENOMEM;
		goto out;
	}

	sslctx_cb.tls_server_cert = config->tls_server_cert;
	sslctx_cb.verbose = verbose;

	rc = curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, _ekmf_header_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_HEADERFUNCTION", verbose,
			 out);
	rc = curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&header_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_HEADERDATA", verbose,
			 out);

	rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _ekmf_write_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_WRITEFUNCTION", verbose,
			 out);
	rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&write_cb);
	CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_WRITEDATA", verbose,
			 out);

	if (config->tls_server_cert != NULL) {
		rc = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION,
				      _ekmf_sslctx_cb);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt "
				 "CURLOPT_SSL_CTX_FUNCTION", verbose, out);
		rc = curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA,
				      &sslctx_cb);
		CURL_ERROR_CHECK(rc, "curl_easy_setopt CURLOPT_SSL_CTX_DATA",
				 verbose, out);
	}

	rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		pr_verbose(verbose, "curl_easy_perform for '%s' failed: %s",
			   url, curl_easy_strerror(rc));
		pr_verbose(verbose, "Error: %s", error_str);

		if (header_cb.error) {
			pr_verbose(verbose, "Unexpected Content-Type");
			rc = -EBADMSG;
			if (error_msg != NULL && *error_msg == NULL) {
				if (asprintf(error_msg, "Unexpected response "
					     "Content-Type") < 0)
					error_msg = NULL;
			}
		}
		if (write_cb.error) {
			pr_verbose(verbose, "JSON parsing failed");
			rc = -EBADMSG;
			if (error_msg != NULL && *error_msg == NULL) {
				if (asprintf(error_msg, "Failed to JSON parse "
					     "the response content") < 0)
					error_msg = NULL;
			}
		}
		goto out;
	}

	rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status_code);
	CURL_ERROR_CHECK(rc, "curl_easy_getinfo CURLINFO_RESPONSE_CODE",
			 verbose, out);

	if (*status_code >= 400 && write_cb.obj != NULL &&
	    error_msg != NULL && *error_msg == NULL) {
		rc = _ekmf_get_api_error(write_cb.obj, error_msg);
		json_object_put(write_cb.obj);
		write_cb.obj = NULL;
		if (rc != 0)
			goto out;
	}

	if (response_data != NULL) {
		*response_data = write_cb.obj;
	} else {
		if (write_cb.obj != NULL)
			json_object_put(write_cb.obj);
	}

out:
	if (write_cb.tok != NULL)
		json_tokener_free(write_cb.tok);
	if (url != NULL)
		free(url);
	if (list != NULL)
		curl_slist_free_all(list);

	if (rc > 0 && error_msg != NULL && *error_msg == NULL) {
		if (asprintf(error_msg, "CURL: %s", strlen(error_str) > 0 ?
				error_str : curl_easy_strerror(rc)) < 0) {
			pr_verbose(verbose, "asprintf failed");
			rc = -ENOMEM;
		}
	}

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, NULL);

	return rc;
}

/**
 * Print the certificate(s) contained in the specified PEM file.
 *
 * @param cert_pem          the file name of the PEM file to print
 * @param verbose           if true, verbose messages are printed
 *
 * @returns -EIO if the file could not be opened. -ENOENT if the PEM file
 *          does not contain any certificates. 0 if success.
 */
int ekmf_print_certificates(const char *cert_pem, bool verbose)
{
	int rc = -ENOENT;
	X509 *cert;
	FILE *fp;

	if (cert_pem == NULL)
		return -EINVAL;

	fp = fopen(cert_pem, "r");
	if (fp == NULL) {
		pr_verbose(verbose, "File '%s': %s", cert_pem, strerror(errno));
		return -EIO;
	}

	while (1) {
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (cert == NULL)
			break;

		X509_print_ex_fp(stdout, cert, 0, X509_FLAG_NO_EXTENSIONS);

		X509_free(cert);
		rc = 0;
	}

	fclose(fp);
	return rc;
}

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
			   char **login_token, bool verbose)
{
	json_object *jwt_payload = NULL;
	json_object *exp_claim = NULL;
	json_object *nbf_claim = NULL;
	char *token = NULL;
	size_t count, size;
	int64_t exp, nbf;
	FILE *fp = NULL;
	struct stat sb;
	int rc = 0;
	time_t now;

	if (config == NULL || valid == NULL)
		return -EINVAL;

	if (config->login_token == NULL) {
		*valid = false;
		return 0;
	}

	if (login_token != NULL)
		*login_token = NULL;

	pr_verbose(verbose, "Reading login token from file : '%s'",
		   config->login_token);

	if (stat(config->login_token, &sb)) {
		rc = -errno;
		pr_verbose(verbose, "stat on file %s failed: '%s'",
			   config->login_token, strerror(-rc));
		return rc;
	}
	size = sb.st_size;
	if (size == 0) {
		pr_verbose(verbose, "File %s is empty", config->login_token);
		rc = -EIO;
		goto out;
	}

	token = (char *)malloc(size + 1);
	if (token == NULL) {
		pr_verbose(verbose, "Failed to allocate a buffer");
		return -ENOMEM;
	}

	fp = fopen(config->login_token, "r");
	if (fp == NULL) {
		rc = -errno;
		pr_verbose(verbose, "Failed to open file %s: '%s'",
			   config->login_token, strerror(-rc));
		goto out;
	}

	count = fread(token, 1, size, fp);
	if (count != size) {
		pr_verbose(verbose, "Failed to read the token");
		rc = -EIO;
		goto out;
	}
	token[size] = '\0';
	if (token[size - 1] == '\n')
		token[size - 1] = '\0';

	fclose(fp);
	fp = NULL;

	time(&now);
	*valid = true;

	rc = parse_json_web_token(token, NULL, &jwt_payload, NULL, NULL);
	if (rc != 0) {
		pr_verbose(verbose, "parse_json_web_token failed");
		goto out;
	}

	if (json_object_object_get_ex(jwt_payload, "exp", &exp_claim) &&
	    json_object_is_type(exp_claim, json_type_int)) {
		exp = json_object_get_int64(exp_claim);
		if (exp == 0) {
			pr_verbose(verbose,
				   "failed to get value from exp claim");
			rc = -EIO;
			goto out;
		}

		if (now > exp) {
			pr_verbose(verbose, "JWT is expired");
			*valid = false;
		}
	}

	if (json_object_object_get_ex(jwt_payload, "nbf", &nbf_claim) &&
	    json_object_is_type(nbf_claim, json_type_int)) {
		nbf = json_object_get_int64(nbf_claim);
		if (nbf == 0) {
			pr_verbose(verbose,
				   "failed to get value from nbf claim");
			rc = -EIO;
			goto out;
		}

		if (now <= nbf) {
			pr_verbose(verbose, "JWT is not yet valid");
			*valid = false;
		}
	}

	if (login_token != NULL && *valid) {
		*login_token = token;
		token = NULL;
	}

out:
	if (jwt_payload != NULL)
		json_object_put(jwt_payload);
	if (token != NULL)
		free(token);
	if (fp != NULL)
		fclose(fp);

	return rc;
}

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
			       const struct ekmf_ext_lib *ext_lib, bool verbose)
{
	unsigned char key_blob[MAX_KEY_BLOB_SIZE];
	size_t key_blob_size = sizeof(key_blob);
	int rc;

	if (config == NULL || info == NULL || ext_lib == NULL)
		return -EINVAL;
	if (config->identity_secure_key == NULL)
		return -EINVAL;

	switch (ext_lib->type) {
	case EKMF_EXT_LIB_CCA:
		switch (info->type) {
		case EKMF_KEY_TYPE_ECC:
			rc = cca_generate_ecc_key_pair(ext_lib->cca,
					info->params.ecc.curve_nid,
					key_blob, &key_blob_size, verbose);
			break;
		case EKMF_KEY_TYPE_RSA:
			rc = cca_generate_rsa_key_pair(ext_lib->cca,
					info->params.rsa.modulus_bits,
					info->params.rsa.pub_exp,
					key_blob, &key_blob_size, verbose);
			break;
		default:
			pr_verbose(verbose, "Invalid key type: %d", info->type);
			return -EINVAL;
		}
		break;
	default:
		pr_verbose(verbose, "Invalid ext lib type: %d", ext_lib->type);
		return -EINVAL;
	}

	if (rc != 0) {
		pr_verbose(verbose, "Failed to generate a key: rc: %d - %s",
			   rc, strerror(-rc));
		return rc;
	}

	rc = write_key_blob(config->identity_secure_key, key_blob,
			    key_blob_size);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to write the key to file '%s' "
			   "rc: %d - %s", config->identity_secure_key, rc,
			   strerror(-rc));
		return rc;
	}

	pr_verbose(verbose, "Secure identity key generated (%lu bytes) "
		   "and written to file '%s'", key_blob_size,
		   config->identity_secure_key);

	return 0;
}

/**
 * Library constructor
 */
void __attribute__ ((constructor)) ekmf_init(void)
{
	curl_global_init(CURL_GLOBAL_ALL);
}

/**
 * Library destructor
 */
void __attribute__ ((destructor)) ekmf_exit(void)
{
	curl_global_cleanup();
}


