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
#include <openssl/rsa.h>
#include <openssl/evp.h>

#include <json-c/json.h>
#ifndef JSON_C_TO_STRING_NOSLASHESCAPE
#define JSON_C_TO_STRING_NOSLASHESCAPE (1 << 4)
#endif

#include "lib/zt_common.h"

#include "ekmfweb/ekmfweb.h"
#include "utilities.h"
#include "cca.h"

#define SERIAL_NUMBER_BIT_SIZE		159

#define DEFAULT_SESSION_EC_KEY_CURVE	NID_secp521r1

#define MAX_KEY_BLOB_SIZE		CCA_MAX_PKA_KEY_TOKEN_SIZE
#define MAX_SYM_KEY_BLOB_SIZE		CCA_MAX_SYM_KEY_TOKEN_SIZE

#define EKMF_URI_SYSTEM_PUBKEY		"/api/v1/system/publicKey"
#define EKMF_URI_SYSTEM_SETTINGS	"/api/v1/system/settings"
#define EKMF_URI_SYSTEM_FEATURES	"/api/v1/system/features"
#define EKMF_URI_SYSTEM_LOGIN		"/api/v1/system/login"
#define EKMF_URI_KEYS_GENERATE		"/api/v1/keys"
#define EKMF_URI_KEYS_EXPORT		"/api/v1/keys/%s/export"
#define EKMF_URI_KEYS_TAGS		"/api/v1/keys/%s/tags"
#define EKMF_URI_KEYS_EXPORT_CONTROL	"/api/v1/keys/%s/exportControl"
#define EKMF_URI_KEYS_SET_TAG		"/api/v1/keys/%s/tags/%s"
#define EKMF_URI_KEYS_GET		"/api/v1/keys/%s"
#define EKMF_URI_KEYS_SET_STATE		"/api/v1/keys/%s"
#define EKMF_URI_KEYS_LIST		"/api/v1/keys"			\
					"?state=%s"			\
					"&orderBy=%s"			\
					"&namePattern=%s"		\
					"&tags=%s"
#define EKMF_URI_KEYS_LIST_STATE	"&state="
#define EKMF_URI_TEMPLATE_GET		"/api/v1/templates/%s"
#define EKMF_URI_TEMPLATE_LIST		"/api/v1/templates"		\
					"?templateStates=%s"		\
					"&orderBy=%s"			\
					"&namePattern=%s"
#define EKMF_URI_TEMPLATE_SEQNO		"/api/v1/templates/%s/sequenceNumber"

#define LIST_ELEMENTS_PER_PAGE		20
#define TEMPLATE_STATE_ACTIVE		"ACTIVE"
#define KEY_STATE_ACTIVE		"ACTIVE"
#define KEY_ALGORITHM_AES		"AES"
#define KEYSTORE_TYPE_PERV_ENCR		"PERVASIVE_ENCRYPTION"
#define ORDER_BY_NAME_ASC		"name%3Aasc"
#define ORDER_BY_LABEL_ASC		"label%3Aasc"
#define SETTING_ID_IDENTITY_TEMPLATE	"ekmf.web.public.identity.template"
#define SETTING_ID_XTS_KEY1_TEMPLATE	"ekmf.web.public.xts.template.1"
#define SETTING_ID_XTS_KEY2_TEMPLATE	"ekmf.web.public.xts.template.2"
#define SETTING_ID_NON_XTS_TEMPLATE	"ekmf.web.public.non-xts.template"
#define FEATURE_ID_PERVASIVE_ENCRYPTION					\
		"com.ibm.ccc.ekmf.web.features.PervasiveEncryptionFeature"

void __attribute__ ((constructor)) ekmf_init(void);
void __attribute__ ((destructor)) ekmf_exit(void);

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

#define JSON_CHECK_OBJ(obj, type, rc_var, rc, text, verbose, label)	\
		do {							\
			if (obj == NULL ||				\
			    !json_object_is_type(obj, type)) {		\
				rc_var = rc;				\
				pr_verbose(verbose, "%s: %s", text,	\
					   strerror(-rc_var));		\
				goto label;				\
			}						\
		} while (0)

#define JSON_CHECK_ERROR(cond, rc_var, rc, text, verbose, label)	\
		do {							\
			if (cond) {					\
				rc_var = rc;				\
				pr_verbose(verbose, "%s: %s", text,	\
					   strerror(-rc_var));		\
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

static const char *accepted_content_types[] = { "application/json",
						"text/x-json",
						NULL};

struct private_data {
	const struct ekmf_ext_lib *ext_lib;
	bool verbose;
};

static int _ekmf_setup_sign_context(const unsigned char *key_blob,
				    size_t key_blob_size, EVP_PKEY *pkey,
				    int digest_nid,
				    struct ekmf_rsa_pss_params *rsa_pss_params,
				    EVP_MD_CTX **md_ctx,
				    EVP_PKEY_CTX **pkey_ctx,
				    struct private_data *private,
				    bool verbose);

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
 * Allocates or reuses a CURL handle. If curl_handle is not NULL, and
 * points to a non-NULL CURL handle, it is used, otherwise a new CURL handle
 * is allocated.
 */
static int _ekmf_get_curl_handle(CURL **curl_handle, CURL **curl)
{
	if (curl == NULL)
		return -EINVAL;

	if (curl_handle != NULL)
		*curl = *curl_handle;

	if (*curl == NULL)
		*curl = curl_easy_init();

	if (*curl == NULL)
		return -EIO;

	return 0;
}

/**
 * Releases a CURL handle. If curl_handle is not NULL, then the used CURL
 * handle is passed back via *curl_handle. If curl_handle is NULL, then the
 * used CURL handle is destroyed.
 */
static void _ekmf_release_curl_handle(CURL **curl_handle, CURL *curl)
{
	if (curl == NULL)
		return;

	if (curl_handle != NULL)
		*curl_handle = curl;
	else
		curl_easy_cleanup(curl);
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
 * Performs a login of the specified user with a passcode. On success the
 * returned login token is stored in the file denoted by field login_token
 * of the config structure, so that it can be used by subsequent requests.
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
 * @param user_id           the user-ID to log-in.
 * @param passcode          the passcode to log-in the user.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if the passcode is no longer valid.
 */
int ekmf_login(const struct ekmf_config *config, CURL **curl_handle,
	       const char *user_id, const char *passcode, char **error_msg,
	       bool verbose)
{
	json_object *response_obj = NULL;
	json_object *request_obj = NULL;
	const char *login_token, *tok;
	CURL *curl = NULL;
	long status_code;
	FILE *fp = NULL;
	size_t count;
	int rc;

	if (config == NULL || user_id == NULL || passcode == NULL)
		return -EINVAL;

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	request_obj = json_object_new_object();
	JSON_CHECK_ERROR(request_obj == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object", verbose, out);

	rc = json_object_object_add_ex(request_obj, "userId",
				       json_object_new_string(user_id), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);

	rc = json_object_object_add_ex(request_obj, "passcode",
				       json_object_new_string(passcode), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);

	rc = _ekmf_perform_request(config, EKMF_URI_SYSTEM_LOGIN, "POST",
				   request_obj, NULL, NULL, &response_obj, NULL,
				   &status_code, error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	case 410:
		pr_verbose(verbose, "The passcode is no longer valid");
		rc = -EACCES;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_object, rc, -EIO,
		       "No or invalid response content", verbose, out);

	login_token = json_get_string(response_obj, "authorizationToken");
	JSON_CHECK_ERROR(login_token == NULL, rc, -EBADMSG,
			 "Invalid response content", verbose, out);

	if (strncmp(login_token, "Bearer ", 7) != 0) {
		rc = -EBADMSG;
		pr_verbose(verbose, "Received token is not a Bearer token");
		goto out;
	}

	tok = &login_token[7];
	while (*tok == ' ')
		tok++;

	fp = fopen(config->login_token, "w");
	if (fp == NULL) {
		rc = -errno;
		pr_verbose(verbose, "Failed to open file %s: '%s'",
			   config->login_token, strerror(-rc));
		goto out;
	}

	count = fwrite(tok, 1, strlen(tok), fp);
	if (count != strlen(tok)) {
		pr_verbose(verbose, "Failed to write the token");
		rc = -EIO;
		goto out;
	}

	pr_verbose(verbose, "Login token successfully updated in file '%s'",
		   config->login_token);

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (request_obj != NULL)
		json_object_put(request_obj);
	if (response_obj != NULL)
		json_object_put(response_obj);
	if (fp != NULL)
		fclose(fp);

	return rc;

}

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
			char **error_msg, bool verbose)
{
	json_object *response_obj = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	EVP_PKEY *pkey = NULL;
	CURL *curl = NULL;
	long status_code;
	int rc;

	if (config == NULL)
		return -EINVAL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	rc = _ekmf_perform_request(config, EKMF_URI_SYSTEM_PUBKEY, "GET",
				   NULL, NULL, login_token, &response_obj, NULL,
				   &status_code, error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_object, rc, -EIO,
		       "No or invalid response content", verbose, out);

	rc = json_web_key_as_pkey(response_obj, EVP_PKEY_RSA, &pkey);
	if (rc != 0) {
		pr_verbose(verbose, "Failed convert the JWK to PKEY");
		goto out;
	}

	rc = write_public_key(config->ekmf_server_pubkey, pkey);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to write public key '%s': %s",
			   config->ekmf_server_pubkey, strerror(-rc));
		goto out;
	}

	pr_verbose(verbose, "EKMFWeb public key written to file '%s'",
		   config->ekmf_server_pubkey);

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (response_obj != NULL)
		json_object_put(response_obj);
	if (login_token != NULL)
		free(login_token);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return rc;
}

/**
 * Finds the setting with the specified ID in the settings array, and returns
 * its value if found, or NULL otherwise. The returned string is allocated
 * and must be freed by the caller when no lnger used.
 *
 * @param settings_array    the JSON array containing the settings
 * @param config            the setting ID to get
 * @param verbose           if true, verbose messages are printed
 *
 * @returns an allocated string conmtaining the setting value, or NULL
 */
static char *_ekmf_find_setting(json_object *settings_array,
				const char *setting_id, bool verbose)
{
	const char *id, *value;
	json_object *obj;
	int rc = 0, i;

	JSON_CHECK_OBJ(settings_array, json_type_array, rc, -EIO,
		       "No settings array", verbose, out);

	for (i = 0; i < (int)json_object_array_length(settings_array); i++) {
		obj = json_object_array_get_idx(settings_array, i);
		JSON_CHECK_OBJ(obj, json_type_object, rc, -EIO,
			       "No settings object", verbose, out);

		id = json_get_string(obj, "id");
		JSON_CHECK_ERROR(id == NULL, rc, -EIO,
				 "No id field in settings object", verbose,
				 out);

		if (strcmp(id, setting_id) != 0)
			continue;

		value = json_get_string(obj, "value");
		JSON_CHECK_ERROR(value == NULL, rc, -EIO,
				 "No value field in settings object", verbose,
				 out);

		return strdup(value);
	}

	pr_verbose(verbose, "Setting '%s' not found", setting_id);
out:
	return NULL;
}

/**
 * Retrieves settings from the EKMFWeb server, such as the template names for
 * generating keys in EKMFWeb.
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
 * @param identity_template on return: If not NULL, the name of the template
 *                          used to generate identity keys with. The caller
 *                          must free the error string when it is not NULL.
 * @param xts_key1_template on return: If not NULL, the name of the template
 *                          used to generate the first XTS key with. The caller
 *                          must free the error string when it is not NULL.
 * @param xts_key1_template on return: If not NULL, the name of the template
 *                          used to generate the second XTS key with. The caller
 *                          must free the error string when it is not NULL.
 * @param xts_key1_template on return: If not NULL, the name of the template
 *                          used to generate a non-XTS key with. The caller
 *                          must free the error string when it is not NULL.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 */
int ekmf_get_settings(const struct ekmf_config *config, CURL **curl_handle,
		      char **identity_template, char **xts_key1_template,
		      char **xts_key2_template, char **non_xts_template,
		      char **error_msg, bool verbose)
{
	json_object *response_obj = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	long status_code;
	int rc;

	if (config == NULL)
		return -EINVAL;

	if (identity_template == NULL && xts_key1_template == NULL &&
	    xts_key2_template == NULL && non_xts_template == NULL)
		return 0;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	rc = _ekmf_perform_request(config, EKMF_URI_SYSTEM_SETTINGS, "GET",
				   NULL, NULL, login_token, &response_obj, NULL,
				   &status_code, error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_array, rc, -EIO,
		       "No or invalid response content", verbose, out);

	if (identity_template != NULL) {
		*identity_template = _ekmf_find_setting(response_obj,
					SETTING_ID_IDENTITY_TEMPLATE, verbose);
		if (*identity_template == NULL) {
			if (error_msg != NULL) {
				if (asprintf(error_msg, "The EKMF Web setting "
					     "'Identity Key Template Name' "
					     "must be configured") < 0)
					error_msg = NULL;
			}
			rc = -EINVAL;
			goto out;
		}
	}

	if (xts_key1_template != NULL) {
		*xts_key1_template = _ekmf_find_setting(response_obj,
					SETTING_ID_XTS_KEY1_TEMPLATE, verbose);
		if (*xts_key1_template == NULL) {
			if (error_msg != NULL) {
				if (asprintf(error_msg, "The EKMF Web setting "
					     "'XTS Key Template Name (Key 1)' "
					     "must be configured") < 0)
					error_msg = NULL;
			}
			rc = -EINVAL;
			goto out;
		}
	}

	if (xts_key2_template != NULL) {
		*xts_key2_template = _ekmf_find_setting(response_obj,
					SETTING_ID_XTS_KEY2_TEMPLATE, verbose);
		if (*identity_template == NULL) {
			if (error_msg != NULL) {
				if (asprintf(error_msg, "The EKMF Web setting "
					     "'XTS Key Template Name (Key 2)' "
					     "must be configured") < 0)
					error_msg = NULL;
			}
			rc = -EINVAL;
			goto out;
		}
	}

	if (non_xts_template != NULL) {
		*non_xts_template = _ekmf_find_setting(response_obj,
					SETTING_ID_NON_XTS_TEMPLATE, verbose);
		if (*non_xts_template == NULL) {
			if (error_msg != NULL) {
				if (asprintf(error_msg, "The EKMF Web setting "
					     "'Non-XTS Key Template Name' "
					     "must be configured") < 0)
					error_msg = NULL;
			}
			rc = -EINVAL;
			goto out;
		}
	}

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (response_obj != NULL)
		json_object_put(response_obj);
	if (login_token != NULL)
		free(login_token);
	if (rc != 0) {
		if (identity_template != NULL && *identity_template != NULL) {
			free(*identity_template);
			*identity_template = NULL;
		}
		if (xts_key1_template != NULL && *xts_key1_template != NULL) {
			free(*xts_key1_template);
			*xts_key1_template = NULL;
		}
		if (xts_key2_template != NULL && *xts_key2_template != NULL) {
			free(*xts_key2_template);
			*xts_key2_template = NULL;
		}
		if (non_xts_template != NULL && *non_xts_template != NULL) {
			free(*non_xts_template);
			*non_xts_template = NULL;
		}
	}

	return rc;
}

/**
 * Checks if the EKMFWeb server has the required Pervasive Encryption feature
 * installed
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
 *          -ENOTSUP is returned, if the feature is not installed.
 */
int ekmf_check_feature(const struct ekmf_config *config, CURL **curl_handle,
		       char **error_msg, bool verbose)
{
	json_object *response_obj = NULL, *obj;
	bool found = false;
	CURL *curl = NULL;
	long status_code;
	const char *id;
	int rc, i;

	if (config == NULL)
		return -EINVAL;

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	rc = _ekmf_perform_request(config, EKMF_URI_SYSTEM_FEATURES, "GET",
				   NULL, NULL, NULL, &response_obj, NULL,
				   &status_code, error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_array, rc, -EIO,
		       "No or invalid response content", verbose, out);

	for (i = 0; i < (int)json_object_array_length(response_obj); i++) {
		obj = json_object_array_get_idx(response_obj, i);
		JSON_CHECK_OBJ(obj, json_type_object, rc, -EIO,
			       "No features object", verbose, out);

		id = json_get_string(obj, "id");
		JSON_CHECK_ERROR(id == NULL, rc, -EIO,
				 "No id field in settings object", verbose,
				 out);

		if (strcmp(id, FEATURE_ID_PERVASIVE_ENCRYPTION) != 0)
			continue;

		found = true;
		break;
	}

	if (!found) {
		pr_verbose(verbose, "Feature '%s' is not installed",
			   FEATURE_ID_PERVASIVE_ENCRYPTION);
		rc = -ENOTSUP;
		if (asprintf(error_msg, "EKMF Web feature "
			     "'Pervasive Encryption' is not installed.")) {
			pr_verbose(verbose, "asprintf failed");
			rc = -ENOMEM;
		}
		goto out;
	}

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (response_obj != NULL)
		json_object_put(response_obj);

	return rc;
}


/**
 * Build the party info JSON object as base64(sha256(key_uuid|timestamp)).
 * Digest_nid specifies the digest to use, ot 0 to use the default (SHA256).
 * The function returns the party info JSON object, as well as the raw party
 * info.
 */
static int _ekmf_build_party_info(const char *key_uuid, const char *timestamp,
				  int digest_nid, unsigned char *party_info,
				  size_t *party_info_length,
				  json_object **party_info_obj, bool verbose)
{
	unsigned int digest_len;
	EVP_MD_CTX *ctx = NULL;
	const EVP_MD *md;
	int rc;

	md = EVP_get_digestbynid(digest_nid != 0 ? digest_nid : NID_sha256);
	if (md == NULL) {
		pr_verbose(verbose, "Failed to get specified digest");
		rc = -EINVAL;
		goto out;
	}

	if (*party_info_length < (size_t)EVP_MD_size(md)) {
		pr_verbose(verbose, "Party info buffer is too small");
		return -ERANGE;
		goto out;
	}

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL) {
		pr_verbose(verbose, "Failed to allocate MD context");
		rc = -ENOMEM;
		goto out;
	}

	rc = EVP_DigestInit_ex(ctx, md, NULL);
	if (rc != 1) {
		pr_verbose(verbose, "Failed to initialize MD context");
		rc = -EIO;
		goto out;
	}

	rc = EVP_DigestUpdate(ctx, key_uuid, strlen(key_uuid));
	if (rc != 1) {
		pr_verbose(verbose, "Failed to add data to the MD context");
		rc = -EIO;
		goto out;
	}

	rc = EVP_DigestUpdate(ctx, timestamp, strlen(timestamp));
	if (rc != 1) {
		pr_verbose(verbose, "Failed to add data to the MD context");
		rc = -EIO;
		goto out;
	}

	rc = EVP_DigestFinal_ex(ctx, party_info, &digest_len);
	if (rc != 1) {
		pr_verbose(verbose, "Failed to finalize the MD context");
		rc = -EIO;
		goto out;
	}

	*party_info_length = digest_len;
	*party_info_obj = json_object_new_base64url(party_info, digest_len);
	rc = 0;

out:
	if (ctx != NULL)
		EVP_MD_CTX_destroy(ctx);

	return rc;
}

/**
 * Builds a (detached) JSON Web Signature using the secure identity key from
 * the payload and returns a signature JSON object
 */
static int _ekmf_build_signature(unsigned char *key_blob,
				 size_t key_blob_length,
				 json_object *payload_obj,
				 json_object **signature_obj,
				 int digest_nid, bool use_rsa_pss,
				 const char *jws_kid,
				 const struct ekmf_ext_lib *ext_lib,
				 bool verbose)
{
	struct ekmf_rsa_pss_params rsa_pss_params;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	struct private_data private;
	EVP_MD_CTX *md_ctx = NULL;
	bool pkey_meth = false;
	EVP_PKEY *pkey = NULL;
	const char *payload;
	const char *jws_alg;
	int rc, curve_nid;
	char *jws = NULL;
	int pkey_type;
	BIO *b;

	switch (ext_lib->type) {
	case EKMF_EXT_LIB_CCA:
		rc = cca_get_key_type(key_blob, key_blob_length, &pkey_type);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to get the identity key "
				   "type");
			goto out;
		}

		switch (pkey_type) {
		case EVP_PKEY_EC:
			rc = cca_get_ecc_pub_key_as_pkey(key_blob,
							 key_blob_length,
							 &pkey, verbose);
			break;
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA_PSS:
			rc = cca_get_rsa_pub_key_as_pkey(key_blob,
							 key_blob_length,
							 use_rsa_pss ?
							     EVP_PKEY_RSA_PSS :
							     EVP_PKEY_RSA,
							 &pkey, verbose);
			break;
		}

		if (rc != 0) {
			pr_verbose(verbose, "Failed to get the identity PKEY");
			goto out;
		}
		break;
	default:
		pr_verbose(verbose, "Invalid ext lib type: %d", ext_lib->type);
		return -EINVAL;
	}

	/*
	 * Only the following combinations are allowed per RFC7518 for JSON
	 * Web Signatures (JWS) using ECC or RSA identity keys:
	 *   alg=ES256: ECDSA using P-256 and SHA-256
	 *   alg=ES384: ECDSA using P-384 and SHA-384
	 *   alg=ES512: ECDSA using P-521 and SHA-512
	 *   alg=RS256: RSA-PKCS1 using SHA-256
	 *   alg=RS384: RSA-PKCS1 using SHA-384
	 *   alg=RS512: RSA-PKCS1 using SHA-512
	 *   alg=PS256: RSA-PSS using SHA-256, MGF1 with SHA-256, salt=digest
	 *   alg=PS384: RSA-PSS using SHA-384, MGF1 with SHA-384, salt=digest
	 *   alg=PS512: RSA-PSS using SHA-512, MGF1 with SHA-512, salt=digest
	 */
	switch (EVP_PKEY_id(pkey)) {
	case EVP_PKEY_EC:
		curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(
						EVP_PKEY_get0_EC_KEY(pkey)));
		switch (curve_nid) {
		case NID_secp521r1:
			digest_nid = NID_sha512;
			jws_alg = "ES512";
			break;
		case NID_secp384r1:
			digest_nid = NID_sha384;
			jws_alg = "ES384";
			break;
		case NID_X9_62_prime256v1:
			digest_nid = NID_sha256;
			jws_alg = "ES256";
			break;
		default:
			pr_verbose(verbose, "Unsupported curve");
			rc = -EINVAL;
			goto out;
		}
		break;
	case EVP_PKEY_RSA:
		switch (digest_nid) {
		case NID_sha256:
			jws_alg = "RS256";
			break;
		case NID_sha384:
			jws_alg = "RS384";
			break;
		case NID_sha512:
		case 0:
			jws_alg = "RS512";
			digest_nid = NID_sha512;
			break;
		default:
			pr_verbose(verbose, "Unsupported digest");
			rc = -EINVAL;
			goto out;
		}
		break;
	case EVP_PKEY_RSA_PSS:
		switch (digest_nid) {
		case NID_sha256:
			jws_alg = "PS256";
			break;
		case NID_sha384:
			jws_alg = "PS384";
			break;
		case NID_sha512:
		case 0:
			jws_alg = "PS512";
			digest_nid = NID_sha512;
			break;
		default:
			pr_verbose(verbose, "Unsupported digest");
			rc = -EINVAL;
			goto out;
		}
		rsa_pss_params.mgf_digest_nid = digest_nid;
		rsa_pss_params.salt_len = RSA_PSS_SALTLEN_DIGEST;
		break;
	default:
		pr_verbose(verbose, "Unsupported key type");
		rc = -EINVAL;
		goto out;
	}

	private.ext_lib = ext_lib;
	private.verbose = verbose;

	rc = _ekmf_setup_sign_context(key_blob, key_blob_length, pkey,
				      digest_nid, &rsa_pss_params, &md_ctx,
				      &pkey_ctx, &private, verbose);
	if (rc != 0)
		goto out;
	pkey_meth = true;

	payload = json_object_to_json_string_ext(payload_obj,
					JSON_C_TO_STRING_PLAIN |
					JSON_C_TO_STRING_NOSLASHESCAPE);
	if (payload == NULL) {
		pr_verbose(verbose, "Failed to get the payload string");
		rc = -EIO;
		goto out;
	}

	if (verbose) {
		pr_verbose(verbose, "JWS Payload: ->%s<-", payload);
		pr_verbose(verbose, "JWS alg: %s", jws_alg);
		pr_verbose(verbose, "Public signing key:");
		b = BIO_new_fp(stderr, BIO_NOCLOSE);
		PEM_write_bio_PUBKEY(b, pkey);
		BIO_free(b);
	}

	rc = create_json_web_signature(jws_alg, false, jws_kid,
				       (unsigned char *)payload,
				       strlen(payload), true, md_ctx, &jws);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build the JWS");
		goto out;
	}

	*signature_obj = json_object_new_string(jws);
	rc = 0;

out:
	if (md_ctx != NULL)
		EVP_MD_CTX_free(md_ctx);
	if (pkey_meth)
		cleanup_secure_key_pkey_method(EVP_PKEY_id(pkey));
	if (pkey != NULL)
		EVP_PKEY_free(pkey);
	if (jws != NULL)
		free(jws);

	return rc;
}

/**
 * Verifies the (detached) JSON Web Signature using the server's public signing
 * key and the response payload.
 * Note: This function removes the signature field from the response JSON
 *       object!
 */
static int _ekmf_verify_signature(json_object *response_obj,
				  EVP_PKEY *server_pubkey, bool verbose)
{
	json_object *signature_obj = NULL;
	const char *sign_payload;
	BIO *b;
	int rc;

	if (response_obj == NULL)
		return -EINVAL;

	json_object_object_get_ex(response_obj, "signature",
				  &signature_obj);
	JSON_CHECK_OBJ(signature_obj, json_type_string, rc, -EIO,
		       "Failed to get the response signature", verbose, out);

	json_object_get(signature_obj); /* Take ownership */
	json_object_object_del(response_obj, "signature");

	sign_payload = json_object_to_json_string_ext(response_obj,
					JSON_C_TO_STRING_PLAIN |
					JSON_C_TO_STRING_NOSLASHESCAPE);
	if (sign_payload == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	if (verbose) {
		pr_verbose(verbose, "JWS Payload: ->%s<-", sign_payload);
		pr_verbose(verbose, "Public signing key:");
		b = BIO_new_fp(stderr, BIO_NOCLOSE);
		PEM_write_bio_PUBKEY(b, server_pubkey);
		BIO_free(b);
	}

	rc = verify_json_web_signature(json_object_get_string(signature_obj),
				       (const unsigned char *)sign_payload,
				       strlen(sign_payload), server_pubkey);
	if (rc != 0) {
		pr_verbose(verbose, "Signature verify of response failed");
		goto out;
	}

	pr_verbose(verbose, "Signature of response successfully verified");

out:
	if (signature_obj != NULL)
		json_object_put(signature_obj);

	return rc;
}

/**
 * Import the key retrieved from EKMFWeb.
 */
static int _ekmf_import_key(unsigned char *req_sess_key,
			    size_t req_sess_key_length,
			    unsigned char *req_party_info,
			    size_t req_party_info_length,
			    unsigned char *resp_party_info,
			    size_t resp_party_info_length,
			    json_object *resp_sess_jwk_obj,
			    json_object *resp_exp_jwk_obj,
			    unsigned char *key_blob, size_t *key_blob_length,
			    const struct ekmf_ext_lib *ext_lib, bool verbose)
{
	size_t resp_sess_ec_key_length, resp_exported_key_length;
	unsigned char resp_exported_key[MAX_SYM_KEY_BLOB_SIZE];
	unsigned char transport_key[MAX_SYM_KEY_BLOB_SIZE];
	unsigned char resp_sess_key[MAX_KEY_BLOB_SIZE];
	size_t party_info_length, transport_key_length;
	unsigned char *party_info = NULL;
	int rc;

	party_info_length = req_party_info_length + resp_party_info_length;
	party_info = malloc(party_info_length);
	if (party_info == NULL) {
		pr_verbose(verbose, "Failed to allocate memory");
		rc = -ENOMEM;
		goto out;
	}

	memcpy(party_info, req_party_info, req_party_info_length);
	memcpy(party_info + req_party_info_length, resp_party_info,
	       resp_party_info_length);

	switch (ext_lib->type) {
	case EKMF_EXT_LIB_CCA:
		resp_sess_ec_key_length = sizeof(resp_sess_key);
		rc = cca_import_key_from_json_web_key(ext_lib->cca,
						      resp_sess_jwk_obj,
						      resp_sess_key,
						      &resp_sess_ec_key_length,
						      verbose);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to import the session EC "
				   "key");
			goto out;
		}

		transport_key_length = sizeof(transport_key);
		rc = cca_ec_dh_derive_importer(ext_lib->cca,
					       req_sess_key,
					       req_sess_key_length,
					       resp_sess_key,
					       resp_sess_ec_key_length,
					       party_info, party_info_length,
					       CCA_KDF_ANS_X9_63_CCA,
					       transport_key,
					       &transport_key_length,
					       verbose);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to derive transport key");
			goto out;
		}

		resp_exported_key_length = sizeof(resp_exported_key);
		rc = cca_import_key_from_json_web_key(ext_lib->cca,
						      resp_exp_jwk_obj,
						      resp_exported_key,
						      &resp_exported_key_length,
						      verbose);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to import the exported "
				   "key");
			goto out;
		}

		rc = cca_import_external_key(ext_lib->cca, resp_exported_key,
					     resp_exported_key_length,
					     transport_key,
					     transport_key_length,
					     key_blob, key_blob_length,
					     verbose);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to unwrap the exported "
				   "key with the transport key");
			goto out;
		}

		break;
	default:
		pr_verbose(verbose, "Invalid ext lib type: %d", ext_lib->type);
		return -EINVAL;
	}

out:
	if (party_info != NULL)
		free(party_info);

	return rc;
}

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
		      const struct ekmf_ext_lib *ext_lib, bool verbose)
{
	size_t req_party_info_length, resp_party_info_length;
	unsigned char req_party_info[SHA512_DIGEST_LENGTH];
	size_t req_sess_ec_key_length, identity_key_length;
	unsigned char req_sess_ec_key[MAX_KEY_BLOB_SIZE];
	unsigned char identity_key[MAX_KEY_BLOB_SIZE];
	json_object *resp_originator_obj = NULL;
	json_object *resp_addl_info_obj = NULL;
	json_object *req_party_info_obj = NULL;
	json_object *req_originator_obj = NULL;
	json_object *req_timestamp_obj = NULL;
	json_object *req_addl_info_obj = NULL;
	json_object *req_signature_obj = NULL;
	unsigned char *resp_party_info = NULL;
	json_object *resp_sess_jwk_obj = NULL;
	json_object *req_sess_jwk_obj = NULL;
	json_object *resp_exp_jwk_obj = NULL;
	json_object *response_obj = NULL;
	json_object *request_obj = NULL;
	EVP_PKEY *server_pubkey = NULL;
	char *escaped_uuid = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	long status_code;
	char *uri = NULL;
	int rc;

	if (config == NULL || key_uuid == NULL || key_blob == NULL ||
	    key_blob_length == NULL || ext_lib == NULL)
		return -EINVAL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	rc = read_public_key(config->ekmf_server_pubkey, &server_pubkey);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to read EKMFWeb server's public key"
			   " '%s': %s", config->ekmf_server_pubkey,
			   strerror(-rc));
		goto out;
	}

	identity_key_length = sizeof(identity_key);
	rc = read_key_blob(config->identity_secure_key, identity_key,
			   &identity_key_length);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to read identity key from file "
			   "'%s': %s", config->identity_secure_key,
			   strerror(-rc));
		goto out;
	}

	switch (ext_lib->type) {
	case EKMF_EXT_LIB_CCA:
		req_sess_ec_key_length = sizeof(req_sess_ec_key);
		rc = cca_generate_ecc_key_pair(ext_lib->cca,
					       sess_ec_curve_nid != 0 ?
						  sess_ec_curve_nid :
						  DEFAULT_SESSION_EC_KEY_CURVE,
					       req_sess_ec_key,
					       &req_sess_ec_key_length,
					       verbose);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to generate a session EC "
				   "key");
			goto out;
		}

		rc = cca_get_ecc_pub_key_as_json_web_key(req_sess_ec_key,
							 req_sess_ec_key_length,
							 &req_sess_jwk_obj,
							 verbose);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to generate session JWK");
			goto out;
		}
		break;
	default:
		pr_verbose(verbose, "Invalid ext lib type: %d", ext_lib->type);
		return -EINVAL;
	}

	req_timestamp_obj = get_json_timestamp();
	JSON_CHECK_ERROR(req_timestamp_obj == NULL, rc, -EIO,
			 "Failed to generate timestamp", verbose, out);

	req_party_info_length = sizeof(req_party_info);
	rc = _ekmf_build_party_info(key_uuid,
				    json_object_get_string(req_timestamp_obj),
				    NID_sha256, req_party_info,
				    &req_party_info_length,
				    &req_party_info_obj, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build the party info");
		goto out;
	}

	/*
	 * Note: The order of the fields is important, EKMFWeb expects it in
	 * exactly this order!
	 */
	req_addl_info_obj = json_object_new_object();
	JSON_CHECK_ERROR(req_addl_info_obj == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object", verbose, out);

	rc = json_object_object_add_ex(req_addl_info_obj, "kdf",
				       json_object_new_string("ANS-X9.63-CCA"),
				       0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);
	rc = json_object_object_add_ex(req_addl_info_obj, "requestedKey",
				       json_object_new_string(key_uuid), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);
	rc = json_object_object_add_ex(req_addl_info_obj, "timestamp",
				       req_timestamp_obj, 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);
	req_timestamp_obj = NULL;

	req_originator_obj = json_object_new_object();
	JSON_CHECK_ERROR(req_originator_obj == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object", verbose, out);

	rc = json_object_object_add_ex(req_originator_obj, "session",
				       req_sess_jwk_obj, 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);
	req_sess_jwk_obj = NULL;
	rc = json_object_object_add_ex(req_originator_obj, "partyInfo",
				       req_party_info_obj, 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);
	req_party_info_obj = NULL;

	request_obj = json_object_new_object();
	JSON_CHECK_ERROR(request_obj == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object", verbose, out);

	rc = json_object_object_add_ex(request_obj, "originator",
				       req_originator_obj, 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);
	req_originator_obj = NULL;
	rc = json_object_object_add_ex(request_obj, "additionalInfo",
				       req_addl_info_obj, 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);
	req_addl_info_obj = NULL;

	rc = _ekmf_build_signature(identity_key, identity_key_length,
				   request_obj, &req_signature_obj,
				   sign_rsa_digest_nid, use_rsa_pss,
				   signature_kid, ext_lib, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build the signature");
		goto out;
	}

	rc = json_object_object_add_ex(request_obj, "signature",
				       req_signature_obj, 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);
	req_signature_obj = NULL;

	escaped_uuid = curl_easy_escape(curl, key_uuid, 0);
	if (escaped_uuid == NULL) {
		pr_verbose(verbose, "Failed to url-escape the key uuid");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_KEYS_EXPORT, escaped_uuid) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = _ekmf_perform_request(config, uri, "POST", request_obj, NULL,
				   login_token, &response_obj, NULL,
				   &status_code, error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	case 400:
		pr_verbose(verbose, "Bad request");
		rc = -EBADMSG;
		goto out;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	case 403:
		pr_verbose(verbose, "Insufficient permissions");
		rc = -EPERM;
		goto out;
	case 404:
		pr_verbose(verbose, "Not found");
		rc = -ENOENT;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_object, rc, -EBADMSG,
		       "No or invalid response", verbose, out);

	rc = _ekmf_verify_signature(response_obj, server_pubkey, verbose);
	if (rc != 0)
		goto out;

	json_object_object_get_ex(response_obj, "originator",
				  &resp_originator_obj);
	JSON_CHECK_OBJ(resp_originator_obj, json_type_object, rc, -EBADMSG,
		       "Failed to get the response originator", verbose, out);

	json_object_object_get_ex(resp_originator_obj, "session",
				  &resp_sess_jwk_obj);
	JSON_CHECK_OBJ(resp_sess_jwk_obj, json_type_object, rc, -EBADMSG,
		       "Failed to get the response session key", verbose, out);

	rc = json_object_get_base64url(resp_originator_obj, "partyInfo",
				       NULL, &resp_party_info_length);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get the response partyInfo");
		goto out;
	}

	resp_party_info = malloc(resp_party_info_length);
	if (resp_party_info == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	rc = json_object_get_base64url(resp_originator_obj, "partyInfo",
				       resp_party_info,
				       &resp_party_info_length);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get the response partyInfo");
		goto out;
	}

	json_object_object_get_ex(response_obj, "additionalInfo",
				  &resp_addl_info_obj);
	JSON_CHECK_OBJ(resp_addl_info_obj, json_type_object, rc, -EBADMSG,
		       "Failed to get the response addl.info", verbose, out);

	json_object_object_get_ex(resp_addl_info_obj, "exportedKey",
				  &resp_exp_jwk_obj);
	JSON_CHECK_OBJ(resp_exp_jwk_obj, json_type_object, rc, -EBADMSG,
		       "Failed to get the response exported key", verbose, out);

	rc = _ekmf_import_key(req_sess_ec_key, req_sess_ec_key_length,
			      req_party_info, req_party_info_length,
			      resp_party_info, resp_party_info_length,
			      resp_sess_jwk_obj, resp_exp_jwk_obj,
			      key_blob, key_blob_length, ext_lib, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to import the retrieved key");
		goto out;
	}

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (req_sess_jwk_obj != NULL)
		json_object_put(req_sess_jwk_obj);
	if (req_timestamp_obj != NULL)
		json_object_put(req_timestamp_obj);
	if (req_addl_info_obj != NULL)
		json_object_put(req_addl_info_obj);
	if (req_party_info_obj != NULL)
		json_object_put(req_party_info_obj);
	if (req_originator_obj != NULL)
		json_object_put(req_originator_obj);
	if (req_signature_obj != NULL)
		json_object_put(req_signature_obj);
	if (request_obj != NULL)
		json_object_put(request_obj);
	if (response_obj != NULL)
		json_object_put(response_obj);
	if (uri != NULL)
		free(uri);
	if (login_token != NULL)
		free(login_token);
	if (server_pubkey != NULL)
		EVP_PKEY_free(server_pubkey);
	if (resp_party_info != NULL)
		free(resp_party_info);
	if (escaped_uuid != NULL)
		curl_free(escaped_uuid);

	return rc;
}

/**
 * Callback function for the _ekmf_list_request function. This callback
 * is called for each result element. The curl handle can be used to perform
 * further requests within the callback. However, the curl handle must not be
 * closed/destroyed!
 */
typedef int (*ekmf_element_cb_t)(CURL *curl, json_object *element,
				 void *private, bool verbose);

/**
 * Performs a list request (GET) on a base list_uri and iterates over
 * multiple pages. The response of a list request is expected to be a
 * JSON array of elements. For each element, the element callback is called
 * with the element.
 * The list_uri must contain anything required to list the desired objects,
 * except the page and perPage UTL parameters. Those are added by this function.
 */
static int _ekmf_list_request(const struct ekmf_config *config,
			      const char *list_uri, CURL *curl,
			      ekmf_element_cb_t element_cb, void *private,
			      const char *login_token, char **error_msg,
			      bool verbose)
{
	json_object *response_obj = NULL;
	json_object *element_obj;
	int num, i, rc = 0;
	unsigned int page;
	char *uri = NULL;
	long status_code;
	bool has_query;

	if (config == NULL || list_uri == NULL || element_cb == NULL ||
	    curl == NULL)
		return -EINVAL;

	has_query = strchr(list_uri, '?') != NULL;

	for (page = 1; ; page++) {
		if (asprintf(&uri, "%s%sperPage=%u&page=%u", list_uri,
			     has_query ? "&" : "?", LIST_ELEMENTS_PER_PAGE,
			     page) < 0) {
			pr_verbose(verbose, "asprintf failed");
			rc = -ENOMEM;
			goto out;
		}

		rc = _ekmf_perform_request(config, uri, "GET", NULL, NULL,
					   login_token, &response_obj, NULL,
					   &status_code, error_msg, curl,
					   verbose);

		free(uri);
		uri = NULL;

		if (rc != 0) {
			pr_verbose(verbose, "Failed perform the REST call");
			if (rc > 0)
				rc = -EIO;
			goto out;
		}

		switch (status_code) {
		case 200:
			break;
		case 400:
			pr_verbose(verbose, "Bad request");
			rc = -EBADMSG;
			goto out;
		case 401:
			pr_verbose(verbose, "Not authorized");
			rc = -EACCES;
			goto out;
		case 403:
			pr_verbose(verbose, "Insufficient permissions");
			rc = -EPERM;
			goto out;
		default:
			pr_verbose(verbose, "REST Call failed with HTTP "
				   "status code: %ld", status_code);
			rc = -EIO;
			goto out;
		}

		JSON_CHECK_OBJ(response_obj, json_type_array, rc, -EIO,
			       "No or invalid response content", verbose, out);

		num = json_object_array_length(response_obj);
		if (num == 0)
			break;

		for (i = 0; i < num; i++) {
			element_obj = json_object_array_get_idx(response_obj,
								i);
			if (element_obj == NULL) {
				pr_verbose(verbose, "Failed to get array "
					   "element for index %d", i);
				rc = -EBADMSG;
				goto out;
			}

			rc = element_cb(curl, element_obj, private, verbose);
			if (rc != 0) {
				pr_verbose(verbose, "Element-callback failed "
					   "for index %d", i);
				goto out;
			}
		}

		if (response_obj != NULL)
			json_object_put(response_obj);
		response_obj = NULL;

		if (num < LIST_ELEMENTS_PER_PAGE)
			break;
	}

out:
	if (uri != NULL)
		free(uri);
	if (response_obj != NULL)
		json_object_put(response_obj);

	return rc;
}

struct ekmf_template_cb_data_t {
	ekmf_template_cb_t template_cb;
	void *cb_private;
};

/**
 * Callback for template list function. Builds the template info structure
 * and calls the application callback.
 */
static int _ekmf_template_cb(CURL *curl, json_object *element,
			     void *private, bool verbose)
{
	struct ekmf_template_cb_data_t *cb_data = private;
	struct ekmf_template_info template = { 0 };
	int rc;

	if (cb_data->template_cb == NULL) {
		pr_verbose(verbose, "No template callback function");
		return -EINVAL;
	}

	rc = json_build_template_info(element, &template, false);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build template info");
		goto out;
	}

	rc = cb_data->template_cb(curl, &template, cb_data->cb_private);
	if (rc != 0) {
		pr_verbose(verbose, "Template callback rc: %d", rc);
		goto out;
	}

out:
	free_tag_def_list(&template.label_tags, false);

	return rc;
}

/**
 * List available key templates. Only templates in state ACTIVE, with key
 * algorithm AES and keystore type PERVASIVE_ENCRYPTION are listed. The
 * templates are ordered by name in ascending order.
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
 * @param template_cb       a callback function that is called for each template
 *                          found
 * @param private           a pointer that is passed as-is to the callback
 * @param name_pattern      a pattern to filter by name, or NULL to list all.
 * @param state             the state of the templates to list. If NULL then
 *                          templates in state 'ACTIVE' are listed
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          list the templates
 */
int ekmf_list_templates(const struct ekmf_config *config, CURL **curl_handle,
			ekmf_template_cb_t template_cb, void *private,
			const char *name_pattern, const char *state,
			char **error_msg, bool verbose)
{
	struct ekmf_template_cb_data_t cb_data;
	char *escaped_name_pattern = NULL;
	char *escaped_state = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	char *uri = NULL;
	int rc;

	if (config == NULL || template_cb == NULL)
		return -EINVAL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	cb_data.template_cb = template_cb;
	cb_data.cb_private = private;

	escaped_name_pattern = curl_easy_escape(curl, name_pattern != NULL ?
							name_pattern : "*", 0);
	if (escaped_name_pattern == NULL) {
		pr_verbose(verbose, "Failed to url-escape the name pattern");
		rc = -EIO;
		goto out;
	}

	escaped_state = curl_easy_escape(curl, state != NULL ? state :
						TEMPLATE_STATE_ACTIVE, 0);
	if (escaped_state == NULL) {
		pr_verbose(verbose, "Failed to url-escape the state");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_TEMPLATE_LIST, escaped_state,
		     ORDER_BY_NAME_ASC, escaped_name_pattern) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = _ekmf_list_request(config, uri, curl, _ekmf_template_cb,
				&cb_data, login_token, error_msg, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to perform the list request");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (login_token != NULL)
		free(login_token);
	if (uri != NULL)
		free(uri);
	if (escaped_name_pattern != NULL)
		curl_free(escaped_name_pattern);
	if (escaped_state != NULL)
		curl_free(escaped_state);

	return rc;
}

/**
 * Get a template by its UUID.
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
 * @param template_uuid     the UUID of the template to get
 * @param template          an address of a template info pointer. On return
 *                          the pointer is updated to point to a newly allocated
 *                          template info struct. It must be freed by the caller
 *                          using ekmf_free_template_info when no longer needed.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          get the template
 */
int ekmf_get_template(const struct ekmf_config *config, CURL **curl_handle,
		      const char *template_uuid,
		      struct ekmf_template_info **template, char **error_msg,
		      bool verbose)
{
	json_object *response_obj = NULL;
	char *escaped_uuid = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	char *uri = NULL;
	long status_code;
	int rc;

	if (config == NULL || template_uuid == NULL || template == NULL)
		return -EINVAL;

	*template = NULL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	escaped_uuid = curl_easy_escape(curl, template_uuid, 0);
	if (escaped_uuid == NULL) {
		pr_verbose(verbose, "Failed to url-escape the template uuid");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_TEMPLATE_GET, escaped_uuid) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = _ekmf_perform_request(config, uri, "GET", NULL, NULL,
				   login_token, &response_obj, NULL,
				   &status_code, error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	case 400:
		pr_verbose(verbose, "Bad request");
		rc = -EBADMSG;
		goto out;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	case 403:
		pr_verbose(verbose, "Insufficient permissions");
		rc = -EPERM;
		goto out;
	case 404:
		pr_verbose(verbose, "Not found");
		rc = -ENOENT;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_object, rc, -EBADMSG,
		       "No or invalid response", verbose, out);

	*template = calloc(1, sizeof(struct ekmf_template_info));
	if (*template == NULL) {
		pr_verbose(verbose, "calloc failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = json_build_template_info(response_obj, *template, true);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build template info");
		goto out;
	}

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (response_obj != NULL)
		json_object_put(response_obj);
	if (login_token != NULL)
		free(login_token);
	if (uri != NULL)
		free(uri);
	if (escaped_uuid != NULL)
		curl_free(escaped_uuid);
	if (rc != 0 && *template != NULL) {
		free_template_info(*template);
		free(*template);
		*template = NULL;
	}

	return rc;
}

/**
 * Get the last used sequence number of a template by its UUID.
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
 * @param template_uuid     the UUID of the template to get
 * @param seqNumber         On return: the last used sequence number of this
 *                          template.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          get the template
 */
int ekmf_get_last_seq_no(const struct ekmf_config *config, CURL **curl_handle,
			 const char *template_uuid, unsigned int *seqNumber,
			 char **error_msg, bool verbose)
{
	json_object *response_obj = NULL, *field = NULL;
	char *escaped_uuid = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	char *uri = NULL;
	long status_code;
	int rc;

	if (config == NULL || template_uuid == NULL || seqNumber == NULL)
		return -EINVAL;

	*seqNumber = 0;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	escaped_uuid = curl_easy_escape(curl, template_uuid, 0);
	if (escaped_uuid == NULL) {
		pr_verbose(verbose, "Failed to url-escape the template uuid");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_TEMPLATE_SEQNO, escaped_uuid) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = _ekmf_perform_request(config, uri, "GET", NULL, NULL,
				   login_token, &response_obj, NULL,
				   &status_code, error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	case 400:
		pr_verbose(verbose, "Bad request");
		rc = -EBADMSG;
		goto out;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	case 403:
		pr_verbose(verbose, "Insufficient permissions");
		rc = -EPERM;
		goto out;
	case 404:
		pr_verbose(verbose, "Not found");
		rc = -ENOENT;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_object, rc, -EBADMSG,
		       "No or invalid response", verbose, out);

	json_object_object_get_ex(response_obj, "lastSequenceNumber", &field);
	JSON_CHECK_OBJ(field, json_type_int, rc, -EBADMSG,
		       "Invalid response", verbose, out);

	*seqNumber = json_object_get_int(field);

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (response_obj != NULL)
		json_object_put(response_obj);
	if (login_token != NULL)
		free(login_token);
	if (uri != NULL)
		free(uri);
	if (escaped_uuid != NULL)
		curl_free(escaped_uuid);

	return rc;
}

/**
 * Clones a template info structure by making a deep copy of all strings and
 * arrays.
 * The copied template info must be freed using ekmf_free_template_info() by
 * the caller.
 *
 * @param src               the source template info structure
 * @param dest              the destination template info structure
 *
 * @returns zero for success, a negative errno in case of an error
 */
int ekmf_clone_template_info(const struct ekmf_template_info *src,
			     struct ekmf_template_info **dest)
{
	if (src == NULL || dest == NULL)
		return -EINVAL;

	*dest = calloc(1, sizeof(struct ekmf_template_info));
	if (*dest == NULL)
		return -ENOMEM;

	return clone_template_info(src, *dest);
}

/**
 * Free a template info structure.
 *
 * @param template          the template to free
 */
void ekmf_free_template_info(struct ekmf_template_info *template)
{
	free_template_info(template);

	free(template);
}

/**
 * Gets the custom tags of a key by key-uuid. The custom tags are returned as
 * JSON array. The returned JSON array must be freed by the caller using
 * json_object_put().
 */
static int _ekmf_get_custom_tags(const struct ekmf_config *config,
				 const char *key_uuid, CURL *curl,
				 json_object **custom_tags,
				 const char *login_token, char **error_msg,
				 bool verbose)
{
	json_object *response_obj = NULL;
	char *escaped_uuid = NULL;
	char *uri = NULL;
	long status_code;
	int rc;

	if (config == NULL || key_uuid == NULL || custom_tags == NULL ||
	    curl == NULL)
		return -EINVAL;

	escaped_uuid = curl_easy_escape(curl, key_uuid, 0);
	if (escaped_uuid == NULL) {
		pr_verbose(verbose, "Failed to url-escape the key uuid");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_KEYS_TAGS, escaped_uuid) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = _ekmf_perform_request(config, uri, "GET", NULL, NULL, login_token,
				   &response_obj, NULL, &status_code, error_msg,
				   curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	case 400:
		pr_verbose(verbose, "Bad request");
		rc = -EBADMSG;
		goto out;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	case 403:
		pr_verbose(verbose, "Insufficient permissions");
		rc = -EPERM;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_array, rc, -EIO,
		       "No or invalid response content", verbose, out);

	*custom_tags = response_obj;
	rc = 0;

out:
	if (uri != NULL)
		free(uri);
	if (escaped_uuid != NULL)
		curl_free(escaped_uuid);
	if (rc != 0 && response_obj != NULL)
		json_object_put(response_obj);

	return rc;
}

/**
 * Gets the export control infos of a key by key-uuid. The export control info
 * is returned as JSON object. The returned JSON object must be freed by the
 * caller using  json_object_put().
 */
static int _ekmf_get_export_control(const struct ekmf_config *config,
				   const char *key_uuid, CURL *curl,
				   json_object **export_control,
				   const char *login_token, char **error_msg,
				   bool verbose)
{
	json_object *response_obj = NULL;
	char *escaped_uuid = NULL;
	char *uri = NULL;
	long status_code;
	int rc;

	if (config == NULL || key_uuid == NULL || export_control == NULL ||
	    curl == NULL)
		return -EINVAL;

	escaped_uuid = curl_easy_escape(curl, key_uuid, 0);
	if (escaped_uuid == NULL) {
		pr_verbose(verbose, "Failed to url-escape the key uuid");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_KEYS_EXPORT_CONTROL, escaped_uuid) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = _ekmf_perform_request(config, uri, "GET", NULL, NULL, login_token,
				   &response_obj, NULL, &status_code, error_msg,
				   curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	case 400:
		pr_verbose(verbose, "Bad request");
		rc = -EBADMSG;
		goto out;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	case 403:
		pr_verbose(verbose, "Insufficient permissions");
		rc = -EPERM;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_object, rc, -EIO,
		       "No or invalid response content", verbose, out);

	*export_control = response_obj;
	rc = 0;

out:
	if (uri != NULL)
		free(uri);
	if (escaped_uuid != NULL)
		curl_free(escaped_uuid);
	if (rc != 0 && response_obj != NULL)
		json_object_put(response_obj);

	return rc;
}

/**
 * Get the custom tags for a key and build the key info structure
 */
static int _ekmf_build_key_info(const struct ekmf_config *config, CURL *curl,
				const char *login_token, json_object *obj,
				struct ekmf_key_info *key, bool copy,
				char **error_msg, bool verbose)
{
	json_object *export_control = NULL;
	json_object *custom_tags = NULL;
	int rc;

	rc = _ekmf_get_custom_tags(config, json_get_string(obj, "keyId"),
				   curl, &custom_tags, login_token, error_msg,
				   verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get the custom tags for key %s",
			   json_get_string(obj, "keyId"));
		goto out;
	}

	rc = _ekmf_get_export_control(config, json_get_string(obj, "keyId"),
				      curl, &export_control, login_token,
				      error_msg, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get the custom tags for key %s",
			   json_get_string(obj, "keyId"));
		goto out;
	}

	rc = json_build_key_info(obj, custom_tags, export_control, key, copy);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build key info");
		goto out;
	}

out:
	/*
	 * Add custom tags and export control JSON objects to the key object,
	 * so that these objects are also owned by the key object, and thus are
	 * freed together with it, when the caller puts/frees the key object.
	 */
	if (custom_tags != NULL)
		json_object_object_add_ex(obj, "_custom_tags_", custom_tags, 0);
	if (export_control != NULL)
		json_object_object_add_ex(obj, "_export_control_",
					  export_control, 0);

	return rc;
}


struct ekmf_key_cb_data_t {
	const struct ekmf_config *config;
	const char *login_token;
	char **error_msg;
	ekmf_key_cb_t key_cb;
	void *cb_private;
};

/**
 * Callback for key list function. Builds the key info structure
 * and calls the application callback.
 */
static int _ekmf_key_cb(CURL *curl, json_object *element,
			void *private, bool verbose)
{
	struct ekmf_key_cb_data_t *cb_data = private;
	struct ekmf_key_info key = { 0 };
	int rc;

	if (cb_data->key_cb == NULL) {
		pr_verbose(verbose, "No key callback function");
		return -EINVAL;
	}

	rc = _ekmf_build_key_info(cb_data->config, curl, cb_data->login_token,
				  element, &key, false, cb_data->error_msg,
				  verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build key info");
		goto out;
	}

	rc = cb_data->key_cb(curl, &key, cb_data->cb_private);
	if (rc != 0) {
		pr_verbose(verbose, "Key callback rc: %d", rc);
		goto out;
	}

out:
	free_tag_list(&key.label_tags, false);
	free_tag_list(&key.custom_tags, false);
	free_export_control(&key.export_control, false);

	return rc;
}

/**
 * Builds the state URL parameter(s) from a comma separated list of states
 *
 * @param curl              the curl handle
 * @param states            a comma separaed list of states
 *
 * @returns an allocated URL parameter value, or NULL in case of an error
 */
static char *_ekmf_build_state_filter(CURL *curl, const char *states)
{
	char *list, *tok, *ret = NULL, *tmp;
	char *escaped_state;

	if (states == NULL)
		goto error;

	list = strdup(states);
	if (list == NULL)
		goto error;

	tok = strtok(list, ",");
	while (tok != NULL) {
		escaped_state = curl_easy_escape(curl, tok, 0);
		if (escaped_state == NULL)
			goto error;

		if (asprintf(&tmp, "%s%s%s", ret != NULL ? ret : "",
			     ret == NULL ? "" : EKMF_URI_KEYS_LIST_STATE,
			     escaped_state) < 0)
			tmp = NULL;
		curl_free(escaped_state);
		if (tmp == NULL)
			goto error;
		if (ret != NULL)
			free(ret);
		ret = tmp;

		tok = strtok(NULL, ",");
	}

	free(list);
	return ret;

error:
	if (ret != NULL)
		free(ret);
	return NULL;
}

/**
 * List available keys. The keys are ordered by name in ascending order.
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
 * @param key_cb            a callback function that is called for each key
 *                          found
 * @param private           a pointer that is passed as-is to the callback
 * @param name_pattern      a pattern to filter by name, or NULL to list all.
 * @param states            the states of the keys to list, or NULL to list keys
 *                          in ACTIVE state only. Multiple states can be
 *                          specified separated by comma.
 * @param tags              a list of custom tags to use as filter, or NULL
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          list the keys
 */
int ekmf_list_keys(const struct ekmf_config *config, CURL **curl_handle,
		   ekmf_key_cb_t key_cb, void *private,
		   const char *name_pattern, const char *states,
		   const struct ekmf_tag_list *tags,
		   char **error_msg, bool verbose)
{
	struct ekmf_key_cb_data_t cb_data;
	char *escaped_name_pattern = NULL;
	json_object *tags_obj = NULL;
	char *state_filter = NULL;
	char *escaped_tags = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	char *uri = NULL;
	size_t i;
	int rc;

	if (config == NULL || key_cb == NULL)
		return -EINVAL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	cb_data.config = config;
	cb_data.login_token = login_token;
	cb_data.error_msg = error_msg;
	cb_data.key_cb = key_cb;
	cb_data.cb_private = private;

	escaped_name_pattern = curl_easy_escape(curl, name_pattern != NULL ?
							name_pattern : "*", 0);
	if (escaped_name_pattern == NULL) {
		pr_verbose(verbose, "Failed to url-escape the name pattern");
		rc = -EIO;
		goto out;
	}

	state_filter = _ekmf_build_state_filter(curl, states != NULL ? states :
						KEY_STATE_ACTIVE);
	if (state_filter == NULL) {
		pr_verbose(verbose, "Failed to build the state filter");
		rc = -EIO;
		goto out;
	}

	tags_obj = json_object_new_object();
	JSON_CHECK_ERROR(tags_obj == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object", verbose, out);
	for (i = 0; tags != NULL && i < tags->num_tags; i++) {
		if (tags->tags[i].name == NULL || tags->tags[i].value == NULL) {
			rc = -EINVAL;
			goto out;
		}

		rc = json_object_object_add_ex(tags_obj, tags->tags[i].name,
					       json_object_new_string(
							tags->tags[i].value),
					       0);
		JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
				 "JSON object", verbose, out);
	}

	escaped_tags = curl_easy_escape(curl, json_object_to_json_string_ext(
				tags_obj, JSON_C_TO_STRING_PLAIN |
					  JSON_C_TO_STRING_NOSLASHESCAPE), 0);
	if (escaped_tags == NULL) {
		pr_verbose(verbose, "Failed to url-escape the tags");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_KEYS_LIST, state_filter,
		     ORDER_BY_LABEL_ASC, escaped_name_pattern,
		     escaped_tags) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = _ekmf_list_request(config, uri, curl, _ekmf_key_cb,
				&cb_data, login_token, error_msg, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to perform the list request");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (login_token != NULL)
		free(login_token);
	if (uri != NULL)
		free(uri);
	if (state_filter != NULL)
		free(state_filter);
	if (escaped_name_pattern != NULL)
		curl_free(escaped_name_pattern);
	if (escaped_tags != NULL)
		curl_free(escaped_tags);
	if (tags_obj != NULL)
		json_object_put(tags_obj);

	return rc;
}

/**
 * Get information about a key by its UUID.
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
 * @param key_uuid          the UUID of the key to get info for
 * @param key               an address of a key info pointer. On return
 *                          the pointer is updated to point to a newly allocated
 *                          key info struct. It must be freed by the caller
 *                          using ekmf_free_key_info when no longer needed.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          get the key info
 */
int ekmf_get_key_info(const struct ekmf_config *config, CURL **curl_handle,
		      const char *key_uuid, struct ekmf_key_info **key,
		      char **error_msg, bool verbose)
{
	json_object *response_obj = NULL;
	char *escaped_uuid = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	char *uri = NULL;
	long status_code;
	int rc;

	if (config == NULL || key_uuid == NULL || key == NULL)
		return -EINVAL;

	*key = NULL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	escaped_uuid = curl_easy_escape(curl, key_uuid, 0);
	if (escaped_uuid == NULL) {
		pr_verbose(verbose, "Failed to url-escape the key uuid");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_KEYS_GET, escaped_uuid) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = _ekmf_perform_request(config, uri, "GET", NULL, NULL,
				   login_token, &response_obj, NULL,
				   &status_code, error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
		break;
	case 400:
		pr_verbose(verbose, "Bad request");
		rc = -EBADMSG;
		goto out;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	case 403:
		pr_verbose(verbose, "Insufficient permissions");
		rc = -EPERM;
		goto out;
	case 404:
		pr_verbose(verbose, "Not found");
		rc = -ENOENT;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_object, rc, -EBADMSG,
		       "No or invalid response", verbose, out);

	*key = calloc(1, sizeof(struct ekmf_key_info));
	if (*key == NULL) {
		pr_verbose(verbose, "calloc failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = _ekmf_build_key_info(config, curl, login_token, response_obj,
				  *key, true, error_msg, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build template info");
		goto out;
	}

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (response_obj != NULL)
		json_object_put(response_obj);
	if (login_token != NULL)
		free(login_token);
	if (uri != NULL)
		free(uri);
	if (escaped_uuid != NULL)
		curl_free(escaped_uuid);
	if (rc != 0 && *key != NULL) {
		free_key_info(*key);
		free(*key);
		*key = NULL;
	}

	return rc;
}

/**
 * Changes the state of a key identified by its UUID. To update a key,
 * the timestamp from the last update is required. This can be found in
 * the key info struct in field update_on.
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
 * @param key_uuid          the UUID of the key to get info for
 * @param new_state         the new state of the key
 * @param updated_on        the timestamp of the last update (must match)
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          update the key.
 *          -EAGAIN is returned if the timestamp does not match, indicating that
 *          the key has been updated in the meantime.
 */
int ekmf_set_key_state(const struct ekmf_config *config, CURL **curl_handle,
		       const char *key_uuid, const char *new_state,
		       const char *updated_on, char **error_msg, bool verbose)
{
	char *request_headers[2] = { NULL, NULL };
	json_object *request_obj = NULL;
	char *escaped_uuid = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	char *if_match_hdr = NULL;
	CURL *curl = NULL;
	char *uri = NULL;
	long status_code;
	int rc;

	if (config == NULL || key_uuid == NULL || new_state == NULL ||
	    updated_on == NULL)
		return -EINVAL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	request_obj = json_object_new_object();
	JSON_CHECK_ERROR(request_obj == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object", verbose, out);

	rc = json_object_object_add_ex(request_obj, "state",
				       json_object_new_string(new_state), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);

	escaped_uuid = curl_easy_escape(curl, key_uuid, 0);
	if (escaped_uuid == NULL) {
		pr_verbose(verbose, "Failed to url-escape the key uuid");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_KEYS_SET_STATE, escaped_uuid) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	if (asprintf(&if_match_hdr, "If-Match : %s", updated_on) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}
	request_headers[0] = if_match_hdr;

	rc = _ekmf_perform_request(config, uri, "PATCH", request_obj,
				   request_headers, login_token, NULL, NULL,
				   &status_code, error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 204:
		break;
	case 400:
		pr_verbose(verbose, "Bad request");
		rc = -EBADMSG;
		goto out;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	case 403:
		pr_verbose(verbose, "Insufficient permissions");
		rc = -EPERM;
		goto out;
	case 404:
		pr_verbose(verbose, "Not found");
		rc = -ENOENT;
		goto out;
	case 409:
		pr_verbose(verbose, "Key was updated in the meantime");
		rc = -EAGAIN;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (request_obj != NULL)
		json_object_put(request_obj);
	if (login_token != NULL)
		free(login_token);
	if (uri != NULL)
		free(uri);
	if (escaped_uuid != NULL)
		curl_free(escaped_uuid);
	if (if_match_hdr != NULL)
		free(if_match_hdr);

	return rc;
}

/**
 * Sets (adds/changes) a custom tag of a key identified by its UUID. To update
 * a key, the timestamp from the last update is required. This can be found in
 * the key info struct in field update_on.
 *
 * @param config            the configuration structure
 * @param curl              the CURL handle
 * @param login_token       the login token to authenticate
 * @param key_uuid          the UUID of the key to get info for
 * @param tag               the tag to set
 * @param updated_on        the timestamp of the last update (must match)
 * @param delete            if true, the tag is deleted, otherwise it is updated
 * @param etag              On return: the new update timestamp returned via
 *                          the etag HTTP header. Must be freed by the caller.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          update the key.
 *          -EAGAIN is returned if the timestamp does not match, indicating that
 *          the key has been updated in the meantime.
 */
static int _ekmf_set_key_tag(const struct ekmf_config *config, CURL *curl,
			     const char *login_token,  const char *key_uuid,
			     const struct ekmf_tag *tag, const char *updated_on,
			     bool delete, char **etag, char **error_msg,
			     bool verbose)
{
	struct curl_slist *response_headers = NULL;
	char *request_headers[2] = { NULL, NULL };
	json_object *request_obj = NULL;
	char *escaped_tag_name = NULL;
	char *escaped_uuid = NULL;
	char *if_match_hdr = NULL;
	char *uri = NULL;
	long status_code;
	int rc;

	if (config == NULL || curl == NULL || login_token == NULL ||
	    key_uuid == NULL || tag == NULL || updated_on == NULL ||
	    etag == NULL)
		return -EINVAL;

	*etag = NULL;

	if (!delete) {
		request_obj = json_object_new_object();
		JSON_CHECK_ERROR(request_obj == NULL, rc, -ENOMEM,
				 "Failed to generate JSON object", verbose,
				 out);

		rc = json_object_object_add_ex(request_obj, "value",
					json_object_new_string(tag->value), 0);
		JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
				 "JSON object", verbose, out);
	}

	escaped_uuid = curl_easy_escape(curl, key_uuid, 0);
	if (escaped_uuid == NULL) {
		pr_verbose(verbose, "Failed to url-escape the key uuid");
		rc = -EIO;
		goto out;
	}

	escaped_tag_name = curl_easy_escape(curl, tag->name, 0);
	if (escaped_tag_name == NULL) {
		pr_verbose(verbose, "Failed to url-escape the tag name");
		rc = -EIO;
		goto out;
	}

	if (asprintf(&uri, EKMF_URI_KEYS_SET_TAG, escaped_uuid,
		     escaped_tag_name) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}

	if (asprintf(&if_match_hdr, "If-Match : %s", updated_on) < 0) {
		pr_verbose(verbose, "asprintf failed");
		rc = -ENOMEM;
		goto out;
	}
	request_headers[0] = if_match_hdr;

	rc = _ekmf_perform_request(config, uri, delete ? "DELETE" : "PUT",
				   request_obj, request_headers, login_token,
				   NULL, &response_headers, &status_code,
				   error_msg, curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 200:
	case 204:
		break;
	case 400:
		pr_verbose(verbose, "Bad request");
		rc = -EBADMSG;
		goto out;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	case 403:
		pr_verbose(verbose, "Insufficient permissions");
		rc = -EPERM;
		goto out;
	case 404:
		pr_verbose(verbose, "Not found");
		rc = -ENOENT;
		goto out;
	case 409:
		pr_verbose(verbose, "Key was updated in the meantime");
		rc = -EAGAIN;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	*etag = get_http_header_value(response_headers, "Etag");
	if (*etag == NULL) {
		pr_verbose(verbose, "No ETag in response headers");
		rc = -EBADMSG;
		goto out;
	}

out:
	if (request_obj != NULL)
		json_object_put(request_obj);
	if (uri != NULL)
		free(uri);
	if (escaped_uuid != NULL)
		curl_free(escaped_uuid);
	if (escaped_tag_name != NULL)
		curl_free(escaped_tag_name);
	if (if_match_hdr != NULL)
		free(if_match_hdr);
	if (response_headers != NULL)
		curl_slist_free_all(response_headers);

	return rc;
}

/**
 * Sets (changed/adds) custom tags of a key identified by its UUID. To update a
 * key, the timestamp from the last update is required. This can be found in
 * the key info struct in field update_on.
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
 * @param key_uuid          the UUID of the key to get info for
 * @param tags              a list of tags to set
 * @param updated_on        the timestamp of the last update (must match)
 * @param new_updated_on    on return: if not NULL, the new timestamp of the
 *                          current update. Can be used for subsequent updates
 *                          on the key.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          update the key.
 *          -EAGAIN is returned if the timestamp does not match, indicating that
 *          the key has been updated in the meantime.
 */
int ekmf_set_key_tags(const struct ekmf_config *config, CURL **curl_handle,
		       const char *key_uuid, const struct ekmf_tag_list *tags,
		       const char *updated_on, char **new_updated_on,
		       char **error_msg, bool verbose)
{
	char *update_ts = (char *)updated_on;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	char *etag = NULL;
	size_t i;
	int rc;

	if (config == NULL || key_uuid == NULL || tags == NULL ||
	    updated_on == NULL)
		return -EINVAL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	for (i = 0; i < tags->num_tags; i++) {
		rc = _ekmf_set_key_tag(config, curl, login_token, key_uuid,
				       &tags->tags[i], update_ts, false, &etag,
				       error_msg, verbose);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to set tag '%s'",
				   tags->tags[i].name);
			goto out;
		}

		if (update_ts != NULL && update_ts != updated_on)
			free(update_ts);
		update_ts = etag;
		etag = NULL;
	}

	if (new_updated_on != NULL)
		*new_updated_on = strdup(update_ts);

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (login_token != NULL)
		free(login_token);
	if (update_ts != NULL && update_ts != updated_on)
		free(update_ts);
	if (etag != NULL)
		free(etag);

	return rc;
}

/**
 * Deletes custom tags of a key identified by its UUID. To update a
 * key, the timestamp from the last update is required. This can be found in
 * the key info struct in field update_on.
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
 * @param key_uuid          the UUID of the key to get info for
 * @param tags              a list of tags to delete. Only the name of the tags
 *                          must be present in the tag structs of the list, the
 *                          values are ignored.
 * @param updated_on        the timestamp of the last update (must match)
 * @param new_updated_on    on return: if not NULL, the new timestamp of the
 *                          current update. Can be used for subsequent updates
 *                          on the key.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          update the key.
 *          -EAGAIN is returned if the timestamp does not match, indicating that
 *          the key has been updated in the meantime.
 */
int ekmf_delete_key_tags(const struct ekmf_config *config, CURL **curl_handle,
			 const char *key_uuid, const struct ekmf_tag_list *tags,
			 const char *updated_on, char **new_updated_on,
			 char **error_msg, bool verbose)
{
	char *update_ts = (char *)updated_on;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	char *etag = NULL;
	size_t i;
	int rc;

	if (config == NULL || key_uuid == NULL || tags == NULL ||
	    updated_on == NULL)
		return -EINVAL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	for (i = 0; i < tags->num_tags; i++) {
		rc = _ekmf_set_key_tag(config, curl, login_token, key_uuid,
				       &tags->tags[i], update_ts, true, &etag,
				       error_msg, verbose);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to delete tag '%s'",
				   tags->tags[i].name);
			goto out;
		}

		if (update_ts != NULL && update_ts != updated_on)
			free(update_ts);
		update_ts = etag;
		etag = NULL;
	}

	if (new_updated_on != NULL)
		*new_updated_on = strdup(update_ts);

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (login_token != NULL)
		free(login_token);
	if (update_ts != NULL && update_ts != updated_on)
		free(update_ts);
	if (etag != NULL)
		free(etag);

	return rc;
}

/**
 * Clones a key info structure by making a deep copy of all strings and
 * arrays.
 * The copied key info must be freed using ekmf_free_key_info() by
 * the caller.
 *
 * @param src               the source key info structure
 * @param dest              the destination key info structure
 *
 * @returns zero for success, a negative errno in case of an error
 */
int ekmf_clone_key_info(const struct ekmf_key_info *src,
			struct ekmf_key_info **dest)
{
	if (src == NULL || dest == NULL)
		return -EINVAL;

	*dest = calloc(1, sizeof(struct ekmf_key_info));
	if (*dest == NULL)
		return -ENOMEM;

	return clone_key_info(src, *dest);
}

/**
 * Free a key info structure.
 *
 * @param key               the key info to free
 */
void ekmf_free_key_info(struct ekmf_key_info *key)
{
	free_key_info(key);

	free(key);
}

/**
 * Build the export control JSON object.
 *
 * @param exporting_key     the key to add as exporting key
 * @param expctl_obj        on return: the export control JSON object
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 */
static int _ekmf_build_export_control(const char *exporting_key,
				      json_object **expctl_obj, bool verbose)
{
	json_object *exp_keys = NULL;
	json_object *exp_ref = NULL;
	char *href = NULL;
	int rc = 0;

	*expctl_obj = json_object_new_object();
	JSON_CHECK_ERROR(*expctl_obj == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object",
			 verbose, out);

	rc = json_object_object_add_ex(*expctl_obj, "exportAllowed",
				       json_object_new_boolean(true), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
			 "JSON object", verbose, out);

	exp_keys = json_object_new_array();
	JSON_CHECK_ERROR(exp_keys == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object",
			 verbose, out);

	exp_ref = json_object_new_object();
	JSON_CHECK_ERROR(exp_ref == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object",
			 verbose, out);

	rc = json_object_object_add_ex(exp_ref, "rel",
			json_object_new_string("exportAllowedWithKey"), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
			 "JSON object", verbose, out);

	JSON_CHECK_ERROR(asprintf(&href, "/keys/%s", exporting_key) < 0, rc,
			 -ENOMEM, "Failed to allocate string", verbose, out);
	rc = json_object_object_add_ex(exp_ref, "href",
				       json_object_new_string(href), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
			 "JSON object", verbose, out);

	rc = json_object_array_add(exp_keys, exp_ref);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
			 "JSON object", verbose, out);
	exp_ref = NULL;

	rc = json_object_object_add_ex(*expctl_obj, "allowedKeys", exp_keys, 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
			 "JSON object", verbose, out);
	exp_keys = NULL;

out:
	if (exp_keys != NULL)
		json_object_put(exp_keys);
	if (exp_ref != NULL)
		json_object_put(exp_ref);
	if (href != NULL)
		free(href);
	if (rc != 0 && *expctl_obj != NULL) {
		json_object_put(*expctl_obj);
		*expctl_obj = NULL;
	}

	return rc;
}

/**
 * Base64-encodes the data
 *
 * @param data              the data to encode
 * @param data_size         the size of the data in bytes
 *
 * @returns the encoded data or NULL in case of an error.
 * The caller must free the string when no longer needed.
 */
static char *_ekmf_base64_encode(const unsigned char *data, size_t data_size)
{
	int outlen, len;
	char *out;

	outlen = (data_size / 3) * 4;
	if (data_size % 3 > 0)
		outlen += 4;

	out = calloc(outlen + 1, 1);
	if (out == NULL)
		return NULL;

	len = EVP_EncodeBlock((unsigned char *)out, data, data_size);
	if (len != outlen) {
		free(out);
		return NULL;
	}

	out[outlen] = '\0';
	return out;
}

/**
 * Build the key material JSON object
 *
 * @param certificate       the certificate to generate an identity key from
 * @param certificate_size  the size of the certificate
 * @param keymat_obj        on return: the key material JSON object
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 */
static int _ekmf_build_key_material(const unsigned char *certificate,
				    size_t certificate_size,
				    json_object **keymat_obj, bool verbose)
{
	char *payload = NULL;
	int rc = 0;

	*keymat_obj = json_object_new_object();
	JSON_CHECK_ERROR(*keymat_obj == NULL, rc, -ENOMEM,
				 "Failed to generate JSON object",
				 verbose, out);

	rc = json_object_object_add_ex(*keymat_obj, "type",
			json_object_new_string("ENCODED-CERTIFICATE"), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
			 "JSON object", verbose, out);

	payload = _ekmf_base64_encode(certificate, certificate_size);
	JSON_CHECK_ERROR(*keymat_obj == NULL, rc, -EIO,
			 "Failed to base64 encode the certificate",
			 verbose, out);

	rc = json_object_object_add_ex(*keymat_obj, "payload",
				json_object_new_string(payload), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
			 "JSON object", verbose, out);

out:
	if (rc != 0 && *keymat_obj != NULL) {
		json_object_put(*keymat_obj);
		*keymat_obj = NULL;
	}
	if (payload != NULL)
		free(payload);

	return rc;
}

/**
 * Generates a new key in EKMFWeb
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
 * @param template          the name of the template to generate the key with
 * @param description       Optional: a textual description of the key (can be
 *                          NULL)
 * @param label_tags        list of label tags. The label tags are required as
 *                          defined in the template
 * @param custom_tags       Optional: list of custom tags (can be NULL)
 * @param exporting_key     Optional: The uuid of the key that is allowed to
 *                          export the newly generated key (can be NULL).
 * @param certificate       Optional: The certificate to generate an identity
 *                          key from. Should be NULL for generating AES keys.
 * @param certificate_size  Optional: the size of the certificate. Required if
 *                          certificate is not NULL.
 * @param key_info          Optional: On return: If not NULL, a key info struct
 *                          is returned here containing key information. This
 *                          must be freed by the caller with ekmf_free_key_info
 *                          when no longer needed.
 * @param error_msg         on return: If not NULL, then a textual error message
 *                          is returned in case of a failing request. The caller
 *                          must free the error string when it is not NULL.
 * @param verbose           if true, verbose messages are printed
 *
 * @returns zero for success, a negative errno in case of an error.
 *          -EACCES is returned, if no or no valid login token is available.
 *          -EPERM is returned if the login token does not have permission to
 *          generate keys
 */
int ekmf_generate_key(const struct ekmf_config *config, CURL **curl_handle,
		      const char *template, const char *description,
		      const struct ekmf_tag_list *label_tags,
		      const struct ekmf_tag_list *custom_tags,
		      const char *exporting_key,
		      const unsigned char *certificate, size_t certificate_size,
		      struct ekmf_key_info **key_info,
		      char **error_msg, bool verbose)
{
	json_object *response_obj = NULL;
	json_object *request_obj = NULL;
	json_object *expctl_obj = NULL;
	json_object *keymat_obj = NULL;
	json_object *tags_obj = NULL;
	char *login_token = NULL;
	bool token_valid = false;
	CURL *curl = NULL;
	long status_code;
	int rc;

	if (config == NULL || template == NULL || label_tags == NULL ||
	    label_tags->num_tags == 0 || label_tags->tags == NULL)
		return -EINVAL;
	if (custom_tags != NULL && custom_tags->num_tags > 0 &&
	    custom_tags->tags == NULL)
		return -EINVAL;
	if (certificate != NULL && certificate_size == 0)
		return -EINVAL;

	if (key_info != NULL)
		*key_info = NULL;

	rc = ekmf_check_login_token(config, &token_valid, &login_token,
				    verbose);
	if (rc != 0 || !token_valid) {
		pr_verbose(verbose, "No valid login token available");
		rc = -EACCES;
		goto out;
	}

	rc = _ekmf_get_curl_handle(curl_handle, &curl);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get CURL handle");
		rc = -EIO;
		goto out;
	}

	request_obj = json_object_new_object();
	JSON_CHECK_ERROR(request_obj == NULL, rc, -ENOMEM,
			 "Failed to generate JSON object", verbose, out);

	rc = json_object_object_add_ex(request_obj, "templateName",
				       json_object_new_string(template), 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);

	rc = build_json_tag_list(label_tags, &tags_obj);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to build label tag JSON object");
		goto out;
	}

	rc = json_object_object_add_ex(request_obj, "labelTags", tags_obj, 0);
	JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to JSON object",
			 verbose, out);
	tags_obj = NULL;

	if (description != NULL) {
		rc = json_object_object_add_ex(request_obj, "description",
					json_object_new_string(description), 0);
		JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
				 "JSON object", verbose, out);
	}

	if (certificate != NULL) {
		rc = _ekmf_build_key_material(certificate, certificate_size,
					      &keymat_obj, verbose);
		if (rc != 0)
			goto out;

		rc = json_object_object_add_ex(request_obj, "keyMaterial",
					       keymat_obj, 0);
		JSON_CHECK_ERROR(rc != 0, rc, -EIO,
				 "Failed to add data to JSON object",
				 verbose, out);
		keymat_obj = NULL;
	}

	if (custom_tags != NULL && custom_tags->num_tags > 0) {
		rc = build_json_tag_list(custom_tags, &tags_obj);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to build custom tag JSON "
				   "object");
			goto out;
		}

		rc = json_object_object_add_ex(request_obj, "customTags",
					       tags_obj, 0);
		JSON_CHECK_ERROR(rc != 0, rc, -EIO, "Failed to add data to "
				 "JSON object", verbose, out);
		tags_obj = NULL;
	}

	if (exporting_key != NULL) {
		rc = _ekmf_build_export_control(exporting_key, &expctl_obj,
						verbose);
		if (rc != 0)
			goto out;

		rc = json_object_object_add_ex(request_obj, "exportControl",
					       expctl_obj, 0);
		JSON_CHECK_ERROR(rc != 0, rc, -EIO,
				 "Failed to add data to JSON object",
				 verbose, out);
		expctl_obj = NULL;
	}

	rc = _ekmf_perform_request(config, EKMF_URI_KEYS_GENERATE, "POST",
				   request_obj, NULL, login_token,
				   &response_obj, NULL, &status_code, error_msg,
				   curl, verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed perform the REST call");
		if (rc > 0)
			rc = -EIO;
		goto out;
	}

	switch (status_code) {
	case 201:
		break;
	case 400:
		pr_verbose(verbose, "Bad request");
		rc = -EBADMSG;
		goto out;
	case 401:
		pr_verbose(verbose, "Not authorized");
		rc = -EACCES;
		goto out;
	case 403:
		pr_verbose(verbose, "Insufficient permissions");
		rc = -EPERM;
		goto out;
	case 409:
		pr_verbose(verbose, "A key with this label exist already");
		rc = -EEXIST;
		goto out;
	default:
		pr_verbose(verbose, "REST Call failed with HTTP status code: "
			   "%ld", status_code);
		rc = -EIO;
		goto out;
	}

	JSON_CHECK_OBJ(response_obj, json_type_object, rc, -EBADMSG,
		       "No or invalid response", verbose, out);

	if (key_info != NULL) {
		*key_info = calloc(1, sizeof(struct ekmf_key_info));
		if (*key_info == NULL) {
			pr_verbose(verbose, "calloc failed");
			rc = -ENOMEM;
			goto out;
		}

		rc = _ekmf_build_key_info(config, curl, login_token,
					  response_obj, *key_info, true,
					  error_msg, verbose);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to build the key info");
			goto out;
		}
	}

out:
	_ekmf_release_curl_handle(curl_handle, curl);

	if (request_obj != NULL)
		json_object_put(request_obj);
	if (response_obj != NULL)
		json_object_put(response_obj);
	if (login_token != NULL)
		free(login_token);
	if (tags_obj != NULL)
		json_object_put(tags_obj);
	if (expctl_obj != NULL)
		json_object_put(expctl_obj);
	if (keymat_obj != NULL)
		json_object_put(keymat_obj);
	if (rc != 0 && key_info != NULL && *key_info != NULL) {
		free(*key_info);
		*key_info = NULL;
	}
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
				 bool verbose)
{
	unsigned char key_blob[MAX_KEY_BLOB_SIZE];
	size_t key_blob_size = sizeof(key_blob);
	const char *out_file;
	int rc;

	if (config == NULL || ext_lib == NULL)
		return -EINVAL;
	if (config->identity_secure_key == NULL)
		return -EINVAL;

	rc = read_key_blob(config->identity_secure_key, key_blob,
			   &key_blob_size);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to read identity key from file "
			   "'%s': %s", config->identity_secure_key,
			   strerror(-rc));
		return rc;
	}

	switch (ext_lib->type) {
	case EKMF_EXT_LIB_CCA:
		rc = cca_reencipher_key(ext_lib->cca, key_blob, key_blob_size,
					to_new, verbose);
		break;
	default:
		pr_verbose(verbose, "Invalid ext lib type: %d", ext_lib->type);
		return -EINVAL;
	}

	if (rc != 0) {
		pr_verbose(verbose, "Failed to re-encipher the secure identity "
			   "key from file '%s': %s",
			   config->identity_secure_key, strerror(-rc));
		return rc;
	}

	out_file = reenc_secure_key != NULL ? reenc_secure_key :
						config->identity_secure_key;
	rc = write_key_blob(out_file, key_blob, key_blob_size);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to write identity key to file "
			   "'%s': %s", out_file, strerror(-rc));
		return rc;
	}

	return 0;
}

/**
 * Wrapper for the RSA sign callback to route the call to the selected
 * secure key library.
 */
static int _ekmf_rsa_sign(const unsigned char *key_blob, size_t key_blob_length,
			  unsigned char *sig, size_t *siglen,
			  const unsigned char *tbs, size_t tbslen,
			  int padding_type, int md_nid, void *private)
{
	struct private_data *prv = (struct private_data *)private;

	if (prv == NULL || prv->ext_lib == NULL)
		return 1;

	switch (prv->ext_lib->type) {
	case EKMF_EXT_LIB_CCA:
		return cca_rsa_sign(prv->ext_lib->cca, key_blob,
				    key_blob_length, sig, siglen, tbs, tbslen,
				    padding_type, md_nid, prv->verbose);
	default:
		return 1;
	}
}

/**
 * Wrapper for the RSA-PSS sign callback to route the call to the selected
 * secure key library.
 */
static int _ekmf_rsa_pss_sign(const unsigned char *key_blob,
			      size_t key_blob_length, unsigned char *sig,
			      size_t *siglen, const unsigned char *tbs,
			      size_t tbslen, int md_nid, int mgfmd_nid,
			      int saltlen, void *private)
{
	struct private_data *prv = (struct private_data *)private;

	if (prv == NULL || prv->ext_lib == NULL)
		return 1;

	switch (prv->ext_lib->type) {
	case EKMF_EXT_LIB_CCA:
		return cca_rsa_pss_sign(prv->ext_lib->cca, key_blob,
					key_blob_length, sig, siglen, tbs,
					tbslen, md_nid, mgfmd_nid, saltlen,
					prv->verbose);
	default:
		return 1;
	}
}

/**
 * Wrapper for the ECDSA sign callback to route the call to the selected
 * secure key library.
 */
static int _ekmf_ecdsa_sign(const unsigned char *key_blob,
			    size_t key_blob_length, unsigned char *sig,
			    size_t *siglen, const unsigned char *tbs,
			    size_t tbslen, int md_nid, void *private)
{
	struct private_data *prv = (struct private_data *)private;

	if (prv == NULL || prv->ext_lib == NULL)
		return 1;

	switch (prv->ext_lib->type) {
	case EKMF_EXT_LIB_CCA:
		return cca_ecdsa_sign(prv->ext_lib->cca, key_blob,
				      key_blob_length, sig, siglen, tbs, tbslen,
				      md_nid, prv->verbose);
	default:
		return 1;
	}
}

/**
 * Gets the public key from the key blob as a PKEY object.
 */
static int _ekmf_get_pub_key_as_pkey(const unsigned char *key_blob,
				     size_t key_blob_size, EVP_PKEY **pkey,
				     bool rsa_pss,
				     const struct ekmf_ext_lib *ext_lib,
				     bool verbose)
{
	int rc, pkey_type;

	switch (ext_lib->type) {
	case EKMF_EXT_LIB_CCA:
		rc = cca_get_key_type(key_blob, key_blob_size, &pkey_type);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to get the identity key "
				   "type: %s", strerror(-rc));
			return rc;
		}

		switch (pkey_type) {
		case EVP_PKEY_EC:
			rc = cca_get_ecc_pub_key_as_pkey(key_blob,
					key_blob_size, pkey, verbose);
			break;
		case EVP_PKEY_RSA:
		case EVP_PKEY_RSA_PSS:
			rc = cca_get_rsa_pub_key_as_pkey(key_blob,
					key_blob_size, rsa_pss ?
						EVP_PKEY_RSA_PSS : pkey_type,
					pkey, verbose);
			break;
		default:
			pr_verbose(verbose, "Invalid identity key type: %d",
				   pkey_type);
			return -EIO;
		}

		if (rc != 0)
			return rc;
		break;
	default:
		pr_verbose(verbose, "Invalid ext lib type: %d", ext_lib->type);
		return -EINVAL;
	}

	return 0;
}

/**
 * Setup a signing context for the specified key, digest_nid, and RSA-PSS
 * parameters.
 */
static int _ekmf_setup_sign_context(const unsigned char *key_blob,
				    size_t key_blob_size, EVP_PKEY *pkey,
				    int digest_nid,
				    struct ekmf_rsa_pss_params *rsa_pss_params,
				    EVP_MD_CTX **md_ctx,
				    EVP_PKEY_CTX **pkey_ctx,
				    struct private_data *private,
				    bool verbose)
{
	struct sk_pkey_sign_func sign_func;
	EVP_PKEY_CTX *pctx = NULL;
	const EVP_MD *md = NULL;
	int rc, default_nid;
	EVP_MD_CTX *ctx;

	rc = setup_secure_key_pkey_method(EVP_PKEY_id(pkey));
	if (rc != 0) {
		pr_verbose(verbose, "Failed to setup secure key PKEY method");
		return rc;
	}

	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		pr_verbose(verbose, "Failed to allocate the digest context");
		rc = -ENOMEM;
		goto out;
	}

	if (digest_nid != 0) {
		md = EVP_get_digestbynid(digest_nid);
		if (md == NULL) {
			pr_verbose(verbose, "Requested digest not supported");
			rc = -ENOTSUP;
			goto out;
		}

		if (EVP_PKEY_get_default_digest_nid(pkey, &default_nid) == 2 &&
		    default_nid == 0) {
			pr_verbose(verbose, "The signing algorithm requires "
				   "there to be no digest");
			md = NULL;
		}
	}

	rc = EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey);
	if (rc != 1) {
		pr_verbose(verbose, "Failed to initialize the signing "
			   "operation");
		rc = -EIO;
		goto out;
	}

	sign_func.rsa_sign = _ekmf_rsa_sign;
	sign_func.rsa_pss_sign = _ekmf_rsa_pss_sign;
	sign_func.ecdsa_sign = _ekmf_ecdsa_sign;

	rc = setup_secure_key_pkey_context(pctx, key_blob, key_blob_size,
					   &sign_func, private);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to setup the secure key PKEY "
			   "context: %s", strerror(-rc));
		goto out;
	}

	if (EVP_PKEY_id(pkey) == EVP_PKEY_RSA_PSS && rsa_pss_params != NULL) {
		rc = setup_rsa_pss_pkey_context(pctx, rsa_pss_params);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to setup RSA-PSS context");
			goto out;
		}
	}

	*md_ctx = ctx;
	*pkey_ctx = pctx;

out:
	if (rc != 0) {
		cleanup_secure_key_pkey_method(EVP_PKEY_id(pkey));
		if (ctx != NULL)
			EVP_MD_CTX_free(ctx);
	}
	return rc;
}

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
		      const struct ekmf_ext_lib *ext_lib, bool verbose)
{
	const STACK_OF(X509_EXTENSION) *cert_exts = NULL;
	unsigned char key_blob[MAX_KEY_BLOB_SIZE];
	size_t key_blob_size = sizeof(key_blob);
	X509_NAME *subject_name = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	struct private_data private;
	EVP_MD_CTX *md_ctx = NULL;
	bool pkey_meth = false;
	EVP_PKEY *pkey = NULL;
	X509_REQ *req = NULL;
	X509 *cert = NULL;
	int rc;

	if (config == NULL || ext_lib == NULL || csr_pem_filename == NULL)
		return -EINVAL;
	if (config->identity_secure_key == NULL)
		return -EINVAL;
	if (renew_cert_filename == NULL &&
	    (subject_rdns == NULL || num_subject_rdns == 0))
		return -EINVAL;
	if (num_extensions != 0 && extensions == NULL)
		return -EINVAL;

	rc = read_key_blob(config->identity_secure_key, key_blob,
			   &key_blob_size);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to read identity key from file "
			   "'%s': %s", config->identity_secure_key,
			   strerror(-rc));
		goto out;
	}

	rc = _ekmf_get_pub_key_as_pkey(key_blob, key_blob_size, &pkey,
				       rsa_pss_params != NULL, ext_lib,
				       verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get identity key as PKEY from "
			   "file '%s': %s", config->identity_secure_key,
			   strerror(-rc));
		goto out;
	}

	req = X509_REQ_new();
	if (req == NULL) {
		pr_verbose(verbose, "X509_REQ_new failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = X509_REQ_set_version(req, 0L);
	if (rc != 1) {
		pr_verbose(verbose, "X509_REQ_set_version failed: rc: %d", rc);
		rc = -EIO;
		goto out;
	}

	if (renew_cert_filename != NULL) {
		rc = read_x509_certificate(renew_cert_filename, &cert);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to open renew cert file "
				   "'%s': %s", renew_cert_filename,
				   strerror(-rc));
			goto out;
		}

		subject_name = X509_NAME_dup(X509_get_subject_name(cert));
		cert_exts = X509_get0_extensions(cert);
	}

	if (subject_rdns != NULL && num_subject_rdns > 0) {
		rc = build_subject_name(&subject_name, subject_rdns,
					num_subject_rdns, subject_utf8);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to parse the subject name "
				   "RDSn: %s", strerror(-rc));
			goto out;
		}
	}

	if (subject_name == NULL) {
		rc = -EINVAL;
		pr_verbose(verbose, "Subject name can not be empty");
		goto out;
	}

	rc = X509_REQ_set_subject_name(req, subject_name);
	if (rc != 1) {
		rc = -EIO;
		pr_verbose(verbose, "Failed to set subject name into request");
		goto out;
	}

	rc = build_certificate_extensions(NULL, req, extensions,
					  num_extensions, cert_exts);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to parse the extensions: "
			   "%s", strerror(-rc));
		goto out;
	}

	rc = X509_REQ_set_pubkey(req, pkey);
	if (rc != 1) {
		pr_verbose(verbose, "Failed to set the public key");
		rc = -EIO;
		goto out;
	}

	private.ext_lib = ext_lib;
	private.verbose = verbose;

	rc = _ekmf_setup_sign_context(key_blob, key_blob_size, pkey, digest_nid,
				      rsa_pss_params, &md_ctx, &pkey_ctx,
				      &private, verbose);
	if (rc != 0)
		goto out;
	pkey_meth = true;

	rc = X509_REQ_sign_ctx(req, md_ctx);
	if (rc <= 0) {
		pr_verbose(verbose, "Failed to perform the signing operation");
		rc = -EIO;
		goto out;
	}

	rc = write_x509_request(csr_pem_filename, req, new_hdr);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to write CSR to file "
			   "'%s': %s", csr_pem_filename, strerror(-rc));
		goto out;
	}

	if (verbose) {
		pr_verbose(verbose, "Certificate Signing Request created:");
		X509_REQ_print_fp(stderr, req);
	}

out:
	if (md_ctx != NULL)
		EVP_MD_CTX_free(md_ctx);
	if (pkey_meth)
		cleanup_secure_key_pkey_method(EVP_PKEY_id(pkey));
	if (subject_name != NULL)
		X509_NAME_free(subject_name);
	if (cert != NULL)
		X509_free(cert);
	if (req != NULL)
		X509_REQ_free(req);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return rc;
}

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
			  const struct ekmf_ext_lib *ext_lib, bool verbose)
{
	const STACK_OF(X509_EXTENSION) *cert_exts = NULL;
	unsigned char key_blob[MAX_KEY_BLOB_SIZE];
	size_t key_blob_size = sizeof(key_blob);
	X509_NAME *subject_name = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	struct private_data private;
	EVP_MD_CTX *md_ctx = NULL;
	bool pkey_meth = false;
	EVP_PKEY *pkey = NULL;
	X509 *rcert = NULL;
	X509 *cert = NULL;
	int rc;

	if (config == NULL || ext_lib == NULL || cert_pem_filename == NULL)
		return -EINVAL;
	if (config->identity_secure_key == NULL)
		return -EINVAL;
	if (renew_cert_filename == NULL &&
	    (subject_rdns == NULL || num_subject_rdns == 0))
		return -EINVAL;
	if (num_extensions != 0 && extensions == NULL)
		return -EINVAL;

	rc = read_key_blob(config->identity_secure_key, key_blob,
			   &key_blob_size);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to read identity key from file "
			   "'%s': %s", config->identity_secure_key,
			   strerror(-rc));
		goto out;
	}

	rc = _ekmf_get_pub_key_as_pkey(key_blob, key_blob_size, &pkey,
				       rsa_pss_params != NULL, ext_lib,
				       verbose);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to get identity key as PKEY from "
			   "file '%s': %s", config->identity_secure_key,
			   strerror(-rc));
		goto out;
	}

	cert = X509_new();
	if (cert == NULL) {
		pr_verbose(verbose, "X509_new failed");
		rc = -ENOMEM;
		goto out;
	}

	rc = X509_set_version(cert, 2L);
	if (rc != 1) {
		pr_verbose(verbose, "X509_set_version failed: rc: %d", rc);
		rc = -EIO;
		goto out;
	}

	rc = generate_x509_serial_number(cert, SERIAL_NUMBER_BIT_SIZE);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to set the serial number: %s",
			   strerror(-rc));
		goto out;
	}

	if (renew_cert_filename != NULL) {
		rc = read_x509_certificate(renew_cert_filename, &rcert);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to open renew cert file "
				   "'%s': %s", renew_cert_filename,
				   strerror(-rc));
			goto out;
		}

		subject_name = X509_NAME_dup(X509_get_subject_name(rcert));
		cert_exts = X509_get0_extensions(rcert);
	}

	if (subject_rdns != NULL && num_subject_rdns > 0) {
		rc = build_subject_name(&subject_name, subject_rdns,
					num_subject_rdns, subject_utf8);
		if (rc != 0) {
			pr_verbose(verbose, "Failed to parse the subject name "
				   "RDSn: %s", strerror(-rc));
			goto out;
		}
	}

	if (subject_name == NULL) {
		rc = -EINVAL;
		pr_verbose(verbose, "Subject name can not be empty");
		goto out;
	}

	rc = X509_set_subject_name(cert, subject_name);
	if (rc != 1) {
		rc = -EIO;
		pr_verbose(verbose, "Failed to set subject name into cert");
		goto out;
	}

	rc = X509_set_issuer_name(cert, subject_name);
	if (rc != 1) {
		rc = -EIO;
		pr_verbose(verbose, "Failed to set issuer name into cert");
		goto out;
	}

	rc = build_certificate_extensions(cert, NULL, extensions,
					  num_extensions, cert_exts);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to parse the extensions: "
			   "%s", strerror(-rc));
		goto out;
	}

	if (X509_gmtime_adj(X509_getm_notBefore(cert), 0) == NULL) {
		rc = -EIO;
		pr_verbose(verbose, "Failed to set notBefore time inti cert");
		goto out;
	}

	if (X509_time_adj_ex(X509_getm_notAfter(cert),
			     validity_days, 0, NULL) == NULL) {
		rc = -EIO;
		pr_verbose(verbose, "Failed to set notAfter time into cert");
		goto out;
	}

	rc = X509_set_pubkey(cert, pkey);
	if (rc != 1) {
		pr_verbose(verbose, "Failed to set the public key");
		rc = -EIO;
		goto out;
	}

	private.ext_lib = ext_lib;
	private.verbose = verbose;

	rc = _ekmf_setup_sign_context(key_blob, key_blob_size, pkey, digest_nid,
				      rsa_pss_params, &md_ctx, &pkey_ctx,
				      &private, verbose);
	if (rc != 0)
		goto out;
	pkey_meth = true;

	rc = X509_sign_ctx(cert, md_ctx);
	if (rc <= 0) {
		pr_verbose(verbose, "Failed to perform the signing operation");
		rc = -EIO;
		goto out;
	}

	rc = write_x509_certificate(cert_pem_filename, cert);
	if (rc != 0) {
		pr_verbose(verbose, "Failed to write Certificate to file "
			   "'%s': %s", cert_pem_filename, strerror(-rc));
		goto out;
	}

	if (verbose) {
		pr_verbose(verbose, "Self-signed Certificate created:");
		X509_print_fp(stderr, cert);
	}

out:
	if (md_ctx != NULL)
		EVP_MD_CTX_free(md_ctx);
	if (pkey_meth)
		cleanup_secure_key_pkey_method(EVP_PKEY_id(pkey));
	if (subject_name != NULL)
		X509_NAME_free(subject_name);
	if (cert != NULL)
		X509_free(cert);
	if (rcert != NULL)
		X509_free(rcert);
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return rc;
}

/**
 * Close the connection to the EKMFWeb server by destroying the CURL handle.
 *
 * @param curl_handle       the CURL handle to destroy
 */
void ekmf_curl_destroy(CURL *curl_handle)
{
	if (curl_handle == NULL)
		return;

	curl_easy_cleanup(curl_handle);
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


