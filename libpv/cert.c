/*
 * Certificate functions and definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/* Must be included before any other header */
#include "config.h"

#include <openssl/pem.h>

#include "libpv/cert.h"
#include "libpv/crypto.h"
#include "libpv/curl.h"

/* Used for the caching of the downloaded CRLs */
static GHashTable *cached_crls;

void pv_cert_init(void)
{
	if (!cached_crls)
		cached_crls = g_hash_table_new_full(g_str_hash, g_str_equal, g_free,
						    (GDestroyNotify)X509_CRL_free);
}

void pv_cert_cleanup(void)
{
	g_clear_pointer(&cached_crls, g_hash_table_destroy);
}

PvX509WithPath *pv_x509_with_path_new(X509 *cert, const char *path)
{
	g_autoptr(PvX509WithPath) ret = g_new(PvX509WithPath, 1);

	g_assert(cert && path);

	if (X509_up_ref(cert) != 1)
		g_abort();
	ret->cert = cert;
	ret->path = g_strdup(path);
	return g_steal_pointer(&ret);
}

void pv_x509_with_path_free(PvX509WithPath *cert)
{
	if (!cert)
		return;

	X509_free(cert->cert);
	g_free(cert->path);
	g_free(cert);
}

PvX509Pair *pv_x509_pair_new_take(X509 **cert, STACK_OF_X509_CRL **crls)
{
	g_autoptr(PvX509Pair) ret = g_new0(PvX509Pair, 1);

	g_assert(cert);
	g_assert(crls);

	ret->cert = g_steal_pointer(cert);
	ret->crls = g_steal_pointer(crls);
	return g_steal_pointer(&ret);
}

void pv_x509_pair_free(PvX509Pair *pair)
{
	if (!pair)
		return;

	sk_X509_CRL_pop_free(pair->crls, X509_CRL_free);
	X509_free(pair->cert);
	g_free(pair);
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

static gboolean certificate_uses_elliptic_curve(EVP_PKEY *key, int nid, GError **error)
{
	g_autoptr(EC_KEY) ec = NULL;
	int rc;

	g_assert(key);

	if (EVP_PKEY_id(key) != EVP_PKEY_EC) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INVALID_PARM, _("No EC key found"));
		return FALSE;
	}

	ec = EVP_PKEY_get1_EC_KEY(key);
	if (!ec) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INVALID_PARM, _("No EC key found"));
		return FALSE;
	}

	if (EC_KEY_check_key(ec) != 1) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INVALID_PARM, _("Invalid EC key"));
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
				g_set_error_literal(error, PV_CERT_ERROR,
						    PV_CERT_ERROR_INVALID_PARM,
						    _("Invalid EC curve"));
				return FALSE;
			}
		} else {
			/* NID was set but doesn't match with the expected NID
			 */
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INVALID_PARM,
				    _("Wrong NID used: '%d'"),
				    EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)));
			return FALSE;
		}
	}
	return TRUE;
}

EVP_PKEY *pv_x509_get_ec_pubkey(X509 *cert, int nid, GError **error)
{
	g_autoptr(EVP_PKEY) ret = NULL;

	ret = X509_get_pubkey(cert);
	if (!ret) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INVALID_PARM,
			    _("Failed to get public key from host-key document"));
		return NULL;
	}

	if (!certificate_uses_elliptic_curve(ret, nid, error)) {
		g_prefix_error(error, _("Host-key document does not use an elliptic EC curve"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

GSList *pv_get_ec_pubkeys(PvCertWithPathList *certs_with_path, int nid, GError **error)
{
	g_autoslist(EVP_PKEY) ret = NULL;

	for (GSList *iterator = certs_with_path; iterator; iterator = iterator->next) {
		const PvX509WithPath *cert_with_path = iterator->data;
		g_autoptr(EVP_PKEY) host_key = NULL;
		X509 *cert = cert_with_path->cert;

		host_key = pv_x509_get_ec_pubkey(cert, nid, error);
		if (!host_key)
			return NULL;

		ret = g_slist_append(ret, g_steal_pointer(&host_key));
	}

	return g_steal_pointer(&ret);
}

PvCertWithPathList *pv_load_certificates(char **cert_paths, GError **error)
{
	g_autoslist(PvX509WithPath) ret = NULL;

	for (char **iterator = cert_paths; iterator != NULL && *iterator != NULL; iterator++) {
		const char *cert_path = *iterator;
		g_autoptr(X509) cert = NULL;

		g_assert(cert_path);

		cert = pv_load_first_cert_from_file(cert_path, error);
		if (!cert)
			return NULL;

		ret = g_slist_append(ret, pv_x509_with_path_new(cert, cert_path));
	}
	if (!ret) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_READ_CERTIFICATE,
			    _("no certificates specified"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

X509 *pv_load_first_cert_from_file(const char *path, GError **error)
{
	g_autoptr(BIO) bio = BIO_new_file(path, "r");
	g_autoptr(X509) cert = NULL;

	if (!bio) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_READ_CERTIFICATE,
			    _("unable to read certificate: '%s'"), path);
		return NULL;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert)
		return g_steal_pointer(&cert);
	ERR_clear_error();
	if (pv_BIO_reset(bio) < 0) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_READ_CERTIFICATE,
			    _("unable to load certificate: '%s'"), path);
		return NULL;
	}

	/* maybe the certificate is stored in DER format */
	cert = d2i_X509_bio(bio, NULL);
	if (cert)
		return g_steal_pointer(&cert);

	g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_READ_CERTIFICATE,
		    _("unable to load certificate: '%s'"), path);
	return NULL;
}

static X509_CRL *load_crl_from_bio(BIO *bio)
{
	g_autoptr(X509_CRL) crl = PEM_read_bio_X509_CRL(bio, NULL, NULL, NULL);
	if (crl)
		return g_steal_pointer(&crl);
	ERR_clear_error();
	if (pv_BIO_reset(bio) < 0)
		return NULL;

	/* maybe the CRL is stored in DER format */
	crl = d2i_X509_CRL_bio(bio, NULL);
	if (crl)
		return g_steal_pointer(&crl);
	return NULL;
}

/* This function reads in only the first CRL and ignores all other. This is only
 * relevant for the PEM file format.
 */
X509_CRL *pv_load_first_crl_from_file(const char *path, GError **error)
{
	g_autoptr(BIO) bio = BIO_new_file(path, "r");
	g_autoptr(X509_CRL) crl = NULL;

	if (!bio) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_READ_CRL,
			    _("unable to read CRL: '%s'"), path);
		return NULL;
	}

	crl = load_crl_from_bio(bio);
	if (!crl) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_READ_CRL,
			    _("unable to load CRL: '%s'"), path);
		return NULL;
	}
	return g_steal_pointer(&crl);
}

static char *pv_X509_NAME_oneline(const X509_NAME *name)
{
	g_autoptr(BIO) key_bio = BIO_new(BIO_s_mem());
	g_autofree char *ret = NULL;
	char *key = NULL;
	long len;

	if (X509_NAME_print_ex(key_bio, name, 0, XN_FLAG_RFC2253) == -1) {
		g_autofree char *openssl_err_msg = pv_get_openssl_errors();

		g_warning(_("Cannot receive X509-NAME from CRL: %s"), openssl_err_msg);
		return NULL;
	}

	len = BIO_get_mem_data(key_bio, &key);
	if (len < 0) {
		g_warning(_("Cannot receive X509-NAME from CRL"));
		return NULL;
	}

	ret = g_malloc0((size_t)len + 1);
	memcpy(ret, key, (size_t)len);
	return g_steal_pointer(&ret);
}

static gboolean cache_crl(const X509_NAME *name, X509_CRL *crl)
{
	g_autofree char *key = NULL;

	g_assert(name);

	key = pv_X509_NAME_oneline(name);
	if (!key) {
		g_warning(_("Cannot receive X509-NAME from CRL"));
		return FALSE;
	}
	if (X509_CRL_up_ref(crl) != 1)
		g_abort();
	return g_hash_table_insert(cached_crls, g_steal_pointer(&key), crl);
}

/* Caller is responsible for free'ing */
static X509_CRL *lookup_crl(const X509_NAME *name)
{
	g_autoptr(X509_CRL) crl = NULL;
	g_autofree char *key = NULL;

	g_assert(name);

	key = pv_X509_NAME_oneline(name);
	if (!key)
		return NULL;
	crl = g_hash_table_lookup(cached_crls, key);
	if (crl) {
		if (X509_CRL_up_ref(crl) != 1)
			g_abort();
		return g_steal_pointer(&crl);
	}
	return NULL;
}

/* Returns empty stack if no CRL downloaded. */
static STACK_OF_X509_CRL *crls_download_cb(const X509_STORE_CTX *ctx, const X509_NAME *nm)
{
	g_autoptr(STACK_OF_X509_CRL) crls = NULL;
	g_autoptr(X509_CRL) crl = NULL;
	/* must not be free'd */
	X509 *cert = NULL;

	crls = sk_X509_CRL_new_null();
	if (!crls)
		g_abort();
	cert = pv_X509_STORE_CTX_get_current_cert(ctx);
	if (!cert)
		return g_steal_pointer(&crls);
	g_assert(X509_NAME_cmp(X509_get_issuer_name(cert), nm) == 0);
	crl = lookup_crl(nm);
	if (!crl) {
		/* ignore error */
		crl = pv_load_first_crl_by_cert(cert, NULL);
		if (!crl)
			return g_steal_pointer(&crls);
		g_assert_true(cache_crl(nm, crl));
	}
	if (sk_X509_CRL_push(crls, g_steal_pointer(&crl)) == 0)
		g_abort();
	return g_steal_pointer(&crls);
}

/* Downloaded CRLs have a higher precedence than the CRLs specified on the
 * command line.
 */
static STACK_OF_X509_CRL *crls_cb(const X509_STORE_CTX *ctx, const X509_NAME *nm)
{
	g_autoptr(STACK_OF_X509_CRL) crls = crls_download_cb(ctx, nm);

	if (sk_X509_CRL_num(crls) > 0)
		return g_steal_pointer(&crls);
	return pv_X509_STORE_CTX_get1_crls(ctx, nm);
}

/* Set up CRL lookup with download support */
void pv_store_setup_crl_download(X509_STORE *st)
{
	pv_X509_STORE_set_lookup_crls(st, crls_cb);
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

static int load_crl_from_web(const char *url, X509_CRL **crl, GError **error)
{
	g_autoptr(X509_CRL) tmp_crl = NULL;
	g_autoptr(GByteArray) data = NULL;
	g_assert(crl);

	data = curl_download(url, CRL_DOWNLOAD_TIMEOUT_MS, CRL_DOWNLOAD_MAX_SIZE, error);
	if (!data) {
		g_prefix_error(error, _("unable to download CRL: "));
		return -1;
	}
	tmp_crl = GByteArray_to_X509_CRL(data);
	if (!tmp_crl) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_CRL_DOWNLOAD_FAILED,
			    _("unable to load CRL from '%s'"), url);
		return -1;
	}
	*crl = g_steal_pointer(&tmp_crl);
	return 0;
}

/* Get the first http[s] URL from a DIST_POINT */
static const char *get_first_dp_url(DIST_POINT *dp)
{
	GENERAL_NAMES *general_names;

	g_assert(dp);

	if (!dp->distpoint || dp->distpoint->type != 0)
		return NULL;

	general_names = dp->distpoint->name.fullname;
	for (int i = 0; i < sk_GENERAL_NAME_num(general_names); i++) {
		GENERAL_NAME *name = sk_GENERAL_NAME_value(general_names, i);
		g_autofree const char *uri_str = NULL;
		ASN1_STRING *uri_asn1;
		const char *uri_data;
		int uri_data_len;
		int type;

		uri_asn1 = GENERAL_NAME_get0_value(name, &type);
		if (type != GEN_URI)
			continue;
		uri_data_len = ASN1_STRING_length(uri_asn1);
		if (uri_data_len < 0)
			continue;
		uri_data = (const char *)ASN1_STRING_get0_data(uri_asn1);
		/* Make sure that uri_str is null-terminated as in general it
		 * cannot be assumed that @uri_data is null-terminated.
		 */
		uri_str = g_strndup(uri_data, (size_t)uri_data_len);
		if (g_str_has_prefix(uri_str, "http://"))
			return uri_data;
		if (g_str_has_prefix(uri_str, "https://"))
			return uri_data;
	}
	return NULL;
}

/* Download a CRL using the URI specified in the distribution @crldp */
static X509_CRL *load_crl_by_dist_point(DIST_POINT *crldp, GError **error)
{
	const char *uri = get_first_dp_url(crldp);
	g_autoptr(X509_CRL) crl = NULL;

	if (!uri) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
			    _("no valid URL specified in distribution point"));
		return NULL;
	}

	if (load_crl_from_web(uri, &crl, error) < 0)
		return NULL;

	return g_steal_pointer(&crl);
}

/* This function returns the first X509_CRL found from the CRL distribution
 * points specified in @cert. This function could be optimized by filtering
 * duplicate certificates and/or filtering duplicated URIs.
 */
X509_CRL *pv_load_first_crl_by_cert(X509 *cert, GError **error)
{
	g_autoptr(STACK_OF_DIST_POINT) crldps = NULL;
	g_autoptr(GError) last_error = NULL;
	g_autoptr(X509_CRL) ret = NULL;
	int dist_points_cnt;

	g_assert(cert);

	crldps = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
	if (!crldps || sk_DIST_POINT_num(crldps) == 0) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_NO_CRLDP,
			    _("no distribution point found"));
		return NULL;
	}

	dist_points_cnt = sk_DIST_POINT_num(crldps);
	for (int i = 0; i < dist_points_cnt; i++) {
		DIST_POINT *crldp = sk_DIST_POINT_value(crldps, i);
		g_assert(crldp);

		g_clear_error(&last_error);
		ret = load_crl_by_dist_point(crldp, &last_error);
		if (ret)
			return g_steal_pointer(&ret);
	}

	/* relabel error */
	if (last_error)
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_FAILED_DOWNLOAD_CRL,
		     "%s", last_error->message);
	else
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_FAILED_DOWNLOAD_CRL,
		     _("failed to download CRL"));
	return NULL;
}

STACK_OF_X509_CRL *pv_try_load_crls_by_certs(GSList *certs_with_path)
{
	g_autoptr(STACK_OF_X509_CRL) ret = sk_X509_CRL_new_null();
	if (!ret)
		g_abort();

	for (GSList *iterator = certs_with_path; iterator; iterator = iterator->next) {
		PvX509WithPath *cert_with_path = iterator->data;
		X509 *cert = cert_with_path->cert;
		g_autoptr(X509_CRL) crl = NULL;
		g_assert(cert);
		/* ignore error */
		crl = pv_load_first_crl_by_cert(cert, NULL);
		if (!crl)
			continue;
		if (sk_X509_CRL_push(ret, g_steal_pointer(&crl)) == 0)
			g_abort();
	}
	return g_steal_pointer(&ret);
}

#define DEFINE_GSLIST_MAP(t2, t1)                                                          \
	typedef t1 *(*g_slist_map_func_##t2##_##t1)(const t2 *x, GError **error);          \
	G_GNUC_UNUSED static GSList *g_slist_map_##t2##_##t1(                              \
		const GSList *list, g_slist_map_func_##t2##_##t1 func, GError **error)     \
	{                                                                                  \
		g_autoslist(t1) ret = NULL;                                                \
		for (const GSList *iterator = list; iterator; iterator = iterator->next) { \
			const t2 *value = iterator->data;                                  \
			t1 *new_value = NULL;                                              \
			g_assert(value);                                                   \
			new_value = func(value, error);                                    \
			if (!new_value)                                                    \
				return NULL;                                               \
			ret = g_slist_append(ret, g_steal_pointer(&new_value));            \
		}                                                                          \
		return g_steal_pointer(&ret);                                              \
	}

#define DEFINE_GSLIST_TO_STACK(t1)                                                      \
	G_GNUC_UNUSED static STACK_OF(t1) * g_slist_to_stack_of_##t1(GSList **list)     \
	{                                                                               \
		g_assert(list);                                                         \
		g_autoptr(STACK_OF_##t1) ret = sk_##t1##_new_null();                    \
		if (!ret)                                                               \
			g_abort();                                                      \
		for (GSList *iterator = *list; iterator; iterator = iterator->next) {   \
			if (sk_##t1##_push(ret, g_steal_pointer(&iterator->data)) == 0) \
				g_abort();                                              \
		}                                                                       \
		g_clear_pointer(list, g_slist_free);                                    \
		return g_steal_pointer(&ret);                                           \
	}

DEFINE_GSLIST_MAP(PvX509WithPath, X509)
DEFINE_GSLIST_TO_STACK(X509)

static X509 *pv_x509_with_path_get_cert(const PvX509WithPath *cert_with_path,
					G_GNUC_UNUSED GError **error)
{
	g_autoptr(X509) cert = NULL;

	g_assert(cert_with_path && cert_with_path->cert);

	cert = cert_with_path->cert;
	if (X509_up_ref(cert) != 1)
		g_abort();
	return g_steal_pointer(&cert);
}

/* @crl_paths is allowed to be NULL */
static int load_crls_to_store(X509_STORE *store, char **crl_paths, gboolean err_out_empty_crls,
			      GError **error)
{
	for (char **iterator = crl_paths; iterator != NULL && *iterator != NULL; iterator++) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
		const char *crl_path = *iterator;
		int count;

		g_assert(crl_path);

		if (!lookup) {
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
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
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_LOAD_CRL,
				    _("unable to load CRL from: '%s'"), crl_path);
			return -1;
		}
	}

	return 0;
}

X509_STORE *pv_store_setup(char *root_ca_path, char **crl_paths, char **cert_with_crl_paths,
			   GError **error)
{
	g_autoptr(X509_STORE) store = X509_STORE_new();
	if (!store)
		g_abort();

	/* if @root_ca_path != NULL use the specified root CA only, otherwise use the
	 * default root CAs found on the system
	 */
	if (root_ca_path) {
		X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
		int count;

		if (!lookup) {
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
				    _("X509 store initialization failed"));
			return NULL;
		}

		/* only the PEM format allows embedded CRLs so we've to
		 * check for it only here and not in case of ASN1
		 */
		count = X509_load_cert_file(lookup, root_ca_path, X509_FILETYPE_PEM);
		if (count > 0) {
			/* Out of security reasons that it can be easily
			 * overseen that there are multiple certificates located
			 * in a PEM-file we raise an error
			 */
			if (count > 1) {
				g_set_error(
					error, PV_CERT_ERROR, PV_CERT_ERROR_LOAD_ROOT_CA,
					_("multiple certificates in one PEM file is not supported: '%s'"),
					root_ca_path);
				return NULL;
			}

			/* PEM format so it's possible there are CRLs embedded
			 */
			(void)X509_load_crl_file(lookup, root_ca_path, X509_FILETYPE_PEM);
		} else {
			/* Maybe the root CA is stored in ASN1 format */
			count = X509_load_cert_file(lookup, root_ca_path, X509_FILETYPE_ASN1);
			if (count != 1) {
				g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_LOAD_ROOT_CA,
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
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_LOAD_DEFAULT_CA,
				    _("failed to load system root certificates"));
			return NULL;
		}
	}

	/* Error out if a CRL file was provided that has not at least one CRL*/
	if (load_crls_to_store(store, crl_paths, TRUE, error) < 0)
		return NULL;

	/* Try to load CRLs from the provided untrusted certificates */
	if (load_crls_to_store(store, cert_with_crl_paths, FALSE, error) < 0)
		return NULL;

	return g_steal_pointer(&store);
}

STACK_OF_X509 *pv_get_x509_stack(const GSList *x509_with_path_list)
{
	g_autoslist(X509) certs = NULL;
	g_autoptr(GError) error = NULL;

	certs = g_slist_map_PvX509WithPath_X509(x509_with_path_list, pv_x509_with_path_get_cert,
						&error);
	g_assert_no_error(error);
	return g_slist_to_stack_of_X509(&certs);
}

int pv_init_store_ctx(X509_STORE_CTX *ctx, X509_STORE *trusted, STACK_OF_X509 *chain,
		      GError **error)
{
	pv_wrapped_g_assert(ctx);
	pv_wrapped_g_assert(trusted);
	pv_wrapped_g_assert(chain);

	if (X509_STORE_CTX_init(ctx, trusted, NULL, chain) != 1) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
			    _("X509 store initialization failed: %s"),
			    X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
		return -1;
	}
	return 0;
}

X509_STORE_CTX *pv_create_store_ctx(X509_STORE *trusted, STACK_OF_X509 *chain, GError **error)
{
	g_autoptr(X509_STORE_CTX) ctx = X509_STORE_CTX_new();

	pv_wrapped_g_assert(trusted);
	pv_wrapped_g_assert(chain);

	if (!ctx)
		return NULL;

	if (pv_init_store_ctx(ctx, trusted, chain, error) < 0)
		return NULL;

	return g_steal_pointer(&ctx);
}

int pv_store_set_verify_param(X509_STORE *store, GError **error)
{
	g_autoptr(X509_VERIFY_PARAM) param = NULL;
	unsigned long flags = X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL |
			      X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_CHECK_SS_SIGNATURE |
			      X509_V_FLAG_X509_STRICT | X509_V_FLAG_POLICY_CHECK;

	/* Create a X509_VERIFY_PARAM structure, which specifies which checks
	 * should be done by the certificate verification operation
	 */
	param = X509_VERIFY_PARAM_new();
	if (!param)
		g_abort();

	/* The maximum depth level of the chain of trust for the verification of
	 * the IBM Z signing key is 2, i.e. IBM Z signing key -> intermediate CA
	 * -> root CA
	 */
	X509_VERIFY_PARAM_set_depth(param, 2);

	/* Set minimum allowed security level to at least 112 bits. */
	X509_VERIFY_PARAM_set_auth_level(param, PV_CERTS_SECURITY_LEVEL);

	/* Set verification purpose to 'Any Purpose' and specify that the
	 * associated trust setting of the default purpose should be used.
	 */
	if (X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY | X509_TRUST_DEFAULT) != 1)
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
	g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
		    _("X509 store initialization failed"));
	return -1;
}

static int x509_name_entry_get0_data(X509_NAME_ENTRY *entry, const uint8_t **data, size_t *data_len)
{
	const ASN1_STRING *asn1_str;
	int tmp_data_len;

	g_assert(data);
	g_assert(data_len);

	asn1_str = X509_NAME_ENTRY_get_data(entry);
	if (!asn1_str)
		return -1;

	tmp_data_len = ASN1_STRING_length(asn1_str);
	if (tmp_data_len < 0)
		return -1;

	*data = ASN1_STRING_get0_data(asn1_str);
	*data_len = (size_t)tmp_data_len;
	return 0;
}

/* The caller must not free *data! */
static int x509_name_get0_data_by_NID(X509_NAME *name, int nid, const uint8_t **data,
				      size_t *data_len)
{
	X509_NAME_ENTRY *entry = NULL;
	int lastpos = -1;

	lastpos = X509_NAME_get_index_by_NID(name, nid, lastpos);
	if (lastpos == -1)
		return -1;

	entry = X509_NAME_get_entry(name, lastpos);
	if (!entry)
		return -1;

	if (x509_name_entry_get0_data(entry, data, data_len) < 0)
		return -1;

	return 0;
}

/* @y must be a NULL-terminated string */
static gboolean x509_name_data_by_nid_equal(X509_NAME *name, int nid, const char *y)
{
	const uint8_t *data = NULL;
	size_t y_len = strlen(y);
	size_t data_len;

	if (x509_name_get0_data_by_NID(name, nid, &data, &data_len) < 0)
		return FALSE;

	if (data_len != y_len)
		return FALSE;

	return memcmp(data, y, data_len) == 0;
}

/* Checks whether the subject of @cert is a IBM signing key subject. For this we
 * must check that the subject is equal to: 'C = US, ST = New York, L =
 * Poughkeepsie or Armonk, O = International Business Machines Corporation, CN =
 * International Business Machines Corporation' and the organization unit (OUT)
 * must end with the suffix ' Key Signing Service'.
 */
static gboolean has_ibm_signing_subject(X509 *cert)
{
	X509_NAME *subject = X509_get_subject_name(cert);
	/* X509_NAME_entry_count is safe to be used with NULL */
	int entry_count = X509_NAME_entry_count(subject);
	g_autofree char *data_str = NULL;
	const uint8_t *data;
	size_t data_len;

	if (entry_count != PV_IMB_Z_SUBJECT_ENTRY_COUNT)
		return FALSE;

	if (!x509_name_data_by_nid_equal(subject, NID_countryName, PV_IBM_Z_SUBJECT_COUNTRY_NAME))
		return FALSE;

	if (!x509_name_data_by_nid_equal(subject, NID_stateOrProvinceName, PV_IBM_Z_SUBJECT_STATE))
		return FALSE;

	if (!(x509_name_data_by_nid_equal(subject, NID_localityName,
					  PV_IBM_Z_SUBJECT_LOCALITY_NAME_POUGHKEEPSIE) ||
	      x509_name_data_by_nid_equal(subject, NID_localityName,
					  PV_IBM_Z_SUBJECT_LOCALITY_NAME_ARMONK)))
		return FALSE;

	if (!x509_name_data_by_nid_equal(subject, NID_organizationName,
					 PV_IBM_Z_SUBJECT_ORGANIZATION_NAME))
		return FALSE;

	if (!x509_name_data_by_nid_equal(subject, NID_commonName, PV_IBM_Z_SUBJECT_COMMON_NAME))
		return FALSE;

	if (x509_name_get0_data_by_NID(subject, NID_organizationalUnitName, &data, &data_len) < 0)
		return FALSE;

	/* Make sure that data_str is null-terminated as in general it cannot be
	 * assumed that @data is null-terminated.
	 */
	data_str = g_strndup((const char *)data, data_len);
	if (!g_str_has_suffix(data_str, PV_IBM_Z_SUBJECT_ORGANIZATIONAL_UNIT_NAME_SUFFIX))
		return FALSE;

	return TRUE;
}

/* Return a list of all IBM Z signing key certificates in @certs and remove them
 * from the chain. Return empty stack if no IBM Z signing key is found.
 */
STACK_OF_X509 *pv_remove_ibm_signing_certs(STACK_OF_X509 *certs)
{
	g_autoptr(STACK_OF_X509) ret = sk_X509_new_null();

	for (int i = 0; i < sk_X509_num(certs); i++) {
		X509 *cert = sk_X509_value(certs, i);

		g_assert(cert);

		if (!has_ibm_signing_subject(cert))
			continue;

		/* Remove this certificate from the list and change i-- as the
		 * array has changed - this is not beautiful, but right now the
		 * easiest solution I came up with.
		 */
		if (sk_X509_delete(certs, i--) != cert)
			g_abort();

		if (sk_X509_push(ret, g_steal_pointer(&cert)) == 0)
			g_abort();
	}

	return g_steal_pointer(&ret);
}

static X509_NAME *x509_name_reorder_attributes(const X509_NAME *name, const int nids[],
					       size_t nids_len)
{
	int entry_count = X509_NAME_entry_count(name);
	g_autoptr(X509_NAME) ret = NULL;

	if (entry_count < 0)
		return NULL;

	if (nids_len != (size_t)entry_count)
		return NULL;

	ret = X509_NAME_new();
	if (!ret)
		g_abort();

	for (size_t i = 0; i < nids_len; i++) {
		const X509_NAME_ENTRY *entry = NULL;
		int nid = nids[i];
		int lastpos = -1;

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

X509_NAME *pv_c2b_name(const X509_NAME *name)
{
	int nids[] = { NID_countryName,	 NID_organizationName,	  NID_organizationalUnitName,
		       NID_localityName, NID_stateOrProvinceName, NID_commonName };
	g_autoptr(X509_NAME) broken_name = NULL;

	g_assert(name);

	/* Try to reorder the attributes */
	broken_name = x509_name_reorder_attributes(name, nids, G_N_ELEMENTS(nids));
	if (broken_name)
		return g_steal_pointer(&broken_name);
	return X509_NAME_dup((X509_NAME *)name);
}

static int security_level_to_bits(int level)
{
	static int security_bits[] = { 0, 80, 112, 128, 192, 256 };

	g_assert(level > 0 && level < (int)G_N_ELEMENTS(security_bits));

	return security_bits[level];
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

static gboolean own_X509_NAME_ENTRY_equal(const X509_NAME_ENTRY *x, const X509_NAME_ENTRY *y)
{
	const ASN1_OBJECT *x_obj = X509_NAME_ENTRY_get_object(x);
	const ASN1_STRING *x_data = X509_NAME_ENTRY_get_data(x);
	const ASN1_OBJECT *y_obj = X509_NAME_ENTRY_get_object(y);
	const ASN1_STRING *y_data = X509_NAME_ENTRY_get_data(y);
	int x_len = ASN1_STRING_length(x_data);
	int y_len = ASN1_STRING_length(y_data);

	if (x_len < 0 || x_len != y_len)
		return FALSE;

	/* ASN1_STRING_cmp(x_data, y_data) == 0 doesn't work because it also
	 * compares the type, which is sometimes different.
	 */
	return OBJ_cmp(x_obj, y_obj) == 0 &&
	       memcmp(ASN1_STRING_get0_data(x_data), ASN1_STRING_get0_data(y_data),
		      (unsigned long)x_len) == 0;
}

static gboolean own_X509_NAME_equal(const X509_NAME *x, const X509_NAME *y)
{
	int x_count = X509_NAME_entry_count(x);
	int y_count = X509_NAME_entry_count(y);

	if (x != y && (!x || !y))
		return FALSE;

	if (x_count != y_count)
		return FALSE;

	for (int i = 0; i < x_count; i++) {
		const X509_NAME_ENTRY *entry_i = X509_NAME_get_entry(x, i);
		gboolean entry_found = FALSE;

		for (int j = 0; j < y_count; j++) {
			const X509_NAME_ENTRY *entry_j = X509_NAME_get_entry(y, j);

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

/* Verify that the used public key algorithm matches the subject signature
 * algorithm
 */
static int check_signature_algo_match(const EVP_PKEY *pkey, const X509 *subject, GError **error)
{
	int pkey_nid;

	if (!pkey) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_NO_PUBLIC_KEY, _("no public key"));
		return -1;
	}

	if (OBJ_find_sigid_algs(X509_get_signature_nid(subject), NULL, &pkey_nid) != 1) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INVALID_SIGNATURE_ALGORITHM,
			    _("unsupported signature algorithm"));
		return -1;
	}

	if (EVP_PKEY_type(pkey_nid) != EVP_PKEY_base_id(pkey)) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_SIGNATURE_ALGORITHM_MISMATCH,
			    _("signature algorithm mismatch"));
		return -1;
	}

	return 0;
}

/* It's almost the same as X509_check_issed from OpenSSL does except that we
 * don't check the key usage of the potential issuer. This means we check:
 * 1. Check whether the akid(cert) (if available) matches the issuer skid
 * 2. Check that the cert algrithm matches the subject algorithm
 * 3. Verify the signature of certificate @cert is using the public key of
 *    @issuer.
 */
static int check_host_key_issued(X509 *cert, X509 *issuer, GError **error)
{
	const X509_NAME *issuer_subject = X509_get_subject_name(issuer);
	const X509_NAME *cert_issuer = X509_get_issuer_name(cert);
	g_autoptr(AUTHORITY_KEYID) akid = NULL;

	akid = X509_get_ext_d2i(cert, NID_authority_key_identifier, NULL, NULL);
	if (akid && X509_check_akid(issuer, akid) != X509_V_OK) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_SKID_AKID_MISMATCH,
			    _("AKID mismatch"));
		return -1;
	}

	if (check_signature_algo_match(X509_get0_pubkey(issuer), cert, error) < 0)
		return -1;

	if (X509_verify(cert, X509_get0_pubkey(issuer)) != 1) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_CERT_SIGNATURE_INVALID,
			    _("Signature verification failed"));
		return -1;
	}

	return 0;
}

static gboolean is_cert_revoked(X509 *cert, X509_CRL *crl)
{
	X509_REVOKED *revoked = NULL;
	int rc;

	if (!cert || !crl)
		g_abort();

	rc = X509_CRL_get0_by_serial(crl, &revoked, (ASN1_INTEGER *)X509_get0_serialNumber(cert));
	if (rc == 0)
		return FALSE;

	if (revoked)
		return TRUE;

	return FALSE;
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
int pv_verify_host_key(X509 *host_key, GSList *issuer_pairs, int verify_flags, int level,
		       GError **error)
{
	const int exp_security_bits = security_level_to_bits(level);
	EVP_PKEY *pkey;
	gboolean successfully_checked = FALSE;
	int pkey_security_bits;

	g_assert(host_key);
	pkey = X509_get0_pubkey(host_key);

	if (!pkey) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
			    _("failed to retrieve public key"));
		return -1;
	}

	/* check key level, if necessary */
	pkey_security_bits = EVP_PKEY_security_bits(pkey);
	if (exp_security_bits > 0 && pkey_security_bits < exp_security_bits) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_VERIFICATION_FAILED,
			    _("not enough bits of security (%d, %d expected)"), pkey_security_bits,
			    exp_security_bits);
		return -1;
	}

	if (!(verify_flags & X509_V_FLAG_NO_CHECK_TIME)) {
		const ASN1_TIME *last = X509_get0_notBefore(host_key);
		const ASN1_TIME *next = X509_get0_notAfter(host_key);

		if (!last || !next || check_validity_period(last, next)) {
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INVALID_VALIDITY_PERIOD,
				    _("validity period is not valid"));
			return -1;
		}
	} else {
		verify_flags &= ~X509_V_FLAG_NO_CHECK_TIME;
	}

	/* Verify that the host_key was issued by a certificate and that it
	 * wasn't revoked.
	 */
	for (GSList *iterator = issuer_pairs; iterator; iterator = iterator->next) {
		const PvX509Pair *pair = iterator->data;
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
			for (int i = 0; i < sk_X509_CRL_num(issuer_crls); i++) {
				X509_CRL *issuer_crl = sk_X509_CRL_value(issuer_crls, i);

				g_assert(issuer_crl);

				if (is_cert_revoked(host_key, issuer_crl)) {
					g_set_error(error, PV_CERT_ERROR,
						    PV_CERT_ERROR_CERT_REVOKED,
						    _("certificate revoked"));
					return -1;
				}

				crl_checked = TRUE;
			}

			if (!crl_checked) {
				g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_NO_CRL,
					    _("no valid CRL found"));
				return -1;
			}
			successfully_checked = TRUE;
			break;
		}
	}

	if (!successfully_checked) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_NO_ISSUER_IBM_Z_FOUND,
			    _("no IBM Z signing key that issued this host-key document found"));
		return -1;
	}

	/* were some unsupported flags specified? */
	g_assert(verify_flags == 0);
	return 0;
}

int pv_verify_cert(X509_STORE_CTX *ctx, X509 *cert, GError **error)
{
	int rc;

	pv_wrapped_g_assert(cert);
	pv_wrapped_g_assert(ctx);

	X509_STORE_CTX_set_cert(ctx, cert);
	rc = X509_verify_cert(ctx);
	if (rc != 1) {
		X509 *tmp_cert = NULL;

		tmp_cert = pv_X509_STORE_CTX_get_current_cert(ctx);
		if (tmp_cert) {
			g_autofree char *subj_name =
				pv_X509_NAME_oneline(X509_get_subject_name(tmp_cert));
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_VERIFICATION_FAILED,
				    _("failed to verify certificate '%s': %s"), subj_name,
				    X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
		} else {
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_VERIFICATION_FAILED,
				    _("failed to verify certificate: %s"),
				    X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
		}
		return -1;
	}
	return 0;
}

/* Verify that SKID(issuer) == AKID(crl) */
static int check_crl_issuer(X509_CRL *crl, X509 *issuer, GError **error)
{
	g_autoptr(AUTHORITY_KEYID) akid = NULL;

	/* If AKID(@crl) is specified it must match with SKID(@issuer) */
	akid = X509_CRL_get_ext_d2i(crl, NID_authority_key_identifier, NULL, NULL);
	if (akid && X509_check_akid(issuer, akid) != X509_V_OK) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_SKID_AKID_MISMATCH,
			    _("AKID mismatch"));
		return -1;
	}

	return 0;
}

int pv_verify_crl(X509_CRL *crl, X509 *cert, int verify_flags, GError **error)
{
	EVP_PKEY *pkey = X509_get0_pubkey(cert);

	g_assert(crl);

	if (!pkey) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
			    _("failed to retrieve public key from the certificate"));
		return -1;
	}

	if (check_crl_issuer(crl, cert, error) < 0)
		return -1;

	/* verify the validity period of the CRL */
	if (!(verify_flags & X509_V_FLAG_NO_CHECK_TIME)) {
		const ASN1_TIME *last = X509_CRL_get0_lastUpdate(crl);
		const ASN1_TIME *next = X509_CRL_get0_nextUpdate(crl);

		if (!last || !next || check_validity_period(last, next)) {
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INVALID_VALIDITY_PERIOD,
				    _("validity period is not valid"));
			return -1;
		}
	} else {
		verify_flags &= ~X509_V_FLAG_NO_CHECK_TIME;
	}

	/* verify the signature */
	if (X509_CRL_verify(crl, pkey) != 1) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_CRL_SIGNATURE_INVALID,
			    _("signature is not valid"));
		return -1;
	}
	g_assert(verify_flags == 0);
	return 0;
}

int pv_check_chain_parameters(const STACK_OF_X509 *chain, GError **error)
{
	const X509_NAME *ca_x509_subject = NULL;
	g_autofree char *ca_subject = NULL;
	int len = sk_X509_num(chain);
	X509 *ca = NULL;

	if (len < 2) {
		g_set_error(
			error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
			_("there must be at least one root and one leaf certificate in the chain of trust"));
		return -1;
	}

	/* get the root certificate of the chain of trust */
	ca = sk_X509_value(chain, len - 1);
	if (!ca) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
			    _("no root certificate found"));
		return -1;
	}

	ca_x509_subject = X509_get_subject_name(ca);
	if (!ca_x509_subject) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
			    _("subject of the root CA cannot be retrieved"));
		return -1;
	}

	ca_subject = pv_X509_NAME_oneline(ca_x509_subject);
	if (!ca_subject) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
			    _("subject name of the root CA cannot be retrieved"));
		return -1;
	}
	g_info(_("Root CA used: '%s'"), ca_subject);

	return 0;
}

/** Replace locality 'Armonk' with 'Pougkeepsie'. If Armonk was not set return
 *  `NULL`.
 */
static X509_NAME *x509_armonk_locality_fixup(const X509_NAME *name)
{
	g_autoptr(X509_NAME) ret = NULL;
	int pos;

	/* Check if ``L=Armonk`` */
	if (!x509_name_data_by_nid_equal((X509_NAME *)name, NID_localityName,
					 PV_IBM_Z_SUBJECT_LOCALITY_NAME_ARMONK))
		return NULL;

	ret = X509_NAME_dup(name);
	if (!ret)
		g_abort();

	pos = X509_NAME_get_index_by_NID(ret, NID_localityName, -1);
	if (pos == -1)
		return NULL;

	X509_NAME_ENTRY_free(X509_NAME_delete_entry(ret, pos));

	/* Create a new name entry at the same position as before */
	if (X509_NAME_add_entry_by_NID(
		    ret, NID_localityName, MBSTRING_UTF8,
		    (const unsigned char *)&PV_IBM_Z_SUBJECT_LOCALITY_NAME_POUGHKEEPSIE,
		    sizeof(PV_IBM_Z_SUBJECT_LOCALITY_NAME_POUGHKEEPSIE) - 1, pos, 0) != 1)
		return NULL;

	return g_steal_pointer(&ret);
}

/* This function contains work-arounds for some known subject(CRT)<->issuer(CRL)
 * issues.
 */
static STACK_OF_X509_CRL *quirk_X509_STORE_ctx_get1_crls(X509_STORE_CTX *ctx,
							 const X509_NAME *subject, GError **err)
{
	g_autoptr(X509_NAME) fixed_subject = NULL;
	g_autoptr(STACK_OF_X509_CRL) ret = NULL;

	ret = pv_X509_STORE_CTX_get1_crls(ctx, subject);
	if (ret && sk_X509_CRL_num(ret) > 0)
		return g_steal_pointer(&ret);

	/* Workaround to fix the mismatch between issuer name of the * IBM
	 * signing CRLs and the IBM signing key subject name. Locality name has
	 * changed from Poughkeepsie to Armonk.
	 */
	fixed_subject = x509_armonk_locality_fixup(subject);
	/* Was the locality replaced? */
	if (fixed_subject) {
		X509_NAME *tmp;

		sk_X509_CRL_free(ret);
		ret = pv_X509_STORE_CTX_get1_crls(ctx, fixed_subject);
		if (ret && sk_X509_CRL_num(ret) > 0)
			return g_steal_pointer(&ret);

		/* Workaround to fix the ordering mismatch between issuer name
		 * of the IBM signing CRLs and the IBM signing key subject name.
		 */
		tmp = fixed_subject;
		fixed_subject = pv_c2b_name(fixed_subject);
		X509_NAME_free(tmp);
		sk_X509_CRL_free(ret);
		ret = pv_X509_STORE_CTX_get1_crls(ctx, fixed_subject);
		if (ret && sk_X509_CRL_num(ret) > 0)
			return g_steal_pointer(&ret);
		X509_NAME_free(fixed_subject);
		fixed_subject = NULL;
	}

	/* Workaround to fix the ordering mismatch between issuer name of the
	 * IBM signing CRLs and the IBM signing key subject name.
	 */
	fixed_subject = pv_c2b_name(subject);
	sk_X509_CRL_free(ret);
	ret = pv_X509_STORE_CTX_get1_crls(ctx, fixed_subject);
	if (ret && sk_X509_CRL_num(ret) > 0)
		return g_steal_pointer(&ret);

	g_set_error(err, PV_CERT_ERROR, PV_CERT_ERROR_NO_CRL, _("no CRL found"));
	return NULL;
}

/* Given a certificate @cert try to find valid revocation lists in @ctx. If no
 * valid CRL was found NULL is returned.
 */
STACK_OF_X509_CRL *pv_store_ctx_find_valid_crls(X509_STORE_CTX *ctx, X509 *cert, GError **error)
{
	g_autoptr(STACK_OF_X509_CRL) ret = NULL;
	const int verify_flags = 0;
	X509_NAME *subject = NULL;

	pv_wrapped_g_assert(ctx);
	pv_wrapped_g_assert(cert);

	subject = X509_get_subject_name(cert);
	if (!subject) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_MALFORMED_CERTIFICATE,
			    _("certificate is malformed"));
		return NULL;
	}

	ret = quirk_X509_STORE_ctx_get1_crls(ctx, subject, error);
	if (!ret)
		return NULL;
	/* Filter out non-valid CRLs for @cert */
	for (int i = 0; i < sk_X509_CRL_num(ret); i++) {
		X509_CRL *crl = sk_X509_CRL_value(ret, i);

		g_assert(crl);

		/* If @crl is not valid remove it from the array and log a
		 * warning.
		 */
		if (pv_verify_crl(crl, cert, verify_flags, error) < 0) {
			g_assert(error);
			g_warning(_("CRL is not valid: %s"), (*error)->message);
			g_clear_error(error);

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
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_NO_CRL, _("no valid CRL found"));
		return NULL;
	}
	return g_steal_pointer(&ret);
}

/*
 * Finds the IBM signing key in the stack.
 * Error out, if there is not exactly one IBM signing key.
 */
static STACK_OF_X509 *get_ibm_signing_certs(STACK_OF_X509 *certs, GError **error)
{
	g_autoptr(STACK_OF_X509) ibm_signing_certs = NULL;
	int ibm_signing_certs_count;

	/* Find all IBM Z signing keys and remove them from the chain as we
	 * have to verify that they're valid. The last step of the chain of
	 * trust verification must be done manually, as the IBM Z signing keys
	 * are not marked as (intermediate) CA and therefore the standard
	 * `X509_verify_cert` function of OpenSSL cannot be used to verify the
	 * actual host-key documents.
	 */
	ibm_signing_certs = pv_remove_ibm_signing_certs(certs);
	ibm_signing_certs_count = sk_X509_num(ibm_signing_certs);
	if (ibm_signing_certs_count < 1) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_NO_IBM_Z_SIGNING_KEY,
			    _("Specify at least one IBM Z signing key"));
		return NULL;
	} else if (ibm_signing_certs_count > 1) {
		g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_NO_IBM_Z_SIGNING_KEY,
			    _("Specify only one IBM Z signing key"));
		return NULL;
	}
	g_assert(ibm_signing_certs_count == 1);

	return g_steal_pointer(&ibm_signing_certs);
}

static gboolean download_crls(X509_STORE *trusted, PvCertWithPathList *host_key_certs_with_path,
			      GError **error)
{
	g_autoptr(STACK_OF_X509_CRL) downloaded_ibm_signing_crls = NULL;

	/* Set up the download routine for the lookup of CRLs. */
	pv_store_setup_crl_download(trusted);

	/* Try to download the CRLs of the IBM Z signing certificates
	 * specified in the host-key documents. Ignore download errors
	 * as it's still possible that a CRL is specified via command
	 * line.
	 */
	downloaded_ibm_signing_crls = pv_try_load_crls_by_certs(host_key_certs_with_path);

	/* Add the downloaded CRLs to the store so they can be used for
	 * the verification later.
	 */
	for (int i = 0; i < sk_X509_CRL_num(downloaded_ibm_signing_crls); i++) {
		X509_CRL *crl = sk_X509_CRL_value(downloaded_ibm_signing_crls, i);

		if (X509_STORE_add_crl(trusted, crl) != 1) {
			g_set_error(error, PV_CERT_ERROR, PV_CERT_ERROR_INTERNAL,
				    _("failed to load CRL"));
			return FALSE;
		}
	}
	return TRUE;
}

gboolean pv_verify_host_key_doc(PvCertWithPathList *host_key_certs_with_path, X509_STORE *trusted,
				STACK_OF_X509 *untrusted_certs, gboolean online, GError **error)
{
	g_autoslist(PvX509Pair) ibm_z_pairs = NULL;
	g_autoptr(STACK_OF_X509) ibm_signing_certs = NULL;
	g_autoptr(X509_STORE_CTX) ctx = NULL;

	pv_wrapped_g_assert(host_key_certs_with_path);
	pv_wrapped_g_assert(trusted);
	pv_wrapped_g_assert(untrusted_certs);

	if (online && !download_crls(trusted, host_key_certs_with_path, error))
		return -1;

	/* Find all IBM Z signing keys and remove them from the chain as we
	 * have to verify that they're valid. The last step of the chain of
	 * trust verification must be done manually, as the IBM Z signing keys
	 * are not marked as (intermediate) CA and therefore the standard
	 * `X509_verify_cert` function of OpenSSL cannot be used to verify the
	 * actual host-key documents.
	 */
	ibm_signing_certs = get_ibm_signing_certs(untrusted_certs, error);
	if (!ibm_signing_certs)
		return -1;

	if (pv_store_set_verify_param(trusted, error) < 0)
		return -1;

	ctx = pv_create_store_ctx(trusted, untrusted_certs, error);
	if (!ctx)
		return -1;
	/*
	 * Get all IBM-signing-[key,crls] pairs.
	 * NOTE: Currently there is only one signing-key allowed
	 */
	for (int i = 0; i < sk_X509_num(ibm_signing_certs); i++) {
		g_autoptr(X509) ibm_signing_cert = sk_X509_pop(ibm_signing_certs);
		g_autoptr(STACK_OF_X509_CRL) ibm_signing_crls = NULL;
		PvX509Pair *ibm_z_pair = NULL;

		/*
		 * Get CRLs for the IBM signing cert
		 */
		ibm_signing_crls = pv_store_ctx_find_valid_crls(ctx, ibm_signing_cert, error);
		if (!ibm_signing_crls) {
			g_prefix_error(error, _("IBM Z signing key: "));
			return -1;
		}

		/* build the pair and add it to the list */
		ibm_z_pair = pv_x509_pair_new_take(&ibm_signing_cert, &ibm_signing_crls);
		g_assert(!ibm_signing_cert);
		g_assert(!ibm_signing_crls);
		ibm_z_pairs = g_slist_append(ibm_z_pairs, ibm_z_pair);
	}

	/* Verify host-key documents by using the IBM Z signing
	 * certificates and the corresponding certificate revocation
	 * lists.
	 */
	for (GSList *iterator = host_key_certs_with_path; iterator; iterator = iterator->next) {
		PvX509WithPath *host_key_with_path = iterator->data;
		const char *host_key_path = host_key_with_path->path;
		X509 *host_key = host_key_with_path->cert;
		int flags = X509_V_FLAG_CRL_CHECK;

		if (pv_verify_host_key(host_key, ibm_z_pairs, flags, PV_CERTS_SECURITY_LEVEL,
				       error) < 0) {
			g_prefix_error(error, "'%s': ", host_key_path);
			return -1;
		}
	}

	/* Verify that all IBM Z signing keys are trustable.
	 * For this we must check:
	 *
	 * 1. Can a chain of trust be established ending in a root CA
	 * 2. Is the correct root CA used? It has either to be the
	 *    System CA or the root CA specified via command line.
	 */
	for (GSList *iterator = ibm_z_pairs; iterator; iterator = iterator->next) {
		const PvX509Pair *ibm_z_pair = iterator->data;

		if (pv_verify_cert(ctx, ibm_z_pair->cert, error) < 0)
			return -1;
		if (pv_check_chain_parameters(X509_STORE_CTX_get0_chain(ctx), error) < 0)
			return -1;
		/* re-init ctx for the next verification */
		X509_STORE_CTX_cleanup(ctx);
		if (pv_init_store_ctx(ctx, trusted, untrusted_certs, error) != 0)
			return -1;
	}
	return 0;
}

int pv_verify_host_key_docs_by_path(char **host_key_paths, char *optional_root_ca_path,
				    char **crl_paths, char **untrusted_cert_paths, gboolean online,
				    GError **error)
{
	g_autoslist(PvX509WithPath) untrusted_certs_with_path = NULL, host_key_certs = NULL;
	g_autoptr(STACK_OF_X509) untrusted_certs = NULL;
	g_autoptr(X509_STORE) trusted = NULL;

	pv_wrapped_g_assert(host_key_paths);
	pv_wrapped_g_assert(untrusted_cert_paths);

	/* Load trusted root CAs of the system if and only if @root_ca_path is
	 * NULL, otherwise use the root CA specified by @root_ca_path.
	 */
	trusted = pv_store_setup(optional_root_ca_path, crl_paths, untrusted_cert_paths, error);
	if (!trusted)
		return -1;

	/* Load all untrusted certificates (e.g. IBM Z signing key and
	 * intermediate CA) that are required to establish a chain of
	 * trust starting from the host-key document up to the root CA (if not
	 * otherwise specified that can be one of the system wide installed
	 * root CAs, e.g. DigiCert).
	 */
	untrusted_certs_with_path = pv_load_certificates(untrusted_cert_paths, error);
	if (!untrusted_certs_with_path)
		return -1;
	/* Convert to STACK_OF(X509) */
	untrusted_certs = pv_get_x509_stack(untrusted_certs_with_path);

	host_key_certs = pv_load_certificates(host_key_paths, error);
	if (!host_key_certs)
		return -1;

	return pv_verify_host_key_doc(host_key_certs, trusted, untrusted_certs, online, error);
}
