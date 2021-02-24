/*
 * PV image related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <glib.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "boot/s390.h"
#include "boot/stage3a.h"
#include "common.h"
#include "include/pv_crypto_def.h"
#include "include/pv_hdr_def.h"
#include "utils/align.h"
#include "utils/crypto.h"
#include "utils/file_utils.h"

#include "pv_args.h"
#include "pv_comps.h"
#include "pv_error.h"
#include "pv_hdr.h"
#include "pv_image.h"
#include "pv_ipib.h"
#include "pv_opt_item.h"
#include "pv_stage3.h"

const PvComponent *pv_img_get_stage3b_comp(const PvImage *img, GError **err)
{
	const PvComponent *comp;

	g_return_val_if_fail(pv_img_comps_length(img->comps) >= 1, NULL);

	comp = pv_img_comps_get_nth_comp(img->comps,
					 pv_img_comps_length(img->comps) - 1);
	if (!pv_component_is_stage3b(comp)) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Failed to get 'stage3b' component"));
		return NULL;
	}
	return comp;
}

typedef gint (*prepare_func)(PvComponent *obj, const gchar *tmp_path,
			     void *opaque, GError **err);

static gint pv_img_prepare_component(const PvImage *img, PvComponent *comp,
				     GError **err)
{
	struct cipher_parms parms = { 0 };
	g_autoptr(PvBuffer) tweak = NULL;
	prepare_func func = NULL;
	void *opaque = NULL;
	gint rc;

	if (img->pcf & PV_CFLAG_NO_DECRYPTION) {
		/* we only need to align the components */
		func = pv_component_align;
		opaque = NULL;
	} else {
		const EVP_CIPHER *cipher = img->xts_cipher;

		g_assert_cmpint((int)img->xts_key->size, ==,
				EVP_CIPHER_key_length(cipher));
		g_assert_cmpint((int)PAGE_SIZE % EVP_CIPHER_block_size(cipher),
				==, 0);
		g_assert_cmpint(sizeof(comp->tweak), ==,
				EVP_CIPHER_iv_length(cipher));
		g_assert(img->xts_key->size <= UINT_MAX);

		tweak = pv_buffer_alloc(sizeof(comp->tweak.data));
		memcpy(tweak->data, comp->tweak.data, tweak->size);
		func = pv_component_align_and_encrypt;
		parms.cipher = cipher;
		parms.key = img->xts_key;
		parms.iv_or_tweak = tweak;

		opaque = &parms;
	}

	rc = (*func)(comp, img->tmp_dir, opaque, err);
	if (rc < 0)
		return -1;

	return 0;
}

static PvBuffer *pv_img_read_key(const gchar *path, guint key_size,
				 GError **err)
{
	g_autoptr(PvBuffer) tmp_ret = NULL;
	PvBuffer *ret = NULL;
	gsize bytes_read;
	FILE *f = NULL;
	gsize size;

	if (file_size(path, &size, err) != 0)
		return NULL;

	if (size - key_size != 0) {
		g_set_error(err, PV_ERROR, PV_CRYPTO_ERROR_INVALID_KEY_SIZE,
			    _("Wrong file size '%s': read %zd, expected %u"), path, size,
			    key_size);
		return NULL;
	}

	f = file_open(path, "rb", err);
	if (!f)
		return NULL;

	tmp_ret = pv_buffer_alloc(size);
	if (file_read(f, tmp_ret->data, 1, tmp_ret->size, &bytes_read, err) < 0)
		goto err;

	if (bytes_read - key_size != 0) {
		g_set_error(err, PV_ERROR, PV_CRYPTO_ERROR_INVALID_KEY_SIZE,
			    _("Wrong file size '%s': read %zd, expected %u"),
			    path, bytes_read, key_size);
		goto err;
	}

	ret = g_steal_pointer(&tmp_ret);
err:
	if (f)
		fclose(f);
	return ret;
}

static EVP_PKEY *pv_img_get_cust_pub_priv_key(gint nid, GError **err)
{
	return generate_ec_key(nid, err);
}

static HostKeyList *pv_img_get_host_keys(GSList *host_keys_with_path, gint nid,
					 GError **err)
{
	g_autoslist(EVP_PKEY) ret = NULL;

	for (GSList *iterator = host_keys_with_path; iterator;
	     iterator = iterator->next) {
		x509_with_path *cert_with_path = iterator->data;
		g_autoptr(EVP_PKEY) host_key = NULL;
		X509 *cert = cert_with_path->cert;

		host_key = read_ec_pubkey_cert(cert, nid, err);
		if (!host_key)
			return NULL;

		ret = g_slist_append(ret, g_steal_pointer(&host_key));
	}

	return g_steal_pointer(&ret);
}

static PvBuffer *pv_img_get_key(const EVP_CIPHER *cipher, const gchar *path,
				GError **err)
{
	gint key_len = EVP_CIPHER_key_length(cipher);

	g_assert(key_len > 0);

	if (path)
		return pv_img_read_key(path, (guint)key_len, err);

	return generate_aes_key((guint)key_len, err);
}

static PvBuffer *pv_img_get_iv(const EVP_CIPHER *cipher, const gchar *path,
			       GError **err)
{
	gint iv_len = EVP_CIPHER_iv_length(cipher);

	g_assert(iv_len > 0);

	if (path)
		return pv_img_read_key(path, (guint)iv_len, err);

	return generate_aes_iv((guint)iv_len, err);
}

static int hex_str_toull(const gchar *nptr, uint64_t *dst,
			 GError **err)
{
	uint64_t value;
	gchar *end;

	g_assert(dst);

	if (!g_str_is_ascii(nptr)) {
		g_set_error(err, PV_ERROR, EINVAL,
			    _("Invalid value: '%s'. A hexadecimal value is required, for example '0xcfe'"),
			    nptr);
		return -1;
	}

	value = g_ascii_strtoull(nptr, &end, 16);
	if ((value == G_MAXUINT64 && errno == ERANGE) ||
	    (end && *end != '\0')) {
		g_set_error(err, PV_ERROR, EINVAL,
			    _("Invalid value: '%s'. A hexadecimal value is required, for example '0xcfe'"),
			    nptr);
		return -1;
	}
	*dst = value;
	return 0;
}

static gint pv_img_set_psw_addr(PvImage *img, const gchar *psw_addr_s,
				GError **err)
{
	if (psw_addr_s) {
		uint64_t psw_addr;

		if (hex_str_toull(psw_addr_s, &psw_addr, err) < 0)
			return -1;

		img->initial_psw.addr = psw_addr;
	}

	return 0;
}

static gint pv_img_set_control_flags(PvImage *img, const gchar *pcf_s,
				     const gchar *scf_s, GError **err)
{
	uint64_t flags;

	if (pcf_s) {
		if (hex_str_toull(pcf_s, &flags, err) < 0)
			return -1;

		img->pcf = flags;
	}

	if (scf_s) {
		if (hex_str_toull(scf_s, &flags, err) < 0)
			return -1;

		img->scf = flags;
	}

	return 0;
}

static gint pv_img_hostkey_verify(GSList *host_key_certs,
				  const gchar *root_ca_path,
				  const gchar *const *crl_paths,
				  const gchar *const *untrusted_cert_paths,
				  gboolean offline, GError **err)
{
	g_autoslist(x509_with_path) untrusted_certs_with_path = NULL;
	g_autoptr(STACK_OF_X509) ibm_signing_certs = NULL;
	g_autoptr(STACK_OF_X509) untrusted_certs = NULL;
	g_autoslist(x509_pair) ibm_z_pairs = NULL;
	g_autoptr(X509_STORE) trusted = NULL;
	gint ibm_signing_certs_count;

	/* Load trusted root CAs of the system if and only if @root_ca_path is
	 * NULL, otherwise use the root CA specified by @root_ca_path.
	 */
	trusted = store_setup(root_ca_path, crl_paths, err);
	if (!trusted)
		goto error;

	if (!offline) {
		g_autoptr(STACK_OF_X509_CRL) downloaded_ibm_signing_crls = NULL;

		/* Set up the download routine for the lookup of CRLs. */
		store_setup_crl_download(trusted);

		/* Try to download the CRLs of the IBM Z signing certificates
		 * specified in the host-key documents. Ignore download errors
		 * as it's still possible that a CRL is specified via command
		 * line.
		 */
		downloaded_ibm_signing_crls = try_load_crls_by_certs(host_key_certs);

		/* Add the downloaded CRLs to the store so they can be used for
		 * the verification later.
		 */
		for (int i = 0; i < sk_X509_CRL_num(downloaded_ibm_signing_crls); i++) {
			X509_CRL *crl = sk_X509_CRL_value(downloaded_ibm_signing_crls, i);

			if (X509_STORE_add_crl(trusted, crl) != 1) {
				g_set_error(err, PV_CRYPTO_ERROR,
					    PV_CRYPTO_ERROR_INTERNAL,
					    _("failed to load CRL"));
				goto error;
			}
		}
	}

	/* Load all untrusted certificates (e.g. IBM Z signing key and
	 * DigiCert intermediate CA) that are required to establish a chain of
	 * trust starting from the host-key document up to the root CA (if not
	 * otherwise specified that's the DigiCert Assured ID Root CA).
	 */
	untrusted_certs_with_path = load_certificates(untrusted_cert_paths, err);
	if (!untrusted_certs_with_path)
		goto error;

	/* Convert to STACK_OF(X509) */
	untrusted_certs = get_x509_stack(untrusted_certs_with_path);

	/* Find all IBM Z signing keys and remove them from the chain as we
	 * have to verify that they're valid. The last step of the chain of
	 * trust verification must be done manually, as the IBM Z signing keys
	 * are not marked as (intermediate) CA and therefore the standard
	 * `X509_verify_cert` function of OpenSSL cannot be used to verify the
	 * actual host-key documents.
	 */
	ibm_signing_certs = delete_ibm_signing_certs(untrusted_certs);
	ibm_signing_certs_count = sk_X509_num(ibm_signing_certs);
	if (ibm_signing_certs_count < 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_NO_IBM_Z_SIGNING_KEY,
			    _("please specify at least one IBM Z signing key"));
		goto error;
	} else if (ibm_signing_certs_count > 1) {
		g_set_error(err, PV_CRYPTO_ERROR, PV_CRYPTO_ERROR_NO_IBM_Z_SIGNING_KEY,
			    _("please specify only one IBM Z signing key"));
		goto error;
	}

	if (store_set_verify_param(trusted, err) < 0)
		goto error;

	/* Verify that the IBM Z signing keys are trustable.
	 * For this we must check:
	 *
	 * 1. Can a chain of trust be established ending in a root CA
	 * 2. Is the correct root CA ued? It has either to be the
	 *    'DigiCert Assured ID Root CA' or the root CA specified via
	 *    command line.
	 */
	for (gint i = 0; i < sk_X509_num(ibm_signing_certs); ++i) {
		X509 *ibm_signing_cert = sk_X509_value(ibm_signing_certs, i);
		g_autoptr(STACK_OF_X509_CRL) ibm_signing_crls = NULL;
		g_autoptr(X509_STORE_CTX) ctx = NULL;
		x509_pair *pair = NULL;

		g_assert(ibm_signing_cert);

		/* Create the verification context and set the trusted
		 * and chain parameters.
		 */
		ctx = create_store_ctx(trusted, untrusted_certs, err);
		if (!ctx)
			goto error;

		/* Verify the IBM Z signing key */
		if (verify_cert(ibm_signing_cert, ctx, err) < 0)
			goto error;

		/* Verify the build chain of trust chain. If the user passes a
		 * trusted root CA on the command line then the check for the
		 * Subject Key Identifier (SKID) is skipped, otherwise let's
		 * check if the SKID meets our expectation.
		 */
		if (!root_ca_path &&
		    check_chain_parameters(X509_STORE_CTX_get0_chain(ctx),
					   get_digicert_assured_id_root_ca_skid(),
					   err) < 0) {
			goto error;
		}

		ibm_signing_crls = store_ctx_find_valid_crls(ctx, ibm_signing_cert, err);
		if (!ibm_signing_crls) {
			g_prefix_error(err, _("IBM Z signing key: "));
			goto error;
		}

		/* Increment reference counter of @ibm_signing_cert as the
		 * certificate will now also be owned by @ibm_z_pairs.
		 */
		if (X509_up_ref(ibm_signing_cert) != 1)
			g_abort();

		pair = x509_pair_new(&ibm_signing_cert, &ibm_signing_crls);
		ibm_z_pairs = g_slist_append(ibm_z_pairs, pair);
		g_assert(!ibm_signing_cert);
		g_assert(!ibm_signing_crls);
	}

	/* Verify host-key documents by using the IBM Z signing
	 * certificates and the corresponding certificate revocation
	 * lists.
	 */
	for (GSList *iterator = host_key_certs; iterator; iterator = iterator->next) {
		x509_with_path *host_key_with_path = iterator->data;
		const gchar *host_key_path = host_key_with_path->path;
		X509 *host_key = host_key_with_path->cert;
		gint flags = X509_V_FLAG_CRL_CHECK;

		if (verify_host_key(host_key, ibm_z_pairs, flags,
				    PV_CERTS_SECURITY_LEVEL, err) < 0) {
			g_prefix_error(err, "'%s': ", host_key_path);
			goto error;
		}
	}

	return 0;
error:
	g_prefix_error(err, _("Failed to verify host-key document: "));
	return -1;
}

/* read in the keys or auto-generate them */
static gint pv_img_set_keys(PvImage *img, const PvArgs *args, GError **err)
{
	g_autoslist(x509_with_path) host_key_certs = NULL;

	g_assert(img->xts_cipher);
	g_assert(img->cust_comm_cipher);
	g_assert(img->gcm_cipher);
	g_assert(img->nid);

	img->xts_key = pv_img_get_key(img->xts_cipher, args->xts_key_path, err);
	if (!img->xts_key)
		return -1;

	img->cust_comm_key = pv_img_get_key(img->cust_comm_cipher,
					    args->cust_comm_key_path, err);
	if (!img->cust_comm_key)
		return -1;

	img->cust_root_key =
		pv_img_get_key(img->gcm_cipher, args->cust_root_key_path, err);
	if (!img->cust_root_key)
		return -1;

	img->gcm_iv = pv_img_get_iv(img->gcm_cipher, args->gcm_iv_path, err);
	if (!img->gcm_iv)
		return -1;

	img->cust_pub_priv_key = pv_img_get_cust_pub_priv_key(img->nid, err);
	if (!img->cust_pub_priv_key)
		return -1;

	/* Load all host-key documents specified on the command line */
	host_key_certs = load_certificates((const gchar **)args->host_keys,
					   err);
	if (!host_key_certs)
		return -1;

	if (!args->no_verify &&
	    pv_img_hostkey_verify(host_key_certs, args->root_ca_path,
				  (const gchar * const *)args->crl_paths,
				  (const gchar * const *)args->untrusted_cert_paths,
				  args->offline, err) < 0) {
		return -1;
	}

	/* Loads the public keys stored in the host-key documents and verify
	 * that the correct elliptic curve is used.
	 */
	img->host_pub_keys =
		pv_img_get_host_keys(host_key_certs, img->nid, err);
	if (!img->host_pub_keys)
		return -1;

	return 0;
}

static void pv_img_add_host_slot(PvImage *img, PvHdrKeySlot *slot)
{
	img->key_slots = g_slist_append(img->key_slots, slot);
}

static void pv_hdr_key_slot_free(PvHdrKeySlot *slot)
{
	if (!slot)
		return;

	g_free(slot);
}

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvHdrKeySlot, pv_hdr_key_slot_free)

static PvHdrKeySlot *pv_hdr_key_slot_new(const EVP_CIPHER *gcm_cipher,
					 const PvBuffer *cust_root_key,
					 EVP_PKEY *cust_key, EVP_PKEY *host_key,
					 GError **err)
{
	g_autoptr(PvHdrKeySlot) ret = g_new0(PvHdrKeySlot, 1);
	g_autofree union ecdh_pub_key *pub = NULL;
	g_autoptr(PvBuffer) exchange_key = NULL;
	g_autoptr(PvBuffer) digest_key = NULL;
	g_autoptr(PvBuffer) iv = NULL;
	PvBuffer pub_buf;
	/* No AAD data is used */
	PvBuffer aad = { .data = NULL, .size = 0 };
	/* Set the output buffers for the encrypted data and the
	 * generated GCM tag
	 */
	PvBuffer enc = { .data = ret->wrapped_key, .size = sizeof(ret->wrapped_key) };
	PvBuffer tag = { .data = ret->tag, .size = sizeof(ret->tag) };
	struct cipher_parms parms;
	int64_t c_len = 0;

	g_assert(EVP_CIPHER_iv_length(gcm_cipher) >= 0);

	pub = evp_pkey_to_ecdh_pub_key(host_key, err);
	if (!pub)
		return NULL;

	pub_buf.data = pub->data;
	pub_buf.size = sizeof(*pub);
	digest_key = sha256_buffer(&pub_buf, err);
	if (!digest_key)
		return NULL;

	g_assert(digest_key->size == sizeof(ret->digest_key));
	/* set `digest_key` field */
	memcpy(ret->digest_key, digest_key->data, sizeof(ret->digest_key));

	exchange_key = compute_exchange_key(cust_key, host_key, err);
	if (!exchange_key)
		return NULL;

	/* initialize cipher parameters */
	g_assert(exchange_key->size <= INT_MAX);
	g_assert(exchange_key->size == (guint)EVP_CIPHER_key_length(gcm_cipher));

	/* create zero IV */
	iv = pv_buffer_alloc((guint)EVP_CIPHER_iv_length(gcm_cipher));
	parms.iv_or_tweak = iv;
	parms.key = exchange_key;
	parms.cipher = gcm_cipher;

	/* Encrypt the customer root key that is used for the encryption
	 * of the PV header
	 */
	c_len = gcm_encrypt(cust_root_key, &aad, &parms, &enc, &tag, err);
	if (c_len < 0)
		return NULL;

	g_assert(c_len == (int64_t)cust_root_key->size);
	return g_steal_pointer(&ret);
}

static gint pv_img_set_host_slots(PvImage *img, GError **err)
{
	for (GSList *iterator = img->host_pub_keys; iterator; iterator = iterator->next) {
		EVP_PKEY *host_key = iterator->data;

		g_assert(host_key);

		PvHdrKeySlot *slot = pv_hdr_key_slot_new(img->gcm_cipher,
							 img->cust_root_key,
							 img->cust_pub_priv_key,
							 host_key, err);
		if (!slot)
			return -1;

		pv_img_add_host_slot(img, slot);
	}

	return 0;
}

static gint pv_img_set_comps_offset(PvImage *img, uint64_t offset, GError **err)
{
	return pv_img_comps_set_offset(img->comps, offset, err);
}

PvImage *pv_img_new(PvArgs *args, const gchar *stage3a_path, GError **err)
{
	g_autoptr(PvImage) ret = g_new0(PvImage, 1);
	uint64_t offset;

	g_assert(args->tmp_dir);
	g_assert(stage3a_path);

	if (args->no_verify)
		g_warning(_("host-key document verification is disabled. Your workload is not secured."));

	if (args->root_ca_path)
		g_warning(_("A different root CA than the default DigiCert root CA is selected. Ensure that this root CA is trusted."));

	ret->comps = pv_img_comps_new(EVP_sha512(), EVP_sha512(), EVP_sha512(), err);
	if (!ret->comps)
		return NULL;

	ret->cust_comm_cipher = EVP_aes_256_gcm();
	ret->gcm_cipher = EVP_aes_256_gcm();
	ret->initial_psw.addr = DEFAULT_INITIAL_PSW_ADDR;
	ret->initial_psw.mask = DEFAULT_INITIAL_PSW_MASK;
	ret->nid = NID_secp521r1;
	ret->tmp_dir = g_strdup(args->tmp_dir);
	ret->xts_cipher = EVP_aes_256_xts();

	/* set initial PSW that will be loaded by the stage3b */
	if (pv_img_set_psw_addr(ret, args->psw_addr, err) < 0)
		return NULL;

	/* set the control flags: PCF and SCF */
	if (pv_img_set_control_flags(ret, args->pcf, args->scf, err) < 0)
		return NULL;

	/* read in the keys */
	if (pv_img_set_keys(ret, args, err) < 0)
		return NULL;

	if (pv_img_set_host_slots(ret, err) < 0)
		return NULL;

	/* allocate enough memory for the stage3a args and load the
	 * stage3a template into memory and set the loader_psw
	 */
	if (pv_img_load_and_set_stage3a(ret, stage3a_path, err) < 0)
		return NULL;

	offset = PAGE_ALIGN(STAGE3A_LOAD_ADDRESS + ret->stage3a->size);

	/* shift right all components by the size of stage3a loader */
	if (pv_img_set_comps_offset(ret, offset, err) < 0)
		return NULL;

	return g_steal_pointer(&ret);
}

void pv_img_free(PvImage *img)
{
	if (!img)
		return;

	g_slist_free_full(img->optional_items,
			  (GDestroyNotify)pv_opt_item_free);
	g_slist_free_full(img->key_slots, (GDestroyNotify)pv_hdr_key_slot_free);
	g_slist_free_full(img->host_pub_keys, (GDestroyNotify)EVP_PKEY_free);
	EVP_PKEY_free(img->cust_pub_priv_key);
	pv_buffer_clear(&img->stage3a);
	pv_img_comps_free(img->comps);
	g_free(img->tmp_dir);
	pv_buffer_free(img->xts_key);
	pv_buffer_free(img->cust_root_key);
	pv_buffer_free(img->gcm_iv);
	pv_buffer_free(img->cust_comm_key);
	g_free(img);
}

static gint pv_img_prepare_and_add_component(PvImage *img, PvComponent **comp,
					     GError **err)
{
	g_assert(comp);
	g_assert(*comp);

	/* prepares the component: does the alignment and encryption
	 * if required
	 */
	if (pv_img_prepare_component(img, *comp, err) < 0)
		return -1;

	/* calculates the memory layout and adds the component to its
	 * internal list
	 */
	if (pv_img_comps_add_component(img->comps, comp, err) < 0)
		return -1;

	g_assert(!*comp);
	return 0;
}

gint pv_img_add_component(PvImage *img, const PvArg *arg, GError **err)
{
	g_autoptr(PvComponent) comp = NULL;

	comp = pv_component_new_file(arg->type, arg->path, err);
	if (!comp)
		return -1;

	if (pv_img_prepare_and_add_component(img, &comp, err) < 0)
		return -1;

	g_assert(!comp);
	return 0;
}

gint pv_img_calc_pld_ald_tld_nep(const PvImage *img, PvBuffer **pld, PvBuffer **ald,
				 PvBuffer **tld, uint64_t *nep, GError **err)
{
	return pv_img_comps_finalize(img->comps, pld, ald, tld, nep, err);
}

static gint pv_img_build_stage3b(PvImage *img, PvBuffer *stage3b, GError **err)
{
	g_autofree struct stage3b_args *args = NULL;

	args = pv_img_comps_get_stage3b_args(img->comps, &img->initial_psw);
	if (!args) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Cannot generate stage3b arguments"));
		return -1;
	}

	build_stage3b(stage3b, args);
	return 0;
}

gint pv_img_add_stage3b_comp(PvImage *img, const gchar *path, GError **err)
{
	g_autoptr(PvComponent) comp = NULL;
	g_autoptr(PvBuffer) stage3b = NULL;

	stage3b = stage3b_getblob(path, err);
	if (!stage3b)
		return -1;

	/* set the stage3b data */
	if (pv_img_build_stage3b(img, stage3b, err) < 0)
		return -1;

	comp = pv_component_new_buf(PV_COMP_TYPE_STAGE3B, stage3b, err);
	if (!comp)
		return -1;

	if (pv_img_prepare_and_add_component(img, &comp, err) < 0)
		return -1;

	g_assert(!comp);
	return 0;
}

static uint32_t pv_img_get_aad_size(const PvImage *img)
{
	uint32_t key_size, size = 0;

	g_assert(sizeof(struct pv_hdr_head) <= UINT32_MAX);
	g_assert(sizeof(struct pv_hdr_key_slot) <= UINT32_MAX);

	g_assert_true(g_uint_checked_add(&size, size,
					 (uint32_t)sizeof(struct pv_hdr_head)));
	g_assert_true(g_uint_checked_mul(&key_size,
					 (uint32_t)sizeof(struct pv_hdr_key_slot),
					 g_slist_length(img->key_slots)));
	g_assert_true(g_uint_checked_add(&size, size, key_size));
	return size;
}

static uint32_t pv_img_get_opt_items_size(const PvImage *img)
{
	uint32_t ret = 0;

	g_assert(img);

	for (GSList *iterator = img->optional_items; iterator;
	     iterator = iterator->next) {
		const struct pv_hdr_opt_item *item = iterator->data;

		g_assert(item);
		g_assert_true(g_uint_checked_add(&ret, ret, pv_opt_item_size(item)));
	}
	return ret;
}

uint32_t pv_img_get_enc_size(const PvImage *img)
{
	uint32_t ret = 0;

	g_assert(sizeof(struct pv_hdr_encrypted) <= UINT32_MAX);

	g_assert_true(g_uint_checked_add(
		&ret, ret, (uint32_t)sizeof(struct pv_hdr_encrypted)));
	g_assert_true(
		g_uint_checked_add(&ret, ret, pv_img_get_opt_items_size(img)));
	return ret;
}

static uint32_t pv_img_get_tag_size(const PvImage *img G_GNUC_UNUSED)
{
	g_assert(sizeof(((struct pv_hdr *)0)->tag) <= UINT32_MAX);

	return (uint32_t)sizeof(((struct pv_hdr *)0)->tag);
}

uint32_t pv_img_get_pv_hdr_size(const PvImage *img)
{
	uint32_t size = 0;

	g_assert_true(
		g_uint_checked_add(&size, size, pv_img_get_aad_size(img)));
	g_assert_true(
		g_uint_checked_add(&size, size, pv_img_get_enc_size(img)));
	g_assert_true(
		g_uint_checked_add(&size, size, pv_img_get_tag_size(img)));
	return size;
}

static gint get_stage3a_data_size(const PvImage *img, gsize *data_size,
				  GError **err)
{
	gsize ipib_size, hdr_size;

	g_assert(data_size);
	g_assert(*data_size == 0);

	ipib_size = pv_ipib_get_size(pv_img_comps_length(img->comps));
	if (ipib_size > PV_V1_IPIB_MAX_SIZE) {
		g_set_error(err, PV_ERROR, PV_ERROR_IPIB_SIZE,
			    _("IPIB size is too large: '%zu' > '%zu'"),
			    ipib_size, PV_V1_IPIB_MAX_SIZE);
		return -1;
	}

	hdr_size = pv_img_get_pv_hdr_size(img);
	if (hdr_size > PV_V1_PV_HDR_MAX_SIZE) {
		g_set_error(err, PV_ERROR, PV_ERROR_PV_HDR_SIZE,
			    _("PV header size is too large: '%zu' > '%zu'"),
			    hdr_size, PV_V1_PV_HDR_MAX_SIZE);
		return -1;
	}

	*data_size += PAGE_ALIGN(ipib_size);
	*data_size += PAGE_ALIGN(hdr_size);
	return 0;
}

gint pv_img_load_and_set_stage3a(PvImage *img, const gchar *path, GError **err)
{
	g_autoptr(PvBuffer) stage3a = NULL;
	gsize bin_size, data_size = 0;

	if (get_stage3a_data_size(img, &data_size, err) < 0)
		return -1;

	stage3a = stage3a_getblob(path, &bin_size, data_size, err);
	if (!stage3a)
		return -1;

	img->stage3a_psw.addr = STAGE3A_ENTRY;
	img->stage3a_psw.mask = DEFAULT_INITIAL_PSW_MASK;

	/* set addresses and size */
	img->stage3a = g_steal_pointer(&stage3a);
	img->stage3a_bin_size = bin_size;
	return 0;
}

/* Creates the PV IPIB and sets the stage3a arguments */
static gint pv_img_build_stage3a(PvBuffer *stage3a, gsize stage3a_bin_size,
				 GSList *comps, const PvBuffer *hdr, GError **err)
{
	g_autofree struct ipl_parameter_block *ipib = NULL;

	g_assert(stage3a);
	g_assert(hdr);

	ipib = pv_ipib_new(comps, hdr, err);
	if (!ipib)
		return -1;

	if (build_stage3a(stage3a, stage3a_bin_size, hdr, ipib, err) < 0)
		return -1;

	g_info("%12s:\t0x%012lx (%12ld / %12ld Bytes)", "stage3a",
	       STAGE3A_LOAD_ADDRESS, stage3a->size, stage3a->size);
	return 0;
}

/* Creates the actual PV header (serialized and AES-GCM encrypted) */
static PvBuffer *pv_img_create_pv_hdr(PvImage *img, GError **err)
{
	g_autoptr(PvBuffer) hdr_buf = NULL;
	g_autoptr(PvHdr) hdr = NULL;

	hdr = pv_hdr_new(img, err);
	if (!hdr)
		return NULL;

	hdr_buf = pv_hdr_serialize(hdr, img, PV_ENCRYPT, err);
	if (!hdr_buf)
		return NULL;

	return g_steal_pointer(&hdr_buf);
}

/* No changes to the components are allowed after calling this
 * function
 */
gint pv_img_finalize(PvImage *pv, const gchar *stage3b_path, GError **err)
{
	g_autoptr(PvBuffer) hdr = NULL;

	/* load stage3b template into memory and add it to the list of
	 * components. This must be done before calling
	 * `pv_img_load_and_set_stage3a`.
	 */
	if (pv_img_add_stage3b_comp(pv, stage3b_path, err) < 0)
		return -1;

	/* create the PV header */
	hdr = pv_img_create_pv_hdr(pv, err);
	if (!hdr)
		return -1;

	/* generate stage3a. At this point in time the PV header and
	 * the stage3b must be generated and encrypted
	 */
	if (pv_img_build_stage3a(pv->stage3a, pv->stage3a_bin_size,
				 pv_img_comps_get_comps(pv->comps), hdr, err) < 0)
		return -1;

	return 0;
}

static gint convert_psw_to_short_psw(const struct psw_t *psw, uint64_t *dst,
				    GError **err)
{
	g_assert(psw);
	g_assert(dst);

	uint64_t psw_addr = psw->addr;
	uint64_t psw_mask = psw->mask;

	/* test if PSW mask can be converted */
	if (psw_mask & PSW32_ADDR_MASK) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Failed to convert PSW to short PSW"));
		return -1;
	}

	/* test for bit 12 */
	if (psw_mask & PSW_MASK_BIT_12) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Failed to convert PSW to short PSW"));
		return -1;
	}

	/* test if PSW addr can be converted  */
	if (psw_addr & ~PSW32_ADDR_MASK) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Failed to convert PSW to short PSW"));
		return -1;
	}

	*dst = psw_mask;
	/* set bit 12 to 1 */
	*dst |= PSW_MASK_BIT_12;
	*dst |= psw_addr;
	return 0;
}

static gint write_short_psw(FILE *f, struct psw_t *psw, GError **err)
{
	uint64_t short_psw, short_psw_be;

	if (convert_psw_to_short_psw(psw, &short_psw, err) < 0)
		return -1;

	short_psw_be = GUINT64_TO_BE(short_psw);
	return file_write(f, &short_psw_be, 1, sizeof(short_psw_be), NULL, err);
}

gint pv_img_write(PvImage *img, const gchar *path, GError **err)
{
	gint ret = -1;
	FILE *f = file_open(path, "wb", err);

	if (!f)
		return -1;

	if (write_short_psw(f, &img->stage3a_psw, err) < 0) {
		g_prefix_error(err, _("Failed to write image '%s': "), path);
		goto err;
	}

	if (seek_and_write_buffer(f, img->stage3a, STAGE3A_LOAD_ADDRESS, err) <
	    0) {
		g_prefix_error(err, _("Failed to write image '%s': "), path);
		goto err;
	}

	/* list is sorted by component type => by address */
	for (GSList *iterator = pv_img_comps_get_comps(img->comps); iterator;
	     iterator = iterator->next) {
		gint rc;
		const PvComponent *comp = iterator->data;

		rc = pv_component_write(comp, f, err);
		if (rc < 0) {
			g_prefix_error(err, _("Failed to write image '%s': "),
				       path);
			goto err;
		}
	}

	ret = 0;
err:
	if (f)
		fclose(f);
	return ret;
}
