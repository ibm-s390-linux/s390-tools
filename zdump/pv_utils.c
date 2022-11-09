/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Utilities to decrypt secure execution guest dumps.
 *
 * Copyright IBM Corp. 2001, 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include "pv_utils.h"

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>

#include "lib/zt_common.h"
#include "lib/util_log.h"
#include "libpv/crypto.h"
#include "libpv/se-hdr.h"
#include "pv_defs.h"

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(Elf64_Phdr, free)

/* Definitions for decrypting memory and deriving dump key */
#define PV_CSS_PAGESIZE	     0x1000U /* Configuration storage state page size */
#define PV_DUMP_V1_HKDF_INFO "IBM Z Ultravisor Dump"
#define PV_DUMP_V1_HKDF_LEN  32
#define PV_DUMP_V1_HKDF_FUN  EVP_sha512()
#define PV_DUMP_V1_CIPHER    EVP_aes_256_gcm()

static gboolean u64_checked_add(u64 *res, u64 lhs, u64 rhs)
{
	guint64 _res = 0;
	gboolean success = g_uint64_checked_add(&_res, (guint64)lhs, (guint64)rhs);

	*res = (u64)_res;
	return success;
}

static u64 page_offset(u64 addr)
{
	return addr % PV_CSS_PAGESIZE;
}

static u64 page_index(u64 addr)
{
	return addr / PV_CSS_PAGESIZE;
}

static u64 page_start_addr(u64 page_idx, GError **error)
{
	gboolean success;
	uint64_t ret;

	success = g_uint64_checked_mul(&ret, page_idx, PV_CSS_PAGESIZE);
	if (G_UNLIKELY(!success)) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PAGE_START_ADDR_OVERFLOW,
			    _("UInt overflow detected: %s: pageidx: %#llx"), __func__, page_idx);
	}
	return ret;
}

static u64 page_end_addr(u64 page_idx, GError **error)
{
	gboolean success;
	uint64_t ret;

	/* (page_idx + 1) * PV_CSS_PAGESIZE - 1; */
	success = g_uint64_checked_add(&ret, page_idx, 1);
	success &= g_uint64_checked_mul(&ret, ret, PV_CSS_PAGESIZE);
	ret -= 1;
	if (G_UNLIKELY(!success)) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PAGE_END_ADDR_OVERFLOW,
			    _("UInt overflow detected: %s: pageidx: %#llx"), __func__, page_idx);
	}
	return ret;
}

static void pv_dump_completion_v1_free(pv_dump_completion_v1_t *cpl)
{
	pv_dump_completion_free((pv_dump_completion_t *)cpl);
}
WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(pv_dump_completion_v1_t, pv_dump_completion_v1_free)

void pv_dump_completion_free(pv_dump_completion_t *cpl)
{
	if (!cpl)
		return;

	if (cpl->version == PV_COMPL_DATA_VERSION_1) {
		pv_dump_completion_v1_t *cpl_v1 = (pv_dump_completion_v1_t *)cpl;
		OPENSSL_cleanse(&cpl_v1->data, sizeof(cpl_v1->data));
	}
	g_free(cpl);
}

GBytes *pv_derive_dump_key_v1(const pv_dump_completion_data_v1_t *cpl_data, GBytes *cck,
			      GError **error)
{
	g_autoptr(GBytes) salt = NULL, info = NULL;
	size_t cck_size;
	size_t exp_cck_size = sizeof_field(struct pv_hdr_encrypted, cust_comm_key);

	assert(cpl_data->aad.version == PV_COMPL_DATA_VERSION_1);

	cck_size = g_bytes_get_size(cck);
	if (cck_size != exp_cck_size) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_WRONG_CCK_SIZE,
			    _("Wrong key size: expected %lu != actual %lu"), exp_cck_size,
			    cck_size);
		return NULL;
	}

	salt = g_bytes_new(&cpl_data->aad.seed, sizeof(cpl_data->aad.seed));
	info = g_bytes_new(PV_DUMP_V1_HKDF_INFO, strlen(PV_DUMP_V1_HKDF_INFO));
	return pv_hkdf_extract_and_expand(PV_DUMP_V1_HKDF_LEN, cck, salt, info, PV_DUMP_V1_HKDF_FUN,
					  error);
}

pv_dump_completion_v1_t *pv_decrypt_dump_completion_v1(const pv_dump_completion_data_v1_t *cpl_data,
						       GBytes *dump_key, GError **error)
{
	g_autoptr(GBytes) encr = NULL, aad = NULL, tag = NULL, decr = NULL, iv = NULL;
	g_autoptr(pv_dump_completion_v1_t) cpl = NULL;
	PvCipherParms params;
	size_t copied;
	void *tmp;

	assert(cpl_data->aad.version == PV_COMPL_DATA_VERSION_1);

	encr = g_bytes_new(&cpl_data->confidential_area, sizeof(cpl_data->confidential_area));
	aad = g_bytes_new(&cpl_data->aad, sizeof(cpl_data->aad));
	tag = g_bytes_new(&cpl_data->tag, sizeof(cpl_data->tag));
	iv = g_bytes_new(&cpl_data->aad.iv, sizeof(cpl_data->aad.iv));
	params.cipher = PV_DUMP_V1_CIPHER;
	params.key = dump_key;
	params.iv = iv;
	params.tag_size = g_bytes_get_size(tag);
	if (pv_gcm_decrypt(encr, aad, tag, &params, &decr, error) < 0)
		return NULL;

	cpl = g_malloc(sizeof(*cpl));
	cpl->super.version = PV_COMPL_DATA_VERSION_1;
	tmp = pv_gbytes_memcpy(&cpl->data.aad, sizeof(cpl->data.aad), aad, &copied);
	if (!tmp || copied != sizeof(cpl->data.aad)) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_WRONG_AAD_SIZE,
			    _("Wrong AAD size"));
		return NULL;
	}

	tmp = pv_gbytes_memcpy(&cpl->data.confidential_area, sizeof(cpl->data.confidential_area),
			       decr, &copied);
	if (!tmp || copied != sizeof(cpl->data.confidential_area)) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_WRONG_CONFIDENTIAL_SIZE,
			    _("Wrong confidential data size"));
		return NULL;
	}

	tmp = pv_gbytes_memcpy(&cpl->data.tag, sizeof(cpl->data.tag), tag, &copied);
	if (!tmp || copied != sizeof(cpl->data.tag)) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_WRONG_TAG_SIZE,
			    _("Wrong tag size"));
		return NULL;
	}

	return g_steal_pointer(&cpl);
}

static long pv_cpu_note_data_get_version(GBytes *note, GError **error)
{
	size_t size;
	const uint32_t *version = g_bytes_get_data(note, &size);
	STATIC_ASSERT(offsetof(pv_cpu_dump_aad_v1_t, version) == 0);

	/* check whether we can dereference @version */
	if (sizeof(*version) > size) {
		g_set_error(
			error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_WRONG_NOTE_SIZE, "%s",
			_("Confidential CPU data has incorrect size. Dump probably corrupted."));
		return -1;
	}

	return *version;
}

dfi_cpu_t *pv_decrypt_cpu_note_data(const unsigned int expected_version, GBytes *cpu_note,
				    GBytes *dump_key, GError **error)
{
	long version = pv_cpu_note_data_get_version(cpu_note, error);
	if (version < 0)
		return NULL;

	if (version != expected_version) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_UNSUPP_SEC_CPU_VER,
			    _("Wrong NT_S390_PV_CPU_DATA version (%ld)"), version);
		return NULL;
	}

	switch (version) {
	case PV_SEC_CPU_DATA_VERSION_1: {
		const pv_cpu_dump_confidential_area_v1_t *pv_cpu;
		const pv_cpu_dump_v1_t *cpu_encrypted;
		size_t cpu_note_size, cpu_decrypted_size;
		g_autoptr(GBytes) cpu_decrypted = NULL;

		cpu_encrypted = g_bytes_get_data(cpu_note, &cpu_note_size);
		if (sizeof(*cpu_encrypted) > cpu_note_size) {
			g_set_error(
				error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_WRONG_NOTE_SIZE,
				_("Confidential CPU data has incorrect size. Dump probably corrupted."));
			return NULL;
		}

		cpu_decrypted = pv_decrypt_cpu_dump_area_v1(cpu_encrypted, dump_key, error);
		if (!cpu_decrypted) {
			g_prefix_error(
				error,
				_("Unable to authenticate confidential CPU data. Dump probably corrupted:" ERR_NEWLINE));
			return NULL;
		}

		pv_cpu = g_bytes_get_data(cpu_decrypted, &cpu_decrypted_size);
		if (cpu_decrypted_size != sizeof(*pv_cpu)) {
			g_set_error(
				error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_WRONG_NOTE_SIZE,
				_("Confidential CPU data has incorrect size. Dump probably corrupted."));
			return NULL;
		}

		/* Check dump flags */
		if (pv_cpu->has_osii)
			util_log_print(UTIL_LOG_WARN,
				       _("CPU state may contain partial instruction results"));

		return pv_dfi_cpu_from_pv_cpu(pv_cpu);
	}
	default:
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_UNSUPP_SEC_CPU_VER,
			    _("Unsupported NT_S390_PV_CPU_DATA version (%ld)"), version);
		return NULL;
	}
}

GBytes *pv_decrypt_cpu_dump_area_v1(const pv_cpu_dump_v1_t *cpu_dump_area, GBytes *dump_key,
				    GError **error)
{
	g_autoptr(GBytes) encr = NULL, aad = NULL, tag = NULL;
	g_autoptr(GBytes) iv = NULL, out = NULL;
	PvCipherParms params;

	encr = g_bytes_new(&cpu_dump_area->confidential_area,
			   sizeof(cpu_dump_area->confidential_area));
	aad = g_bytes_new(&cpu_dump_area->aad, sizeof(cpu_dump_area->aad));
	tag = g_bytes_new(&cpu_dump_area->tag, sizeof(cpu_dump_area->tag));
	iv = g_bytes_new(&cpu_dump_area->aad.iv, sizeof(cpu_dump_area->aad.iv));
	params.cipher = PV_DUMP_V1_CIPHER;
	params.key = dump_key;
	params.iv = iv;
	params.tag_size = g_bytes_get_size(tag);
	if (pv_gcm_decrypt(encr, aad, tag, &params, &out, error) < 0)
		return NULL;
	return g_steal_pointer(&out);
}

dfi_cpu_t *pv_dfi_cpu_from_pv_cpu(const pv_cpu_dump_confidential_area_v1_t *pv_cpu)
{
	g_autoptr(dfi_cpu_t) ret = dfi_cpu_alloc();

	STATIC_ASSERT(sizeof(ret->gprs) == sizeof(pv_cpu->gprs));
	(void)memcpy(ret->gprs, pv_cpu->gprs, sizeof(ret->gprs));
	STATIC_ASSERT(sizeof(ret->psw) == sizeof(pv_cpu->psw));
	(void)memcpy(ret->psw, pv_cpu->psw, sizeof(ret->psw));

	ret->prefix = pv_cpu->prefix;
	ret->fpc = pv_cpu->fpc;
	ret->todpreg = pv_cpu->todpreg;
	ret->timer = pv_cpu->timer;
	ret->todcmp = pv_cpu->todcmp;

	STATIC_ASSERT(sizeof(ret->acrs) == sizeof(pv_cpu->acrs));
	(void)memcpy(ret->acrs, pv_cpu->acrs, sizeof(ret->acrs));

	STATIC_ASSERT(sizeof(ret->ctrs) == sizeof(pv_cpu->ctrs));
	(void)memcpy(ret->ctrs, pv_cpu->ctrs, sizeof(ret->ctrs));

	/* Copy floating point register and the high part of the first 16 vector
	 * register
	 */
	STATIC_ASSERT(ARRAY_SIZE(ret->fprs) == ARRAY_SIZE(pv_cpu->vector_register_low));
	STATIC_ASSERT(ARRAY_SIZE(pv_cpu->vector_register_low) == ARRAY_SIZE(ret->vxrs_low));
	dfi_cpu_content_fac_add(DFI_CPU_CONTENT_FAC_VX);
	for (unsigned int i = 0; i < ARRAY_SIZE(ret->fprs); i++) {
		ret->fprs[i] = pv_cpu->vector_register_low[i].low;
		ret->vxrs_low[i] = pv_cpu->vector_register_low[i].high;
	}

	STATIC_ASSERT(sizeof(ret->vxrs_high) == sizeof(pv_cpu->vector_register_high));
	(void)memcpy(ret->vxrs_high, pv_cpu->vector_register_high, sizeof(ret->vxrs_high));

	/* Set guarded storage registers */
	ret->reserved = 0;
	ret->gsd = pv_cpu->gsd;
	ret->gssm = pv_cpu->gssm;
	ret->gs_epl_a = pv_cpu->gs_epl_a;
	/* Add GS facility */
	dfi_cpu_content_fac_add(DFI_CPU_CONTENT_FAC_GS);

	/* NOTE: In the future it might be useful to store `@pv_cpu->dump_flags`
	 * in the `struct dfi_cpu`. Currently, we don't have any use case for
	 * it.
	 */

	return g_steal_pointer(&ret);
}

/* Utilities for decrypting the memory */

struct _pv_crypto_ctx {
	EVP_CIPHER_CTX *cipher_ctx;
	BIO *input;
	BIO *filter;
	/* To be allocated/deallocated using OpenSSL malloc and clear+free */
	pv_tweak_nonce_t *nonce;

	/* scratch area */
	pv_tweak_t tweak_scratch;
};

static BIO *pv_BIO_cipher_new(const EVP_CIPHER *cipher, const unsigned char *key, size_t key_len,
			      enum PvCryptoMode mode, GError **error)
{
	bool encrypt = mode == PV_ENCRYPT;
	EVP_CIPHER_CTX *ctx = NULL;
	g_autoptr(BIO) ret = NULL;
	ENGINE *engine = NULL;

	ret = BIO_new(BIO_f_cipher());
	if (!ret) {
		abort();
		return NULL;
	}

	if (BIO_get_cipher_ctx(ret, &ctx) != 1) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_BIO_FAIL,
			    _("BIO_get_cipher_ctx failed"));
		return NULL;
	}
	g_assert(ctx);

	if (EVP_CipherInit_ex(ctx, cipher, engine, NULL, NULL, encrypt) != 1) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_BIO_FAIL,
			    _("EVP_Cipher_init failed"));
		return NULL;
	}

	/* Check key length */
	if (EVP_CIPHER_CTX_key_length(ctx) != (int)key_len) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_BIO_KEY,
			    _("Passed key has incorrect size: %ld != %d"), key_len,
			    EVP_CIPHER_key_length(cipher));
		return NULL;
	}

	/* Set key */
	if (EVP_CipherInit_ex(ctx, NULL, NULL, key, NULL, -1) != 1) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_BIO_FAIL,
			    _("EVP_Cipher_init set_key failed"));
		return NULL;
	}

	return g_steal_pointer(&ret);
}

pv_crypto_ctx_t *pv_crypto_ctx_new(BIO *input, const unsigned char *key, size_t key_size,
				   const pv_tweak_nonce_t *nonce, enum PvCryptoMode mode,
				   GError **error)
{
	g_autoptr(pv_crypto_ctx_t) ret = NULL;
	g_autoptr(BIO) xts_filter = NULL;

	g_assert(input);
	STATIC_ASSERT(sizeof_field(pv_crypto_ctx_t, nonce) == sizeof(nonce));

	ret = g_new0(pv_crypto_ctx_t, 1);
	xts_filter = pv_BIO_cipher_new(EVP_aes_256_xts(), key, key_size, mode, error);
	if (!xts_filter) {
		g_prefix_error(error,
			       _("Initializing the zdump crypto context failed" ERR_NEWLINE));
		return NULL;
	}

	if (BIO_get_cipher_ctx(xts_filter, &ret->cipher_ctx) != 1) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_CRYPTO_CTX,
			    _("Initializing the zdump crypto context failed"));
		return NULL;
	}
	g_assert(ret->cipher_ctx);

	/* set-up BIO chain for the encryption/decryption */
	ret->filter = BIO_push(g_steal_pointer(&xts_filter), input);
	g_assert(ret->filter);

	if (BIO_up_ref(input) != 1) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_CRYPTO_CTX,
			    _("Initializing the zdump crypto context failed"));
		return NULL;
	}
	ret->input = input;

	ret->nonce = OPENSSL_malloc(sizeof(*ret->nonce));
	if (!ret->nonce)
		abort();
	(void)memcpy(ret->nonce, nonce, sizeof(*ret->nonce));
	return g_steal_pointer(&ret);
}

void pv_crypto_ctx_free(pv_crypto_ctx_t *ctx)
{
	if (!ctx)
		return;

	g_clear_pointer(&ctx->input, BIO_vfree);
	g_clear_pointer(&ctx->filter, BIO_vfree);
	/* It's intentional that we don't free @ctx->cipher_ctx since it's not
	 * owned by us, but the BIO chain */
	ctx->cipher_ctx = NULL;
	OPENSSL_clear_free(ctx->nonce, sizeof(*ctx->nonce));
	g_free(ctx);
}

void calculate_tweak(const pv_tweak_component_t *tweak, const pv_tweak_nonce_t *nonce,
		     pv_tweak_t *out)
{
	for (size_t i = 0; i < ARRAY_SIZE(out->value); i++)
		out->value[i] = tweak->value[i] | nonce->value[i];
}

int pv_read_page(BIO *input, BIO *output, GError **error)
{
	char data[PAGE_SIZE];
	int rc;

	rc = BIO_read(input, data, ARRAY_SIZE(data));
	if (rc != ARRAY_SIZE(data)) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_BIO, _("BIO_read failed"));
		return -1;
	}

	rc = BIO_write(output, data, ARRAY_SIZE(data));
	if (rc != ARRAY_SIZE(data)) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_BIO, _("BIO_write failed"));
		return -1;
	}
	return rc;
}

unsigned long pv_page_state(const pv_tweak_component_t *comp)
{
	unsigned long ret = PV_INVAL_PAGE_STATE;

	if (comp->special.indicator != PV_SPECIAL_INDICATOR)
		return PV_ENCRYPTED_PAGE;

	if (comp->special.flag_reserved1 || comp->special.flag_reserved2 ||
	    comp->special.is_zero_page + comp->special.is_shared_page +
			    comp->special.is_mapped_page <
		    1)
		return PV_INVAL_PAGE_STATE;

	if (comp->special.is_zero_page)
		ret |= PV_ZERO_PAGE;
	if (comp->special.is_shared_page)
		ret |= PV_SHARED_PAGE;
	if (comp->special.is_mapped_page)
		ret |= PV_MAPPED_PAGE;
	return ret;
}

static const unsigned char NULL_DATA[PV_CSS_PAGESIZE] = { 0x0 };

static bool pv_BIO_is_seekable(BIO *bio)
{
	const int type = BIO_method_type(bio);

	return type == BIO_TYPE_FD || type == BIO_TYPE_FILE;
}

static int pv_BIO_seek(BIO *bio, long long offset)
{
	/* The documentation of @BIO_seeks says @offset is a `int` but the
	 * source code actually shows it's a long. Therefore add these
	 * additional checks here to detect in case something changes in
	 * OpenSSL.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic error "-Wconversion"
#pragma GCC diagnostic error "-Wsign-conversion"
	return BIO_seek(bio, offset);
#pragma GCC diagnostic pop
}

static int update_tweak(pv_crypto_ctx_t *crypto_ctx, GError **error)
{
	EVP_CIPHER_CTX *ctx = crypto_ctx->cipher_ctx;
	u8 *tweak = crypto_ctx->tweak_scratch.value;

	/* Check tweak length */
	if (EVP_CIPHER_CTX_iv_length(ctx) != ARRAY_SIZE(crypto_ctx->tweak_scratch.value)) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_TWEAK,
			    _("Tweak has wrong size"));
		return -1;
	}

	/* set the new tweak IV */
	if (EVP_CipherInit_ex(ctx, NULL, NULL, NULL, tweak, -1) != 1) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_TWEAK,
			    _("Initializing tweaks failed"));
		return -1;
	}
	return 0;
}

ssize_t pv_process_pglist(pv_crypto_ctx_t *ctx, BIO *output,
			  const pv_tweak_component_t *tweak_components, size_t tweak_components_len,
			  long input_off, GError **error)
{
	bool is_output_seekable = pv_BIO_is_seekable(output);
	long cur_in_off = input_off, cur_out_off = 0;
	ssize_t page_idx;
	int rc;

	assert(ctx->input);
	assert(ctx->filter);
	assert(output);
	assert(tweak_components_len <= SSIZE_MAX);

	/* See https://www.openssl.org/docs/man1.1.0/man3/BIO_seek.html */
	if (!pv_BIO_is_seekable(ctx->input)) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PGLIST_BIO,
			    _("Input source is not seekable"));
		return -1;
	}

	if (pv_BIO_seek(ctx->input, cur_in_off) == -1) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PGLIST_BIO,
			    _("BIO_seek failed"));
		return -1;
	}

	if (tweak_components_len > LONG_MAX / PV_CSS_PAGESIZE) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PAGELIST_ELF_OFFSET_TOO_LARGE,
			    _("Possible long overflow detected: Try to read %li pages"),
			    tweak_components_len);
	}

	for (page_idx = 0; page_idx < (ssize_t)tweak_components_len; page_idx++) {
		const pv_tweak_component_t *tweak_comp = &tweak_components[page_idx];
		unsigned long page_state;
		BIO *input = NULL;

		g_assert_nonnull(tweak_comp);

		page_state = pv_page_state(tweak_comp);
		if (page_state & PV_INVAL_PAGE_STATE) {
			g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PGLIST_BIO,
				    _("Invalid page state"));
			return -1;
		}

		/* g_assert(page_state & PV_MAPPED_PAGE); */
		page_state &= ~PV_MAPPED_PAGE;
		if (page_state & PV_ZERO_PAGE) {
			/* Nothing to do here for BIO_FILE because a sparse file
			 * is filled with zeros by default. Therefore we can
			 * simply calculate the new output offset. For a
			 * BIO_s_mem BIO_seek doesn't work therefore we've to
			 * work around.
			 */

			cur_out_off += PV_CSS_PAGESIZE;
			cur_in_off += PV_CSS_PAGESIZE;
			if (G_UNLIKELY(pv_BIO_seek(ctx->input, cur_in_off) == -1)) {
				g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PGLIST_BIO,
					    _("BIO_seek failed"));
				return -1;
			}
			if (is_output_seekable) {
				if (G_UNLIKELY(pv_BIO_seek(output, cur_out_off) == -1)) {
					g_set_error(error, ZDUMP_PV_UTILS_ERROR,
						    ZDUMP_ERR_PGLIST_BIO, _("BIO_seek failed"));
					return -1;
				}
			} else {
				if (G_UNLIKELY(
					    BIO_write(output, NULL_DATA, ARRAY_SIZE(NULL_DATA)) !=
					    ARRAY_SIZE(NULL_DATA))) {
					g_set_error(error, ZDUMP_PV_UTILS_ERROR,
						    ZDUMP_ERR_PGLIST_BIO, _("BIO_write failed"));
					return -1;
				}
			}
			if (page_state & ~PV_ZERO_PAGE) {
				g_set_error(error, ZDUMP_PV_UTILS_ERROR,
					    ZDUMP_ERR_PGLIST_INVAL_STATE,
					    _("Invalid page state. page-idx: %#lx, state: %#lx"),
					    page_idx, page_state);
				return -1;
			}
			continue;
		}

		if (page_state & PV_SHARED_PAGE) {
			/* shared pages are not encrypted */
			input = ctx->input;
			if (page_state & ~PV_SHARED_PAGE) {
				g_set_error(error, ZDUMP_PV_UTILS_ERROR,
					    ZDUMP_ERR_PGLIST_INVAL_STATE,
					    _("Invalid page state. page-idx: %#lx, state: %#lx"),
					    page_idx, page_state);
				return -1;
			}
		} else if (page_state & PV_ENCRYPTED_PAGE) {
			input = ctx->filter;
			calculate_tweak(tweak_comp, ctx->nonce, &ctx->tweak_scratch);

			/* set new tweak */
			if (update_tweak(ctx, error) < 0)
				return -1;

			if (page_state & ~PV_ENCRYPTED_PAGE) {
				g_set_error(error, ZDUMP_PV_UTILS_ERROR,
					    ZDUMP_ERR_PGLIST_INVAL_STATE,
					    _("Invalid page state. page-idx: %#lx, state: %#lx"),
					    page_idx, page_state);
				return -1;
			}
		} else {
			g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PGLIST_INVAL_STATE,
				    _("Invalid page state. page-idx: %#lx, state: %#lx"), page_idx,
				    page_state);
			return -1;
		}

		rc = pv_read_page(input, output, error);
		if (rc != PV_CSS_PAGESIZE)
			return -1;

		/* adapt the offsets */
		cur_in_off += rc;
		cur_out_off += rc;
	}

	return page_idx;
}

bool pv_is_pv_elf(const Elf64_Shdr *shdrs, const unsigned int shnum, const char *shstrtab,
		  const size_t shstrtab_size)
{
	return find_elf_shdr_by_name(shdrs, shnum, shstrtab, shstrtab_size,
				     PV_ELF_SECTION_NAME_COMPL) != NULL;
}

struct _storage_state_mmap {
	void *first_page_ptr;
	size_t mapped_size;
	pv_tweak_component_t *tweak_components;
	size_t num_tweaks;
	gatomicrefcount ref_count;
};

storage_state_mmap_t *storage_state_mmap_new(const int fd, const u64 offset, const u64 size,
					     GError **error)
{
	size_t tweak_components_cnt, start_addr, in_page_offset, mmapped_size;
	g_autoptr(storage_state_mmap_t) ret = NULL;
	int saved_errno = 0;
	u8 *ptr;

	if (size == 0 || size % sizeof(pv_tweak_component_t) != 0) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_MMAP,
			    _("StorageState MMAP: size  (%#llx) not a multiple of (%#lx)"), size,
			    sizeof(pv_tweak_component_t));
		return NULL;
	}

	start_addr = page_start_addr(page_index(offset), error);
	if (*error)
		return NULL;

	tweak_components_cnt = size / sizeof(pv_tweak_component_t);
	in_page_offset = page_offset(offset);
	mmapped_size = size + in_page_offset;

	if (start_addr > SSIZE_MAX) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_MMAP,
			    _("StorageState MMAP: page start address is too large (%#lx)"),
			    start_addr);
		return NULL;
	}
	ptr = mmap(NULL, mmapped_size, PROT_READ, MAP_POPULATE | MAP_PRIVATE, fd,
		   (ssize_t)start_addr);
	saved_errno = errno;
	if (ptr == MAP_FAILED) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_MMAP, _("mmap failed: %s"),
			    g_strerror(saved_errno));
		return NULL;
	}

	ret = g_new0(typeof(*ret), 1);
	ret->first_page_ptr = ptr;
	ret->tweak_components = (pv_tweak_component_t *)(ptr + in_page_offset);
	ret->num_tweaks = tweak_components_cnt;
	ret->mapped_size = mmapped_size;
	g_atomic_ref_count_init(&ret->ref_count);
	return g_steal_pointer(&ret);
}

storage_state_mmap_t *storage_state_mmap_ref(storage_state_mmap_t *storage_state)
{
	g_assert(storage_state);
	g_atomic_ref_count_inc(&storage_state->ref_count);
	return storage_state;
}

void storage_state_mmap_unref(storage_state_mmap_t *storage_state)
{
	if (!storage_state)
		return;
	if (storage_state->ref_count && !g_atomic_ref_count_dec(&storage_state->ref_count))
		return;
	if (storage_state->first_page_ptr) {
		int rc = munmap(storage_state->first_page_ptr, storage_state->mapped_size);
		if (rc != 0)
			util_log_print(UTIL_LOG_WARN, _("munmap has failed"));
	}
	g_free(storage_state);
}

pv_elf_ctx_t *pv_elf_ctx_new(const int fd,
			     const pv_dump_completion_confidential_area_v1_t *cpl_conf,
			     storage_state_mmap_t *storage_state_data, const u64 elf_load_offset,
			     GError **error)
{
	g_autoptr(pv_elf_ctx_t) ret = NULL;
	g_autoptr(BIO) input = NULL;

	input = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!input) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_ELF_CTX_BIO,
			    _("cannot open file"));
		return NULL;
	}

	ret = g_new0(typeof(*ret), 1);
	ret->pv_ctx = pv_crypto_ctx_new(input, cpl_conf->key, sizeof(cpl_conf->key),
					&cpl_conf->nonce, PV_DECRYPT, error);
	if (!ret->pv_ctx)
		return NULL;
	ret->storage_state_data = storage_state_mmap_ref(storage_state_data);
	ret->elf_load_off = elf_load_offset;
	return g_steal_pointer(&ret);
}

void pv_elf_ctx_free(pv_elf_ctx_t *p)
{
	if (!p)
		return;

	g_clear_pointer(&p->pv_ctx, pv_crypto_ctx_free);
	g_clear_pointer(&p->storage_state_data, storage_state_mmap_unref);
	g_clear_pointer(&p->output, BIO_vfree);
	g_free(p);
}

const pv_tweak_component_t *pv_get_tweak_components(storage_state_mmap_t *storage_state_data,
						    u64 page_idx, u64 page_cnt)
{
	u64 last_page_idx;

	g_assert_cmpuint(page_cnt, >=, 1);

	if (!u64_checked_add(&last_page_idx, page_idx, page_cnt - 1))
		return NULL;
	if (last_page_idx >= storage_state_data->num_tweaks)
		return NULL;

	return &storage_state_data->tweak_components[page_idx];
}

/* Return version number if possible */
static long completion_data_get_version(GBytes *cpl_data, GError **error)
{
	size_t size;
	const uint32_t *version = g_bytes_get_data(cpl_data, &size);
	STATIC_ASSERT(offsetof(pv_dump_completion_aad_v1_t, version) == 0);

	/* check whether we can dereference @version */
	if (sizeof(*version) > size) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_UNSUPP_COMPL_VER,
			    _("Unsupported " PV_ELF_SECTION_NAME_COMPL " section size (%#lx)"),
			    size);
		return -1;
	}

	return *version;
}

int pv_process_section_data(const int fd, GBytes *completion_sec, const u64 storage_state_offset,
			    const size_t storage_state_size, GBytes *cck,
			    pv_dump_completion_t **completion_decr, GBytes **dump_key,
			    storage_state_mmap_t **storage_state, GError **error)
{
	g_autoptr(pv_dump_completion_t) _completion_decr = NULL;
	g_autoptr(storage_state_mmap_t) _storage_state_data = NULL;
	g_autoptr(GBytes) _dump_key = NULL;
	g_assert(completion_sec);
	long version;

	version = completion_data_get_version(completion_sec, error);
	if (version < 0)
		return -1;

	switch (version) {
	case PV_COMPL_DATA_VERSION_1: {
		const pv_dump_completion_data_v1_t *ccd;
		size_t size;

		ccd = g_bytes_get_data(completion_sec, &size);
		if (sizeof(*ccd) > size) {
			g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_CORRUPTED_COMPL_DATA,
				    _("Corrupted completion configuration data"));
			return -1;
		}

		if (ccd->aad.len != sizeof(*ccd)) {
			g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_CORRUPTED_COMPL_DATA,
				    _("Incorrect completion configuration data length"));
			return -1;
		}

		_dump_key = pv_derive_dump_key_v1(ccd, cck, error);
		if (!_dump_key) {
			g_prefix_error(error, _("Unable to derive dump key: "));
			return -1;
		}

		_completion_decr = (pv_dump_completion_t *)pv_decrypt_dump_completion_v1(
			ccd, _dump_key, error);
		if (!_completion_decr) {
			g_prefix_error(error,
				       _("Unable to decrypt completion configuration data: "));
			return -1;
		}
		break;
	}
	default:
		g_set_error(
			error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_UNSUPP_COMPL_VER,
			_("Unsupported dump completion version (%#lx) found in section " PV_ELF_SECTION_NAME_COMPL),
			version);
		return -1;
	}

	_storage_state_data =
		storage_state_mmap_new(fd, storage_state_offset, storage_state_size, error);
	if (!_storage_state_data)
		return -1;

	*dump_key = g_steal_pointer(&_dump_key);
	*completion_decr = g_steal_pointer(&_completion_decr);
	*storage_state = g_steal_pointer(&_storage_state_data);
	return 0;
}

int pv_elf_read(const pv_elf_ctx_t *elf_ctx, const u64 start_addr, void *dst, const u64 size,
		GError **error)
{
	u64 pglist_size, pglist_start_idx, pglist_end_idx, pglist_num_pages;
	const pv_tweak_component_t *pglist_tweak_components;
	u64 pglist_start_addr, pglist_end_addr, pglist_elf_off, page_off;
	const unsigned char *data = NULL;
	g_autoptr(BIO) output = NULL;
	gssize num_processed_pages;
	long data_size;
	u64 end_addr;

	/* nothing to do then */
	if (size == 0)
		return 0;

	end_addr = start_addr + size - 1;
	if (end_addr < start_addr) {
		g_set_error(
			error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_ELF_READ_END_ADDR_OVERFLOW,
			_("UInt Overflow during reading memory detected. start_addr %p, size: %#llx"),
			(void *)start_addr, size);
		return -1;
	}

	page_off = page_offset(start_addr);
	pglist_start_idx = page_index(start_addr);
	pglist_start_addr = page_start_addr(pglist_start_idx, error);
	/* Could never happen here */
	if (*error)
		return -1;
	pglist_end_idx = page_index(end_addr);
	pglist_end_addr = page_end_addr(pglist_end_idx, error);
	if (*error)
		return -1;
	pglist_size = pglist_end_addr - pglist_start_addr + 1;
	pglist_num_pages = pglist_end_idx - pglist_start_idx + 1;

	g_assert(IS_ALIGNED(pglist_start_addr, PV_CSS_PAGESIZE));
	g_assert(IS_ALIGNED(pglist_end_addr + 1, PV_CSS_PAGESIZE));
	g_assert(IS_ALIGNED(pglist_size, PV_CSS_PAGESIZE));
	/* must be true, is max UINT64_T/0x1000 + 1 < SSIZE_MAX */
	g_assert(pglist_num_pages <= SSIZE_MAX);
	g_assert(pglist_num_pages > 0);

	pglist_tweak_components = pv_get_tweak_components(elf_ctx->storage_state_data,
							  pglist_start_idx, pglist_num_pages);
	if (!pglist_tweak_components) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_ELF_READ,
			    _("Page tweaks were not found idx %llu num %llu"), pglist_start_idx,
			    pglist_num_pages);
		return -1;
	}

	output = BIO_new(BIO_s_mem());
	if (!output)
		abort();

	if (!u64_checked_add(&pglist_elf_off, elf_ctx->elf_load_off, pglist_start_addr)) {
		g_set_error(
			error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PAGELIST_ELF_OFFSET_TOO_LARGE,
			_("UInt overflow detected: ELF load offset %#llx page start address %#llx"),
			elf_ctx->elf_load_off, pglist_start_addr);
		return -1;
	}

	if (pglist_elf_off > LONG_MAX) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_PAGELIST_ELF_OFFSET_TOO_LARGE,
			    _("ELF load offset is too large"));
		return -1;
	}

	/* Process the pages - in this case do the decryption */
	num_processed_pages = pv_process_pglist(elf_ctx->pv_ctx, output, pglist_tweak_components,
						pglist_num_pages, (long)pglist_elf_off, error);
	if (num_processed_pages < 0)
		return -1;

	if (num_processed_pages != (gssize)pglist_num_pages) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_ELF_READ,
			    _("Processed page count isn't correct"));
		return -1;
	}

	if (BIO_flush(output) != 1) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_ELF_READ, _("BIO_flush failed"));
		return -1;
	}

	data_size = BIO_get_mem_data(output, &data);
	if (data_size < 0 || !data) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_ELF_READ,
			    _("BIO_get_mem_data failed"));
		return -1;
	}

	if ((u64)data_size != pglist_size) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_ELF_READ,
			    _("Decrypting memory failed"));
		return -1;
	}

	/* NOTE previous assertions/overflow checks assure that this can never happen.
	 * We keep this to be extra sure and protect the following memcpy from
	 * malicious copying.
	 */
	if (page_off + size > (u64)data_size) {
		g_set_error(error, ZDUMP_PV_UTILS_ERROR, ZDUMP_ERR_ELF_READ, _("%s: Illegal state"),
			    __func__);
		return -1;
	}

	(void)memcpy(dst, data + page_off, size);
	return 0;
}
