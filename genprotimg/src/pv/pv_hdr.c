/*
 * PV header related functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <glib.h>
#include <glib/gtypes.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>

#include "boot/s390.h"
#include "include/pv_crypto_def.h"
#include "utils/buffer.h"
#include "utils/crypto.h"

#include "pv_comp.h"
#include "pv_hdr.h"
#include "pv_image.h"

void pv_hdr_free(PvHdr *hdr)
{
	if (!hdr)
		return;

	g_free(hdr->optional_items);
	g_free(hdr->encrypted);
	g_free(hdr->slots);
	g_free(hdr);
}

uint32_t pv_hdr_size(const PvHdr *hdr)
{
	return GUINT32_FROM_BE(hdr->head.phs);
}

gboolean pv_hdr_uses_encryption(const PvHdr *hdr)
{
	return !(GUINT64_FROM_BE(hdr->head.pcf) & PV_CFLAG_NO_DECRYPTION);
}

uint64_t pv_hdr_enc_size(const PvHdr *hdr)
{
	return GUINT64_FROM_BE(hdr->head.sea);
}

uint32_t pv_hdr_enc_size_casted(const PvHdr *hdr)
{
	uint64_t size = pv_hdr_enc_size(hdr);

	if (size > UINT32_MAX)
		g_abort();

	return (uint32_t)size;
}

static guint pv_hdr_tag_size(const PvHdr *hdr)
{
	return sizeof(hdr->tag);
}

uint32_t pv_hdr_aad_size(const PvHdr *hdr)
{
	return pv_hdr_size(hdr) - pv_hdr_enc_size_casted(hdr) -
	       pv_hdr_tag_size(hdr);
}

uint64_t pv_hdr_get_nks(const PvHdr *hdr)
{
	return GUINT64_FROM_BE(hdr->head.nks);
}

/* In-place modification of ``buf`` */
static gint pv_hdr_encrypt(const PvHdr *hdr, const PvImage *img, PvBuffer *buf,
			   GError **err)
{
	uint32_t hdr_len = pv_hdr_size(hdr);
	uint32_t aad_len = pv_hdr_aad_size(hdr);
	guint tag_len = pv_hdr_tag_size(hdr);
	uint32_t enc_len = pv_hdr_enc_size_casted(hdr);
	const PvBuffer aad_part = { .data = buf->data, .size = aad_len };
	PvBuffer enc_part = { .data = (uint8_t *)buf->data + aad_len,
			    .size = enc_len };
	PvBuffer tag_part = { .data = (uint8_t *)buf->data + hdr_len - tag_len,
			    .size = tag_len };
	struct cipher_parms parms;
	int64_t c_len;

	g_assert(aad_part.size + enc_part.size + tag_part.size == buf->size);
	g_assert(img->cust_root_key->size <= INT_MAX);
	g_assert(img->gcm_iv->size <= INT_MAX);
	g_assert(EVP_CIPHER_key_length(img->gcm_cipher) ==
		 (int)img->cust_root_key->size);
	g_assert(EVP_CIPHER_iv_length(img->gcm_cipher) == (int)img->gcm_iv->size);

	parms.key = img->cust_root_key;
	parms.iv_or_tweak = img->gcm_iv;
	parms.cipher = img->gcm_cipher;

	/* in-place encryption */
	c_len = gcm_encrypt(&enc_part, &aad_part, &parms, &enc_part, &tag_part, err);
	if (c_len < 0)
		return -1;

	g_assert(c_len == enc_len);
	return 0;
}

/* Initializes the unencrypted, but integrity protected part of the PV
 * header
 */
static gint pv_hdr_aad_init(PvHdr *hdr, const PvImage *img, GError **err)
{
	g_autofree union ecdh_pub_key *cust_pub_key = NULL;
	struct pv_hdr_key_slot *hdr_slot = hdr->slots;
	struct pv_hdr_head *head = &hdr->head;
	g_autoptr(PvBuffer) pld = NULL;
	g_autoptr(PvBuffer) ald = NULL;
	g_autoptr(PvBuffer) tld = NULL;
	uint64_t nep = 0;

	g_assert(sizeof(head->iv) == img->gcm_iv->size);
	g_assert(sizeof(head->cust_pub_key) == sizeof(*cust_pub_key));

	cust_pub_key = evp_pkey_to_ecdh_pub_key(img->cust_pub_priv_key, err);
	if (!cust_pub_key)
		return -1;

	head->magic = GUINT64_TO_BE(PV_MAGIC_NUMBER);
	head->version = GUINT32_TO_BE(PV_VERSION_1);
	/* ``phs`` is already set so we can skip it here */
	memcpy(head->iv, img->gcm_iv->data, sizeof(head->iv));
	/* ``nks`` is already set so we can skip it here */
	/* ``sea`` is already set so we can skip it here */
	head->pcf = GUINT64_TO_BE(img->pcf);
	memcpy(head->cust_pub_key.data, cust_pub_key,
	       sizeof(head->cust_pub_key));

	if (pv_img_calc_pld_ald_tld_nep(img, &pld, &ald, &tld, &nep, err) < 0)
		return -1;

	g_assert(sizeof(head->pld) == pld->size);
	g_assert(sizeof(head->ald) == ald->size);
	g_assert(sizeof(head->tld) == tld->size);

	head->nep = GUINT64_TO_BE(nep);
	memcpy(head->pld, pld->data, sizeof(head->pld));
	memcpy(head->ald, ald->data, sizeof(head->ald));
	memcpy(head->tld, tld->data, sizeof(head->tld));

	/* set the key slots */
	for (GSList *iterator = img->key_slots; iterator; iterator = iterator->next) {
		const PvHdrKeySlot *slot = iterator->data;

		g_assert(slot);

		/* the memory for the slots is pre-allocated so we
		 * have not to allocate and since PvHdrKeySlot is
		 * stored in the big-edian format we can simply use
		 * memcpy.
		 */
		memcpy(hdr_slot++, slot, sizeof(*slot));
	}

	return 0;
}

/* Initializes the encrypted and also integrity protected part of the
 * PV header
 */
static gint pv_hdr_enc_init(PvHdr *hdr, const PvImage *img, GError **err)
{
	struct pv_hdr_encrypted *enc = hdr->encrypted;
	const PvComponent *stage3b;
	struct psw_t psw;

	g_assert(sizeof(enc->img_enc_key_1) + sizeof(enc->img_enc_key_2) ==
		 EVP_CIPHER_key_length(img->xts_cipher));
	g_assert(sizeof(enc->cust_comm_key) == img->cust_comm_key->size);
	g_assert(img->xts_key->size ==
		 (guint)EVP_CIPHER_key_length(img->xts_cipher));

	stage3b = pv_img_get_stage3b_comp(img, err);
	if (!stage3b)
		return -1;

	memcpy(enc->cust_comm_key, img->cust_comm_key->data,
	       sizeof(enc->cust_comm_key));
	memcpy(enc->img_enc_key_1, img->xts_key->data,
	       sizeof(enc->img_enc_key_1));
	memcpy(enc->img_enc_key_2,
	       (uint8_t *)img->xts_key->data + sizeof(enc->img_enc_key_1),
	       sizeof(enc->img_enc_key_2));

	/* Setup program check handler */
	psw.mask = GUINT64_TO_BE(DEFAULT_INITIAL_PSW_MASK);
	psw.addr = GUINT64_TO_BE(pv_component_get_src_addr(stage3b));
	enc->psw = psw;
	enc->scf = GUINT64_TO_BE(img->scf);
	enc->noi = GUINT32_TO_BE(g_slist_length(img->optional_items));

	/* set the optional items */
	for (GSList *iterator = img->optional_items; iterator;
	     iterator = iterator->next) {
		const struct pv_hdr_opt_item *item = iterator->data;

		g_assert(item);

		/* not supported in the first version */
		g_assert_not_reached();
	}

	return 0;
}

PvHdr *pv_hdr_new(const PvImage *img, GError **err)
{
	uint32_t noi = g_slist_length(img->optional_items);
	uint32_t hdr_size = pv_img_get_pv_hdr_size(img);
	gsize nks = g_slist_length(img->key_slots);
	uint32_t sea = pv_img_get_enc_size(img);
	g_autoptr(PvHdr) ret = NULL;

	g_assert(nks > 0);
	/* must be a multiple of AES block size */
	g_assert(sea % AES_BLOCK_SIZE == 0);
	g_assert(sea >= sizeof(struct pv_hdr_encrypted));

	ret = g_new0(PvHdr, 1);
	ret->slots = g_new0(struct pv_hdr_key_slot, nks);
	ret->head.phs = GUINT32_TO_BE(hdr_size);
	ret->head.nks = GUINT64_TO_BE(nks);
	ret->head.sea = GUINT64_TO_BE(sea);

	ret->encrypted = g_new0(struct pv_hdr_encrypted, 1);
	ret->optional_items = g_malloc0(sea - sizeof(struct pv_hdr_encrypted));
	ret->encrypted->noi = GUINT32_TO_BE(noi);

	if (pv_hdr_aad_init(ret, img, err) < 0)
		return NULL;

	if (pv_hdr_enc_init(ret, img, err) < 0)
		return NULL;

	return g_steal_pointer(&ret);
}

static void pv_hdr_memcpy(const PvHdr *hdr, const PvBuffer *dst)
{
	uint64_t nks = pv_hdr_get_nks(hdr);
	uint8_t *data;

	g_assert(dst->size == pv_hdr_size(hdr));
	g_assert(pv_hdr_enc_size_casted(hdr) >= sizeof(*hdr->encrypted));

	data = memcpy(dst->data, &hdr->head, sizeof(hdr->head));
	data = memcpy(data + sizeof(hdr->head), hdr->slots,
		      sizeof(struct pv_hdr_key_slot) * nks);
	data = memcpy(data + sizeof(struct pv_hdr_key_slot) * nks,
		      hdr->encrypted, sizeof(*hdr->encrypted));
	if (pv_hdr_enc_size_casted(hdr) - sizeof(*hdr->encrypted) > 0) {
		(void)memcpy(data + sizeof(*hdr->encrypted),
			     hdr->optional_items,
			     pv_hdr_enc_size_casted(hdr) - sizeof(*hdr->encrypted));
	}
}

PvBuffer *pv_hdr_serialize(const PvHdr *hdr, const PvImage *img,
			   enum PvCryptoMode mode, GError **err)
{
	uint32_t hdr_size = pv_hdr_size(hdr);
	g_autoptr(PvBuffer) ret = NULL;

	ret = pv_buffer_alloc(hdr_size);
	pv_hdr_memcpy(hdr, ret);

	if (mode == PV_ENCRYPT) {
		/* The buffer @ret is modified in-place */
		if (pv_hdr_encrypt(hdr, img, ret, err) < 0)
			return NULL;
	} else {
		/* Simply copy the tag */
		memcpy((uint8_t *)ret->data + hdr_size - pv_hdr_tag_size(hdr),
		       hdr->tag, pv_hdr_tag_size(hdr));
	}

	return g_steal_pointer(&ret);
}
