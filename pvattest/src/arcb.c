/*
 * Attestation Request Control Block related functions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include <openssl/evp.h>
#include <stdlib.h>

#include "libpv/crypto.h"
#include "libpv/hash.h"

#include "arcb.h"
#include "common.h"
#include "log.h"

#define ARVN_VERSION_1 0x0100
#define MAX_ARL 0x2000

typedef struct arcb_v1_hdr {
	uint64_t reserved0; /* 0x0000  */
	be32_t arvn; /* 0x0008  */
	be32_t arl; /* 0x000c  */
	uint8_t iv[ARCB_V1_IV_SIZE]; /* 0x0010  */
	uint32_t reserved1c; /* 0x001c  */
	uint8_t reserved20[7]; /* 0x0020  */
	uint8_t nks; /* 0x0027  */
	uint32_t reserved28; /* 0x0028  */
	be32_t sea; /* 0x002c  */
	be64_t paf; /* 0x0030  */
	be32_t mai; /* 0x0038  */
	uint32_t reserved3c; /* 0x003c  */
	PvEcdhPubKey cpk; /* 0x0040  */
} __packed arcb_v1_hdr_t;
G_STATIC_ASSERT(sizeof(arcb_v1_hdr_t) == 0xe0);

typedef struct arcb_v1_key_slot {
	uint8_t phkh[ARCB_V1_PHKH_SIZE];
	uint8_t warpk[ARCB_V1_ATTEST_PROT_KEY_SIZE];
	uint8_t kst[ARCB_V1_TAG_SIZE];
} __packed arcb_v1_key_slot_t;
G_STATIC_ASSERT(sizeof(arcb_v1_key_slot_t) == 0x50);

struct arcb_v1 {
	/* authenticated data */
	uint32_t arvn;
	uint32_t mai;
	uint64_t paf;
	GBytes *iv;
	EVP_PKEY *evp_cust_pub_key;
	GSList *host_key_slots;

	/* confidential data */
	GBytes *confidential_measurement_key;
	GBytes *confidential_optional_nonce;
	GBytes *confidential_att_req_prot_key;
};

void arcb_v1_clear_free(arcb_v1_t *arcb)
{
	if (!arcb)
		return;

	g_slist_free_full(arcb->host_key_slots, g_free);
	g_bytes_unref(arcb->confidential_measurement_key);
	g_bytes_unref(arcb->confidential_optional_nonce);
	g_bytes_unref(arcb->confidential_att_req_prot_key);
	g_bytes_unref(arcb->iv);
	EVP_PKEY_free(arcb->evp_cust_pub_key);
	g_free(arcb);
}

static void arcb_v1_set_paf(arcb_v1_t *arcb, const uint64_t paf, GError **error)
{
	const uint64_t known_flags = ARCB_V1_PAF_ALL & ~ARCB_V1_PAF_NONCE;

	if ((paf & ARCB_V1_PAF_NONCE) != 0) {
		g_set_error(error, ARCB_ERROR, ARCB_ERR_INVALID_PAF,
			    _("The given paf (%#.16lx) specifies the NONCE flag (%#.16lx)."), paf,
			    ARCB_V1_PAF_NONCE);
		return;
	}
	if ((paf & ~known_flags) != 0)
		pvattest_log_warning(
			_("The given paf (%#.16lx) specifies unknown flags. Use at your own risk!"),
			paf, known_flags);
	arcb->paf = paf;
}

arcb_v1_t *arcb_v1_new(GBytes *arpk, GBytes *iv, uint32_t mai, EVP_PKEY *evp_cpk, GBytes *mkey,
		       uint64_t paf, GError **error)
{
	g_autoptr(arcb_v1_t) arcb = g_new0(arcb_v1_t, 1);

	g_assert(g_bytes_get_size(iv) == ARCB_V1_IV_SIZE);
	g_assert(g_bytes_get_size(arpk) == ARCB_V1_ATTEST_PROT_KEY_SIZE);
	g_assert(g_bytes_get_size(mkey) == HMAC_SHA512_KEY_SIZE);

	pv_wrapped_g_assert(arpk);
	pv_wrapped_g_assert(iv);
	pv_wrapped_g_assert(evp_cpk);
	pv_wrapped_g_assert(mkey);

	arcb->arvn = ARVN_VERSION_1;
	arcb->mai = mai;
	arcb_v1_set_paf(arcb, paf, error);
	if (*error)
		return NULL;
	arcb->iv = g_bytes_ref(iv);

	if (EVP_PKEY_up_ref(evp_cpk) != 1)
		g_abort();
	arcb->evp_cust_pub_key = evp_cpk;

	arcb->confidential_att_req_prot_key = g_bytes_ref(arpk);
	arcb->confidential_measurement_key = g_bytes_ref(mkey);

	return g_steal_pointer(&arcb);
}

int arcb_v1_add_key_slot(arcb_v1_t *arcb, EVP_PKEY *evp_host, GError **error)
{
	g_autoptr(GBytes) warpk = NULL, tag = NULL, phkh = NULL;
	g_autoptr(GBytes) exchange_key = NULL, iv = NULL;
	g_autofree arcb_v1_key_slot_t *key_slot = NULL;
	g_autofree PvEcdhPubKey *ecdh_host = NULL;
	g_autofree uint8_t *iv_raw = NULL;
	PvCipherParms parms;
	int64_t gcm_rc;

	g_assert(arcb->confidential_att_req_prot_key);

	pv_wrapped_g_assert(arcb);
	pv_wrapped_g_assert(evp_host);

	/* encrypt (=wrap) attestation request protection key, store warpk + tag */
	exchange_key = pv_derive_exchange_key(arcb->evp_cust_pub_key, evp_host, error);
	if (!exchange_key)
		return -1;

	iv_raw = g_malloc0(ARCB_V1_IV_SIZE);
	iv = g_bytes_new_take(g_steal_pointer(&iv_raw), ARCB_V1_IV_SIZE);
	if (!iv)
		g_abort();

	parms.key = exchange_key;
	parms.iv = iv;
	parms.cipher = EVP_aes_256_gcm();
	parms.tag_size = ARCB_V1_TAG_SIZE;
	gcm_rc = pv_gcm_encrypt(arcb->confidential_att_req_prot_key, NULL, &parms, &warpk, &tag,
				error);
	if (gcm_rc != ARCB_V1_ATTEST_PROT_KEY_SIZE)
		return -1;

	/* calculate public host key hash */
	ecdh_host = pv_evp_pkey_to_ecdh_pub_key(evp_host, error);
	if (!ecdh_host)
		return -1;
	phkh = pv_sha256_hash(ecdh_host->data, sizeof(ecdh_host->data), error);
	if (!phkh)
		return -1;

	/* copy to list */
	g_assert(g_bytes_get_size(warpk) == sizeof(key_slot->warpk));
	g_assert(g_bytes_get_size(tag) == sizeof(key_slot->kst));
	g_assert(g_bytes_get_size(phkh) == sizeof(key_slot->phkh));

	key_slot = g_malloc0(sizeof(*key_slot));
	pv_gbytes_memcpy(key_slot->warpk, sizeof(key_slot->warpk), warpk, NULL);
	pv_gbytes_memcpy(key_slot->kst, sizeof(key_slot->warpk), tag, NULL);
	pv_gbytes_memcpy(key_slot->phkh, sizeof(key_slot->warpk), phkh, NULL);

	arcb->host_key_slots = g_slist_prepend(arcb->host_key_slots, g_steal_pointer(&key_slot));
	return 0;
}

void arcb_v1_set_nonce(arcb_v1_t *arcb, GBytes *nonce)
{
	pv_wrapped_g_assert(arcb);
	pv_wrapped_g_assert(nonce);
	arcb_v1_rm_nonce(arcb);
	g_assert(!arcb->confidential_optional_nonce);

	g_assert(g_bytes_get_size(nonce) == ARCB_V1_NONCE_SIZE);
	arcb->confidential_optional_nonce = g_bytes_ref(nonce);

	arcb->paf |= ARCB_V1_PAF_NONCE;
}

void arcb_v1_rm_nonce(arcb_v1_t *arcb)
{
	pv_wrapped_g_assert(arcb);
	if (!arcb->confidential_optional_nonce)
		return;
	g_bytes_unref(arcb->confidential_optional_nonce);
	arcb->confidential_optional_nonce = NULL;
	arcb->paf &= ~ARCB_V1_PAF_NONCE;
}

GBytes *arcb_v1_serialize(const arcb_v1_t *arcb, GError **error)
{
	pv_wrapped_g_assert(arcb);
	g_autoptr(GByteArray) arcb_gba = NULL;
	g_autoptr(GBytes) confidential_area = NULL;
	g_autoptr(GBytes) aad = NULL;
	g_autoptr(GBytes) art = NULL;
	g_autoptr(GBytes) encrypted_area = NULL;
	g_autoptr(GBytes) result = NULL;
	g_autofree PvEcdhPubKey *ecdh_cpk = NULL;
	PvCipherParms parms = {
		.cipher = EVP_aes_256_gcm(),
		.tag_size = AES_256_GCM_TAG_SIZE,
	};
	size_t att_req_len = 0, nks = 0, sea = 0;

	arcb_v1_hdr_t hdr = {
		.arvn = GUINT32_TO_BE(arcb->arvn),
		.paf = GUINT64_TO_BE(arcb->paf),
		.mai = GUINT32_TO_BE(arcb->mai),
	};

	g_assert(arcb->host_key_slots);

	/* calculate sizes */
	nks = g_slist_length(arcb->host_key_slots);
	g_assert(nks < 0xFF);

	sea = g_bytes_get_size(arcb->confidential_measurement_key);
	if (arcb->confidential_optional_nonce)
		sea += g_bytes_get_size(arcb->confidential_optional_nonce);

	g_assert(sea == HMAC_SHA512_KEY_SIZE || sea == HMAC_SHA512_KEY_SIZE + ARCB_V1_NONCE_SIZE);

	att_req_len = sizeof(hdr) + nks * sizeof(arcb_v1_key_slot_t) + HMAC_SHA512_KEY_SIZE +
		      ARCB_V1_TAG_SIZE;
	if (arcb->confidential_optional_nonce)
		att_req_len += ARCB_V1_NONCE_SIZE;

	g_assert(att_req_len <= MAX_ARL);

	/* copy plain data to contiguous memory  */
	hdr.arl = GUINT32_TO_BE((uint32_t)att_req_len);

	pv_gbytes_memcpy(hdr.iv, ARCB_V1_IV_SIZE, arcb->iv, NULL);
	hdr.nks = (uint8_t)nks;
	hdr.sea = GUINT32_TO_BE((uint32_t)sea);
	ecdh_cpk = pv_evp_pkey_to_ecdh_pub_key(arcb->evp_cust_pub_key, error);
	memcpy(&hdr.cpk, ecdh_cpk, sizeof(*ecdh_cpk));
	arcb_gba = g_byte_array_sized_new((guint)att_req_len);
	g_byte_array_append(arcb_gba, (const uint8_t *)&hdr, sizeof(hdr));

	for (GSList *elem = arcb->host_key_slots; elem; elem = elem->next)
		g_byte_array_append(arcb_gba, elem->data, sizeof(arcb_v1_key_slot_t));

	/* encrypt the confidential data */
	confidential_area = secure_gbytes_concat(arcb->confidential_measurement_key,
						 arcb->confidential_optional_nonce);
	parms.key = arcb->confidential_att_req_prot_key;
	parms.iv = arcb->iv;
	aad = g_bytes_new(arcb_gba->data, arcb_gba->len);
	pv_gcm_encrypt(confidential_area, aad, &parms, &encrypted_area, &art, error);
	if (*error)
		return NULL;

	g_byte_array_append(arcb_gba, g_bytes_get_data(encrypted_area, NULL), (guint)sea);
	g_byte_array_append(arcb_gba, g_bytes_get_data(art, NULL), ARCB_V1_TAG_SIZE);

	result = g_byte_array_free_to_bytes(arcb_gba);
	arcb_gba = NULL;
	return g_steal_pointer(&result);
}

uint32_t arcb_v1_get_required_measurement_size(const arcb_v1_t *arcb, GError **error)
{
	pv_wrapped_g_assert(arcb);
	switch (arcb->mai) {
	case MAI_HMAC_SHA512:
		return HMAC_SHA512_KEY_SIZE;
	default:
		g_set_error(error, ARCB_ERROR, ARCB_ERR_INVALID_MAI,
			    _("Unknown measurement algorithm ID specified (%#x)."), arcb->mai);
		return 0;
	}
}

uint32_t arcb_v1_get_required_additional_size(const arcb_v1_t *arcb)
{
	uint32_t size = 0;

	pv_wrapped_g_assert(arcb);

	if (arcb_v1_additional_has_phkh_image(arcb))
		size += ARCB_V1_PHKH_SIZE;
	if (arcb_v1_additional_has_phkh_attest(arcb))
		size += ARCB_V1_PHKH_SIZE;
	return size;
}

gboolean arcb_v1_use_nonce(const arcb_v1_t *arcb)
{
	pv_wrapped_g_assert(arcb);
	return arcb->confidential_optional_nonce != NULL;
}

gboolean arcb_v1_additional_has_phkh_image(const arcb_v1_t *arcb)
{
	pv_wrapped_g_assert(arcb);
	return (arcb->paf & ARCB_V1_PAF_AAD_PHKH_HEADER) != 0;
}

gboolean arcb_v1_additional_has_phkh_attest(const arcb_v1_t *arcb)
{
	pv_wrapped_g_assert(arcb);
	return (arcb->paf & ARCB_V1_PAF_AAD_PHKH_ATTEST) != 0;
}

GBytes *arcb_v1_get_measurement_key(const arcb_v1_t *arcb)
{
	pv_wrapped_g_assert(arcb);
	return g_bytes_ref(arcb->confidential_measurement_key);
}

GBytes *arcb_v1_get_nonce(const arcb_v1_t *arcb)
{
	pv_wrapped_g_assert(arcb);
	if (arcb->confidential_optional_nonce)
		return g_bytes_ref(arcb->confidential_optional_nonce);
	return NULL;
}

GBytes *arcb_v1_get_arp_key(const arcb_v1_t *arcb)
{
	pv_wrapped_g_assert(arcb);
	return g_bytes_ref(arcb->confidential_att_req_prot_key);
}

static gboolean is_v1_arcb(size_t aad_size, size_t sea, size_t arl, size_t serialized_arcb_size,
			   uint32_t arcb_version, gboolean has_nonce)
{
	gboolean result = aad_size + sea + ARCB_V1_TAG_SIZE == arl;

	result &= arl <= serialized_arcb_size;
	result &= arcb_version == ARVN_VERSION_1;
	result &= has_nonce ? sea == HMAC_SHA512_KEY_SIZE + ARCB_V1_NONCE_SIZE :
				    sea == HMAC_SHA512_KEY_SIZE;
	return result;
}

gboolean arcb_v1_verify_serialized_arcb(GBytes *serialized_arcb, GBytes *arpk,
					GBytes **measurement_key, GBytes **optional_nonce,
					GError **error)
{
	g_autoptr(GBytes) encr = NULL, decr = NULL, aad = NULL, tag = NULL, iv = NULL;
	const struct arcb_v1_hdr *serialized_arcb_hdr;
	const uint8_t *encr_u8, *aad_u8, *tag_u8;
	const uint8_t *serialized_arcb_u8;
	size_t serialized_arcb_size;
	uint32_t arcb_version, mai;
	size_t aad_size, arl, sea;
	PvCipherParms parms;
	gboolean has_nonce;
	uint64_t paf;

	pv_wrapped_g_assert(serialized_arcb);
	pv_wrapped_g_assert(arpk);
	serialized_arcb_u8 = g_bytes_get_data(serialized_arcb, &serialized_arcb_size);
	serialized_arcb_hdr = (const arcb_v1_hdr_t *)serialized_arcb_u8;
	arl = GUINT32_FROM_BE(serialized_arcb_hdr->arl);
	arcb_version = GUINT32_FROM_BE(serialized_arcb_hdr->arvn);
	mai = GUINT32_FROM_BE(serialized_arcb_hdr->mai);

	aad_u8 = serialized_arcb_u8;
	aad_size = sizeof(*serialized_arcb_hdr) +
		   serialized_arcb_hdr->nks * sizeof(arcb_v1_key_slot_t);
	encr_u8 = aad_u8 + aad_size;
	sea = GUINT32_FROM_BE(serialized_arcb_hdr->sea);
	tag_u8 = encr_u8 + sea;
	paf = GUINT64_FROM_BE(serialized_arcb_hdr->paf);
	has_nonce = (paf & ARCB_V1_PAF_NONCE) != 0;

	if (!is_v1_arcb(aad_size, sea, arl, serialized_arcb_size, arcb_version, has_nonce)) {
		g_set_error(error, ARCB_ERROR, ARCB_ERR_INVALID_ARCB,
			    _("The provided attestation request is not valid"));
		return FALSE;
	}
	if (mai != MAI_HMAC_SHA512) {
		g_set_error(error, ARCB_ERROR, ARCB_ERR_INVALID_MAI,
			    _("Unsupported measurement argument ID (%#x)"), mai);
		return FALSE;
	}

	aad = g_bytes_new(aad_u8, aad_size);
	encr = g_bytes_new(encr_u8, sea);
	tag = g_bytes_new(tag_u8, ARCB_V1_TAG_SIZE);
	iv = g_bytes_new(serialized_arcb_hdr->iv, sizeof(serialized_arcb_hdr->iv));

	parms.cipher = EVP_aes_256_gcm();
	parms.tag_size = AES_256_GCM_TAG_SIZE;
	parms.key = arpk;
	parms.iv = iv;
	pv_gcm_decrypt(encr, aad, tag, &parms, &decr, error);
	if (*error) {
		GError *tmp_error = NULL;

		g_set_error(&tmp_error, ARCB_ERROR, ARCB_ERR_INVALID_ARCB,
			    _("Cannot verify the attestation request: %s"), (*error)->message);
		g_clear_error(error);
		g_propagate_error(error, tmp_error);
		return FALSE;
	}
	if (measurement_key)
		*measurement_key = g_bytes_new(g_bytes_get_data(decr, NULL), HMAC_SHA512_KEY_SIZE);
	if (optional_nonce && has_nonce)
		*optional_nonce =
			g_bytes_new((uint8_t *)g_bytes_get_data(decr, NULL) + HMAC_SHA512_KEY_SIZE,
				    ARCB_V1_NONCE_SIZE);
	return TRUE;
}
