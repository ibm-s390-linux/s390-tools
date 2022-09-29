/*
 * Attestation related functions
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
/* Must be included before any other header */
#include "config.h"

#include "libpv/cert.h"
#include "libpv/hash.h"
#include "libpv/se-hdr.h"

#include "exchange_format.h"
#include "attestation.h"

G_STATIC_ASSERT(sizeof(((att_meas_ctx_t *)0)->pld) == sizeof(((struct pv_hdr_head *)0)->pld));
G_STATIC_ASSERT(sizeof(((att_meas_ctx_t *)0)->ald) == sizeof(((struct pv_hdr_head *)0)->ald));
G_STATIC_ASSERT(sizeof(((att_meas_ctx_t *)0)->tld) == sizeof(((struct pv_hdr_head *)0)->tld));
G_STATIC_ASSERT(sizeof(((att_meas_ctx_t *)0)->tag) == sizeof(((struct pv_hdr *)0)->tag));

struct att_meas_sizes {
	uint16_t user_data_len;
	uint16_t zeros;
	uint32_t additional_data_len;
} __packed;
G_STATIC_ASSERT(sizeof(struct att_meas_sizes) == 8);

/*
 * All optional arguments may be NULL
 * user_data is up to 256 bytes long, or NULL.
 * nonce is 16 bytes long or NULL.
 * additional_data is up to 32768 bytes long or NULL.
 */
GBytes *att_gen_measurement_hmac_sha512(const att_meas_ctx_t *meas_ctx, GBytes *measurement_key,
					GBytes *optional_user_data, GBytes *optional_nonce,
					GBytes *optional_additional_data, GError **error)
{
	struct att_meas_sizes meas_sizes = {};
	g_autoptr(HMAC_CTX) hmac_ctx = NULL;
	size_t additional_data_size = 0;
	size_t user_data_size = 0;
	size_t nonce_size = 0;

	pv_wrapped_g_assert(meas_ctx);
	pv_wrapped_g_assert(measurement_key);

	if (optional_user_data)
		user_data_size = g_bytes_get_size(optional_user_data);
	if (optional_additional_data)
		additional_data_size = g_bytes_get_size(optional_additional_data);
	if (optional_nonce)
		nonce_size = g_bytes_get_size(optional_nonce);

	/* checks for these sizes resulting in GErrors are done before */
	g_assert(user_data_size <= PVATTEST_USER_DATA_MAX_SIZE);
	g_assert(additional_data_size <= PVATTEST_ADDITIONAL_MAX_SIZE);
	g_assert(nonce_size == 0 || nonce_size == ARCB_V1_NONCE_SIZE);

	pv_wrapped_g_assert(meas_ctx);
	pv_wrapped_g_assert(measurement_key);

	hmac_ctx = pv_hmac_ctx_new(measurement_key, EVP_sha512(), error);
	if (!hmac_ctx)
		return NULL;

	meas_sizes.user_data_len = GUINT16_TO_BE((uint16_t)user_data_size);
	meas_sizes.zeros = 0;
	meas_sizes.additional_data_len = GUINT32_TO_BE((uint32_t)additional_data_size);

	if (pv_hmac_ctx_update_raw(hmac_ctx, meas_ctx, sizeof(*meas_ctx), error) != 0)
		return NULL;

	/* add the sizes of user and additional data. */
	if (pv_hmac_ctx_update_raw(hmac_ctx, &meas_sizes, sizeof(meas_sizes), error))
		return NULL;

	/* update optional data. if NULL passed (or size = 0) nothing will happen to the HMAC_CTX */
	if (pv_hmac_ctx_update(hmac_ctx, optional_user_data, error) != 0)
		return NULL;
	if (pv_hmac_ctx_update(hmac_ctx, optional_nonce, error) != 0)
		return NULL;
	if (pv_hmac_ctx_update(hmac_ctx, optional_additional_data, error) != 0)
		return NULL;
	return pv_hamc_ctx_finalize(hmac_ctx, error);
}

att_meas_ctx_t *att_extract_from_hdr(GBytes *se_hdr, GError **error)
{
	g_autofree att_meas_ctx_t *meas = NULL;
	const struct pv_hdr *hdr = NULL;
	size_t se_hdr_tag_offset;
	size_t se_hdr_size;
	uint8_t *hdr_u8;

	pv_wrapped_g_assert(se_hdr);

	hdr = g_bytes_get_data(se_hdr, &se_hdr_size);
	hdr_u8 = (uint8_t *)hdr;

	if (se_hdr_size < PV_V1_PV_HDR_MIN_SIZE) {
		g_set_error(error, ATT_ERROR, ATT_ERR_INVALID_HDR,
			    _("Invalid SE header provided."));
		return NULL;
	}

	if (GUINT32_FROM_BE(hdr->head.phs) != se_hdr_size ||
	    GUINT64_FROM_BE(hdr->head.magic) != PV_MAGIC_NUMBER) {
		g_set_error(error, ATT_ERROR, ATT_ERR_INVALID_HDR,
			    _("Invalid SE header provided."));
		return NULL;
	}

	se_hdr_tag_offset = GUINT32_FROM_BE(hdr->head.phs) - sizeof(hdr->tag);
	meas = g_new0(att_meas_ctx_t, 1);

	memcpy(meas->pld, hdr->head.pld, sizeof(meas->pld));
	memcpy(meas->ald, hdr->head.ald, sizeof(meas->ald));
	memcpy(meas->tld, hdr->head.tld, sizeof(meas->tld));
	memcpy(meas->tag, hdr_u8 + se_hdr_tag_offset, sizeof(meas->tag));

	return g_steal_pointer(&meas);
}

void att_add_uid(att_meas_ctx_t *meas_ctx, GBytes *config_uid)
{
	pv_wrapped_g_assert(meas_ctx);
	pv_wrapped_g_assert(config_uid);

	g_assert(g_bytes_get_size(config_uid) == ATT_CONFIG_UID_SIZE);
	pv_gbytes_memcpy(meas_ctx->config_uid, ATT_CONFIG_UID_SIZE, config_uid, NULL);
}

gboolean att_verify_measurement(const GBytes *calculated_measurement,
				const GBytes *uvio_measurement, GError **error)
{
	pv_wrapped_g_assert(calculated_measurement);
	pv_wrapped_g_assert(uvio_measurement);

	if (g_bytes_compare(calculated_measurement, uvio_measurement) != 0) {
		g_set_error(error, ATT_ERROR, ATT_ERR_MEASUREMENT_VERIFICATION_FAILED,
			    _("Calculated and received attestation measurement are not equal."));
		return FALSE;
	}
	return TRUE;
}
