/*
 * PV header related functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_HDR_H
#define PV_HDR_H

#include <glib.h>
#include <stdint.h>

#include "boot/s390.h"
#include "include/pv_hdr_def.h"
#include "utils/crypto.h"
#include "utils/buffer.h"

#include "pv_image.h"

PvHdr *pv_hdr_new(const PvImage *img, GError **err);
void pv_hdr_free(PvHdr *hdr);
G_GNUC_UNUSED gboolean pv_hdr_uses_encryption(const PvHdr *hdr);
PvBuffer *pv_hdr_serialize(const PvHdr *hdr, const PvImage *img,
			   enum PvCryptoMode mode, GError **err);
uint32_t pv_hdr_size(const PvHdr *hdr);
uint32_t pv_hdr_aad_size(const PvHdr *hdr);
uint64_t pv_hdr_enc_size(const PvHdr *hdr);
uint32_t pv_hdr_enc_size_casted(const PvHdr *hdr);
uint64_t pv_hdr_get_nks(const PvHdr *hdr);

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvHdr, pv_hdr_free)

#endif
