/*
 * PV image related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_IMAGE_H
#define PV_IMAGE_H

#include <glib.h>
#include <glib/gtypes.h>
#include <openssl/evp.h>
#include <stdint.h>

#include "boot/s390.h"
#include "utils/buffer.h"

#include "pv_args.h"
#include "pv_comp.h"
#include "pv_comps.h"
#include "pv_stage3.h"

typedef struct {
	gchar *tmp_dir; /* directory used for temporary files */
	PvBuffer *stage3a; /* stage3a containing IPIB and PV header */
	gsize stage3a_bin_size; /* size of stage3a.bin */
	struct psw_t stage3a_psw; /* (short) PSW that is written to
				   * location 0 of the created image
				   */
	struct psw_t initial_psw; /* PSW loaded by stage3b */
	EVP_PKEY *cust_pub_priv_key; /* customer private/public key */
	GSList *host_pub_keys; /* public host keys */
	gint nid; /* Elliptic Curve used for the key derivation */
	/* keys and cipher used for the AES-GCM encryption */
	PvBuffer *cust_root_key;
	PvBuffer *gcm_iv;
	const EVP_CIPHER *gcm_cipher;
	/* Information for the IPIB and PV header */
	uint64_t pcf;
	uint64_t scf;
	PvBuffer *cust_comm_key;
	const EVP_CIPHER *cust_comm_cipher;
	PvBuffer *xts_key;
	const EVP_CIPHER *xts_cipher;
	GSList *key_slots;
	GSList *optional_items;
	PvImgComps *comps;
} PvImage;

PvImage *pv_img_new(PvArgs *args, const gchar *stage3a_path, GError **err);
void pv_img_free(PvImage *img);
gint pv_img_add_component(PvImage *img, const PvArg *arg, GError **err);
gint pv_img_finalize(PvImage *img, const gchar *stage3b_path, GError **err);
gint pv_img_calc_pld_ald_tld_nep(const PvImage *img, PvBuffer **pld, PvBuffer **ald,
				 PvBuffer **tld, uint64_t *nep, GError **err);
gint pv_img_load_and_set_stage3a(PvImage *img, const gchar *path, GError **err);
const PvComponent *pv_img_get_stage3b_comp(const PvImage *img, GError **err);
gint pv_img_add_stage3b_comp(PvImage *img, const gchar *path, GError **err);
uint32_t pv_img_get_enc_size(const PvImage *img);
uint32_t pv_img_get_pv_hdr_size(const PvImage *img);
gint pv_img_write(PvImage *img, const gchar *path, GError **err);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvImage, pv_img_free)

#endif
