/*
 * PV component related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_COMP_H
#define PV_COMP_H

#include <glib.h>
#include <openssl/evp.h>
#include <stdint.h>

#include "utils/crypto.h"

/* The order of this enum also implicitly defines the order of the
 * components within the PV image!
 */
typedef enum {
	PV_COMP_TYPE_KERNEL  = 0,
	PV_COMP_TYPE_CMDLINE = 1,
	PV_COMP_TYPE_INITRD  = 2,
	PV_COMP_TYPE_STAGE3B = 3,
} PvComponentType;

typedef enum {
	DATA_FILE = 0,
	DATA_BUFFER,
} PvComponentDataType;

typedef struct comp_file {
	gchar *path;
	gsize size;
} CompFile;

typedef struct {
	gint type; /* PvComponentType */
	gint d_type; /* PvComponentDataType */
	union {
		struct comp_file *file;
		PvBuffer *buf;
		void *data;
	};
	uint64_t src_addr;
	uint64_t orig_size;
	union tweak tweak; /* used for the AES XTS encryption */
} PvComponent;

PvComponent *pv_component_new_file(PvComponentType type, const gchar *path,
				   GError **err);
PvComponent *pv_component_new_buf(PvComponentType type, const PvBuffer *buf,
				  GError **err);
void pv_component_free(PvComponent *component);
gint pv_component_type(const PvComponent *component);
const gchar *pv_component_name(const PvComponent *component);
uint64_t pv_component_size(const PvComponent *component);
uint64_t pv_component_get_src_addr(const PvComponent *component);
uint64_t pv_component_get_orig_size(const PvComponent *component);
uint64_t pv_component_get_tweak_prefix(const PvComponent *component);
gboolean pv_component_is_stage3b(const PvComponent *component);
gint pv_component_align_and_encrypt(PvComponent *component, const gchar *tmp_path,
				    void *opaque, GError **err);
gint pv_component_align(PvComponent *component, const gchar *tmp_path,
			void *opaque G_GNUC_UNUSED, GError **err);
int64_t pv_component_update_pld(const PvComponent *comp, EVP_MD_CTX *ctx,
				GError **err);
int64_t pv_component_update_ald(const PvComponent *comp, EVP_MD_CTX *ctx,
				GError **err);
int64_t pv_component_update_tld(const PvComponent *comp, EVP_MD_CTX *ctx,
				GError **err);
gint pv_component_write(const PvComponent *component, FILE *f, GError **err);

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(PvComponent, pv_component_free)

#endif
