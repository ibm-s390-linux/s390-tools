/*
 * PV component related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <glib.h>
#include <glib/gtypes.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "boot/s390.h"
#include "common.h"
#include "utils/align.h"
#include "utils/buffer.h"
#include "utils/crypto.h"
#include "utils/file_utils.h"

#include "pv_comp.h"
#include "pv_error.h"

static void comp_file_free(CompFile *comp)
{
	if (!comp)
		return;

	g_free(comp->path);
	g_free(comp);
}

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(CompFile, comp_file_free)

static PvComponent *pv_component_new(PvComponentType type, gsize size,
				     PvComponentDataType d_type, void **data,
				     GError **err)
{
	g_autoptr(PvComponent) ret = g_new0(PvComponent, 1);

	g_assert(type >= 0 && type <= UINT16_MAX);

	ret->type = (int)type;
	ret->d_type = (int)d_type;
	ret->data = g_steal_pointer(data);
	ret->orig_size = size;

	if (generate_tweak(&ret->tweak, (uint16_t)type, err) < 0)
		return NULL;

	return g_steal_pointer(&ret);
}

PvComponent *pv_component_new_file(PvComponentType type, const gchar *path,
				   GError **err)
{
	g_autoptr(CompFile) file = g_new0(CompFile, 1);
	gsize size;
	gint rc;

	g_assert(path != NULL);

	rc = file_size(path, &size, err);
	if (rc < 0)
		return NULL;

	file->path = g_strdup(path);
	file->size = size;
	return pv_component_new(type, size, DATA_FILE, (void **)&file, err);
}

PvComponent *pv_component_new_buf(PvComponentType type, const PvBuffer *buf,
				  GError **err)
{
	g_assert(buf);

	g_autoptr(PvBuffer) dup_buf = pv_buffer_dup(buf, FALSE);
	return pv_component_new(type, buf->size, DATA_BUFFER, (void **)&dup_buf,
				err);
}

void pv_component_free(PvComponent *component)
{
	if (!component)
		return;

	switch ((PvComponentDataType)component->d_type) {
	case DATA_BUFFER:
		pv_buffer_clear(&component->buf);
		break;
	case DATA_FILE:
		comp_file_free(component->file);
		break;
	}

	g_free(component);
}

gint pv_component_type(const PvComponent *component)
{
	return component->type;
}

const gchar *pv_component_name(const PvComponent *component)
{
	gint type = pv_component_type(component);

	switch ((PvComponentType)type) {
	case PV_COMP_TYPE_KERNEL:
		return "kernel";
	case PV_COMP_TYPE_INITRD:
		return "ramdisk";
	case PV_COMP_TYPE_CMDLINE:
		return "parmline";
	case PV_COMP_TYPE_STAGE3B:
		return "stage3b";
	}

	g_assert_not_reached();
}

uint64_t pv_component_size(const PvComponent *component)
{
	switch ((PvComponentDataType)component->d_type) {
	case DATA_BUFFER:
		return component->buf->size;
	case DATA_FILE:
		return component->file->size;
	}

	g_assert_not_reached();
}

uint64_t pv_component_get_src_addr(const PvComponent *component)
{
	return component->src_addr;
}

uint64_t pv_component_get_orig_size(const PvComponent *component)
{
	return component->orig_size;
}

uint64_t pv_component_get_tweak_prefix(const PvComponent *component)
{
	return GUINT64_FROM_BE(component->tweak.cmp_idx.data);
}

gboolean pv_component_is_stage3b(const PvComponent *component)
{
	return pv_component_type(component) == PV_COMP_TYPE_STAGE3B;
}

gint pv_component_align_and_encrypt(PvComponent *component, const gchar *tmp_path,
				    void *opaque, GError **err)
{
	struct cipher_parms *parms = opaque;

	switch ((PvComponentDataType)component->d_type) {
	case DATA_BUFFER: {
		g_autoptr(PvBuffer) enc_buf = NULL;

		if (!(IS_PAGE_ALIGNED(pv_component_size(component)))) {
			g_autoptr(PvBuffer) new = NULL;

			/* create a page aligned copy */
			new = pv_buffer_dup(component->buf, TRUE);
			pv_buffer_clear(&component->buf);
			component->buf = g_steal_pointer(&new);
		}
		enc_buf = encrypt_buf(parms, component->buf, err);
		if (!enc_buf)
			return -1;

		pv_buffer_clear(&component->buf);
		component->buf = g_steal_pointer(&enc_buf);
		return 0;
	}
	case DATA_FILE: {
		const gchar *comp_name = pv_component_name(component);
		gchar *path_in = component->file->path;
		g_autofree gchar *path_out = NULL;
		gsize orig_size;
		gsize prep_size;

		g_assert(path_in);

		path_out = g_build_filename(tmp_path, comp_name, NULL);
		if (encrypt_file(parms, path_in, path_out, &orig_size,
				 &prep_size, err) < 0)
			return -1;

		if (component->orig_size != orig_size) {
			g_set_error(err, G_FILE_ERROR, PV_ERROR_INTERNAL,
				    _("File has changed during the preparation '%s'"),
				    path_out);
			return -1;
		}

		g_free(component->file->path);
		component->file->size = prep_size;
		component->file->path = g_steal_pointer(&path_out);
		return 0;
	}
	}

	g_assert_not_reached();
}

/* Page align the size of the component */
gint pv_component_align(PvComponent *component, const gchar *tmp_path,
			void *opaque G_GNUC_UNUSED, GError **err)
{
	if (IS_PAGE_ALIGNED(pv_component_size(component)))
		return 0;

	switch (component->d_type) {
	case DATA_BUFFER: {
		g_autoptr(PvBuffer) buf = NULL;

		buf = pv_buffer_dup(component->buf, TRUE);
		pv_buffer_clear(&component->buf);
		component->buf = g_steal_pointer(&buf);
		return 0;
	} break;
	case DATA_FILE: {
		const gchar *comp_name = pv_component_name(component);
		g_autofree gchar *path_out =
			g_build_filename(tmp_path, comp_name, NULL);
		gchar *path_in = component->file->path;
		gsize size_out;

		if (pad_file_right(path_out, path_in, &size_out, PAGE_SIZE,
				   err) < 0)
			return -1;

		g_free(component->file->path);
		component->file->path = g_steal_pointer(&path_out);
		component->file->size = size_out;
		return 0;
	} break;
	}

	g_assert_not_reached();
}

/* Convert uint64_t address to byte array */
static void uint64_to_uint8_buf(uint8_t dst[8], uint64_t addr)
{
	uint8_t *p = (uint8_t *)&addr;

	g_assert(dst);

	for (gint i = 0; i < 8; i++) {
		/* cppcheck-suppress objectIndex */
		dst[i] = p[i];
	}
}

int64_t pv_component_update_ald(const PvComponent *comp, EVP_MD_CTX *ctx,
				GError **err)
{
	uint64_t addr = pv_component_get_src_addr(comp);
	uint64_t size = pv_component_size(comp);
	uint64_t cur = addr;
	int64_t nep = 0;

	g_assert(IS_PAGE_ALIGNED(size) && size != 0);

	do {
		uint64_t cur_be = GUINT64_TO_BE(cur);
		uint8_t addr_buf[8];

		uint64_to_uint8_buf(addr_buf, cur_be);

		if (EVP_DigestUpdate(ctx, addr_buf, sizeof(addr_buf)) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_DigestUpdate failed"));
			return -1;
		}

		cur += PAGE_SIZE;
		nep++;
	} while (cur < addr + size);

	return nep;
}

int64_t pv_component_update_pld(const PvComponent *comp, EVP_MD_CTX *ctx,
				GError **err)
{
	uint64_t size = pv_component_size(comp);
	int64_t nep = 0;

	g_assert(IS_PAGE_ALIGNED(size) && size != 0);

	switch (comp->d_type) {
	case DATA_BUFFER: {
		const PvBuffer *buf = comp->buf;

		g_assert(buf->size <= INT64_MAX);
		g_assert(buf->size == size);

		if (EVP_DigestUpdate(ctx, buf->data, buf->size) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_DigestUpdate failed"));
			return -1;
		}

		nep = (int64_t)(buf->size / PAGE_SIZE);
		break;
	}
	case DATA_FILE: {
		const gchar *in_path = comp->file->path;
		guchar in_buf[PAGE_SIZE];
		gsize num_bytes_read_total = 0;
		gsize num_bytes_read = 0;
		FILE *f_in;

		f_in = file_open(in_path, "rb", err);
		if (!f_in)
			return -1;

		do {
			/* Read data in blocks. Update the digest
			 * context each read.
			 */
			if (file_read(f_in, in_buf, sizeof(*in_buf),
				      sizeof(in_buf), &num_bytes_read,
				      err) < 0) {
				fclose(f_in);
				return -1;
			}
			num_bytes_read_total += num_bytes_read;

			if (EVP_DigestUpdate(ctx, in_buf, sizeof(in_buf)) != 1) {
				g_set_error(err, PV_CRYPTO_ERROR,
					    PV_CRYPTO_ERROR_INTERNAL,
					    _("EVP_DigestUpdate failed"));
				fclose(f_in);
				return -1;
			}

			nep++;
		} while (num_bytes_read_total < pv_component_size(comp) &&
			 num_bytes_read != 0);

		if (num_bytes_read_total != pv_component_size(comp)) {
			g_set_error(err, G_FILE_ERROR, PV_ERROR_INTERNAL,
				    _("'%s' has changed during the preparation"),
				    in_path);
			fclose(f_in);
			return -1;
		}
		fclose(f_in);
		break;
	}
	default:
		g_assert_not_reached();
	}

	return nep;
}

int64_t pv_component_update_tld(const PvComponent *comp, EVP_MD_CTX *ctx,
				GError **err)
{
	uint64_t size = pv_component_size(comp);
	const union tweak *tweak = &comp->tweak;
	g_autoptr(BIGNUM) tweak_num = NULL;
	int64_t nep = 0;

	g_assert(IS_PAGE_ALIGNED(size) && size != 0);

	tweak_num = BN_bin2bn(tweak->data, sizeof(tweak->data), NULL);
	if (!tweak_num) {
		g_set_error(err, PV_CRYPTO_ERROR,
			    PV_CRYPTO_ERROR_INTERNAL,
			    _("BN_bin2bn failed"));
	}

	for (uint64_t cur = 0; cur < size; cur += PAGE_SIZE) {
		guchar tmp[sizeof(tweak->data)] = { 0 };

		g_assert(BN_num_bytes(tweak_num) >= 0);
		g_assert(sizeof(tmp) - (guint)BN_num_bytes(tweak_num) > 0);

		if (BN_bn2binpad(tweak_num, tmp, sizeof(tmp)) < 0) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("BN_bn2binpad failed"));
		}

		if (EVP_DigestUpdate(ctx, tmp, sizeof(tmp)) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("EVP_DigestUpdate failed"));
			return -1;
		}

		/* calculate new tweak value */
		if (BN_add_word(tweak_num, PAGE_SIZE) != 1) {
			g_set_error(err, PV_CRYPTO_ERROR,
				    PV_CRYPTO_ERROR_INTERNAL,
				    _("BN_add_word failed"));
		}

		nep++;
	}

	return nep;
}

gint pv_component_write(const PvComponent *component, FILE *f, GError **err)
{
	uint64_t offset = pv_component_get_src_addr(component);

	g_assert(f);

	switch (component->d_type) {
	case DATA_BUFFER: {
		const PvBuffer *buf = component->buf;

		if (seek_and_write_buffer(f, buf, offset, err) < 0)
			return -1;

		return 0;
	}
	case DATA_FILE: {
		const CompFile *file = component->file;

		if (seek_and_write_file(f, file, offset, err) < 0)
			return -1;

		return 0;
	}
	}

	g_assert_not_reached();
}
