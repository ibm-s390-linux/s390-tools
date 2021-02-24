/*
 * PV stage3 loader related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <glib.h>
#include <stdint.h>
#include <string.h>

#include "boot/ipl.h"
#include "boot/stage3a.h"
#include "boot/stage3b.h"
#include "common.h"
#include "utils/align.h"

#include "pv_error.h"
#include "pv_stage3.h"

#define STAGE3A_ARGS(data_ptr, loader_size)                         \
	((struct stage3a_args *)((uint64_t)data_ptr + loader_size - \
				 sizeof(struct stage3a_args)))

static PvBuffer *loader_getblob(const gchar *filename, gsize *loader_size,
				gsize args_size, gsize data_size,
				gboolean data_aligned, GError **err)
{
	g_autoptr(GMappedFile) mapped_file = NULL;
	g_autoptr(PvBuffer) ret = NULL;
	gsize size, tmp_loader_size;
	gchar *loader_data;

	g_assert(loader_size);

	mapped_file = g_mapped_file_new(filename, FALSE, err);
	if (!mapped_file)
		return NULL;

	loader_data = g_mapped_file_get_contents(mapped_file);
	if (!loader_data) {
		g_set_error(err, G_FILE_ERROR, G_FILE_ERROR_BADF,
			    _("File '%s' is empty"), filename);
		return NULL;
	}
	tmp_loader_size = g_mapped_file_get_length(mapped_file);

	if (tmp_loader_size < args_size) {
		g_set_error(err, G_FILE_ERROR, G_FILE_ERROR_BADF,
			    _("File size less than expected: %lu < %ln"),
			    tmp_loader_size, loader_size);
		return NULL;
	}

	/* For example, the PV header and IPIB data must be page
	 * aligned.
	 */
	size = (data_aligned ? PAGE_ALIGN(tmp_loader_size) : tmp_loader_size) +
	       data_size;

	ret = pv_buffer_alloc(size);

	/* copy the loader "template" */
	memcpy(ret->data, loader_data, tmp_loader_size);
	/* reset our dummy data (offsets and length) to zeros */
	memset((uint8_t *)ret->data + tmp_loader_size - args_size, 0,
	       args_size);
	*loader_size = tmp_loader_size;
	return g_steal_pointer(&ret);
}

PvBuffer *stage3a_getblob(const gchar *filename, gsize *loader_size,
			  gsize data_size, GError **err)
{
	return loader_getblob(filename, loader_size,
			      sizeof(struct stage3a_args), data_size, TRUE,
			      err);
}

/* For the memory layout see stage3a.lds */
/* Set the right offsets and sizes in the stage3a template + add
 * the IPIB block with the PV header
 */
static gint stage3a_set_data(PvBuffer *loader, gsize loader_size,
			     const PvBuffer *hdr, struct ipl_parameter_block *ipib,
			     GError **err)
{
	uint32_t ipib_size = GUINT32_FROM_BE(ipib->hdr.len);
	gsize args_size = sizeof(struct stage3a_args);
	uint32_t hdr_size = (uint32_t)hdr->size;
	uint64_t args_addr, next_data_addr;

	if (hdr->size > UINT32_MAX) {
		g_set_error(err, PV_ERROR, PV_ERROR_INTERNAL,
			    _("Invalid header size: %zu"), hdr->size);
		return -1;
	}

	/* we assume here that the loader ``stage3a`` is loaded page
	 * aligned in the guest
	 */
	args_addr = (uint64_t)loader->data + loader_size - args_size;

	/* therefore `next_data_addr` is also page aligned */
	next_data_addr = (uint64_t)loader->data + PAGE_ALIGN(loader_size);

	/* copy IPIB data */
	memcpy((void *)next_data_addr, ipib, ipib_size);

	/* set IPIB offset in relation to the stage3a arguments */
	STAGE3A_ARGS(loader->data, loader_size)->ipib_offs =
		GUINT64_TO_BE(next_data_addr - args_addr);

	next_data_addr = next_data_addr + PAGE_ALIGN(ipib_size);
	/* copy PV header */
	memcpy((void *)next_data_addr, hdr->data, hdr_size);
	/* set PV header size and offset in relation to the stage3a
	 * arguments
	 */
	STAGE3A_ARGS(loader->data, loader_size)->hdr_offs =
		GUINT64_TO_BE(next_data_addr - args_addr);
	STAGE3A_ARGS(loader->data, loader_size)->hdr_size = GUINT64_TO_BE(hdr_size);

	return 0;
}

gint build_stage3a(PvBuffer *loader, gsize loader_size, const PvBuffer *hdr,
		   struct ipl_parameter_block *ipib, GError **err)
{
	return stage3a_set_data(loader, loader_size, hdr, ipib, err);
}

PvBuffer *stage3b_getblob(const gchar *filename, GError **err)
{
	g_autoptr(PvBuffer) ret = NULL;
	gsize rb_size;

	ret = loader_getblob(filename, &rb_size, sizeof(struct stage3b_args), 0,
			     FALSE, err);
	if (!ret)
		return NULL;

	g_assert(ret->size == rb_size);
	return g_steal_pointer(&ret);
}

void build_stage3b(PvBuffer *stage3b, const struct stage3b_args *args)
{
	g_assert(stage3b->size > sizeof(*args));

	/* at the end of the stage3b there are the stage3b args
	 * positioned
	 */
	memcpy((uint8_t *)stage3b->data + stage3b->size - sizeof(*args), args,
	       sizeof(*args));
}

void memblob_init(struct memblob *arg, uint64_t src, uint64_t size)
{
	arg->src = GUINT64_TO_BE(src);
	arg->size = GUINT64_TO_BE(size);
}
