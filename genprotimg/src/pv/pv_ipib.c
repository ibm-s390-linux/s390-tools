/*
 * PV IPIB related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <glib.h>
#include <glib/gtypes.h>
#include <stdint.h>
#include <stdio.h>

#include "boot/ipl.h"
#include "boot/s390.h"
#include "common.h"
#include "include/pv_hdr_def.h"
#include "lib/zt_common.h"
#include "utils/align.h"
#include "utils/buffer.h"

#include "pv_comp.h"
#include "pv_error.h"
#include "pv_ipib.h"

uint64_t pv_ipib_get_size(uint32_t num_comp)
{
	gsize ipib_size = sizeof(struct ipl_pl_hdr) +
			  sizeof(struct ipl_pb0_pv) +
			  num_comp * sizeof(struct ipl_pb0_pv_comp);

	/* the minimal size is one page */
	return MAX(ipib_size, PAGE_SIZE);
}

static gint pv_ipib_init(IplParameterBlock *ipib, GSList *comps,
			 const PvBuffer *hdr)
{
	g_assert(sizeof(struct ipl_pl_hdr) <= UINT32_MAX);
	g_assert(sizeof(struct ipl_pb0_pv_comp) <= UINT32_MAX);
	g_assert(sizeof(struct ipl_pb0_pv) <= UINT32_MAX);
	g_assert(ipib);

	guint comps_length = g_slist_length(comps);
	uint32_t ipl_pl_hdr_size = (uint32_t)sizeof(struct ipl_pl_hdr);
	struct ipl_pb0_pv *pv = &ipib->pv;
	uint32_t ipib_comps_size;
	uint32_t blk0_len;
	uint32_t ipib_size;
	gsize i;

	g_assert_true(
		g_uint_checked_mul(&ipib_comps_size, comps_length,
				   (uint32_t)sizeof(struct ipl_pb0_pv_comp)));
	g_assert_true(g_uint_checked_add(&blk0_len, (uint32_t)sizeof(*pv),
					 ipib_comps_size));
	g_assert(ipl_pl_hdr_size + blk0_len <= PAGE_SIZE);

	ipib_size = MAX(ipl_pl_hdr_size + blk0_len, (uint32_t)PAGE_SIZE);
	g_assert(pv_ipib_get_size(comps_length) == ipib_size);

	pv->pbt = IPL_TYPE_PV;
	pv->len = GUINT32_TO_BE(blk0_len);
	pv->num_comp = GUINT32_TO_BE(comps_length);
	/* both values will be overwritten during the IPL process by
	 * the stage3a loader
	 */
	pv->pv_hdr_addr = GUINT64_TO_BE(0x0);
	pv->pv_hdr_size = GUINT64_TO_BE(hdr->size);

	ipib->hdr.len = GUINT32_TO_BE(ipib_size);
	ipib->hdr.version = IPL_PARM_BLOCK_VERSION;

	i = 0;
	for (GSList *iterator = comps; iterator; iterator = iterator->next, i++) {
		const PvComponent *comp = iterator->data;
		uint64_t comp_addr, comp_size;

		g_assert(comp);

		comp_addr = pv_component_get_src_addr(comp);
		comp_size = pv_component_size(comp);

		g_assert(IS_PAGE_ALIGNED(comp_size));

		pv->components[i].addr = GUINT64_TO_BE(comp_addr);
		pv->components[i].len = GUINT64_TO_BE(comp_size);
		pv->components[i].tweak_pref =
			GUINT64_TO_BE(pv_component_get_tweak_prefix(comp));
		if (i > 0) {
			/* tweak prefixes of the components must grow
			 * strictly monotonous
			 */
			g_assert(GUINT64_FROM_BE(pv->components[i].tweak_pref) >
				 GUINT64_FROM_BE(pv->components[i - 1].tweak_pref));
		}
	}

	return 0;
}

IplParameterBlock *pv_ipib_new(GSList *comps, const PvBuffer *hdr, GError **err)
{
	uint64_t ipib_size = pv_ipib_get_size(g_slist_length(comps));
	g_autoptr(IplParameterBlock) ret = NULL;

	if (ipib_size > PV_V1_IPIB_MAX_SIZE) {
		g_set_error(err, PV_ERROR, PV_ERROR_IPIB_SIZE,
			    _("IPIB size is too large: %lu < %lu"), ipib_size,
			    PAGE_SIZE);
		return NULL;
	}

	ret = g_malloc0(ipib_size);
	if (pv_ipib_init(ret, comps, hdr) < 0)
		return NULL;

	return g_steal_pointer(&ret);
}

void pv_ipib_free(IplParameterBlock *ipib)
{
	if (!ipib)
		return;

	g_free(ipib);
}
