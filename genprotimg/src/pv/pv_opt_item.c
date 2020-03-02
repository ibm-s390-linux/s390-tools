/*
 * PV optional item related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <glib.h>

#include "pv_opt_item.h"

uint32_t pv_opt_item_size(const struct pv_hdr_opt_item *item G_GNUC_UNUSED)
{
	/* not implemented yet */
	g_assert_not_reached();
}

void pv_opt_item_free(struct pv_hdr_opt_item *item)
{
	if (!item)
		return;

	g_free(item);
}
