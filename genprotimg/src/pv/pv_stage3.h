/*
 * PV stage3 loader related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_STAGE3_H
#define PV_STAGE3_H

#include <glib.h>
#include <glib/gtypes.h>
#include <stdint.h>

#include "boot/ipl.h"
#include "boot/s390.h"
#include "boot/stage3b.h"
#include "utils/buffer.h"

Buffer *stage3a_getblob(const gchar *filename, gsize *loader_size,
			gsize data_size, GError **err);
gint build_stage3a(Buffer *dc, gsize dc_size, const Buffer *hdr,
		   struct ipl_parameter_block *ipib, GError **err);
Buffer *stage3b_getblob(const gchar *filename, GError **err);
void build_stage3b(Buffer *stage3b, const struct stage3b_args *args);
void memblob_init(struct memblob *arg, uint64_t src, uint64_t size);

#endif
