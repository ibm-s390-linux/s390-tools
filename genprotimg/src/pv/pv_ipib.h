/*
 * PV IPIB related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_IPIB_H
#define PV_IPIB_H

#include <glib.h>
#include <stdint.h>

#include "boot/ipl.h"
#include "utils/buffer.h"

typedef struct ipl_parameter_block IplParameterBlock;

uint64_t pv_ipib_get_size(uint32_t num_comp);
IplParameterBlock *pv_ipib_new(GSList *comps, const PvBuffer *hdr, GError **err);
void pv_ipib_free(IplParameterBlock *ipib);

WRAPPED_G_DEFINE_AUTOPTR_CLEANUP_FUNC(IplParameterBlock, pv_ipib_free)

#endif
