/*
 * PV optional item related definitions and functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_OPT_ITEM_H
#define PV_OPT_ITEM_H

#include <stdint.h>

#include "include/pv_hdr_def.h"

uint32_t pv_opt_item_size(const struct pv_hdr_opt_item *item);
void pv_opt_item_free(struct pv_hdr_opt_item *item);

#endif
