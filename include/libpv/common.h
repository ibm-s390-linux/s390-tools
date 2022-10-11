/*
 * Libpv common definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */
#ifndef LIBPV_COMMON_H
#define LIBPV_COMMON_H

/* must be included before any (other) glib header to verify that
 * the glib version is supported
 */
#include "libpv/glib-helper.h"

#include <glib/gi18n.h>

#include "libpv/openssl-compat.h"
#include "libpv/macros.h"

/** pv_init:
 *
 * Must be called before any libpv call.
 */
int pv_init(void);

/** pv_cleanup:
 *
 * Must be called when done with using libpv.
 */
void pv_cleanup(void);

#endif /* LIBPV_COMMON_H */
