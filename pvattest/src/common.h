/*
 * Common functions for pvattest.
 *
 *  IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef PVATTEST_COMMON_H
#define PVATTEST_COMMON_H
/* Must be included before any other header */
#include "config.h"

#include <glib/gi18n.h>
#include <stdio.h>

#include "libpv/glib-helper.h"
#include "libpv/macros.h"
#include "lib/zt_common.h"

#include "types.h"

#define COPYRIGHT_NOTICE "Copyright IBM Corp. 2022"

#define AES_256_GCM_TAG_SIZE 16

gboolean wrapped_g_file_set_content(const char *filename, GBytes *bytes, mode_t mode,
				    GError **error);

/**
 * just ref's up if one of them is NULL.
 * If both NULL returns NULL.
 * Otherwise returns lh ++ rh
 */
GBytes *secure_gbytes_concat(GBytes *lh, GBytes *rh);

#endif /* PVATTEST_COMMON_H */
