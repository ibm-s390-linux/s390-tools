/*
 * Libpv common macro definitions.
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */
#ifndef LIBPV_MACROS_H
#define LIBPV_MACROS_H

#include <stdint.h>

#define PV_NONNULL(...)
#define DO_PRAGMA(x) _Pragma(#x)

/* Most significant bit */
#define PV_MSB(idx) ((uint64_t)1 << (63 - (idx)))

#endif /* LIBPV_MACROS_H */
