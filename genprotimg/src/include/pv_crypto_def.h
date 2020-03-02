/*
 * PV cryptography related definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PV_CRYPTO_DEF_H
#define PV_CRYPTO_DEF_H

#include <stdint.h>

#include "lib/zt_common.h"

union ecdh_pub_key {
	struct {
		uint8_t x[80];
		uint8_t y[80];
	};
	uint8_t data[160];
} __packed;

#endif
