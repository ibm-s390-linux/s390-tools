/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the CCA host library.
 *
 * Copyright IBM Corp. 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef UTILS_H
#define UTILS_H

#include "lib/zt_common.h"

int sysfs_is_card_online(int card);

int sysfs_is_apqn_online(int card, int domain);

int sysfs_get_serialnr(int card, char serialnr[9], bool verbose);

#endif
