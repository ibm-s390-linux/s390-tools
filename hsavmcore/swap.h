/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_SWAP_H
#define _HSAVMCORE_SWAP_H

int swap_on(const char *path);

int swap_off(const char *path);

#endif
