/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_OVERLAY_H
#define _HSAVMCORE_OVERLAY_H

#include <stdbool.h>

#include "proxy.h"

/*
 * A vmcore Overlay exports a vmcore Proxy as a normal read-only file
 * that could be used, for instance, by *makedumpfile*.
 */

struct vmcore_overlay;

struct vmcore_overlay *make_vmcore_overlay(struct vmcore_proxy *vmcore_proxy,
					   const char *mount_point,
					   bool fuse_debug);

void destroy_vmcore_overlay(struct vmcore_overlay *overlay);

/*
 * This method handles all file system calls and blocks until a signal arrives.
 */
int serve_vmcore_overlay(struct vmcore_overlay *overlay);

#endif
