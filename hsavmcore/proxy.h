/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_PROXY_H
#define _HSAVMCORE_PROXY_H

#include "hsa.h"

/*
 * A vmcore Proxy combines the original /proc/vmcore file with a HSA memory
 * reader into a new interface which can be used to read vmcore data w/o being
 * aware that the HSA memory region is NOT contained in the file /proc/vmcore.
 *
 * After releasing the HSA memory, the original /proc/vmcore will contain
 * a *hole* where the HSA memory was located. The vmcore proxy hides this
 * inconvenience from the user of this interface.
 */

struct vmcore_proxy;

struct vmcore_proxy *make_vmcore_proxy(const char *vmcore_path,
				       struct hsa_reader *hsa_reader);

void destroy_vmcore_proxy(struct vmcore_proxy *proxy);

long vmcore_proxy_size(struct vmcore_proxy *proxy);

int read_vmcore_proxy_at(struct vmcore_proxy *proxy, long offset, void *buf,
			 int size);

#endif
