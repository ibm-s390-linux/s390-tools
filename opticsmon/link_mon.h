/*
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#pragma once
#include <stdint.h>

#include <linux/if.h>

#include "lib/pci_list.h"

typedef void (*link_mon_nl_cb)(struct zpci_netdev *, void *arg);

struct link_mon_nl_ctx {
	/* private fields */
	struct nl_sock *sk;
	struct nl_cache *cache;
	link_mon_nl_cb cb;
	void *arg;
};

int link_mon_nl_waitfd_create(struct link_mon_nl_ctx *ctx, link_mon_nl_cb cb, void *arg);
void link_mon_nl_waitfd_read(struct link_mon_nl_ctx *ctx);
void link_mon_nl_waitfd_destroy(struct link_mon_nl_ctx *ctx);
int link_mon_nl_waitfd_getfd(struct link_mon_nl_ctx *ctx);
