/*
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <linux/if.h>

#include <netlink/route/link.h>
#include <netlink/netlink.h>

#include "link_mon.h"

#define MAX_EVENTS 32

static void nl_obj_parsed_cb(struct nl_object *obj, void *arg)
{
	struct link_mon_nl_ctx *ctx = arg;
	struct rtnl_link *link;
	struct zpci_netdev netdev;

	if (strcmp(nl_object_get_type(obj), "route/link") != 0)
		return;
	link = (struct rtnl_link *)obj;
	netdev.name = rtnl_link_get_name(link);
	netdev.operstate = rtnl_link_get_operstate(link);
	ctx->cb(&netdev, ctx->arg);
}

static int nl_rtnl_lnkgrp_cb(struct nl_msg *msg, void *arg)
{
	if (nl_msg_parse(msg, &nl_obj_parsed_cb, arg) < 0)
		fprintf(stderr, "<<EVENT>> Unknown message type\n");
	return NL_STOP;
}

void link_mon_nl_waitfd_read(struct link_mon_nl_ctx *ctx)
{
	nl_recvmsgs_default(ctx->sk);
}

int link_mon_nl_waitfd_getfd(struct link_mon_nl_ctx *ctx)
{
	return nl_socket_get_fd(ctx->sk);
}

int link_mon_nl_waitfd_create(struct link_mon_nl_ctx *ctx, link_mon_nl_cb cb, void *arg)
{
	int ret = 0, rc = 0;

	ctx->sk = nl_socket_alloc();
	if (!ctx->sk)
		return -ENOMEM;
	ctx->cb = cb;
	ctx->arg = arg;
	nl_socket_disable_seq_check(ctx->sk);
	nl_socket_modify_cb(ctx->sk, NL_CB_VALID, NL_CB_CUSTOM, nl_rtnl_lnkgrp_cb, ctx);

	rc = nl_connect(ctx->sk, NETLINK_ROUTE);
	if (rc < 0) {
		ret = rc;
		goto err_free;
	}

	rc = nl_socket_add_membership(ctx->sk, RTNLGRP_LINK);
	if (rc < 0) {
		ret = rc;
		goto err_close;
	}

	rc = rtnl_link_alloc_cache(ctx->sk, AF_UNSPEC, &ctx->cache);
	if (rc < 0) {
		ret = rc;
		goto err_close;
	}
	nl_cache_mngt_provide(ctx->cache);
	return 0;

err_close:
	nl_close(ctx->sk);
err_free:
	nl_socket_free(ctx->sk);
	return ret;
}

void link_mon_nl_waitfd_destroy(struct link_mon_nl_ctx *ctx)
{
	nl_cache_free(ctx->cache);
	nl_close(ctx->sk);
	nl_socket_free(ctx->sk);
}
