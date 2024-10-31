#pragma once
#include "optics_info.h"

struct ethtool_nl_ctx {
	struct nl_sock *sk;
	int ethtool_id;
};

int ethtool_nl_connect(struct ethtool_nl_ctx *ctx);
void ethtool_nl_close(struct ethtool_nl_ctx *ctx);
int ethtool_nl_get_optics(struct ethtool_nl_ctx *ctx, const char *netdev, struct optics **oi);
