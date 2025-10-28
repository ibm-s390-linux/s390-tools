#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <linux/netlink.h>
#include <linux/ethtool_netlink.h>

#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <netlink/attr.h>

#include "lib/util_libc.h"

#include "ethtool.h"

static int ethtool_nl_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[ETHTOOL_A_MODULE_EEPROM_DATA + 1] = {};
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct optics **oi = arg;
	int rc = 0;
	size_t len;

	rc = genlmsg_parse(hdr, 0, attrs, ETHTOOL_A_MODULE_EEPROM_DATA, NULL);
	if (rc) {
		nl_perror(rc, "genlmsg parse");
		return NL_STOP;
	}

	len = nla_len(attrs[ETHTOOL_A_MODULE_EEPROM_DATA]);

	/* Extend optics info*/
	if (!(*oi)->raw)
		(*oi)->raw = util_malloc(len);
	else
		(*oi)->raw = util_realloc((*oi)->raw, (*oi)->size + len);
	memcpy((*oi)->raw + (*oi)->size, nla_data(attrs[ETHTOOL_A_MODULE_EEPROM_DATA]), len);
	(*oi)->size += len;

	return NL_OK;
}

int ethtool_nl_connect(struct ethtool_nl_ctx *ctx)
{
	struct nl_sock *sk;
	int ethtool_id;
	int rc = 0;

	sk = nl_socket_alloc();
	if (!sk) {
		nl_perror(NLE_NOMEM, "alloc");
		return EXIT_FAILURE;
	}

	rc = genl_connect(sk);
	if (rc) {
		nl_perror(rc, "connect");
		rc = EXIT_FAILURE;
		goto err_free;
	}

	ethtool_id = genl_ctrl_resolve(sk, ETHTOOL_GENL_NAME);
	if (ethtool_id < 0) {
		if (ethtool_id == -NLE_OBJ_NOTFOUND)
			fprintf(stderr, "Ethtool netlink family not found\n");
		else
			nl_perror(ethtool_id, "ctrl resolve");
		rc = EXIT_FAILURE;
		goto err_close;
	}
	ctx->sk = sk;
	ctx->ethtool_id = ethtool_id;
	return rc;

err_close:
	nl_close(sk);
err_free:
	nl_socket_free(sk);
	return rc;
}

void ethtool_nl_close(struct ethtool_nl_ctx *ctx)
{
	nl_close(ctx->sk);
	nl_socket_free(ctx->sk);
}

static int ethtool_nl_put_req_hdr(struct ethtool_nl_ctx *ctx, struct nl_msg *msg, uint8_t cmd,
				  const char *netdev)
{
	struct nlattr *opts;
	void *user_hdr;
	int rc = 0;

	user_hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ctx->ethtool_id, 0,
			       NLM_F_REQUEST | NLM_F_ACK, cmd, ETHTOOL_GENL_VERSION);
	if (!user_hdr) {
		fprintf(stderr, "genlmsg put failed\n");
		return EXIT_FAILURE;
	}

	opts = nla_nest_start(msg, ETHTOOL_A_MODULE_EEPROM_HEADER);
	if (!opts) {
		fprintf(stderr, "nla nest for start failed\n");
		return EXIT_FAILURE;
	}

	NLA_PUT_STRING(msg, ETHTOOL_A_HEADER_DEV_NAME, netdev);
	nla_nest_end(msg, opts);
	return rc;

nla_put_failure:
	nla_nest_cancel(msg, opts);
	return EXIT_FAILURE;
}

static int ethtool_nl_put_eeprom_get_attrs(struct nl_msg *msg, uint8_t addr, uint8_t page,
					   uint32_t offset)
{
	NLA_PUT_U32(msg, ETHTOOL_A_MODULE_EEPROM_LENGTH, SFF8636_PAGE_SIZE);
	NLA_PUT_U8(msg, ETHTOOL_A_MODULE_EEPROM_PAGE, page);
	NLA_PUT_U32(msg, ETHTOOL_A_MODULE_EEPROM_OFFSET, offset);
	NLA_PUT_U8(msg, ETHTOOL_A_MODULE_EEPROM_BANK, 0);
	NLA_PUT_U8(msg, ETHTOOL_A_MODULE_EEPROM_I2C_ADDRESS, addr);

	return 0;

nla_put_failure:
	return EXIT_FAILURE;
}

static int ethtool_nl_get_page(struct ethtool_nl_ctx *ctx, const char *netdev, uint8_t addr,
			       uint8_t page, uint32_t offset)
{
	struct nl_msg *msg;
	int rc = 0;

	msg = nlmsg_alloc();
	if (!msg) {
		nl_perror(NLE_NOMEM, "nlmsg alloc");
		return -ENOMEM;
	}
	ethtool_nl_put_req_hdr(ctx, msg, ETHTOOL_MSG_MODULE_EEPROM_GET, netdev);
	ethtool_nl_put_eeprom_get_attrs(msg, addr, page, offset);
	rc = nl_send_auto(ctx->sk, msg);
	if (rc < 0) {
		nl_perror(rc, "Failed to send netlink message");
		rc = -EIO;
		goto free_msg;
	}

	rc = nl_recvmsgs_default(ctx->sk);
	if (rc < 0) {
		if (rc == -NLE_NODEV) {
			rc = -ENODEV;
		} else {
			nl_perror(rc, "Failed to receive netlink message");
			rc = -EIO;
		}
		goto free_msg;
	}

	/* Ethtool netlink sends ACKs need to pick them up */
	rc = nl_wait_for_ack(ctx->sk);
	if (rc < 0) {
		nl_perror(rc, "Failed to wait for netlink ack");
		rc = -EIO;
		goto free_msg;
	}
free_msg:
	nlmsg_free(msg);
	return rc;
}

static int ethtool_nl_get_sfp(struct ethtool_nl_ctx *ctx, const char *netdev, struct optics *oi)
{
	int rc = 0;

	/* Page A0h upper */
	rc = ethtool_nl_get_page(ctx, netdev, SFF8079_I2C_ADDRESS_LOW, 0x0, SFF8636_PAGE_SIZE);
	if (rc < 0)
		return rc;

	/* If page A2h is not present we're done */
	if (!(oi->raw[SFF8472_DIAGNOSTICS_TYPE_OFFSET] & SFF8472_DIAGNOSTICS_TYPE_MASK))
		return 0;

	/* Page A2h lower */
	rc = ethtool_nl_get_page(ctx, netdev, SFF8079_I2C_ADDRESS_HIGH, 0x0, 0);
	if (rc < 0)
		return rc;

	/* Page A2h upper */
	rc = ethtool_nl_get_page(ctx, netdev, SFF8079_I2C_ADDRESS_HIGH, 0x0, SFF8636_PAGE_SIZE);
	if (rc < 0)
		return rc;

	return 0;
}

static int ethtool_nl_get_qsfp(struct ethtool_nl_ctx *ctx, const char *netdev, struct optics *oi)
{
	int rc = 0;

	/* Page 00h upper */
	rc = ethtool_nl_get_page(ctx, netdev, SFF8079_I2C_ADDRESS_LOW, 0x0, SFF8636_PAGE_SIZE);
	if (rc)
		return rc;

	/* Page 01h  */
	if (oi->raw[SFF8636_PAGE_OFFSET] & SFF8636_P01H) {
		/* Page 01h upper only */
		rc = ethtool_nl_get_page(ctx, netdev, SFF8079_I2C_ADDRESS_LOW, 0x1,
					 SFF8636_PAGE_SIZE);
		if (rc < 0)
			return rc;
	}

	/* Page 02h  */
	if (oi->raw[SFF8636_PAGE_OFFSET] & SFF8636_P02H) {
		/* Page 02h upper only */
		rc = ethtool_nl_get_page(ctx, netdev, SFF8079_I2C_ADDRESS_LOW, 0x2,
					 SFF8636_PAGE_SIZE);
		if (rc < 0)
			return rc;
	}

	/* Page 03h is present if flatmem is not set */
	if (!(oi->raw[SFF8636_STATUS_2_OFFSET] & SFF8636_STATUS_FLAT_MEM)) {
		/* Page 03h upper only */
		rc = ethtool_nl_get_page(ctx, netdev, SFF8079_I2C_ADDRESS_LOW, 0x3,
					 SFF8636_PAGE_SIZE);
		if (rc < 0)
			return rc;
	}

	return 0;
}

int ethtool_nl_get_optics(struct ethtool_nl_ctx *ctx, const char *netdev, struct optics **oi)
{
	int rc = 0;
	int type;

	*oi = util_zalloc(sizeof(**oi));
	nl_socket_modify_cb(ctx->sk, NL_CB_VALID, NL_CB_CUSTOM, ethtool_nl_cb, oi);

	/* Page 00h lower */
	rc = ethtool_nl_get_page(ctx, netdev, SFF8079_I2C_ADDRESS_LOW, 0x0, 0);
	if (rc < 0)
		goto out_err_free_oi;

	type = optics_type(*oi);
	switch (type) {
	case OPTICS_TYPE_SFP:
		rc = ethtool_nl_get_sfp(ctx, netdev, *oi);
		break;
	case OPTICS_TYPE_QSFP28:
		rc = ethtool_nl_get_qsfp(ctx, netdev, *oi);
		break;
	};
	if (rc < 0)
		goto out_err_free_oi;

	return rc;

out_err_free_oi:
	free(*oi);
	*oi = NULL;
	return rc;
}
