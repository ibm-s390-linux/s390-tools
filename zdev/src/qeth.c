/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>

#include "attrib.h"
#include "ccw.h"
#include "ccwgroup.h"
#include "device.h"
#include "devtype.h"
#include "internal.h"
#include "misc.h"
#include "namespace.h"
#include "nic.h"
#include "qeth.h"
#include "qeth_auto.h"
#include "setting.h"
#include "udev_ccwgroup.h"

#define DEVNAME			"QETH device"

/*
 * QETH device ID namespace methods.
 */
static exit_code_t qeth_parse_devid(struct ccwgroup_devid *devid_ptr,
				    const char *id, err_t err)
{
	struct ccwgroup_devid devid;
	const char *reason = NULL;
	exit_code_t rc;

	rc = ccwgroup_parse_devid(&devid, id, err);
	if (rc)
		return rc;

	if (devid.num > 1 && devid.num < QETH_NUM_DEVS) {
		reason = "Not enough CCW device IDs specified";
		rc = EXIT_INVALID_ID;
	} else if (devid.num > QETH_NUM_DEVS) {
		reason = "Too many CCW device IDs specified";
		rc = EXIT_INVALID_ID;
	} else if (devid_ptr)
		*devid_ptr = devid;

	if (reason) {
		err_t_print(err, "Error in %s ID format: %s: %s\n", DEVNAME,
			    reason, id);
	}

	return rc;
}

static exit_code_t qeth_parse_devid_range(struct ccwgroup_devid *from_ptr,
					  struct ccwgroup_devid *to_ptr,
					  const char *range, err_t err)
{
	char *from_str, *to_str;
	struct ccwgroup_devid from, to;
	exit_code_t rc;
	const char *reason = NULL;

	/* Split range. */
	from_str = misc_strdup(range);
	to_str = strchr(from_str, '-');
	if (!to_str) {
		rc = EXIT_INVALID_ID;
		reason = "Missing hyphen";
		goto out;
	}
	*to_str = 0;
	to_str++;

	/* Parse range start and end ID. */
	rc = qeth_parse_devid(&from, from_str, err);
	if (rc)
		goto out;

	rc = qeth_parse_devid(&to, to_str, err);
	if (rc)
		goto out;

	/* Only allow ranges on CCWGROUP devices specified as single ID. */
	if (from.num != 1 || to.num != 1) {
		rc = EXIT_INVALID_ID;
		reason = "Ranges only supported on single CCW device IDs";
		goto out;
	}

	rc = EXIT_OK;
	if (from_ptr)
		*from_ptr = from;
	if (to_ptr)
		*to_ptr = to;

out:
	free(from_str);

	if (reason) {
		err_t_print(err, "Error in %s ID range format: %s: %s\n",
			    DEVNAME, reason, range);
	}

	return rc;
}

static bool qeth_parse_devid_range_simple(struct ccwgroup_devid *from,
					  struct ccwgroup_devid *to,
					  const char *range)
{
	if (qeth_parse_devid_range(from, to, range, err_ignore) == EXIT_OK)
		return true;

	return false;
}

static exit_code_t qeth_ns_is_id_valid(const char *id, err_t err)
{
	return qeth_parse_devid(NULL, id, err);
}

static char *qeth_ns_normalize_id(const char *id)
{
	struct ccwgroup_devid devid;

	if (qeth_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return NULL;

	return ccwgroup_devid_to_str(&devid);
}

static void *qeth_ns_parse_id(const char *id, err_t err)
{
	struct ccwgroup_devid *devid;

	devid = misc_malloc(sizeof(struct ccwgroup_devid));
	if (qeth_parse_devid(devid, id, err) != EXIT_OK) {
		free(devid);
		return NULL;
	}

	return devid;
}

static exit_code_t qeth_ns_is_id_range_valid(const char *range, err_t err)
{
	return qeth_parse_devid_range(NULL, NULL, range, err);
}

static unsigned long qeth_ns_num_ids_in_range(const char *range)
{
	struct ccwgroup_devid f, t;

	if (!qeth_parse_devid_range_simple(&f, &t, range))
		return 0;

	if (f.devid[0].cssid != t.devid[0].cssid ||
	    f.devid[0].ssid != t.devid[0].ssid)
		return 0;

	if (f.devid[0].devno > t.devid[0].devno)
		return 0;

	return t.devid[0].devno - f.devid[0].devno + 1;
}

static void qeth_ns_range_start(struct ns_range_iterator *it, const char *range)
{
	struct ccwgroup_devid from, to;

	if (!qeth_parse_devid_range_simple(&from, &to, range)) {
		memset(it, 0, sizeof(struct ns_range_iterator));
		return;
	}

	it->devid = ccwgroup_copy_devid(&from);
	it->devid_last = ccwgroup_copy_devid(&to);
	it->id = ccwgroup_devid_to_str(it->devid);
}

static bool qeth_ns_is_id_blacklisted(const char *id)
{
	struct ccwgroup_devid devid;
	char *ccw_id;
	unsigned int i;
	bool result = false;

	if (qeth_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return false;
	for (i = 0; i < devid.num; i++) {
		ccw_id = ccw_devid_to_str(&devid.devid[i]);
		result = ccw_is_id_blacklisted(ccw_id);
		free(ccw_id);
		if (result)
			break;
	}

	return result;
}

static void qeth_ns_unblacklist_id(const char *id)
{
	struct ccwgroup_devid devid;
	char *ccw_id;
	unsigned int i;

	if (qeth_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return;
	for (i = 0; i < devid.num; i++) {
		ccw_id = ccw_devid_to_str(&devid.devid[i]);
		if (ccw_is_id_blacklisted(ccw_id))
			ccw_unblacklist_id(ccw_id);
		free(ccw_id);
	}
}

/*
 * QETH device ID namespace.
 */

struct namespace qeth_namespace = {
	.devname		= DEVNAME,
	.is_id_valid		= qeth_ns_is_id_valid,
	.is_id_similar		= ccwgroup_is_id_similar,
	.cmp_ids		= ccwgroup_cmp_ids,
	.normalize_id		= qeth_ns_normalize_id,
	.parse_id		= qeth_ns_parse_id,
	.cmp_parsed_ids		= ccwgroup_cmp_parsed_ids,
	.qsort_cmp		= ccwgroup_qsort_cmp,
	.is_id_range_valid	= qeth_ns_is_id_range_valid,
	.num_ids_in_range	= qeth_ns_num_ids_in_range,
	.is_id_in_range		= ccwgroup_is_id_in_range,
	.range_start		= qeth_ns_range_start,
	.range_next		= ccwgroup_range_next,

	/* Blacklist handling. */
	.is_blacklist_active	= ccw_is_blacklist_active,
	.is_id_blacklisted	= qeth_ns_is_id_blacklisted,
	.is_id_range_blacklisted = ccw_is_id_range_blacklisted,
	.unblacklist_id		= qeth_ns_unblacklist_id,
	.unblacklist_id_range	= ccw_unblacklist_id_range,
	.blacklist_persist	= ccw_blacklist_persist,
};


/*
 * QETH specific attribute data.
 */

struct qeth_attrib_data {
	enum qeth_layer_type {
		layer_any,
		layer_2,
		layer_3
	} layer_type;
	enum qeth_attr_group_type {
		group_none,
		group_bridge,
		group_vnicc
	} attr_group;
};

#define QETH_DATA(layer, group)			\
	((struct qeth_attrib_data []) { {	\
		.layer_type = layer,		\
		.attr_group = group,		\
		} })

/*
 * QETH device attributes.
 */

static struct attrib qeth_attr_layer2 = {
	.name = "layer2",
	.title = "Configure layer discipline",
	.desc =
	"Control layer mode for a QETH device:\n"
	"  0: Device works in layer 3 mode\n"
	"  1: Device works in layer 2 mode\n"
	" -1: Driver attempts autodetection (read-only value)\n",
	.defval = "-1",
	.order_cmp = ccw_offline_only_order_cmp,
	.check = ccw_offline_only_check,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(-1, 1)),
};

/* Use this function as order_cmp for attributes that should be set after
 * 'layer2' and before 'online=1'.
 * */
static int after_layer2_order_cmp(struct setting *a, struct setting *b)
{
	if (b->attrib == &qeth_attr_layer2)
		return 1;

	return ccw_offline_only_order_cmp(a, b);
}

static struct attrib qeth_attr_portname = {
	.name = "portname",
	.title = "Configure port name",
	.desc =
	"Specify a 1-8 character name used to identify the port associated\n"
	"with a QETH device.\n",
	.defval = "",
	.order_cmp = ccw_offline_only_order_cmp,
	.check = ccw_offline_only_check,
	.map = VALUE_MAP_ARRAY(VALUE_MAP("no portname required", "")),
	.st_data = QETH_DATA(layer_any, group_none),
};

static struct attrib qeth_attr_priority_queueing = {
	.name = "priority_queueing",
	.title = "Configure priority queues for outgoing packets",
	.desc =
	"Specify the method used to assign priority queues to outgoing\n"
	"packets on a QETH device if more than 1 outbound queue is offered:\n"
	"  prio_queueing_vlan: Queue based on VLAN priority code point\n"
	"  prio_queueing_skb:  Queue based on socket buffer priority flag\n"
	"  prio_queueing_prec: Queue based on IP precedence field\n"
	"  no_prio_queueing:   Use queue 2 for all packets\n"
	"  no_prio_queueing:0: Use queue 0 for all packets\n"
	"  no_prio_queueing:1: Use queue 1 for all packets\n"
	"  no_prio_queueing:2: Use queue 2 for all packets\n"
	"  no_prio_queueing:3: Use queue 3 for all packets\n",
	.defval = "no_prio_queueing",
	.order_cmp = ccw_offline_only_order_cmp,
	.check = ccw_offline_only_check,
	.accept = ACCEPT_ARRAY(
		ACCEPT_STR("prio_queueing_vlan"),
		ACCEPT_STR("prio_queueing_skb"),
		ACCEPT_STR("prio_queueing_prec"),
		ACCEPT_STR("no_prio_queueing"),
		ACCEPT_STR("no_prio_queueing:0"),
		ACCEPT_STR("no_prio_queueing:1"),
		ACCEPT_STR("no_prio_queueing:2"),
		ACCEPT_STR("no_prio_queueing:3")
	),
	.unstable = 1,
	.st_data = QETH_DATA(layer_any, group_none),
};

static struct attrib qeth_attr_buffer_count = {
	.name = "buffer_count",
	.title = "Set number of buffers used for incoming packets",
	.desc =
	"Specify the number of buffers used for incoming packets on a QETH\n"
	"device. The size of each buffer is determined by the value of\n"
	"attribute inbuf_size.\n",
	.order_cmp = ccw_offline_only_order_cmp,
	.check = ccw_offline_only_check,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(8, 128)),
	.st_data = QETH_DATA(layer_any, group_none),
};

static struct attrib qeth_attr_portno = {
	.name = "portno",
	.title = "Specify the network adapter port",
	.desc =
	"Specify the network adapter port number to use.\n",
	.defval = "0",
	.order_cmp = ccw_offline_only_order_cmp,
	.check = ccw_offline_only_check,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_any, group_none),
};

static struct attrib qeth_attr_hsuid = {
	.name = "hsuid",
	.title = "HiperSockets IUCV identifier",
	.desc =
	"Specify a 1-8 character identifier used to identify a HiperSockets\n"
	"QETH device in the AF_IUCV addressing family support.\n",
	.defval = "",
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_recover = {
	.name = "recover",
	.title = "Trigger device recovery",
	.desc =
	"Write '1' to this attribute to restart the recovery process for the\n"
	"QETH device.\n",
	/* The following is not a strict requirement but helps prevent a
	 * situation where a QETH device is configured but layer2 was not
	 * set from auto-detected values. */
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_NUM(1)),
	.writeonly = 1,
	.activeonly = 1,
	.st_data = QETH_DATA(layer_any, group_none),
};

static struct attrib qeth_attr_isolation = {
	.name = "isolation",
	.title = "Specify isolation mode",
	.desc =
	"Specify how packets transmitted between operating system instances\n"
	"sharing an OSA port are handled:\n"
	"  none:    Packets are transmitted as normal\n"
	"  drop:    Drop packets to or from other users of the same OSA port\n"
	"  forward: All packets are forwarded to an adjacent switch\n",
	.defval = "none",
	.accept = ACCEPT_ARRAY(ACCEPT_STR("none"), ACCEPT_STR("drop"),
			       ACCEPT_STR("forward")),
	.st_data = QETH_DATA(layer_any, group_none),
};

static struct attrib qeth_attr_performance_stats = {
	.name = "performance_stats",
	.title = "Control performance statistics collection",
	.desc =
	"Control the collection of QETH performance statistics data:\n"
	"  0: Performance statistics data is not collected\n"
	"  1: Performance statistics data is collected\n",
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_any, group_none),
};

static struct attrib qeth_attr_hw_trap = {
	.name = "hw_trap",
	.title = "Control hardware traces",
	.desc =
	"Control the capturing of hardware traces\n"
	"  disarm: Hardware tracing is disabled\n"
	"  arm:    Hardware traces are captured automatically if there are\n"
	"          errors\n"
	"  trap:   Hardware traces are captured immediately\n",
	.defval = "disarm",
	.accept = ACCEPT_ARRAY(ACCEPT_STR("disarm"), ACCEPT_STR("arm"),
			       ACCEPT_STR("trap")),
	.st_data = QETH_DATA(layer_any, group_none),
};

static struct attrib qeth_attr_route4 = {
	.name = "route4",
	.title = "Configure QETH device as IPV4 router",
	.desc =
	"Configure a QETH device as an IPv4 router:\n"
	"  no_router:           Disable router functionality\n"
	"  multicast_router:    Receive all multicast packets\n"
	"  primary_router:      Act as primary router between networks (OSA)\n"
	"  secondary_router:    Act as backup router between networks (OSA)\n"
	"  primary_connector:   Act as primary router between HiperSockets\n"
	"                       and an external network\n"
	"  secondary_connector: Act as backup router between HiperSockets and\n"
	"                       an external network\n",
	.defval = "no_router",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_STR("no_router"),
			       ACCEPT_STR("multicast_router"),
			       ACCEPT_STR("primary_router"),
			       ACCEPT_STR("secondary_router"),
			       ACCEPT_STR("primary_connector"),
			       ACCEPT_STR("secondary_connector")),
	.map = VALUE_MAP_ARRAY(
			VALUE_MAP("no", "no_router"),
			VALUE_MAP("primary router", "primary_router"),
			VALUE_MAP("secondary router", "secondary_router"),
			VALUE_MAP("multicast router+", "multicast_router"),
			VALUE_MAP("multicast router", "multicast_router"),
			VALUE_MAP("primary connector+", "primary_connector"),
			VALUE_MAP("primary connector", "primary_connector"),
			VALUE_MAP("secondary connector+",
				  "secondary_connector"),
			VALUE_MAP("secondary connector",
				   "secondary_connector")),
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_route6 = {
	.name = "route6",
	.title = "Configure QETH device as IPV6 router",
	.desc =
	"Configure a QETH device as an IPv6 router:\n"
	"  no_router:           Disable router functionality\n"
	"  multicast_router:    Receive all multicast packets\n"
	"  primary_router:      Act as primary router between networks (OSA)\n"
	"  secondary_router:    Act as backup router between networks (OSA)\n"
	"  primary_connector:   Act as primary router between HiperSockets\n"
	"                       and an external network\n"
	"  secondary_connector: Act as backup router between HiperSockets and\n"
	"                       an external network\n",
	.defval = "no_router",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_STR("no_router"),
			       ACCEPT_STR("multicast_router"),
			       ACCEPT_STR("primary_router"),
			       ACCEPT_STR("secondary_router"),
			       ACCEPT_STR("primary_connector"),
			       ACCEPT_STR("secondary_connector")),
	.map = VALUE_MAP_ARRAY(
			VALUE_MAP("no", "no_router"),
			VALUE_MAP("primary router", "primary_router"),
			VALUE_MAP("secondary router", "secondary_router"),
			VALUE_MAP("multicast router+", "multicast_router"),
			VALUE_MAP("multicast router", "multicast_router"),
			VALUE_MAP("primary connector+", "primary_connector"),
			VALUE_MAP("primary connector", "primary_connector"),
			VALUE_MAP("secondary connector+",
				  "secondary_connector"),
			VALUE_MAP("secondary connector",
				   "secondary_connector")),
	.unstable = 1,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_ipa_takeover_enable = {
	.name = "ipa_takeover/enable",
	.title = "Control IP address takeover",
	.desc =
	"Control whether a QETH device can take over the IP address of\n"
	"another QETH device on the same CHPID.\n"
	"  0: Disable IP address takeover\n"
	"  1: Enable IP address takeover\n",
	.defval = "0",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_ipa_takeover_add4 = {
	.name = "ipa_takeover/add4",
	.title = "Add IPv4 address to takeover list",
	.desc =
	"Write an IPv4 address range to this attribute to add it to the list\n"
	"of address ranges defined for IP address takeover. The address range\n"
	"should be specified in the following format:\n"
	"<ip_address>/<mask_bits>\n",
	.defval = "",
	.multi = 1,
	.activerem = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_ipa_takeover_add6 = {
	.name = "ipa_takeover/add6",
	.title = "Add IPv6 address to takeover list",
	.desc =
	"Write an IPv6 address range to this attribute to add it to the list\n"
	"of address ranges defined for IP address takeover. The address range\n"
	"should be specified in the following format:\n"
	"<ip_address>/<mask_bits>\n",
	.defval = "",
	.multi = 1,
	.activerem = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_ipa_takeover_del4 = {
	.name = "ipa_takeover/del4",
	.title = "Remove an IPv4 address from takeover list",
	.desc =
	"Remove an IPv4 address range previously registered for takeover by\n"
	"writing it in the following format to this attribute:\n"
	"<ip_address>/<mask_bits>\n",
	.rewrite = 1,
	.writeonly = 1,
	.activeonly = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_ipa_takeover_del6 = {
	.name = "ipa_takeover/del6",
	.title = "Remove an IPv6 address from takeover list",
	.desc =
	"Remove an IPv6 address range previously registered for takeover by\n"
	"writing it in the following format to this attribute:\n"
	"<ip_address>/<mask_bits>\n",
	.writeonly = 1,
	.activeonly = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_ipa_takeover_invert4 = {
	.name = "ipa_takeover/invert4",
	.title = "Control IPv4 takeover address list meaning",
	.desc =
	"Control the meaning of the IPv4 address range list maintained by\n"
	"attribute ipa_takeover/add4:\n"
	"  0: Addresses on the list are enabled for takeover\n"
	"  1: All addresses except those on the list are enabled for\n"
	"     takeover\n",
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_ipa_takeover_invert6 = {
	.name = "ipa_takeover/invert6",
	.title = "Control IPv6 takeover address list meaning",
	.desc =
	"Control the meaning of the IPv6 address range list maintained by\n"
	"attribute ipa_takeover/add6:\n"
	"  0: Addresses on the list are enabled for takeover\n"
	"  1: All addresses except those on the list are enabled for\n"
	"     takeover\n",
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_rxip_add4 = {
	.name = "rxip/add4",
	.title = "Add IPv4 address to ARP proxy list",
	.desc =
	"Write an IPv4 address to this attribute to add it to the list of\n"
	"addresses for which this QETH device should act as ARP proxy.\n",
	.defval = "",
	.multi = 1,
	.activerem = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_rxip_add6 = {
	.name = "rxip/add6",
	.title = "Add IPv6 address to NDP proxy list",
	.desc =
	"Write an IPv6 address to this attribute to add it to the list of\n"
	"addresses for which this QETH device should act as NDP proxy.\n",
	.defval = "",
	.multi = 1,
	.activerem = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_rxip_del4 = {
	.name = "rxip/del4",
	.title = "Remove IPv4 address from ARP proxy list",
	.desc =
	"Write an IPv4 address to this attribute to remove it from the list\n"
	"of addresses for which this QETH device acts as an ARP proxy.\n",
	.writeonly = 1,
	.activeonly = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_rxip_del6 = {
	.name = "rxip/del6",
	.title = "Remove IPv6 address from NDP proxy list",
	.desc =
	"Write an IPv6 address to this attribute to remove it from the list\n"
	"of addresses for which this QETH device acts as an NDP proxy.\n",
	.writeonly = 1,
	.activeonly = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_sniffer = {
	.name = "sniffer",
	.title = "Configure HiperSockets LAN sniffer",
	.desc =
	"Configure a QETH HiperSockets device as a HiperSockets LAN sniffer:\n"
	"  0: Disable LAN sniffer mode\n"
	"  1: Enable LAN sniffer mode\n",
	.defval = "0",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_vipa_add4 = {
	.name = "vipa/add4",
	.title = "Add IPv4 address to virtual IP address list",
	.desc =
	"Write an IPv4 address to this attribute to add it to the list of\n"
	"virtual IP addresses for which this QETH device accepts packets.\n",
	.defval = "",
	.multi = 1,
	.activerem = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_vipa_add6 = {
	.name = "vipa/add6",
	.title = "Add IPv6 address to virtual IP address list",
	.desc =
	"Write an IPv6 address to this attribute to add it to the list of\n"
	"virtual IP addresses for which this QETH device accepts packets.\n",
	.defval = "",
	.multi = 1,
	.activerem = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_vipa_del4 = {
	.name = "vipa/del4",
	.title = "Remove IPv4 address from virtual IP address list",
	.desc =
	"Write an IPv4 address to this attribute to remove it from the list\n"
	"of virtual IP addresses for which this QETH device accepts packets.\n",
	.writeonly = 1,
	.activeonly = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_vipa_del6 = {
	.name = "vipa/del6",
	.title = "Remove IPv6 address from virtual IP address list",
	.desc =
	"Write an IPv6 address to this attribute to remove it from the list\n"
	"of virtual IP addresses for which this QETH device accepts packets.\n",
	.writeonly = 1,
	.activeonly = 1,
	.order_cmp = after_layer2_order_cmp,
	.st_data = QETH_DATA(layer_3, group_none),
};

static struct attrib qeth_attr_bridge_role = {
	.name = "bridge_role",
	.title = "Control bridge role of QETH device port",
	.desc =
	"Configure a QETH device as a bridge port:\n"
	"  primary:   The device acts as the primary bridge port\n"
	"  secondary: The device acts as a secondary bridge port\n"
	"  none:      The device has no bridge port role\n"
	"  n/a (VNIC characteristics):\n"
	"             The device is configured with VNIC characteristics\n"
	"             and cannot have a bridge role (read-only)\n",
	.defval = "none",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_STR("primary"),
			       ACCEPT_STR("secondary"),
			       ACCEPT_STR("none")),
	.st_data = QETH_DATA(layer_2, group_bridge),
};

static struct attrib qeth_attr_bridge_hostnotify = {
	.name = "bridge_hostnotify",
	.title = "Control generation of host connection events",
	.desc =
	"Control whether host connection and disconnection events are\n"
	"reported through kernel uevents:\n"
	"  0: Notifications are disabled\n"
	"  1: Notifications are enabled\n"
	"  n/a (VNIC characteristics):\n"
	"     The device is configured with VNIC characteristics\n"
	"     and cannot have a bridge role (read-only)\n",
	.defval = "0",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_2, group_bridge),
};

static struct attrib qeth_attr_bridge_reflect_promisc = {
	.name = "bridge_reflect_promisc",
	.title = "Control automatic setting of bridge port role",
	.desc =
	"Control how the bridge port role of the QETH device should be\n"
	"changed when promiscuous mode is enabled on the associated\n"
	"networking device:\n"
	"  none:      No change is made\n"
	"  primary:   Attempt to configure the device as the primary bridge\n"
	"             port\n"
	"  secondary: Attempt to configure the device as a secondary bridge\n"
	"             port\n"
	"  n/a (VNIC characteristics):\n"
	"             The device is configured with VNIC characteristics\n"
	"             and cannot have a bridge role (read-only)\n",
	.defval = "none",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_STR("primary"),
			       ACCEPT_STR("secondary"),
			       ACCEPT_STR("none")),
	.st_data = QETH_DATA(layer_2, group_bridge),
};

static struct attrib qeth_attr_vnicc_flooding = {
	.name = "vnicc/flooding",
	.title = "Control setting of VNICC flooding",
	.desc =
	"Control and show the VNIC characteristic flooding\n"
	"on the networking device:\n"
	"  0:   Flooding disabled\n"
	"  1:   Flooding enabled\n"
	"  n/a: Information unavailable (read-only)\n"
	"  n/a (BridgePort):\n"
	"       The device is part of a Linux bridge and cannot be\n"
	"       configured with VNIC characteristics (read-only)\n",
	.defval = "0",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_2, group_vnicc),
};

static struct attrib qeth_attr_vnicc_mcast_flooding = {
	.name = "vnicc/mcast_flooding",
	.title = "Control setting of VNICC multicast flooding",
	.desc =
	"Control and show the VNIC characteristic multicast flooding\n"
	"on the networking device:\n"
	"  0:   Multicast flooding disabled\n"
	"  1:   Multicast flooding enabled\n"
	"  n/a: Information unavailable (read-only)\n"
	"  n/a (BridgePort):\n"
	"       The device is part of a Linux bridge and cannot be\n"
	"       configured with VNIC characteristics (read-only)\n",
	.defval = "0",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_2, group_vnicc),
};

static struct attrib qeth_attr_vnicc_learning = {
	.name = "vnicc/learning",
	.title = "Control setting of VNICC learning",
	.desc =
	"Control and show the VNIC characteristic learning\n"
	"on the networking device:\n"
	"  0:   Learning disabled\n"
	"  1:   Learning enabled\n"
	"  n/a: Information unavailable (read-only)\n"
	"  n/a (BridgePort):\n"
	"       The device is part of a Linux bridge and cannot be\n"
	"       configured with VNIC characteristics (read-only)\n",
	.defval = "0",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_2, group_vnicc),
};

static struct attrib qeth_attr_vnicc_learning_timeout = {
	.name = "vnicc/learning_timeout",
	.title = "Control setting of the VNICC learning timeout",
	.desc =
	"Control and show the timeout of the VNIC characteristic learning\n"
	"on the networking device:\n"
	"  <N>: Timeout in seconds\n"
	"  n/a: Information unavailable (read-only)\n"
	"  n/a (BridgePort):\n"
	"       The device is part of a Linux bridge and cannot be\n"
	"       configured with VNIC characteristics (read-only)\n",
	.defval = "600",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(60, 86400)),
	.st_data = QETH_DATA(layer_2, group_vnicc),
};

static struct attrib qeth_attr_vnicc_takeover_setvmac = {
	.name = "vnicc/takeover_setvmac",
	.title = "Control setting of VNICC takeover SETVMAC",
	.desc =
	"Control and show the VNIC characteristic takeover SETVMAC\n"
	"on the networking device:\n"
	"  0:   Takeover SETVMAC disabled\n"
	"  1:   Takeover SETVMAC enabled\n"
	"  n/a: Information unavailable (read-only)\n"
	"  n/a (BridgePort):\n"
	"       The device is part of a Linux bridge and cannot be\n"
	"       configured with VNIC characteristics (read-only)\n",
	.defval = "0",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_2, group_vnicc),
};

static struct attrib qeth_attr_vnicc_takeover_learning = {
	.name = "vnicc/takeover_learning",
	.title = "Control setting of VNICC takeover learning",
	.desc =
	"Control and show the VNIC characteristic takeover learning\n"
	"on the networking device:\n"
	"  0:   Takeover learning disabled\n"
	"  1:   Takeover learning enabled\n"
	"  n/a: Information unavailable (read-only)\n"
	"  n/a (BridgePort):\n"
	"       The device is part of a Linux bridge and cannot be\n"
	"       configured with VNIC characteristics (read-only)\n",
	.defval = "0",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_2, group_vnicc),
};

static struct attrib qeth_attr_vnicc_bridge_invisible = {
	.name = "vnicc/bridge_invisible",
	.title = "Control setting of VNICC bridge invisible",
	.desc =
	"Control and show the VNIC characteristic bridge invisible\n"
	"on the networking device:\n"
	"  0:   Bridge invisible disabled\n"
	"  1:   Bridge invisible enabled\n"
	"  n/a: Information unavailable (read-only)\n"
	"  n/a (BridgePort):\n"
	"       The device is part of a Linux bridge and cannot be\n"
	"       configured with VNIC characteristics (read-only)\n",
	.defval = "0",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_2, group_vnicc),
};

static struct attrib qeth_attr_vnicc_rx_bcast = {
	.name = "vnicc/rx_bcast",
	.title = "Control setting of VNICC receive broadcast",
	.desc =
	"Control and show the VNIC characteristic receive broadcast\n"
	"on the networking device:\n"
	"  0:   Receive broadcast disabled\n"
	"  1:   Receive broadcast enabled\n"
	"  n/a: Information unavailable (read-only)\n"
	"  n/a (BridgePort):\n"
	"       The device is part of a Linux bridge and cannot be\n"
	"       configured with VNIC characteristics (read-only)\n",
	.defval = "1",
	.order_cmp = after_layer2_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
	.st_data = QETH_DATA(layer_2, group_vnicc),
};

/*
 * QETH subtype methods.
 */

/* Determine valid layer2 setting. */
static int detect_layer2(struct device *dev)
{
	struct ccwgroup_devid *devid = dev->devid;
	char *ccwid = NULL;
	struct nic_data data;
	int layer2 = -1;

	if (!is_zvm())
		goto out;
	if (devid->devid[0].cssid != 0 || devid->devid[0].ssid != 0)
		goto out;

	ccwid = misc_asprintf("%04x", devid->devid[0].devno);
	if (!nic_data_get(ccwid, &data))
		goto out;
	if (data.type == nic_hipers) {
		/* HiperSocket in z/VM always indicates layer 3. */
		layer2 = 0;
	} else if (data.type == nic_qdio) {
		if (data.target == nic_vswitch)
			nic_vswitch_get_layer2(data.name, &layer2);
		else if (data.target == nic_lan)
			nic_lan_get_layer2(data.name, data.owner, &layer2);
	}

out:
	free(ccwid);

	return layer2;
}

/* Special sausagery for magical qeth attributes. */
static exit_code_t qeth_st_configure_active(struct subtype *st,
					    struct device *dev)
{
	exit_code_t rc;
	struct setting_list *list, *old;
	struct setting *s, *copy;
	struct attrib *replacement;
	struct {
		struct attrib *from;
		struct attrib *to;
	} add2del[] = {
		{ &qeth_attr_ipa_takeover_add4, &qeth_attr_ipa_takeover_del4 },
		{ &qeth_attr_ipa_takeover_add6, &qeth_attr_ipa_takeover_del6 },
		{ &qeth_attr_rxip_add4, &qeth_attr_rxip_del4 },
		{ &qeth_attr_rxip_add6, &qeth_attr_rxip_del6 },
		{ &qeth_attr_vipa_add4, &qeth_attr_vipa_del4 },
		{ &qeth_attr_vipa_add6, &qeth_attr_vipa_del6 },
	};
	unsigned int i;

	/* Turn removed "add" settings into "del" settings. */
	list = setting_list_new();
	util_list_iterate(&dev->active.settings->list, s) {
		copy = setting_copy(s);
		if (!copy->removed || !copy->attrib)
			goto add;

		/* Find replacement instructions. */
		replacement = NULL;
		for (i = 0; i < ARRAY_SIZE(add2del); i++) {
			if (copy->attrib == add2del[i].from) {
				replacement = add2del[i].to;
				break;
			}
		}
		if (!replacement)
			goto add;

		free(copy->name);
		copy->attrib = replacement;
		copy->name = misc_strdup(replacement->name);
		copy->removed = 0;
		copy->modified = 1;

add:
		setting_list_add(list, copy);
	}

	/* Note: Hack, but works unless this code is run multi-threaded. */
	old = dev->active.settings;
	dev->active.settings = list;

	/* Apply setting. */
	rc = st->super->configure_active(st, dev);

	/* Recreate original settings list. */
	dev->active.settings = old;
	setting_list_free(list);

	return rc;
}

static exit_code_t layer2_mismatch(int detected, int modified)
{
	const char *text = "Value for setting 'layer2' differs from "
			   "auto-detected value (%d)\n";

	if (force || !modified) {
		delayed_warn(text, detected);

		return EXIT_OK;
	}
	delayed_forceable(text, detected);

	return EXIT_INVALID_CONFIG;
}

static exit_code_t setting_ineffective(struct setting *s, int layer2)
{
	const char *text = "Setting '%s' is only effective when layer2=%d\n";

	if (!s->modified || s->removed)
		return EXIT_OK;
	if (force) {
		delayed_warn(text, s->name, layer2);
		return EXIT_OK;
	}
	delayed_forceable(text, s->name, layer2);

	return EXIT_INVALID_CONFIG;
}

static enum qeth_layer_type get_layer_type(struct setting *s)
{
	struct qeth_attrib_data *data;

	if (!s->attrib)
		return layer_any;
	data = s->attrib->st_data;

	if (!data)
		return layer_any;
	else
		return data->layer_type;
}

static enum qeth_attr_group_type get_attr_group_type(struct setting *s)
{
	struct qeth_attrib_data *data;

	if (!s->attrib)
		return group_none;
	data = s->attrib->st_data;

	if (!data)
		return group_none;
	else
		return data->attr_group;
}

static void add_layer2_setting(struct setting_list *list, int layer2)
{
	setting_list_apply(list, &qeth_attr_layer2,
			   qeth_attr_layer2.name, layer2 ? "1" : "0");
}

static exit_code_t incompatible_attrib(struct setting *a, struct setting *b)
{
	const char *text = "Settings '%s' and '%s' require incompatible "
			   "layer2 values\n";

	if (force) {
		delayed_warn(text, a->attrib->name, b->attrib->name);

		return EXIT_OK;
	}
	delayed_forceable(text, a->attrib->name, b->attrib->name);

	return EXIT_INVALID_CONFIG;
}

/* Generate implicit layer2 setting if required by a setting that relies
 * on a specific layer2 value. */
static exit_code_t generate_layer2(char *list_type, struct setting_list *list,
				   int *layer2, int *modified)
{
	const char *text = "Adding layer2=%d to %s configuration (required by "
			   "%s)\n";
	struct setting *s, *l2 = NULL, *l3 = NULL;
	enum qeth_layer_type t;

	util_list_iterate(&list->list, s) {
		t = get_layer_type(s);
		if (t == layer_2)
			l2 = s;
		else if (t == layer_3)
			l3 = s;
	}

	if (l2 && l3)
		return incompatible_attrib(l2, l3);

	if (l2 || l3) {
		*layer2 = l2 ? 1 : 0;
		*modified = 1;
		delayed_info(text, *layer2, list_type,
			     (l2 ? l2 : l3)->attrib->name);
		add_layer2_setting(list, *layer2);
	}

	return EXIT_OK;
}

static exit_code_t check_ineffective_settings(struct setting_list *list,
					      int layer2)
{
	struct setting *s;
	enum qeth_layer_type t;
	exit_code_t rc = EXIT_OK;

	util_list_iterate(&list->list, s) {
		t = get_layer_type(s);
		if (t == layer_2 && layer2 == 0)
			rc = setting_ineffective(s, 1);
		else if (t == layer_3 && layer2 == 1)
			rc = setting_ineffective(s, 0);
		if (rc)
			break;
	}

	return rc;
}

/* Check if a possibly conflicting setting is active in the configuration */
static bool conflict_setting_active(struct setting *s)
{
	enum qeth_attr_group_type t;

	t = get_attr_group_type(s);
	if (t != group_bridge && t != group_vnicc) {
		/* Check BridgePort and VNICC attributes only */
		return false;
	}
	if (s->specified) {
		/* Specified on the command line: We are strict here and do not
		 * allow to specify VNICC and BridgePort attributes in the same
		 * command to avoid issues when attributes are enabled/disabled
		 * in the wrong order. Example: disable VNICC and enable
		 * BridgePort in the same command would	result in an error
		 * because BridgePort attributes are set first.
		 */
		return true;
	}
	if (attrib_match_default(s->attrib, s->value)) {
		/* Not active if set to default value */
		return false;
	}
	if (s->actual_value && strncmp(s->actual_value, "n/a", 3) == 0) {
		/* Not active if in n/a state (conflicting attribute set) */
		return false;
	}
	return true;
}

/* Check if there are conflicting attribute settings */
static exit_code_t check_conflicting_settings(struct setting_list *list)
{
	const char *text = "Settings %s and %s are in conflict\n";
	struct setting *bridge = NULL, *vnicc = NULL;
	enum qeth_attr_group_type t;
	struct setting *s;

	util_list_iterate(&list->list, s) {
		if (s->removed)
			continue;
		if (!conflict_setting_active(s))
			continue;
		t = get_attr_group_type(s);
		if (t == group_bridge && (!bridge || !bridge->specified))
			bridge = s;
		if (t == group_vnicc && (!vnicc || !vnicc->specified))
			vnicc = s;
	}

	/* BridgePort and VNICC cannot both be configured at the same time */
	if (bridge && vnicc && (bridge->specified || vnicc->specified)) {
		if (force) {
			delayed_warn(text, bridge->attrib->name,
				     vnicc->attrib->name);
			return EXIT_OK;
		}
		delayed_forceable(text, bridge->attrib->name,
				  vnicc->attrib->name);
		return EXIT_INVALID_CONFIG;
	}
	return EXIT_OK;
}

/* Check if layer2 setting can be correctly applied. */
static exit_code_t check_layer2(struct device *dev, config_t config)
{
	struct setting *l;
	int layer2_detected, layer2_active = -1, layer2_persistent = -1,
	    layer2_autoconf = -1, layer2_modified = 0;
	exit_code_t rc = EXIT_OK;

	layer2_detected = detect_layer2(dev);
	l = setting_list_find(dev->active.settings, qeth_attr_layer2.name);
	if (l) {
		layer2_active = atoi(l->value);
		layer2_modified |= l->modified;
	} else if (SCOPE_ACTIVE(config)) {
		rc = generate_layer2("active", dev->active.settings,
				     &layer2_active, &layer2_modified);
		if (rc)
			goto out;
	}
	l = setting_list_find(dev->persistent.settings, qeth_attr_layer2.name);
	if (l) {
		layer2_persistent = atoi(l->value);
		layer2_modified |= l->modified;
	} else if (SCOPE_PERSISTENT(config)) {
		rc = generate_layer2("persistent", dev->persistent.settings,
				     &layer2_persistent, &layer2_modified);
		if (rc)
			goto out;
	}
	l = setting_list_find(dev->autoconf.settings, qeth_attr_layer2.name);
	if (l) {
		layer2_autoconf = atoi(l->value);
		layer2_modified |= l->modified;
	} else if (SCOPE_AUTOCONF(config)) {
		rc = generate_layer2("autoconf", dev->autoconf.settings,
				     &layer2_autoconf, &layer2_modified);
		if (rc)
			goto out;
	}

	/* Check correct layer2 setting. */
	if (layer2_detected != -1) {
		if ((SCOPE_ACTIVE(config) && layer2_active != -1 &&
		     layer2_active != layer2_detected) ||
		    (SCOPE_PERSISTENT(config) && layer2_persistent != -1 &&
		     layer2_persistent != layer2_detected) ||
		    (SCOPE_AUTOCONF(config) && layer2_autoconf != -1 &&
		     layer2_autoconf != layer2_detected)) {
			rc = layer2_mismatch(layer2_detected, layer2_modified);
			if (rc)
				goto out;
		}
	}

	if (SCOPE_ACTIVE(config)) {
		rc = check_ineffective_settings(dev->active.settings,
						layer2_active);
		if (rc)
			goto out;
	}
	if (SCOPE_PERSISTENT(config)) {
		rc = check_ineffective_settings(dev->persistent.settings,
						layer2_persistent);
		if (rc)
			goto out;
	}
	if (SCOPE_AUTOCONF(config)) {
		rc = check_ineffective_settings(dev->autoconf.settings,
						layer2_autoconf);
		if (rc)
			goto out;
	}
	/* check for conflicting layer2 attribute groups */
	if (SCOPE_ACTIVE(config)) {
		rc = check_conflicting_settings(dev->active.settings);
		if (rc)
			goto out;
	}
	if (SCOPE_PERSISTENT(config)) {
		rc = check_conflicting_settings(dev->persistent.settings);
		if (rc)
			goto out;
	}
	if (SCOPE_AUTOCONF(config))
		rc = check_conflicting_settings(dev->autoconf.settings);

out:
	return rc;
}

static exit_code_t qeth_st_check_pre_configure(struct subtype *st,
					       struct device *dev,
					       int prereq, config_t config)
{
	exit_code_t rc;

	/* No need to check if device is deconfigured. */
	if ((SCOPE_ACTIVE(config) && dev->active.deconfigured) ||
	    (SCOPE_PERSISTENT(config) && dev->persistent.deconfigured) ||
	    (SCOPE_AUTOCONF(config) && dev->autoconf.deconfigured))
		return EXIT_OK;

	rc = check_layer2(dev, config);
	if (rc)
		return rc;

	return EXIT_OK;
}

static exit_code_t qeth_st_is_definable(struct subtype *st, const char *id,
					err_t err)
{
	struct ccwgroup_subtype_data *data = st->data;
	struct ccwgroup_devid devid;
	exit_code_t rc;

	rc = ccwgroup_parse_devid(&devid, id, err);
	if (rc)
		return rc;

	if (subtype_device_exists_active(st, id))
		return EXIT_OK;

	if (devid.num == data->num_devs)
		return qeth_auto_is_possible(&devid, err);

	if (devid.num == 1)
		return qeth_auto_get_devid(NULL, &devid.devid[0], err);

	err_t_print(err, "Invalid number of CCW device IDs\n");

	return EXIT_INVALID_ID;
}

/**
 * device_detect_definable - Detect configuration of definable device
 * @st: Device subtype
 * @dev: Device
 *
 * Detect the full ID and default parameters for non-existing but definable
 * device @dev and update active.definable. Return %EXIT_OK on success, or an
 * error code otherwise.
 */
static exit_code_t qeth_st_detect_definable(struct subtype *st,
					    struct device *dev)
{
	struct ccwgroup_devid *devid;
	int layer2;
	exit_code_t rc;

	devid = dev->devid;
	if (devid->num == 1) {
		/* Detect possible group for this device. */
		rc = qeth_auto_get_devid(devid, &devid->devid[0],
					 err_delayed_print);
		if (rc) {
			error("Auto-detection failed for %s %s\n"
			      "Please be sure to specify full CCWGROUP ID!\n",
			      st->devname, dev->id);
			return rc;
		}
		free(dev->id);
		dev->id = ccwgroup_devid_to_str(dev->devid);
	}

	layer2 = detect_layer2(dev);
	if (layer2 > -1)
		add_layer2_setting(dev->active.settings, layer2);

	dev->active.definable = 1;

	return EXIT_OK;
}

static void qeth_st_add_definable_ids(struct subtype *st, struct util_list *ids)
{
	qeth_auto_add_ids(ids);
}

/*
 * QETH subtype.
 */

static struct ccwgroup_subtype_data qeth_data = {
	.ccwgroupdrv	= QETH_CCWGROUPDRV_NAME,
	.ccwdrv		= QETH_CCWDRV_NAME,
	.rootdrv	= QETH_ROOTDRV_NAME,
	.mod		= QETH_MOD_NAME,
	.num_devs	= QETH_NUM_DEVS,
};

struct subtype qeth_subtype_qeth = {
	.super		= &ccwgroup_subtype,
	.devtype	= &qeth_devtype,
	.name		= "qeth",
	.title		= "OSA-Express and HiperSockets network devices",
	.devname	= DEVNAME,
	.modules	= STRING_ARRAY(QETH_MOD_NAME),
	.namespace	= &qeth_namespace,
	.data		= &qeth_data,

	.dev_attribs = ATTRIB_ARRAY(
		&ccw_attr_online,
		&qeth_attr_layer2,
		&qeth_attr_portname,
		&qeth_attr_priority_queueing,
		&qeth_attr_buffer_count,
		&qeth_attr_portno,
		&qeth_attr_hsuid,
		&qeth_attr_recover,
		&qeth_attr_isolation,
		&qeth_attr_performance_stats,
		&qeth_attr_hw_trap,
		&qeth_attr_route4,
		&qeth_attr_route6,
		&qeth_attr_ipa_takeover_enable,
		&qeth_attr_ipa_takeover_add4,
		&qeth_attr_ipa_takeover_add6,
		&qeth_attr_ipa_takeover_del4,
		&qeth_attr_ipa_takeover_del6,
		&qeth_attr_ipa_takeover_invert4,
		&qeth_attr_ipa_takeover_invert6,
		&qeth_attr_rxip_add4,
		&qeth_attr_rxip_add6,
		&qeth_attr_rxip_del4,
		&qeth_attr_rxip_del6,
		&qeth_attr_sniffer,
		&qeth_attr_vipa_add4,
		&qeth_attr_vipa_add6,
		&qeth_attr_vipa_del4,
		&qeth_attr_vipa_del6,
		&qeth_attr_bridge_role,
		&qeth_attr_bridge_hostnotify,
		&qeth_attr_bridge_reflect_promisc,
		&qeth_attr_vnicc_flooding,
		&qeth_attr_vnicc_mcast_flooding,
		&qeth_attr_vnicc_learning,
		&qeth_attr_vnicc_learning_timeout,
		&qeth_attr_vnicc_takeover_setvmac,
		&qeth_attr_vnicc_takeover_learning,
		&qeth_attr_vnicc_bridge_invisible,
		&qeth_attr_vnicc_rx_bcast,
		&internal_attr_early,
	),
	.unknown_dev_attribs	= 1,
	.support_definable	= 1,

	.configure_active	= &qeth_st_configure_active,
	.check_pre_configure	= &qeth_st_check_pre_configure,

	.is_definable		= &qeth_st_is_definable,
	.detect_definable	= &qeth_st_detect_definable,
	.add_definable_ids	= &qeth_st_add_definable_ids,
};

/*
 * QETH devtype methods.
 */

/* Clean up all resources used by devtype object. */
static void qeth_devtype_exit(struct devtype *dt)
{
	setting_list_free(dt->active_settings);
	setting_list_free(dt->persistent_settings);
}

static exit_code_t qeth_devtype_read_settings(struct devtype *dt,
					      config_t config)
{
	/* No kernel or module parameters exist for the qeth device driver,
	 * but at least determine module loaded state. */
	dt->active_settings = setting_list_new();
	dt->persistent_settings = setting_list_new();

	if (SCOPE_ACTIVE(config))
		dt->active_exists = devtype_is_module_loaded(dt);

	return EXIT_OK;
}

static exit_code_t qeth_devtype_write_settings(struct devtype *dt,
					       config_t config)
{
	/* No kernel or module parameters exist for the qeth device driver. */

	return EXIT_OK;
}

/*
 * QETH devtype.
 */

struct devtype qeth_devtype = {
	.name		= "qeth",
	.title		= "", /* Only use subtypes. */
	.devname	= "QETH",

	.subtypes = SUBTYPE_ARRAY(
		&qeth_subtype_qeth,
	),

	.type_attribs = ATTRIB_ARRAY(),

	.exit			= &qeth_devtype_exit,

	.read_settings		= &qeth_devtype_read_settings,
	.write_settings		= &qeth_devtype_write_settings,
};
