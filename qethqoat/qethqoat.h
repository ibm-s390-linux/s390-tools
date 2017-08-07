/*
 * qethqoat - Query the OSA address table and display physical and logical
 *            device information
 *
 * Copyright IBM Corp. 2012, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _QETHQOAT_H
#define _QETHQOAT_H

#include <linux/types.h>

#define SIOC_QETH_QUERY_OAT (SIOCDEVPRIVATE + 7)

struct qeth_query_oat_data {
	__u32 command;		/* scope of the query */
	__u32 buffer_len;	/* length of the buffer */
	__u32 response_len;	/* length of the response in the buffer */
	__u64 ptr;		/* pointer to buffer */
};

struct qeth_qoat_ipa_reply {
	__u16 len;
	__u8 reserved1[2];
	__u32 command;
	__u16 rc;
	__u8 frames_total;
	__u8 frames_seq;
	__u8 reserved2[4];
	__u32 subcommand;
	__u8 reserved3[4];
	__u32 supported_scope;
	__u32 supported_descriptor;
} __attribute__((packed));

struct qeth_qoat_physical {
	__u16 pchid;
	__u16 chpid;
	__u8 physical_mac[6];
	__u8 logical_mac[6];
	__u16 data_sub_channel;
	__u8 cula;
	__u8 unit_address;
	__u16 physical_port;
	__u16 nr_out_queues;
	__u16 nr_in_queues;
	__u16 nr_active_in_queues;
#define OAT_IFF_CHPID_TYPE_OSD 0x0
#define OAT_IFF_CHPID_TYPE_OSX 0x1
#define OAT_IFF_CHPID_TYPE_OSM 0x2
	__u32 interface_flags_chpid_type:4;
	__u32 interface_flags:28;

#define OAT_OSA_GEN_OSAE3 0x01
#define OAT_OSA_GEN_OSAE4S 0x02
#define OAT_OSA_GEN_OSAE5S 0x03
#define OAT_OSA_GEN_OSAE6S 0x04
	__u8 osa_gen;
#define OAT_PORT_SPEED_UNKNOWN      0x00
#define OAT_PORT_SPEED_10mbs_half   0x01
#define OAT_PORT_SPEED_10mbs_full   0x02
#define OAT_PORT_SPEED_100mbs_half  0x03
#define OAT_PORT_SPEED_100mbs_full  0x04
#define OAT_PORT_SPEED_1000mbs_half 0x05
#define OAT_PORT_SPEED_1000mbs_full 0x06
#define OAT_PORT_SPEED_NA           0x07
#define OAT_PORT_SPEED_10gbs_full   0x08
	__u8 port_speed;
#define OAT_PORT_MEDIA_COPPER      0x01
#define OAT_PORT_MEDIA_MULTI_MODE  0x02
#define OAT_PORT_MEDIA_SINGLE_MODE 0x04
	__u8 port_media;
#define OAT_PORT_MEDIA_ATT_JUMBO 0x80
	__u8 port_media_att;
	__u32 firmware;
	__u8 reserved1[24];
} __attribute__((packed));

struct qeth_qoat_logical {
	__u8 ip4_primary_router:1;
	__u8 ip4_secondary_router:1;
	__u8 ip4_active_router:1;
	__u8 ip6_primary_router:1;
	__u8 ip6_secondary_router:1;
	__u8 ip6_active_router:1;
	__u8 ip4_vmac_router:1;
	__u8 ip6_vmac_router:1;

	__u8 ip4_vmac_active:1;
	__u8 ip4_vmac_source:1;
	__u8 ip4_global_vlan_active:1;
	__u8 ip6_vmac_active:1;
	__u8 ip6_vmac_source:1;
	__u8 ip6_global_vlan_active:1;
	__u8 reserved1:2;

	__u8 port_name_f:1;
	__u8 isolation_f:1;
	__u8 isolation_vepa:1;
	__u8 reserved2:5;

	__u8 reserved3;
	__u16 ip4_global_vlanid;
	__u8 ip4_vmac[6];
	__u16 ip6_global_vlanid;
	__u8 ip6_vmac[6];
	__u8 port_name[8];
	__u32 ip4_ass_enabled;
	__u32 ip6_ass_enabled;
	__u32 out_csum_enabled;
	__u32 out_csum_enabled6;
	__u32 in_csum_enabled;
	__u32 in_csum_enabled6;
	__u32 reserved4;
	__u16 l2_vlanid;
	__u8 l2_vmac[6];
	__u16 nr_des;
	__u8 reserved5[14];
} __attribute__((packed));

struct qeth_qoat_des_ip4 {
	__u32 ip4_address;
	__u32 flags;
} __attribute__((packed));

struct qeth_qoat_des_ip4mc {
	__u32 ip4_mc_address;
	__u8 ip4_mc_mac[6];
	__u8 reserved[6];
} __attribute__((packed));

struct qeth_qoat_des_ip6 {
	__u8 ip6_address[16];
	__u32 flags;
	__u8 reserved[4];
} __attribute__((packed));

struct qeth_qoat_des_ip6mc {
	__u8 ip6_mc_address[16];
	__u8 ip6_mc_mac[6];
	__u8 reserved[2];
} __attribute__((packed));

struct qeth_qoat_des_vmac {
	__u8 vmac[6];
	__u8 reserved[2];
} __attribute__((packed));

struct qeth_qoat_des_vlan {
	__u16 vlanid;
	__u8 reserved[2];
} __attribute__((packed));

struct qeth_qoat_des_gmac {
	__u8 gmac[6];
	__u8 reserved[2];
} __attribute__((packed));

struct qeth_qoat_des_aiq {
	__u32 protocol;
	__u8 src_address[16];
	__u8 des_address[16];
	__u16 src_port;
	__u16 des_port;
} __attribute__((packed));

struct qeth_qoat_descriptor {
#define OAT_DES_TYPE_IP4   0x00000001
#define OAT_DES_TYPE_IP4MC 0x00000002
#define OAT_DES_TYPE_IP6   0x00000004
#define OAT_DES_TYPE_IP6MC 0x00000008
#define OAT_DES_TYPE_VMAC  0x00000100
#define OAT_DES_TYPE_VLAN  0x00000200
#define OAT_DES_TYPE_GMAC  0x00000400
#define OAT_DES_TYPE_AIQ   0x00010000
	__u32 des_type;
	__u32 rv_type;
	__u16 rv_version;
	__u16 qid;
	__u32 reply_entry_len;
	__u16 reply_entry_version;
	__u16 reply_entry_count;
	__u16 dh;
	__u8 reserved[10];
} __attribute__((packed));

struct qeth_qoat_hdr {
#define OAT_HDR_TYPE_PHYSICAL   0x0004
#define OAT_HDR_TYPE_LOGICAL    0x0008
#define OAT_HDR_TYPE_DESCRIPTOR 0x0010
	__u16 hdr_type;
	__u16 len;
	__u16 version;
	__u8 reserved1[6];
	__u32 ec;
	union {
		struct qeth_qoat_physical physical;
		struct qeth_qoat_logical logical;
		struct qeth_qoat_descriptor descriptor;
	} type;
} __attribute__((packed));

struct qeth_print_hdr {
	int ip4_h;
	int ip4mc_h;
	int ip6_h;
	int ip6mc_h;
	int vmac_h;
	int vlan_h;
	int gmac_h;
	int aiq_h;
};

struct qoat_opts {
	int raw;
	char *ifname;
	int scope;
	char *file;
};

#endif
