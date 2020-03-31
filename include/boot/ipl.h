/*
 * IPL related definitions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef IPL_H
#define IPL_H

#include "lib/zt_common.h"
#include "s390.h"

#define IPL_FLAG_SECURE		 0x40

#define IPL_RB_COMPONENT_FLAG_SIGNED	0x80
#define IPL_RB_COMPONENT_FLAG_VERIFIED	0x40

#define IPL_MAX_SUPPORTED_VERSION	0
#define IPL_PARM_BLOCK_VERSION		0x1

/* IPL Types */
#define IPL_TYPE_PV			0x5


#ifndef __ASSEMBLER__

#include <stdint.h>

/* IPL Parameter List header */
struct ipl_pl_hdr {
	uint32_t len;
	uint8_t  flags;
	uint8_t  reserved1[2];
	uint8_t  version;
} __packed;

/* IPL Parameter Block header */
struct ipl_pb_hdr {
	uint32_t len;
	uint8_t  pbt;
} __packed;

/* IPL Parameter Block 0 with common fields */
struct ipl_pb0_common {
	uint32_t len;
	uint8_t  pbt;
	uint8_t  flags;
	uint8_t  reserved1[2];
	uint8_t  loadparm[8];
	uint8_t  reserved2[84];
} __packed;

/* IPL Parameter Block 0 for FCP */
struct ipl_pb0_fcp {
	uint32_t len;
	uint8_t  pbt;
	uint8_t  reserved1[3];
	uint8_t  loadparm[8];
	uint8_t  reserved2[304];
	uint8_t  opt;
	uint8_t  reserved3[3];
	uint8_t  cssid;
	uint8_t  reserved4[1];
	uint8_t  devno;
	uint8_t  reserved5[4];
	uint64_t wwpn;
	uint64_t lun;
	uint32_t bootprog;
	uint8_t  reserved6[12];
	uint64_t br_lba;
	uint32_t scp_data_len;
	uint8_t  reserved7[260];
	uint8_t  scp_data[];
} __packed;

/* IPL Parameter Block 0 for CCW */
struct ipl_pb0_ccw {
	uint32_t len;
	uint8_t  pbt;
	uint8_t  flags;
	uint8_t  reserved1[2];
	uint8_t  loadparm[8];
	uint8_t  reserved2[84];
	uint16_t reserved3 : 13;
	uint8_t  ssid : 3;
	uint16_t devno;
	uint8_t  vm_flags;
	uint8_t  reserved4[3];
	uint32_t vm_parm_len;
	uint8_t  nss_name[8];
	uint8_t  vm_parm[64];
	uint8_t  reserved5[8];
} __packed;

/* Structure must not have any padding */
struct ipl_pb0_pv_comp {
	uint64_t tweak_pref;
	uint64_t addr;
	uint64_t len;
};
STATIC_ASSERT(sizeof(struct ipl_pb0_pv_comp) == 3 * 8)

/* IPL Parameter Block 0 for PV */
struct ipl_pb0_pv {
	uint32_t len;
	uint8_t  pbt;
	uint8_t  reserved1[3];
	uint8_t  loadparm[8];
	uint8_t  reserved2[84];
	uint8_t  reserved3[3];
	uint8_t  version;
	uint8_t  reserved4[4];
	uint32_t num_comp;
	uint64_t pv_hdr_addr;
	uint64_t pv_hdr_size;
	struct ipl_pb0_pv_comp components[];
} __packed;

struct ipl_parameter_block {
	struct ipl_pl_hdr hdr;
	union {
		struct ipl_pb_hdr pb0_hdr;
		struct ipl_pb0_common common;
		struct ipl_pb0_fcp fcp;
		struct ipl_pb0_ccw ccw;
		struct ipl_pb0_pv pv;
		char raw[PAGE_SIZE - sizeof(struct ipl_pl_hdr)];
	};
} __packed;

/* IPL Report List header */
struct ipl_rl_hdr {
	uint32_t len;
	uint8_t  flags;
	uint8_t  reserved1[2];
	uint8_t  version;
	uint8_t  reserved2[8];
} __packed;

/* IPL Report Block header */
/* Structure must not have any padding */
struct ipl_rb_hdr {
	uint32_t len;
	uint8_t  rbt;
	uint8_t  reserved1[11];
};
STATIC_ASSERT(sizeof(struct ipl_rb_hdr) == 4 + 1 + 11)

/* IPL Report Block types */
enum ipl_rbt {
	IPL_RBT_CERTIFICATES = 1,
	IPL_RBT_COMPONENTS = 2,
};

/* IPL Report Block for the certificate list */
struct ipl_rb_certificate_entry {
	uint64_t addr;
	uint64_t len;
} __packed;

struct ipl_rb_certificates {
	uint32_t len;
	uint8_t  rbt;
	uint8_t  reserved1[11];
	struct ipl_rb_certificate_entry entries[];
} __packed;

/* IPL Report Block for the component list */
struct ipl_rb_component_entry {
	uint64_t addr;
	uint64_t len;
	uint8_t  flags;
	uint8_t  reserved1[5];
	uint16_t certificate_index;
	uint8_t  reserved2[8];
};

/* Structure must not have any padding */
struct ipl_rb_components {
	uint32_t len;
	uint8_t  rbt;
	uint8_t  reserved1[11];
	struct ipl_rb_component_entry entries[];
};
STATIC_ASSERT(sizeof(struct ipl_rb_components) == 4 + 1 + 11)

#endif /* __ASSEMBLER__ */
#endif /* IPL_H */
