/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Main program for stage3 bootloader.
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef STAGE3_H
#define STAGE3_H

#include "libc.h"
#include "s390.h"

#define IPL_DEVICE		 0x10404UL
#define INITRD_START		 0x10408UL
#define INITRD_SIZE		 0x10410UL
#define OLDMEM_BASE		 0x10418UL
#define OLDMEM_SIZE		 0x10420UL
#define COMMAND_LINE		 0x10480UL
#define COMMAND_LINE_SIZE	 896
#define COMMAND_LINE_EXTRA       0xE000

#define STAGE3_FLAG_SCSI	 0x0001000000000000ULL
#define STAGE3_FLAG_KDUMP	 0x0002000000000000ULL

#define IPL_FLAG_SECURE		 0x40

#define DEFAULT_IMAGE_ADDR	 0x10000
#define DEFAULT_PSW_LOAD	 0x0008000080010000UL
#define PSW_ADDR_MASK		 0x000000007FFFFFFFUL
#define KERNEL_HEADER_SIZE	 65536

#define UNSPECIFIED_ADDRESS		-1UL


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

struct ipl_parameter_block {
	struct ipl_pl_hdr hdr;
	union {
		struct ipl_pb_hdr pb0_hdr;
		struct ipl_pb0_common common;
		struct ipl_pb0_fcp fcp;
		struct ipl_pb0_ccw ccw;
		char raw[PAGE_SIZE - sizeof(struct ipl_pl_hdr)];
	};
} __packed __aligned(PAGE_SIZE);

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

#define IPL_RB_COMPONENT_FLAG_SIGNED	0x80
#define IPL_RB_COMPONENT_FLAG_VERIFIED	0x40

/* Structure must not have any padding */
struct ipl_rb_components {
	uint32_t len;
	uint8_t  rbt;
	uint8_t  reserved1[11];
	struct ipl_rb_component_entry entries[];
};

extern unsigned long long _parm_addr;   /* address of parmline */
extern unsigned long long _initrd_addr; /* address of initrd */
extern unsigned long long _initrd_len;  /* length of initrd */
extern unsigned long long _load_psw;    /*  load psw of kernel */
extern unsigned long long _extra_parm;  /* use extra parm line mechanism? */
extern unsigned long long stage3_flags; /*  flags (e.g. STAGE3_FLAG_KDUMP) */
extern unsigned long long _image_len;   /* length of kernel */
extern unsigned long long _image_addr;  /* target address of kernel */
extern void kdump_stage3();

#endif /* STAGE3_H */
