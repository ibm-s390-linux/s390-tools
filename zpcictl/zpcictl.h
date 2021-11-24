/*
 * zpcictl - Manage PCI devices on z Systems
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZPCICTL_H
#define ZPCICTL_H

#include <linux/types.h>
#include "lib/zt_common.h"

#define SCLP_ERRNOTIFY_AQ_RESET			0
#define SCLP_ERRNOTIFY_AQ_DECONF		1
#define SCLP_ERRNOTIFY_AQ_REPORT_ERR		2

#define PCI_CLASS_UNCLASSIFIED	0x000000U
#define PCI_CLASS_NVME		0x010802U
#define PCI_CLASS_NETWORK	0x020000U

struct options {
	unsigned int reset;
	unsigned int reset_fw;
	unsigned int deconfigure;
	unsigned int report;
};

struct zpci_device {
	u16 fid;
	u16 pchid;
	u32 class;
	char slot[13];
	char *device;
};

struct zpci_report_error_header {
	__u8 version;	/* Interface version byte */
	__u8 action;	/* Action qualifier byte
			 * 0: Adapter Reset Request
			 * 1: Deconfigure and repair action requested
			 * 2: Informational Report
			 */
	__u16 length;	/* Length of Subsequent Data (up to 4K – SCLP header) */
	__u8 data[0];	/* Subsequent Data passed verbatim to SCLP ET 24 */
};

struct zpci_report_error_data {
	__u64 timestamp;
	__u64 err_log_id;
	char log_data[4054]; /* We cannot exceed a total of 4074 bytes (header + data) */
};

struct zpci_report_error {
	struct zpci_report_error_header header;
	struct zpci_report_error_data data;
} __packed;

#endif /* ZPCICTL_H */
