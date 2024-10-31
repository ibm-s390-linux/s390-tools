/**
 * @defgroup pci_sclp_h libzpci: zPCI device handling
 * @{
 * @brief Issue SCLPs for zPCI devices
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_ZPCI_PCI_SCLP_H
#define LIB_ZPCI_PCI_SCLP_H

#include <linux/types.h>
#include <stddef.h>

#include "lib/zt_common.h"

#define SCLP_ERRNOTIFY_AQ_RESET			0
#define SCLP_ERRNOTIFY_AQ_DECONF		1
#define SCLP_ERRNOTIFY_AQ_REPORT_ERR		2
#define SCLP_ERRNOTIFY_AQ_OPTICS_DATA		3

#define SCLP_ERRNOTIFY_ID_ZPCICTL		0x4713
#define SCLP_ERRNOTIFY_ID_OPTICSMON		0x4714

#define SCLP_ERRNOTIFY_DATA_SIZE		4054

struct zpci_report_error_header {
	__u8 version;	/* Interface version byte */
	__u8 action;	/* Action qualifier byte
			 * 0: Adapter Reset Request
			 * 1: Deconfigure and repair action requested
			 * 2: Informational Report
			 * 3: Optics Data
			 */
	__u16 length;	/* Length of Subsequent Data (up to 4K – SCLP header) */
} __packed;

struct zpci_report_error_data {
	__u64 timestamp;
	__u64 err_log_id;
	/* We cannot exceed a total of 4074 bytes (header + data) */
	char log_data[SCLP_ERRNOTIFY_DATA_SIZE];
} __packed;

struct zpci_report_error {
	struct zpci_report_error_header header;
	struct zpci_report_error_data data;
} __packed;

int zpci_sclp_issue_action(char *pci_addr, int action,
			   char *data, size_t length, u64 err_log_id);

#endif /* LIB_ZPCI_PCI_SCLP_H */
