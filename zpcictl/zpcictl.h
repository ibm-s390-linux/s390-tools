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

#endif /* ZPCICTL_H */
