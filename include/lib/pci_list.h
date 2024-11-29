/**
 * @defgroup pci_list_h libzpci: zPCI device handling
 * @{
 * @brief Work with zPCI devices
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_ZPCI_PCI_LIST_H
#define LIB_ZPCI_PCI_LIST_H

#include <stdint.h>
#include <stdbool.h>

#include "util_list.h"

enum zpci_pft {
	ZPCI_PFT_UNCLASSIFIED = 0x00,

	ZPCI_PFT_ROCE_EXPRESS = 0x02,
	ZPCI_PFT_ROCE_EXPRESS2 = 0x0a,
	ZPCI_PFT_CNW = 0x0d,
	ZPCI_PFT_NETH =	0x0c,
	ZPCI_PFT_NETD = 0x0f,

	ZPCI_PFT_NVME = 0x0b,
	ZPCI_PFT_ISM = 0x05
};

/*
 * Follows RFC 2863 operational states with the
 * numeric values from IF_OPER_* in linux/if.h:
 */
typedef uint8_t operstate_t;

struct zpci_netdev {
	char *name;
	operstate_t operstate;
};

struct zpci_dev {
	struct util_list_node entry;
	/* PCI Domain */
	uint32_t domain_nr;
	/* PCI Bus (8 bits), Device (5 bits), Function (3 bits) */
	union {
		uint16_t val;
		struct {
			uint16_t bus : 8;
			uint16_t dev : 5;
			uint16_t fn : 3;
		};
	} bdf;

	/* Function attributes (see linux/Documentation/arch/s390/pci.rst) */
	uint32_t fid;
	uint32_t uid;
	uint16_t pchid;
	uint16_t vfn;
	uint8_t port;
	enum zpci_pft pft;
	bool uid_is_unique;
	/* Configuration state 0 - Standby, 1 Configured */
	bool conf;

	/* Associated netdevs if any */
	int num_netdevs;
	struct zpci_netdev *netdevs;
};

/**
 * Get if a PCI device is a PCI Virtual Function
 *
 * @param[in]	zdev	The device in question
 *
 * @return true if the device is a VF false otherwise
 */
static inline bool zpci_is_vf(struct zpci_dev *zdev)
{
	return !!zdev->vfn;
}

struct util_list *zpci_dev_list(void);
void zpci_free_dev_list(struct util_list *zpci_list);
void zpci_free_dev(struct zpci_dev *zdev);

char *zpci_pci_addr(struct zpci_dev *zdev);
const char *zpci_pft_str(struct zpci_dev *zdev);

const char *zpci_operstate_str(operstate_t state);
operstate_t zpci_operstate_from_str(const char *oper_str);

#endif /* LIB_ZPCI_PCI_LIST_H */
