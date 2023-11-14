/**
 * libzpci - Functions to handle zPCI devices and their properties
 *
 * Copyright IBM Corp. 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lib/pci_list.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_path.h"
#include "lib/util_scandir.h"

/**
 * Get the function type name for the given device
 *
 * The device type name is suitable for presentation to a user.
 *
 * @param[in]	zdev	The device in question
 *
 * @return a string representing the PCI device type
 */
const char *zpci_pft_str(struct zpci_dev *zdev)
{
	switch (zdev->pft) {
	case ZPCI_PFT_UNCLASSIFIED:
		return "unclassified";
	case ZPCI_PFT_ROCE_EXPRESS:
		return "RoCE Express";
	case ZPCI_PFT_ROCE_EXPRESS2:
		return "RoCE Express-2";
	case ZPCI_PFT_CNW:
		return "Cloud Network Adapter";
	case ZPCI_PFT_NETH:
		return "Network Express Hybrid";
	case ZPCI_PFT_NETD:
		return "Network Express Dedicated";
	case ZPCI_PFT_NVME:
		return "NVMe";
	case ZPCI_PFT_ISM:
		return "ISM";
	default:
		return "unknown";
	}
}

/**
 * Get a textual representation of the device's PCI address
 *
 * The representation has extended "DDDD:bb:dd.f" format used
 * by Linux tooling such as lspci.
 *
 * @param[in]	zdev	The device in question
 *
 * @return the string representing the PCI address
 */
char *zpci_pci_addr(struct zpci_dev *zdev)
{
	uint8_t bus = zdev->bdf.bus;
	uint8_t dev = zdev->bdf.dev;
	uint8_t fn = zdev->bdf.fn;
	char *pci_addr;

	util_asprintf(&pci_addr, "%04x:%02x:%02x.%x", zdev->domain_nr, bus, dev, fn);
	return pci_addr;
}

static int zpci_populate_from_slot_dir(struct zpci_dev *zdev, const char *slot_dir,
				       const char *slot_name)
{
	char buf_addr[11]; /* "dddd:bb:dd\0" */
	uint8_t bus, df;
	uint32_t domain;
	int val, rc;

	rc = sscanf(slot_name, "%x", &zdev->fid);
	if (rc != 1)
		return -EINVAL;

	rc = util_file_read_line(buf_addr, sizeof(buf_addr), "%s/%s/address", slot_dir, slot_name);
	if (rc) {
		warn("Reading address from slot %s/%s", slot_dir, slot_name);
		return rc;
	}
	rc = sscanf(buf_addr, "%04x:%02hhx:%02hhx", &domain, &bus, &df);
	if (rc != 3)
		return -EINVAL;
	zdev->domain_nr = domain;
	zdev->bdf.val = (((uint16_t)bus) << 8) | df;

	rc = util_file_read_i(&val, 10, "%s/%s/power", slot_dir, slot_name);
	if (rc) {
		warn("Reading power from slot %s/%s", slot_dir, slot_name);
		return rc;
	}
	zdev->conf = val > 0;

	return 0;
}

static int zpci_populate_netdevices(struct zpci_dev *zdev, const char *dev_dir)
{
	const char *netdev_patt = "en.*";
	struct dirent **de_vec;
	int count, i, rc = 0;
	char *net_dir;

	util_asprintf(&net_dir, "%s/net", dev_dir);
	count = util_scandir(&de_vec, alphasort, net_dir, netdev_patt);
	if (count == -1) {
		warn("Reading netdevice information for %s/net failed", dev_dir);
		rc = -EINVAL;
		goto out_net_dir;
	}
	/* A directory per netdev */
	for (i = 0; i < count; i++) {
		if (de_vec[i]->d_type != DT_DIR) {
			rc = -EINVAL;
			goto out_scan_dir;
		}
	}
	zdev->num_netdevs = count;
	if (!count)
		goto out_scan_dir;
	zdev->netdevs = util_zalloc(sizeof(char *) * zdev->num_netdevs);
	for (i = 0; i < count; i++)
		zdev->netdevs[i] = util_strdup(de_vec[i]->d_name);

out_scan_dir:
	util_scandir_free(de_vec, count);
out_net_dir:
	free(net_dir);
	return rc;
}

static int zpci_populate_from_dev_dir(struct zpci_dev *zdev)
{
	char *pci_addr = zpci_pci_addr(zdev);
	int rc, val;
	char *path;

	path = util_path_sysfs("bus/pci/devices/%s", pci_addr);
	if (!path) {
		rc = -EINVAL;
		goto out_pci_addr;
	}
	if (!util_path_exists(path)) {
		rc = -ENODEV;
		goto out_path;
	}

	rc = util_file_read_i(&val, 16, "%s/uid", path);
	if (rc)
		goto out_path;
	zdev->uid = val;

	/* In old Linux versions uid_is_unique doesn't exist
	 * so don't treat this as an error.
	 */
	rc = util_file_read_i(&val, 10, "%s/uid_is_unique", path);
	if (!rc)
		zdev->uid_is_unique = !!val;

	rc = util_file_read_i(&val, 16, "%s/pchid", path);
	if (rc)
		goto out_path;
	zdev->pchid = val;

	rc = util_file_read_i(&val, 16, "%s/vfn", path);
	if (rc)
		goto out_path;
	zdev->vfn = val;

	rc = util_file_read_i(&val, 10, "%s/port", path);
	if (rc)
		goto out_path;
	zdev->port = val;

	rc = util_file_read_i(&val, 16, "%s/pft", path);
	if (rc)
		goto out_path;
	zdev->pft = val;

	if (util_path_is_readable("%s/net", path)) {
		rc = zpci_populate_netdevices(zdev, path);
		if (rc)
			goto out_path;
	}
out_path:
	free(path);
out_pci_addr:
	free(pci_addr);
	return rc;
}

/**
 * Get a list of all configured and standby PCI devices
 *
 * @return a list of struct zpci_dev in case of success,
 *	   NULL in case of failure
 */
struct util_list *zpci_dev_list(void)
{
	char *path = util_path_sysfs("bus/pci/slots/");
	const char *zpci_slot_patt = "[0-9a-f]{8}";
	struct util_list *zpci_list = NULL;
	struct dirent **de_vec;
	struct zpci_dev *zdev;
	int count, i, rc;

	count = util_scandir(&de_vec, alphasort, path, zpci_slot_patt);
	if (count == -1) {
		warn("util_scandir failed");
		goto error_path;
	}
	zpci_list = util_list_new(struct zpci_dev, entry);

	for (i = 0; i < count; i++) {
		if (de_vec[i]->d_type != DT_DIR)
			continue;
		zdev = util_zalloc(sizeof(*zdev));
		rc = zpci_populate_from_slot_dir(zdev, path, de_vec[i]->d_name);
		if (rc) {
			free(zdev);
			continue;
		}
		if (zdev->conf) {
			rc = zpci_populate_from_dev_dir(zdev);
			if (rc) {
				free(zdev);
				continue;
			}
		}
		util_list_add_tail(zpci_list, zdev);
	}

	util_scandir_free(de_vec, count);
error_path:
	free(path);
	return zpci_list;
}

/**
 * Free a PCI device struct
 *
 * This frees both the struct zpci_dev and its associated netdevs array
 *
 * @param[in]	zdev		The device struct to free
 */
void zpci_free_dev(struct zpci_dev *zdev)
{
	int i;

	if (zdev->num_netdevs) {
		for (i = 0; i < zdev->num_netdevs; i++)
			free(zdev->netdevs[i]);
		free(zdev->netdevs);
	}
	free(zdev);
}

/**
 * Free a PCI device list
 *
 * This frees all elements in the list
 *
 * @param[in]	zpci_list	The device list to free
 */
void zpci_free_dev_list(struct util_list *zpci_list)
{
	struct zpci_dev *zdev, *tmp;

	util_list_iterate_safe(zpci_list, zdev, tmp) {
		util_list_remove(zpci_list, zdev);
		zpci_free_dev(zdev);
	}
	util_list_free(zpci_list);
}
