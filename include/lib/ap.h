/*
 * libap - A collection of tools for ap/vfio-ap management
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_AP_H
#define LIB_AP_H

#include <stdbool.h>

#include "lib/util_list.h"

#define VFIO_AP_PATH "/sys/devices/vfio_ap"
#define VFIO_AP_PARENT_PATH "devices/vfio_ap/matrix"
#define VFIO_AP_CONFIG_PATH "/etc/mdevctl.d/matrix"
#define VFIO_AP_TYPE "vfio_ap-passthrough"
#define AP_UDEV_FILE "/etc/udev/rules.d/41-ap.rules"
#define AP_LOCKFILE "/run/lock/s390apconfig.lock"

#define AP_LOCK_RETRIES 15

/* apmask and aqmask are each represented as 67 character strings with:
 *  '0x' leading characters
 *  64 hex digits (to represent 256 bits)
 *  terminating character
 */
#define AP_MASK_SIZE 67
#define AP_MAX_MASK_VALUE 255

/* List structure used for keeping track of lists of adapter/domain IDs */
struct vfio_ap_node {
	struct util_list_node node;	/* prev/next list info */
	unsigned int id;		/* list entry (adapter, domain, etc) */
};

/*
 * Structure used to represent a vfio_ap-passthrough device configuration.
 * The list of adapters and domains can be used to derive the APQNs for the
 * device.  The type value is used to verify that the device (when read from
 * a mdevctl config file) is of type vfio_ap-passthrough.  The manual value
 * represents whether the device is started on-demand after boot (true) or
 * automatically during boot (false).
 */
struct vfio_ap_device {
	char *uuid;			/* Unique ID for this mdev */
	struct util_list *adapters;	/* List of adapters for device */
	struct util_list *domains;	/* List of usage domains for device */
	struct util_list *controls;	/* List of control domains for device */
	char *type;			/* mdev type string */
	bool manual;			/* manual/auto start setting for mdev */
};

/* General Utility Functions */
void print_ap_device(struct vfio_ap_device *dev);
bool is_valid_uuid(const char *uuid);
int ap_test_bit(int n, const char *hexbytestr);
void ap_set_bit(int n, char *hexbytestr, bool val);

/* Path-related functions */
char *path_get_vfio_ap_mdev(const char *uuid);
char *path_get_vfio_ap_mdev_config(const char *uuid);
char *path_get_vfio_ap_attr(const char *uuid, const char *attr);
char *path_get_ap_udev(void);

/* Functions for manipulating sysfs to read active device info */
void vfio_ap_parse_matrix(struct vfio_ap_device *dev, char *matrix);
void vfio_ap_sort_matrix_results(struct vfio_ap_device *dev);
void vfio_ap_parse_control(struct vfio_ap_device *dev, char *control);

/* Functions for reading JSON device config */
int vfio_ap_read_device_config(const char *path, struct vfio_ap_device *dev);

/* Functions for managing vfio_ap device structures */
struct vfio_ap_device *vfio_ap_device_new(void);
void vfio_ap_device_clear(struct vfio_ap_device *dev);
void vfio_ap_device_free(struct vfio_ap_device *dev);

/* Functions for acquiring current vfio_ap device info */
int ap_read_sysfs_masks(char *ap, char *aq, int size);
bool ap_read_udev_masks(char *path, char *ap, char *aq, bool *read_ap,
			bool *read_aq);
void ap_mask_to_list(char *mask, struct util_list *list);
void ap_list_remove_all(struct util_list *list);

/* Lock Functions */
int ap_get_lock(void);
int ap_get_lock_callout(void);
int ap_release_lock(void);
int ap_release_lock_callout(void);

#endif /* LIB_AP_H */
