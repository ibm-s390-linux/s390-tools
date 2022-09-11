/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DEVICE_H
#define DEVICE_H

#include "lib/util_list.h"

#include "exit_code.h"
#include "hash.h"
#include "misc.h"

struct subtype;
struct setting_list;

/**
 * Currently zdev supports 10 sites. Which means, zdev support 10 different
 * set of attributes which are specific to each site. When the user does
 * not provide any site information, the common set will be used which is
 * not specific to any site. So, total we have 11 persistent attribute sets
 * Where,
 * 0- 9: Site specific attributes
 * 10: Common attributes which do not belong to any sites
 */

#define NUM_SITES 11
#define NUM_USER_SITES (NUM_SITES - 1)
#define SITE_FALLBACK NUM_USER_SITES

/**
 * struct device_state - Represent the state of a device in a configuration
 * @settings: List of attribute settings
 * @exists: Device exists
 * @modified: Device state has been modified
 * @deconfigured: Device has been deconfigured
 * @definable: Device can be defined
 * @blacklisted: Device is on the blacklist
 */
struct device_state {
	struct setting_list *settings;
	unsigned int exists:1;
	unsigned int modified:1;
	unsigned int deconfigured:1;
	unsigned int definable:1;
	unsigned int blacklisted:1;
};

/**
 * struct device - Represent a device configuration
 * @subtype: Pointer to device subtype definition
 * @id: Textual device ID
 * @devid: Parsed device ID
 * @node: Node for adding this device to a list
 * @active: Device state in the active configuration
 * @persistent: Device state in the persistent configuration
 * @autoconf: Auto-configured device state
 * @errors: A strlist of error and warning messages issued for the device
 * @processed: Device has been processed
 */
struct device {
	/* Static data */
	struct subtype *subtype;
	char *id;
	void *devid;

	/* Dynamic data */
	struct util_list_node node;

	struct device_state active;
	struct device_state persistent;
	struct device_state autoconf;
	struct device_state site_specific[NUM_SITES];

	unsigned int processed:1;
};

/**
 * struct device_list - A list of devices
 * @hash: Hash for maintaining a list of devices
 * @modified: Indication of whether this list was modified
 */
struct device_list {
	struct hash hash;
	unsigned int modified:1;
};

struct device *device_new(struct subtype *, const char *);
void device_free(struct device *);
void device_reset(struct device *, config_t);
void device_print(struct device *, int);

bool device_needs_writing(struct device *, config_t);
exit_code_t device_apply_strlist(struct device *, config_t, struct util_list *);
exit_code_t device_apply_settings(struct device *, config_t,
				  struct util_list *);
void device_add_modules(struct util_list *, struct device *);
char *device_read_active_attrib(struct device *, const char *);
void device_read_active_settings(struct device *, read_scope_t);
exit_code_t device_write_active_settings(struct device *);
exit_code_t device_check_settings(struct device *, config_t, err_t);

struct device_list *device_list_new(struct subtype *);
void device_list_free(struct device_list *);
void device_list_add(struct device_list *, struct device *);
struct device *device_list_find(struct device_list *, const char *,
				struct device *);
void device_list_print(struct device_list *, int);
struct setting_list *device_get_setting_list(struct device *dev,
					     config_t config,
					     int site_id);

config_t device_get_config(struct device *dev);

#endif /* DEVICE_H */
