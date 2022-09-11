/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DEVTYPE_H
#define DEVTYPE_H

#include <stddef.h>

#include "exit_code.h"
#include "misc.h"

#define DEVTYPE_TITLE_LEN	60

struct devtype;
struct device;
struct devnode;
struct namespace;
struct selected_dev_node;
struct subtype;
struct util_list;

/* NULL-terminated list of device types. */
extern struct devtype *devtypes[];

/* Define a NULL-terminated list of struct subtypes */
#define SUBTYPE_ARRAY(...)	((struct subtype *[]) { __VA_ARGS__ NULL })

/**
 * struct devtype - Definition of a device type
 * @name: Short name of this device type
 * @title: Short description of this device type (max. 60 characters).
 *         devtypes with empty title will not be shown with --list-types.
 * @devname: Short name for devices of this device type
 * @modules: (Optional) Array of kernel modules required for this devtype
 * @site_support: Support for site-specific configuration for the device-type
 * @subtypes: Array of subtypes
 * @type_attribs: Array of device type attributes (may point to empty array)
 * @unknown_type_attribs: Allow specification of unknown device type attributes
 * @processed: Set if device type has already been processed
 *
 * @active_settings: Device type settings from the active configuration
 * @persistent_settings: Device type settings from the persistent configuration
 * @active_exists: Devtype configuration exists in active configuration
 * @persistent_exists: Devtype configuration exists in persistent configuration
 *
 * @init: Initialize device type
 * @exit: Release dynamically allocated resources associated with this type
 * @read_settings: Retrieve device type settings from specified configuration
 * @write_settings: Apply device type settings to specified configuration
 */
struct devtype {
	/* Static data */
	const char	*name;
	const char	title[DEVTYPE_TITLE_LEN + 1];
	const char	*devname;
	const char	**modules;
	unsigned int	site_support:1;

	struct subtype **subtypes;
	struct attrib **type_attribs;
	unsigned int	unknown_type_attribs:1;

	/* Dynamic data */
	struct setting_list *active_settings;
	struct setting_list *persistent_settings;
	unsigned int	active_exists:1;
	unsigned int	persistent_exists:1;
	unsigned int	processed:1;

	/* Methods */
	void		(*init)(struct devtype *);
	void		(*exit)(struct devtype *);

	/* Devtype settings. */
	exit_code_t	(*read_settings)(struct devtype *, config_t);
	exit_code_t	(*write_settings)(struct devtype *, config_t);
};

void devtypes_init(void);
void devtypes_exit(void);

void devtype_print(struct devtype *, int);

struct devtype *devtype_find(const char *);
struct attrib *devtype_find_type_attrib(struct devtype *, const char *);
struct attrib *devtype_find_dev_attrib(struct devtype *, const char *);

exit_code_t devtype_apply_settings(struct devtype *, config_t,
				   struct util_list *);
exit_code_t devtype_apply_strlist(struct devtype *, config_t,
				  struct util_list *);

bool devtype_is_id_valid(struct devtype *, const char *);
bool devtype_is_id_range_valid(struct devtype *, const char *);
bool devtype_needs_writing(struct devtype *, config_t);

void devtype_add_modules(struct util_list *, struct devtype *, int);
bool devtype_is_module_loaded(struct devtype *);
int devtype_count_namespaces(struct devtype *);
int devtype_count_subtypes(struct devtype *);

struct namespace *devtype_most_similar_namespace(struct devtype *,
						 struct subtype *,
						 const char *id);

#endif /* DEVTYPE_H */
