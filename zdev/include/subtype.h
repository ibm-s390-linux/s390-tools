/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef SUBTYPE_H
#define SUBTYPE_H

#include "exit_code.h"
#include "misc.h"

#define SUBTYPE_TITLE_LEN	60

struct devtype;
struct device;
struct devnode;
struct namespace;
struct selected_dev_node;
struct subtype;
struct util_list;

extern struct subtype subtype_base;

/**
 * subtype_cb_t - Callback for subtype.for_each_id()
 * @subtype: Subtype
 * @id: Device ID
 * @config: Configuration specified to subtype.for_each_id()
 * @data: Private data pointer passed to subtype.for_each_id()
 *
 * This callback is called once for each device ID of a device that exists
 * in any of the configuration sets specified to subtype.for_each_id().
 * If the callback returns a value other than EXIT_OK, the loop is aborted
 * and the exit code is returned to the caller of subtype.for_each_id().
 */
typedef exit_code_t (*subtype_cb_t)(struct subtype *st, const char *id,
				    config_t config, void *data);

/**
 * struct subtype - Definition of a sub-type
 * @super: Use methods of the super subtype if this subtype does not implement
 *         a method.
 * @devtype: Pointer to device type
 * @name: Short name of this sub-type. Must be unique within this devtype.
 *        May be the same as the devtype name.
 * @title: Short description of this sub-type (max. 60 characters)
 * @devname: Short name for devices of this sub-type
 * @modules: (Optional) Array of kernel modules required for this subtype
 * @namespace: Namespace for devices of this device type
 * @data: Arbitrary data used by subtype methods
 * @dev_attribs: Array of device attributes
 * @prefix: Array of device attribut prefixes that are searched for
 *          attributes not listed in @dev_attribs. Trailing slashes must not be
 *          included.
 * @unknown_dev_attribs: Allow specification of unknown device attributes
 * @support_definable: Allow definition of devices
 * @generic: This is a generic subtype that is intended as a fallback only
 *
 * @devices: Devices of this subtype
 *
 * @init: Initialize subtype
 * @exit: Release dynamically allocated resources associated with this type
 *
 * @exists_active: Check if device exists in active configuration
 * @exists_persistent: Check if device exists in persistent configuration
 *
 * @add_active_ids: Add IDs of all devices existing in active configuration to
 *                  specified strlist
 * @add_persistent_ids: Add IDs of all devices existing in persistent
 *                      configuration to specified strlist
 *
 * @read_active: Read device configuration from active configuration
 * @read_persistent: Read device configuration from persistent configuration
 *
 * @configure_active: Apply configuration to active configuration
 * @configure_persistent: Apply configuration to persistent configuration
 *
 * @check_pre_write: Optional: Determine if the given configuration is valid
 *                   for the specified device. If not, emit warning messages
 *                   and return an exit code other than EXIT_OK. This function
 *                   is called before writing the device configuration.
 * @check_post_write: Optional: Determine if the given configuration is valid
 *                    for the specified device. If not, emit warning messages
 *                    and return an exit code other than EXIT_OK. This function
 *                    is called after writing the device configuration.
 *
 * @online_set: Optional: Set the online state of a device
 * @online_get: Optional: Retrieve device online state (0=offline, 1=online,
 *                        -1=not set)
 * @online_specified: Optional: Check if online setting was specified
 *
 * @add_errors: Optional: Add textual summaries of known error conditions
 *                        found for the specified device to the strlist.
 *
 * @add_devnodes: Optional: Add struct devnodes to specified ptrlist for each
 *                Linux device node or network interface that is provided by
 *                the device with the specified ID.
 * @resolve_devnode: Optional: Attempt to find the device ID of the device
 *                   providing the specified devnode. The result is a newly
 *                   allocated device ID string or %NULL.
 * @add_prereqs: Optional: For devices that require the configuration of
 *               other devices first, add corresponding selected_dev_nodes
 *               to list.
 * @add_modules: Optional: Add list of kernel module names required by
 *               device to strlist.
 * @remove_combined: Optional: For devices that combine multiple devices into
 *                   one "group" device, remove the IDs of devices that are
 *                   combined in the specified group device from the
 *                   selected_dev_nodes list.
 * @get_active_attrib_path: Optional: Return the absolute path to the specified
 *                          device attribute or device attribute prefix.
 * @get_active_attrib: Optional: Return the value of the specified device
 *                     attribute.
 *
 * @is_definable: Optional: Check if device can be defined
 * @detect_definable: Optional:  Detect configuration of definable device
 * @device_define: Optional: Define a device (e.g. group CCWGROUP device)
 * @device_undefine: Optional: Undefine a device
 * @add_definable_ids: Optional: Add IDs of all devices that can be defined to
 *                     specified strlist
 */
struct subtype {
	/* Static data. */
	struct subtype	*super;

	struct devtype	*devtype;
	const char	*name;
	const char	title[SUBTYPE_TITLE_LEN + 1];
	const char	*devname;
	const char	**modules;
	struct namespace *namespace;
	void		*data;

	struct attrib	**dev_attribs;
	const char	**prefixes;
	unsigned int	unknown_dev_attribs:1;
	unsigned int	support_definable:1;
	unsigned int	generic:1;

	/* Dynamic data. */
	struct device_list *devices;

	/* Methods */
	void		(*init)(struct subtype *);
	void		(*exit)(struct subtype *);

	bool		(*exists_active)(struct subtype *, const char *);
	bool		(*exists_persistent)(struct subtype *, const char *);

	void		(*add_active_ids)(struct subtype *, struct util_list *);
	void		(*add_persistent_ids)(struct subtype *,
					      struct util_list *);

	exit_code_t	(*read_active)(struct subtype *, struct device *,
				       read_scope_t);
	exit_code_t	(*read_persistent)(struct subtype *, struct device *,
					   read_scope_t);

	exit_code_t	(*configure_active)(struct subtype *, struct device *);
	exit_code_t	(*configure_persistent)(struct subtype *,
						struct device *);

	exit_code_t	(*deconfigure_active)(struct subtype *,
					      struct device *);
	exit_code_t	(*deconfigure_persistent)(struct subtype *,
						  struct device *);

	exit_code_t	(*check_pre_configure)(struct subtype *,
					       struct device *, int, config_t);
	exit_code_t	(*check_post_configure)(struct subtype *,
						struct device *, int, config_t);

	void		(*online_set)(struct subtype *, struct device *, int,
				      config_t);
	int		(*online_get)(struct subtype *, struct device *,
				      config_t);
	bool		(*online_specified)(struct subtype *, struct device *,
					  config_t);

	void		(*add_errors)(struct subtype *, const char *,
				      struct util_list *);

	void		(*add_devnodes)(struct subtype *, const char *,
					struct util_list *);
	char		*(*resolve_devnode)(struct subtype *, struct devnode *);
	void		(*add_prereqs)(struct subtype *, const char *,
				       struct util_list *);
	void		(*add_modules)(struct subtype *, struct device *,
				       struct util_list *);
	void		(*rem_combined)(struct subtype *, struct device *,
					struct selected_dev_node *,
					struct util_list *);
	char		*(*get_active_attrib_path)(struct subtype *,
						   struct device *,
						   const char *);
	char		*(*get_active_attrib)(struct subtype *, struct device *,
					      const char *);

	/* Optional methods for definable devices. */
	exit_code_t	(*is_definable)(struct subtype *, const char *, err_t);
	exit_code_t	(*detect_definable)(struct subtype *,
					    struct device *);
	exit_code_t	(*device_define)(struct subtype *, struct device *);
	exit_code_t	(*device_undefine)(struct subtype *, struct device *);
	void		(*add_definable_ids)(struct subtype *,
					     struct util_list *);
};

/* Subtype method accessor functions. */

void subtype_init(struct subtype *);
void subtype_exit(struct subtype *);

bool subtype_device_exists_active(struct subtype *, const char *);
bool subtype_device_exists_persistent(struct subtype *, const char *);

void subtype_add_active_ids(struct subtype *, struct util_list *);
void subtype_add_persistent_ids(struct subtype *, struct util_list *);

exit_code_t subtype_device_read_active(struct subtype *, struct device *,
				       read_scope_t);
exit_code_t subtype_device_read_persistent(struct subtype *, struct device *,
					   read_scope_t);

exit_code_t subtype_device_configure_active(struct subtype *, struct device *);
exit_code_t subtype_device_configure_persistent(struct subtype *,
						struct device *);

exit_code_t subtype_device_deconfigure_active(struct subtype *,
					      struct device *);
exit_code_t subtype_device_deconfigure_persistent(struct subtype *st,
						  struct device *);

exit_code_t subtype_check_pre_configure(struct subtype *, struct device *, int,
					config_t);
exit_code_t subtype_check_post_configure(struct subtype *, struct device *, int,
					 config_t);

void subtype_online_set(struct subtype *, struct device *, int, config_t);
int subtype_online_get(struct subtype *, struct device *, config_t);
bool subtype_online_specified(struct subtype *, struct device *, config_t);

void subtype_add_errors(struct subtype *, const char *, struct util_list *);
struct util_list *subtype_get_errors(struct subtype *st, const char *);

void subtype_add_modules(struct subtype *, struct device *, struct util_list *);
void subtype_add_devnodes(struct subtype *, const char *, struct util_list *);
char *subtype_resolve_devnode(struct subtype *, struct devnode *);
char *subtype_get_devnodes_str(struct subtype *, const char *, int, int, int,
			       int);
void subtype_add_prereqs(struct subtype *, const char *, struct util_list *);
void subtype_rem_combined(struct subtype *, struct device *,
			  struct selected_dev_node *, struct util_list *);
char *subtype_get_active_attrib_path(struct subtype *, struct device *,
				     const char *);
char *subtype_get_active_attrib(struct subtype *, struct device *,
				const char *);

exit_code_t subtype_device_is_definable(struct subtype *, const char *, err_t);
exit_code_t subtype_detect_definable(struct subtype *, struct device *);
exit_code_t subtype_device_define(struct subtype *, struct device *);
exit_code_t subtype_device_undefine(struct subtype *, struct device *);
void subtype_add_definable_ids(struct subtype *, struct util_list *);

/* Subtype helper functions. */
bool subtype_device_exists(struct subtype *st, const char *id,
			       config_t config);
exit_code_t subtype_for_each_id(struct subtype *st, config_t config,
				subtype_cb_t cb, void *data);
struct util_list *subtype_get_devnodes(struct subtype *st, const char *id);
exit_code_t subtype_read_device(struct subtype *st, const char *id,
				config_t config, read_scope_t,
				struct device **dev_ptr);
exit_code_t subtype_reread_device(struct subtype *st, const char *id,
				  config_t config, read_scope_t,
				  struct device **dev_ptr);
exit_code_t subtype_write_device(struct subtype *st, struct device *dev,
				 config_t config);

/* Generic helper functions. */
struct subtype *subtype_find(const char *name);
struct attrib *subtype_find_dev_attrib(struct subtype *st, const char *str);
exit_code_t subtype_read_all_devices(struct subtype *st, config_t config,
				     read_scope_t);
bool subtypes_find_by_devnode(struct devnode *devnode,
				  struct subtype **st_ptr, char **id_ptr);
void subtype_devices_print_all(void);
void subtype_add_static_modules(struct util_list *, struct subtype *);
unsigned long subtype_count_ids(struct subtype *, config_t);

void subtype_print(struct subtype *st, int indent);

#endif /* SUBTYPE_H */
