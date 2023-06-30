/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

#include "lib/util_path.h"

#include "devnode.h"
#include "misc.h"
#include "net.h"
#include "path.h"

struct add_linked_cb_data {
	struct util_list *list;
	const char *prefix;
	size_t prefix_len;
	bool result;
};

/* Add a devnode to data->list for each sysfs link that indicates a linked
 * device. */
static exit_code_t add_linked_cb(const char *abs_path, const char *rel_path,
				 void *data)
{
	struct add_linked_cb_data *cb_data = data;
	const char *name;
	struct devnode *d;

	if (starts_with(rel_path, cb_data->prefix)) {
		name = rel_path + cb_data->prefix_len;
		d = devnode_new(NETDEV, 0, 0, name);
		ptrlist_add(cb_data->list, d);
		cb_data->result = true;
	}

	return EXIT_OK;
}

/* Add devnodes for all networking devices that are linked to @devnode via
 * a link starting with @prefix to @list. */
static bool add_devnodes_from_link(struct util_list *list,
				   struct devnode *devnode, const char *prefix)
{
	struct add_linked_cb_data cb_data;
	char *path;

	cb_data.list = list;
	cb_data.prefix = prefix;
	cb_data.prefix_len = strlen(prefix);
	cb_data.result = false;
	path = path_get_sys_class("net", devnode->name);
	if (util_path_exists(path))
		path_for_each(path, add_linked_cb, &cb_data);
	free(path);

	return cb_data.result;
}

/* Add devnodes for all devices to @list that are linked as "lower" devices
 * of network interface @devnode. */
bool net_add_linked_devnodes(struct util_list *list, struct devnode *devnode)
{
	return add_devnodes_from_link(list, devnode, "lower_");
}

#define DEVICE_PREFIX	"Device:"

/* If @devnode refers to a vlan device, add a devnode representing its
 * base device to @list. */
bool net_add_vlan_base(struct util_list *list, struct devnode *devnode)
{
	char *path, *text, *name, *end;
	bool rc = false;

	path = path_get("/proc/net/vlan/%s", devnode->name);
	text = misc_read_text_file(path, 0, err_ignore);
	if (!text)
		goto out;

	name = strstr(text, DEVICE_PREFIX);
	if (!name)
		goto out;
	name += sizeof(DEVICE_PREFIX) - 1;

	for (; *name && isspace(*name); name++) ;
	for (end = name; *end && !isspace(*end); end++) ;
	if (name == end)
		goto out;
	*end = 0;
	ptrlist_add(list, devnode_new(NETDEV, 0, 0, name));
	rc = true;

out:
	free(text);
	free(path);

	return rc;
}

/* If @devnode refers to a bonding device, add a devnode representing its
 * base device to @list. */
bool net_add_bonding_base(struct util_list *list, struct devnode *devnode)
{
	return add_devnodes_from_link(list, devnode, "slave_");
}
