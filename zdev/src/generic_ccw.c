/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>

#include "attrib.h"
#include "ccw.h"
#include "ccwgroup.h"
#include "devnode.h"
#include "devtype.h"
#include "generic_ccw.h"
#include "namespace.h"
#include "path.h"
#include "subtype.h"

/*
 * Generic CCW device sub-type.
 */

static struct ccw_subtype_data generic_ccw_data = {
	.ccwdrv		= NULL,
	.mod		= NULL,
};

/* Check if there is a non-generic subtype in the CCW namespace that uses the
 * specified CCW device driver. */
static bool match_non_generic(const char *drv)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	struct ccw_subtype_data *ccwdata;
	struct ccwgroup_subtype_data *ccwgroupdata;
	const char *ccwdrv;

	for (i = 0; (dt = devtypes[i]); i++) {
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (st->generic || !st->data)
				continue;
			if (st->namespace == &ccw_namespace) {
				ccwdata = st->data;
				ccwdrv = ccwdata->ccwdrv;
			} else if (st->namespace->cmp_parsed_ids ==
				   &ccwgroup_cmp_parsed_ids) {
				ccwgroupdata = st->data;
				ccwdrv = ccwgroupdata->ccwdrv;
			} else
				continue;
			if (!ccwdrv)
				continue;
			if (strcmp(drv, ccwdrv) == 0)
				return true;
		}
	}

	return false;
}

/* Determine if the specified device exists in the CCW namespace and is not
 * handled by another subtype. */
static bool generic_exists(struct subtype *st, const char *id, int fast)
{
	struct ccw_devid devid;
	char *drv = NULL;
	bool result = false;

	if (ccw_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		goto out;
	if (!fast && !ccw_exists(NULL, NULL, id))
		goto out;
	drv = ccw_get_driver(&devid);
	if (!drv) {
		/* Account devices with no driver to generic-ccw to make them
		 * visible. */
		result = true;
		goto out;
	}
	result = !match_non_generic(drv);

out:
	free(drv);

	return result;
}

static bool generic_ccw_st_exists_active(struct subtype *st, const char *id)
{
	return generic_exists(st, id, 0);
}

static bool get_ids_cb(const char *file, void *data)
{
	/* We use fast=1 here to prevent another stat() syscall per device
	 * when we already know that the directory exists. */
	return generic_exists(data, file, 1);
}

/* Add the IDs of all CCW devices existing in the active configuration which
 * are not handled by other subtypes. */
static void generic_ccw_st_add_active_ids(struct subtype *st,
					  struct util_list *ids)
{
	char *path;

	cio_settle(0);
	path = path_get_ccw_devices(NULL);
	misc_read_dir(path, ids, get_ids_cb, st);
	free(path);
}

struct add_cb_data {
	struct util_list *devnodes;
	const char *id;
};

static exit_code_t add_cb(const char *abs_path, const char *rel_path,
			  void *data)
{
	struct add_cb_data *cb_data = data;
	char *link, *target, *name;
	static const char *prefix[] = { "vmrdr-", "vmpun-", "vmprt-" };
	unsigned int i, major, minor;
	struct devnode *devnode;

	link = misc_readlink(abs_path);
	if (!link)
		return EXIT_OK;

	target = basename(link);
	for (i = 0; i < ARRAY_SIZE(prefix); i++) {
		name = misc_asprintf("%s%s", prefix[i], cb_data->id);
		if (strcmp(target, name) != 0)
			goto next;
		if (sscanf(rel_path, "%u:%u", &major, &minor) != 2)
			goto next;
		devnode = devnode_new(CHARDEV, major, minor, target);
		ptrlist_add(cb_data->devnodes, devnode);
next:
		free(name);
	}
	free(link);

	return EXIT_OK;
}

/* Add struct devnodes to ptrlist @devnodes for each Linux device that is
 * provided by the CCW device with the specified ID. Since this is a generic
 * CCW driver covering multiple device drivers, this is somewhat of trial
 * and error work. */
static void generic_ccw_st_add_devnodes(struct subtype *st, const char *id,
					struct util_list *devnodes)
{
	struct add_cb_data cb_data;
	char *path;

	cb_data.devnodes = devnodes;
	cb_data.id = id;
	path = path_get_sys_dev_char_devices();
	if (dir_exists(path))
		path_for_each(path, add_cb, &cb_data);
	free(path);
}

static struct subtype generic_ccw_subtype = {
	.super		= &ccw_subtype,
	.devtype	= &generic_ccw_devtype,
	.name		= "generic-ccw",
	.title		= "Generic Channel-Command-Word (CCW) devices",
	.devname	= "Generic CCW device",
	.modules	= NULL,
	.namespace	= &ccw_namespace,
	.data		= &generic_ccw_data,

	.dev_attribs = ATTRIB_ARRAY(
		&ccw_attr_online,
		&ccw_attr_cmb_enable,
	),
	.unknown_dev_attribs	= 1,
	.generic		= 1,

	.exists_active		= &generic_ccw_st_exists_active,
	.add_active_ids		= &generic_ccw_st_add_active_ids,
	.add_devnodes		= &generic_ccw_st_add_devnodes,
};

/*
 * Generic CCW device type methods.
 */

/* Clean up all resources used by devtype object. */
static void generic_ccw_devtype_exit(struct devtype *dt)
{
	setting_list_free(dt->active_settings);
	setting_list_free(dt->persistent_settings);
}

static exit_code_t generic_ccw_devtype_read_settings(struct devtype *dt,
						     config_t config)
{
	dt->active_settings = setting_list_new();
	dt->persistent_settings = setting_list_new();

	return EXIT_OK;
}

static exit_code_t generic_ccw_devtype_write_settings(struct devtype *dt,
						      config_t config)
{
	return EXIT_OK;
}

/*
 * Generic CCW device type.
 */

struct devtype generic_ccw_devtype = {
	.name		= "generic-ccw",
	.title		= "", /* Only use subtypes. */
	.devname	= "Generic CCW device",
	.modules	= NULL,

	.subtypes = SUBTYPE_ARRAY(
		&generic_ccw_subtype,
	),

	.type_attribs = ATTRIB_ARRAY(),

	.exit			= &generic_ccw_devtype_exit,

	.read_settings		= &generic_ccw_devtype_read_settings,
	.write_settings		= &generic_ccw_devtype_write_settings,
};
