/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>

#include "lib/util_path.h"

#include "device.h"
#include "devtype.h"
#include "internal.h"
#include "misc.h"
#include "path.h"
#include "root.h"
#include "select.h"
#include "setting.h"
#include "subtype.h"

static bool is_early_removed(struct device *dev)
{
	struct setting *s;

	s = setting_list_find(dev->persistent.settings,
			      internal_attr_early.name);
	if (!s || !s->modified)
		return false;
	if (!s->actual_value || strcmp(s->actual_value, "1") != 0)
		return false;
	if (s->removed || strcmp(s->value, "0") == 0)
		return true;
	return false;
}

static void add_early_removed(struct util_list *selected)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	struct device *dev;

	for (i = 0; devtypes[i]; i++) {
		dt = devtypes[i];
		for (j = 0; dt->subtypes[j]; j++) {
			st = dt->subtypes[j];
			util_list_iterate(&st->devices->hash.list, dev) {
				if (is_early_removed(dev)) {
					selected_dev_list_add(selected, dt, st,
						dev->id, NULL, EXIT_OK);
				}
			}
		}
	}
}

static void add_pers_removed(struct util_list *strlist)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	struct device *dev;

	for (i = 0; devtypes[i]; i++) {
		dt = devtypes[i];
		for (j = 0; dt->subtypes[j]; j++) {
			st = dt->subtypes[j];
			util_list_iterate(&st->devices->hash.list, dev) {
				if (dev->persistent.deconfigured) {
					strlist_add(strlist, "%s %s",
						    dev->subtype->devname, dev->id);
				}
			}
		}
	}
}

static bool is_zdev_early_0(struct selected_dev_node *sel)
{
	struct setting *s;
	struct device *dev;

	dev = device_list_find(sel->st->devices, sel->id, NULL);
	if (!dev)
		return false;
	s = setting_list_find(dev->persistent.settings,
			      internal_attr_early.name);
	if (!s)
		return false;
	if (s->specified && strcmp(s->value, "0") == 0)
		return true;

	return false;
}

/* Determine if initial RAM-disk needs updating. If so, run the corresponding
 * scripts if available. */
exit_code_t initrd_check(bool all_pers)
{
	struct util_list *selected, *params, *mod = strlist_new();
	struct selected_dev_node *sel;
	struct device *dev;
	char *params_str;
	exit_code_t rc = EXIT_OK;
	struct strlist_node *s;
	struct devtype *dt;
	struct select_opts *select;

	debug("Checking for required initial RAM-disk update\n");

	/* Get list of devices that provide the root device or require
	 * early configuration. */
	selected = selected_dev_list_new();

	if (all_pers) {
		/* Add all persistently configured devices. */
		select = select_opts_new();
		select->configured = 1;
		select_devices(select, selected, 1, 0, 0, config_persistent,
			       scope_mandatory, err_ignore);
		select_opts_free(select);

		/* Ensure that removed devices are considered. */
		add_pers_removed(mod);
		goto check_mod;
	}

	/* First add devices that had zdev:early removed or changed to 0.
	 * The subsequent call to select_devices() will filter out any
	 * duplicates. */
	add_early_removed(selected);
	/* Now add devices required for root file system. */
	if (select_by_path(NULL, selected, config_active, scope_mandatory,
			   NULL, NULL, PATH_ROOT, err_ignore)) {
		/* Running from an unknown root device is not an error. */
		verb("Note: Could not determine if root device configuration "
		     "needs to be updated\n");
	}
	/* Finally add devices with zdev:early=1. */
	select = select_opts_new();
	strlist_add(&select->by_attr, "%s=1", INTERNAL_ATTR_EARLY);
	select_devices(select, selected, 1, 0, 0,
		       config_active | config_persistent, scope_mandatory,
		       err_ignore);
	select_opts_free(select);

check_mod:
	/* Determine if any of the devices or device types has been modified. */
	util_list_iterate(selected, sel) {
		dt = sel->st->devtype;

		/* Check devtype. */
		if (devtype_needs_writing(dt, config_persistent)) {
			strlist_add(mod, "Device type %s",
				    sel->st->devtype->name);
		}

		/* Check devices. */
		dev = device_list_find(sel->st->devices, sel->id, NULL);
		if (dev && dev->persistent.exists &&
		    (device_needs_writing(dev, config_persistent) || force)) {
			strlist_add(mod, "%s %s", dev->subtype->devname,
				    dev->id);
		}
	}

	if (util_list_is_empty(mod))
		goto out;
	info("Note: The initial RAM-disk must be updated for these changes to take effect:\n");
	util_list_iterate(mod, s)
		info("       - %s\n", s->str);

	/* Check if script is available. */
	if (!util_path_is_reg_file(PATH_ROOT_SCRIPT)) {
		warn("A manual update of the initial RAM-disk is required.\n");
		goto out;
	}

	if (!all_pers) {
		/* Ask for confirmation. */
		if (!confirm("Update initial RAM-disk now?")) {
			rc = EXIT_ABORTED;
			goto out;
		}
	}

	/* Build the command line. */
	params = strlist_new();
	util_list_iterate(selected, sel) {
		/* From the selected list, remove the devices with zdev:early=0 */
		if (!is_zdev_early_0(sel)) {
			strlist_add(params, "%s", sel->st->name);
			strlist_add(params, "%s", sel->id);
		}
	}
	params_str = strlist_flatten(params, " ");
	strlist_free(params);

	/* Run update command. */
	if (misc_system(err_delayed_print, "%s %s", PATH_ROOT_SCRIPT,
			params_str) != 0) {
		error("Failure while updating initial RAM-disk\n");
		delayed_print(DELAY_INDENT);
		rc = EXIT_RUNTIME_ERROR;
	}
	free(params_str);

out:
	strlist_free(mod);
	selected_dev_list_free(selected);

	return rc;
}
