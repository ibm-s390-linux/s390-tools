/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>

#include "lib/util_path.h"

#include "device.h"
#include "devtype.h"
#include "misc.h"
#include "path.h"
#include "root.h"
#include "select.h"
#include "setting.h"
#include "subtype.h"

/* Determine if the root device was modified. If it was modified, run the
 * corresponding root-install scripts. */
exit_code_t root_check(void)
{
	struct util_list *selected, *params, *mod = NULL;
	struct selected_dev_node *sel;
	struct device *dev;
	char *params_str;
	exit_code_t rc;
	struct strlist_node *s;
	struct devtype *dt;

	debug("Checking for modified root device configuration\n");

	/* Get list of devices that provide the root device. */
	selected = selected_dev_list_new();
	rc = select_by_path(NULL, selected, config_active, scope_mandatory,
			    NULL, NULL, PATH_ROOT, err_print);
	if (rc)
		goto out;

	/* Determine if any of the devices or device types has been modified. */
	mod = strlist_new();
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
		    device_needs_writing(dev, config_persistent)) {
			strlist_add(mod, "%s %s", dev->subtype->devname,
				    dev->id);
		}
	}

	if (util_list_is_empty(mod))
		goto out;
	info("Note: Some of the changes affect devices providing the root "
	     "file system:\n");
	util_list_iterate(mod, s)
		info("       - %s\n", s->str);
	info("      Additional steps such as rebuilding the RAM-disk might be "
	     "required.\n");

	/* Check if script is available. */
	if (!util_path_is_reg_file(PATH_ROOT_SCRIPT))
		goto out;

	/* Ask for confirmation. */
	if (!confirm("Update persistent root device configuration now?")) {
		rc = EXIT_ABORTED;
		goto out;
	}

	/* Build the command line. */
	params = strlist_new();
	util_list_iterate(selected, sel) {
		strlist_add(params, "%s", sel->st->name);
		strlist_add(params, "%s", sel->id);
	}
	params_str = strlist_flatten(params, " ");
	strlist_free(params);

	/* Run update command. */
	if (misc_system(err_delayed_print, "%s %s", PATH_ROOT_SCRIPT,
			params_str) != 0) {
		error("Failure while updating root device configuration\n");
		delayed_print(DELAY_INDENT);
		rc = EXIT_RUNTIME_ERROR;
	}
	free(params_str);

out:
	strlist_free(mod);
	selected_dev_list_free(selected);

	return rc;
}
