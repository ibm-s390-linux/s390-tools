/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attrib.h"
#include "ccw.h"
#include "device.h"
#include "devtype.h"
#include "internal.h"
#include "misc.h"
#include "path.h"
#include "setting.h"
#include "zfcp.h"
#include "zfcp_host.h"

/*
 * zfcp host attributes.
 */

static struct attrib zfcp_host_attr_failed = {
	.name = "failed",
	.title = "Check and restart FCP device recovery",
	.desc =
	"This attribute shows if error recovery of an FCP device has failed:\n"
	"  0: Error recovery has not failed or was not started\n"
	"  1: Error recovery was started and failed to complete\n"
	"     successfully even after several automatic retries\n\n"
	"Write the value 0 to this attribute to restart the error recovery\n"
	"process after resolving the root cause of the failure.\n",
	.activeonly = 1,
	.rewrite = 1,
	.unstable = 1,
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM(0)),
};

static struct attrib zfcp_host_attr_port_remove = {
	.name = "port_remove",
	.title = "Unregister a remote port from the FCP device",
	.desc =
	"Unregister a remote port from the FCP device by writing its WWPN\n"
	"to this attribute. The WWPN must be in a format with 16 hexadecimal\n"
	"digits and 0x prefix and no manually configured FCP LUNs may be\n"
	"registered with that remote port.\n\n"
	"Note: The next port scan will register all available ports again,\n"
	"including any previously removed ports. To prevent removed ports\n"
	"from being registered automatically, use zoning.\n",
	.writeonly = 1,
};

static struct attrib zfcp_host_attr_port_rescan = {
	.name = "port_rescan",
	.title = "Trigger a port rescan for the FCP device",
	.desc =
	"Rescan FCP device for available remote ports by writing the value 1\n"
	"to this attribute.\n",
	.activeonly = 1,
	.writeonly = 1,
	.accept = ACCEPT_ARRAY(ACCEPT_NUM(1)),
};

static struct attrib zfcp_host_attr_fc_security = {
	.name = "fc_security",
	.title = "Show FC Endpoint Security capability of FCP device",
	.desc =
	"This read-only attribute shows the Fibre Channel Endpoint Security\n"
	"capabilities of the FCP device.\n"
	"\n"
	"Possible values are either one of the following:\n"
	"  unknown       : The Fibre Channel Endpoint Security capabilities\n"
	"                  of the FCP device are not known\n"
	"  unsupported   : The FCP device does not support Fibre Channel\n"
	"                  Endpoint Security\n"
	"  none          : The FCP device does not report any Fibre Channel\n"
	"                  Endpoint Security capabilities\n"
	"\n"
	"Or one or more comma-separated values:\n"
	"  Authentication: The FCP device supports authentication\n"
	"  Encryption    : The FCP device supports encryption\n",
	.readonly = 1,
};

/*
 * zfcp host methods.
 */

static exit_code_t check_cmb_enable(struct subtype *st, struct device *dev,
				    config_t config)
{
	struct setting *c, *o;

	c = setting_list_find(dev->active.settings, ccw_attr_cmb_enable.name);
	o = setting_list_find(dev->active.settings, ccw_attr_online.name);

	if (!c || !o) {
		/* Could not determine attribute states. */
		return EXIT_OK;
	}

	if (c->modified && o->actual_value &&
	    strcmp(o->actual_value, "1") == 0 && strcmp(o->value, "0") != 0) {
		delayed_forceable("Cannot modify cmb_enable setting while "
				  "device is online\n");
		return EXIT_INVALID_CONFIG;
	}

	return EXIT_OK;
}

static exit_code_t zfcp_host_st_check_pre_configure(struct subtype *st,
						    struct device *dev,
						    int prereq, config_t config)
{
	exit_code_t rc;

	/* No need to check if device is deconfigured. */
	if (dev->active.deconfigured)
		return EXIT_OK;

	rc = check_cmb_enable(st, dev, config);
	if (rc)
		return rc;

	return EXIT_OK;
}

static char *get_port_type_path(const char *id)
{
	char *devpath, *path = NULL;
	struct util_list *files;
	struct strlist_node *s;

	devpath = path_get_ccw_device(ZFCP_CCWDRV_NAME, id);
	files = strlist_new();
	if (!misc_read_dir(devpath, files, NULL, NULL))
		goto out;
	util_list_iterate(files, s) {
		if (!starts_with(s->str, "host"))
			continue;
		path = misc_asprintf("%s/%s/fc_host/%s/port_type", devpath,
				     s->str, s->str);
	}
out:
	free(devpath);
	strlist_free(files);

	return path;
}

exit_code_t zfcp_host_check_npiv(const char *id, int *enabled)
{
	char *path, *type = NULL;
	exit_code_t rc = EXIT_RUNTIME_ERROR;

	path = get_port_type_path(id);
	if (!path)
		goto out;

	type = misc_read_text_file(path, 1, err_ignore);
	if (!type)
		goto out;

	/* Check FCP port type. */
	if (strcmp(type, "NPIV VPORT") == 0)
		*enabled = 1;
	else
		*enabled = 0;
	rc = EXIT_OK;

out:
	free(path);
	free(type);

	return rc;
}

static exit_code_t check_npiv(struct subtype *st, struct device *dev,
			      int prereq, config_t config)
{
	int npiv, allow_lun_scan;
	static int warn_done;

	if (prereq) {
		/* FCP device is configured as part of 3-tuple. */
		return EXIT_OK;
	}

	if (subtype_online_get(st, dev, config) != 1) {
		/* FCP device is set offline. */
		return EXIT_OK;
	}

	/* Check FCP port type. */
	if (zfcp_host_check_npiv(dev->id, &npiv)) {
		/* Could not determine NPIV setting. */
		return EXIT_OK;
	}
	if (!npiv) {
		delayed_info("Note: NPIV mode disabled - LUNs must be "
			     "configured manually\n");
		return EXIT_INVALID_CONFIG;
	}

	/* Check allow_lun_scan setting. */
	if (zfcp_check_allow_lun_scan(&allow_lun_scan, config)) {
		/* Could not determine allow_lun_scan setting. */
		return EXIT_OK;
	}
	if (!allow_lun_scan && !warn_done) {
		delayed_info("Note: Automatic LUN scan disabled - LUNs must "
			     "be configured manually\n");
		return EXIT_INVALID_CONFIG;
	}

	return EXIT_OK;
}

/* Perform post-write checks specific to zfcp hosts. */
static exit_code_t zfcp_host_st_check_post_configure(struct subtype *st,
						     struct device *dev,
						     int prereq,
						     config_t config)
{
	/* No need to check if device is deconfigured. */
	if (dev->active.deconfigured)
		return EXIT_OK;

	/* Check for NPIV but don't route exit code to caller - we only
	 * want to show a warning. */
	check_npiv(st, dev, prereq, config);

	return EXIT_OK;
}

/*
 * zfcp host sub-type.
 */

static struct ccw_subtype_data zfcp_host_data = {
	.ccwdrv		= ZFCP_CCWDRV_NAME,
	.mod		= ZFCP_MOD_NAME,
};

struct subtype zfcp_host_subtype = {
	.super		= &ccw_subtype,

	.devtype	= &zfcp_devtype,
	.name		= "zfcp-host",
	.title		= "FCP devices",
	.devname	= "FCP device",
	.modules	= STRING_ARRAY(ZFCP_MOD_NAME),
	.namespace	= &ccw_namespace,
	.data		= &zfcp_host_data,

	.dev_attribs = ATTRIB_ARRAY(
		&ccw_attr_online,
		&ccw_attr_cmb_enable,
		&zfcp_host_attr_failed,
		&zfcp_host_attr_port_remove,
		&zfcp_host_attr_port_rescan,
		&zfcp_host_attr_fc_security,
		&internal_attr_early,
	),
	.unknown_dev_attribs	= 1,

	.check_pre_configure	= &zfcp_host_st_check_pre_configure,
	.check_post_configure	= &zfcp_host_st_check_post_configure,
};
