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
#include "misc.h"
#include "modprobe.h"
#include "module.h"
#include "path.h"
#include "setting.h"
#include "udev.h"
#include "zfcp.h"
#include "zfcp_host.h"
#include "zfcp_lun.h"

/*
 * zfcp type attributes.
 */

static struct attrib zfcp_tattr_dbfsize = {
	.name = "dbfsize",
	.title = "Modify buffer size for debugging records",
	.desc =
	"Control the number of 4 KB pages to be used for the debug feature\n",
	.defval = "4",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM_GE(1)),
};

static struct attrib zfcp_tattr_dbflevel = {
	.name = "dbflevel",
	.title = "Modify the minimum log level for debugging records",
	.desc =
	"Control the initial log level of the debug feature.\n",
	.defval = "3",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 6)),
};

static struct attrib zfcp_tattr_queue_depth = {
	.name = "queue_depth",
	.title = "Modify the initial maximum SCSI device queue depth",
	.desc =
	"Control the initial upper limit on the number of outstanding SCSI\n"
	"commands per SCSI device.\n",
	.nounload = 1,
	.defval = "32",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM_GE(1)),
};

static struct attrib zfcp_tattr_allow_lun_scan = {
	.name = "allow_lun_scan",
	.title = "Disable automatic LUN scanning in NPIV mode",
	.desc =
	"Control the use of the automatic LUN scanning feature for FCP\n"
	"devices that are configured in N_PORT ID Virtualization mode.\n"
	"  0: Automatic LUN scanning is disabled\n"
	"  1: Automatic LUN scanning is enabled\n",
	.nounload = 1,
	.defval = "1",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
};

static struct attrib zfcp_tattr_dif = {
	.name = "dif",
	.title = "Enable DIF data consistency checking",
	.desc =
	"Control the use of the DIF data consistency checking\n"
	"mechanism:\n"
	"  0: DIF is disabled\n"
	"  1: DIF is enabled when supported by the FCP device hardware\n",
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
};

static struct attrib zfcp_tattr_dix = {
	.name = "dix",
	.title = "Enable DIF&DIX data consistency checking",
	.desc =
	"Control the use of the end-to-end data consistency checking\n"
	"mechanism (DIF&DIX):\n"
	"  0: DIF&DIX is disabled\n"
	"  1: DIF&DIX is enabled when supported by the FCP device hardware\n",
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
};

static struct attrib zfcp_tattr_datarouter = {
	.name = "datarouter",
	.title = "Enable hardware data routing",
	.desc =
	"Control the use of the hardware data routing (DR) feature:\n"
	"  0: DR is disabled\n"
	"  1: DR is enabled when supported by the FCP device hardware\n",
	.defval = "1",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
};

static struct attrib zfcp_tattr_no_auto_port_rescan = {
	.name = "no_auto_port_rescan",
	.title = "Inhibit automatic port rescan",
	.desc =
	"Control the automatic port rescan feature:\n"
	"  0: Automatic port rescan is enabled\n"
	"  1: Automatic port rescan is disabled\n",
	.nounload = 1,
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
};

static struct attrib zfcp_tattr_port_scan_ratelimit = {
	.name = "port_scan_ratelimit",
	.title = "Minimum delay between automatic port scans",
	.desc =
	"Control the automatic port scan ratelimit:\n"
	"  0: Ratelimit is disabled\n"
	" >0: Minimum delay in milliseconds\n",
	.nounload = 1,
	.defval = "60000",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 4294967295)),
};

static struct attrib zfcp_tattr_port_scan_backoff = {
	.name = "port_scan_backoff",
	.title = "Avoid simultaneous automatic port scans",
	.desc =
	"Control the automatic port scan backoff:\n"
	"  0: Backoff is disabled\n"
	" >0: Random delay between 0 and given value in milliseconds\n",
	.nounload = 1,
	.defval = "500",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 4294967295)),
};

/*
 * ZFCP methods.
 */

/* Clean up all resources used by devtype object. */
static void zfcp_devtype_exit(struct devtype *dt)
{
	setting_list_free(dt->active_settings);
	setting_list_free(dt->persistent_settings);
}

static void bool_to_num(char *s)
{
	if (!s)
		return;
	if (strcasecmp(s, "y") == 0)
		*s = '1';
	else if (strcasecmp(s, "n") == 0)
		*s = '0';
}

static void all_bools_to_num(struct setting_list *list)
{
	struct setting *s;

	util_list_iterate(&list->list, s) {
		if (s->attrib == &zfcp_tattr_allow_lun_scan ||
		    s->attrib == &zfcp_tattr_dif ||
		    s->attrib == &zfcp_tattr_dix ||
		    s->attrib == &zfcp_tattr_datarouter ||
		    s->attrib == &zfcp_tattr_no_auto_port_rescan) {
			/* Convert Y to 1 and N to 0. */
			bool_to_num(s->value);
			bool_to_num(s->actual_value);
		}
	}
}

static exit_code_t zfcp_devtype_read_settings(struct devtype *dt,
					      config_t config)
{
	struct setting_list *list;
	char *path;
	exit_code_t rc = EXIT_OK;

	if (SCOPE_ACTIVE(config) && !dt->active_settings) {
		dt->active_exists = 0;
		rc = module_get_params(ZFCP_MOD_NAME, dt->type_attribs, &list);
		if (rc)
			return rc;
		if (list) {
			all_bools_to_num(list);
			dt->active_settings = list;
			setting_list_mark_default_derived(dt->active_settings);
			setting_list_apply_defaults(dt->active_settings,
						    dt->type_attribs, false);
			dt->active_exists = 1;
		} else
			dt->active_settings = setting_list_new();
	}

	if (SCOPE_PERSISTENT(config) && !dt->persistent_settings) {
		dt->persistent_exists = 0;
		path = path_get_modprobe_conf(dt);
		rc = modprobe_read_settings(path, ZFCP_MOD_NAME,
					    dt->type_attribs, &list);
		free(path);
		if (rc)
			return rc;
		if (list) {
			dt->persistent_settings = list;
			setting_list_apply_defaults(dt->persistent_settings,
						    dt->type_attribs, false);
			dt->persistent_exists = 1;
		} else
			dt->persistent_settings = setting_list_new();
	}

	return rc;
}

static exit_code_t zfcp_devtype_write_settings(struct devtype *dt,
					       config_t config)
{
	char *path;
	exit_code_t rc = EXIT_OK;

	if (SCOPE_ACTIVE(config) && dt->active_settings) {
		/* Try setting parameters directly via Sysfs. */
		if (module_set_params(ZFCP_MOD_NAME, dt->active_settings))
			goto persistent;

		/* Re-load kernel module.*/
		rc = module_load(ZFCP_MOD_NAME, NULL, dt->active_settings,
				 err_delayed_print);
		if (rc)
			return rc;
	}

persistent:
	if (SCOPE_PERSISTENT(config) && dt->persistent_settings) {
		path = path_get_modprobe_conf(dt);
		if (!rc) {
			rc = modprobe_write_settings(path, ZFCP_MOD_NAME,
						     dt->persistent_settings);
		}
		free(path);
	}

	return rc;
}

/* Determine the value of the allow_lun_scan zfcp attribute. */
exit_code_t zfcp_check_allow_lun_scan(int *allow, config_t config)
{
	struct devtype *dt = &zfcp_devtype;
	exit_code_t rc;
	struct setting *s;

	/* Check auto_lun_scan_setting. */
	rc = dt->read_settings(dt, config);
	if (rc)
		return rc;

	*allow = 1;

	if (SCOPE_ACTIVE(config)) {
		s = setting_list_find(dt->active_settings, "allow_lun_scan");
		if (s && strcmp(s->value, "0") == 0)
			*allow = 0;
	}

	if (SCOPE_PERSISTENT(config)) {
		s = setting_list_find(dt->persistent_settings,
				      "allow_lun_scan");
		if (s && strcmp(s->value, "0") == 0)
			*allow = 0;
	}

	return EXIT_OK;
}

/*
 * ZFCP device type.
 */

struct devtype zfcp_devtype = {
	.name		= "zfcp",
	.title		= "SCSI-over-Fibre Channel (FCP) devices and SCSI "
			  "devices",
	.devname	= "zFCP device",
	.modules	= STRING_ARRAY(ZFCP_MOD_NAME),

	.subtypes = SUBTYPE_ARRAY(
		&zfcp_host_subtype,
		&zfcp_lun_subtype,
	),

	.type_attribs = ATTRIB_ARRAY(
		&zfcp_tattr_dbfsize,
		&zfcp_tattr_dbflevel,
		&zfcp_tattr_queue_depth,
		&zfcp_tattr_allow_lun_scan,
		&zfcp_tattr_dif,
		&zfcp_tattr_dix,
		&zfcp_tattr_datarouter,
		&zfcp_tattr_no_auto_port_rescan,
		&zfcp_tattr_port_scan_ratelimit,
		&zfcp_tattr_port_scan_backoff,
	),
	.unknown_type_attribs	= 1,

	.exit			= &zfcp_devtype_exit,

	.read_settings		= &zfcp_devtype_read_settings,
	.write_settings		= &zfcp_devtype_write_settings,
};
