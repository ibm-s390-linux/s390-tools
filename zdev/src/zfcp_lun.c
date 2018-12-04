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

#include "lib/util_path.h"

#include "attrib.h"
#include "ccw.h"
#include "device.h"
#include "devnode.h"
#include "devtype.h"
#include "misc.h"
#include "internal.h"
#include "namespace.h"
#include "path.h"
#include "scsi.h"
#include "select.h"
#include "udev.h"
#include "udev_zfcp_lun.h"
#include "zfcp.h"
#include "zfcp_host.h"
#include "zfcp_lun.h"

#define DEVNAME			"zFCP LUN"
#define FC_SECURITY_VATTR	"fc_security"

/*
 * zfcp lun namespace.
 *
 * ID format: <fcp_dev>:<wwpn>:<lun>
 * fcp_dev: FCP device bus-ID (CCW device ID): aaaa or aa.b.cccc
 * wwpn: Target port World Wide Port Name: aaaaaaaaaaaaaaaa or
 *       0xaaaaaaaaaaaaaaaa
 * lun: FCP LUN: aaaaaaaaaaaaaaaa or 0xaaaaaaaaaaaaaaaa
 */

exit_code_t zfcp_lun_parse_devid(struct zfcp_lun_devid *devid_ptr,
				 const char *id, err_t err)
{
	exit_code_t rc = EXIT_INVALID_ID;
	char *copy, *curr, *delim, *reason = NULL;
	struct ccw_devid fcp_dev;
	uint64_t wwpn, lun;
	char dummy;

	copy = misc_strdup(id);
	curr = copy;

	/* Parse FCP device ID. */
	delim = strchr(curr, ':');
	if (!delim) {
		reason = "Missing colon (':')";
		goto out;
	}
	*delim = 0;

	if (ccw_parse_devid(&fcp_dev, copy, err) != EXIT_OK)
		goto out;

	curr = delim + 1;

	/* Parse WWPN. */
	delim = strchr(curr, ':');
	if (!delim) {
		reason = "Missing second colon (':')";
		goto out;
	}
	*delim = 0;
	if (strncasecmp(curr, "0x", 2) == 0)
		curr += 2;
	if (strlen(curr) != 16) {
		reason = "WWPN not in 16 digit format";
		rc = EXIT_ZFCP_INVALID_WWPN;
		goto out;
	}
	if (sscanf(curr, "%16" SCNx64 " %c", &wwpn, &dummy) != 1) {
		reason = "WWPN not a valid hex number";
		rc = EXIT_ZFCP_INVALID_WWPN;
		goto out;
	}
	curr = delim + 1;

	/* Parse LUN. */
	if (strncasecmp(curr, "0x", 2) == 0)
		curr += 2;
	if (strlen(curr) != 16) {
		reason = "LUN not in 16 digit format";
		rc = EXIT_ZFCP_INVALID_LUN;
		goto out;
	}
	if (sscanf(curr, "%16" SCNx64 " %c", &lun, &dummy) != 1) {
		reason = "LUN not a valid hex number";
		rc = EXIT_ZFCP_INVALID_LUN;
		goto out;
	}

	if (devid_ptr) {
		devid_ptr->fcp_dev = fcp_dev;
		devid_ptr->wwpn = wwpn;
		devid_ptr->lun = lun;
	}
	rc = EXIT_OK;

out:
	if (reason) {
		err_t_print(err, "Error in %s ID format: %s: %s\n", DEVNAME,
			    reason, id);
	}
	free(copy);

	return rc;
}

/* Check for a valid ID. */
static exit_code_t zfcp_lun_is_id_valid(const char *id, err_t err)
{
	return zfcp_lun_parse_devid(NULL, id, err);
}

/* Check if @ID is roughly similar in format to a zfcp LUN ID. */
static bool zfcp_lun_is_id_similar(const char *id)
{
	char *copy, *start, *end;
	bool result = false;

	copy = misc_strdup(id);
	start = copy;

	/* ccwid:hex:hex */
	end = strchr(start, ':');
	if (!end)
		goto out;
	*end = 0;
	if (!ccw_is_id_similar(start))
		goto out;
	start = end + 1;

	end = strchr(start, ':');
	if (!end)
		goto out;
	*end = 0;
	if (!valid_hex(start))
		goto out;
	start = end + 1;

	if (valid_hex(start))
		result = true;

out:
	free(copy);

	return result;
}

/* Compare two IDs in parsed format. */
static int zfcp_lun_cmp_parsed_ids(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct zfcp_lun_devid));
}

/* Compare two IDs. */
int zfcp_lun_cmp_devids(struct zfcp_lun_devid *a, struct zfcp_lun_devid *b)
{
	return zfcp_lun_cmp_parsed_ids(a, b);
}

/* Compare two IDs in textual format. */
static int zfcp_lun_cmp_ids(const char *a_str, const char *b_str)
{
	struct zfcp_lun_devid a, b;

	if (zfcp_lun_parse_devid(&a, a_str, err_ignore) != EXIT_OK ||
	    zfcp_lun_parse_devid(&b, b_str, err_ignore) != EXIT_OK)
		return -1;

	return zfcp_lun_cmp_parsed_ids(&a, &b);
}

static int zfcp_lun_qsort_cmp(const void *a_ptr, const void *b_ptr)
{
	const char *a = *((const char **) a_ptr);
	const char *b = *((const char **) b_ptr);

	return zfcp_lun_cmp_ids(a, b);
}

/* Return a newly allocated string representing the specified device ID. */
char *zfcp_lun_devid_to_str(struct zfcp_lun_devid *devid)
{
	return misc_asprintf("%x.%x.%04x:0x%016" PRIx64 ":0x%016" PRIx64,
			     devid->fcp_dev.cssid, devid->fcp_dev.ssid,
			     devid->fcp_dev.devno, devid->wwpn, devid->lun);
}

/* Return a newly allocated, normalized textual representation of the specified
 * ID. */
static char *zfcp_lun_normalize_id(const char *id)
{
	struct zfcp_lun_devid devid;

	if (zfcp_lun_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return NULL;

	return zfcp_lun_devid_to_str(&devid);
}

/* Return a newly allocated parsed device ID object. */
static void *zfcp_lun_parse_id(const char *id, err_t err)
{
	struct zfcp_lun_devid *devid;

	devid = misc_malloc(sizeof(struct zfcp_lun_devid));
	if (zfcp_lun_parse_devid(devid, id, err) != EXIT_OK) {
		free(devid);
		return NULL;
	}

	return devid;
}

/* Check if a range is valid. */
static exit_code_t zfcp_lun_is_id_range_valid(const char *range, err_t err)
{
	/* No ranges are supported on zfcp lun IDs. */
	err_t_print(err, "Ranges not supported on %s device ID: %s\n",
		    DEVNAME, range);

	return EXIT_INVALID_ID;
}

static unsigned long zfcp_lun_num_ids_in_range(const char *range)
{
	/* No ranges are supported on zfcp lun IDs. */
	return 0;
}

static bool zfcp_lun_is_id_in_range(const char *id, const char *range)
{
	/* No ranges are supported on zfcp lun IDs. */
	return false;
}

static void zfcp_lun_range_start(struct ns_range_iterator *it,
				 const char *range)
{
	/* No ranges are supported on zfcp lun IDs. */
	memset(it, 0, sizeof(struct ns_range_iterator));
}

static void zfcp_lun_range_next(struct ns_range_iterator *it)
{
	/* No ranges are supported on zfcp lun IDs. */
}

static char *get_fcp_id(const char *id)
{
	char *fcp_id, *end;

	fcp_id = misc_strdup(id);
	end = strchr(fcp_id, ':');
	if (end)
		*end = 0;

	return fcp_id;
}

static bool zfcp_lun_is_id_blacklisted(const char *id)
{
	struct namespace *ns = zfcp_host_subtype.namespace;
	char *fcp_id = get_fcp_id(id);
	bool result = false;

	if (ns && ns->is_id_blacklisted)
		result = ns->is_id_blacklisted(fcp_id);
	free(fcp_id);

	return result;
}

static void zfcp_lun_unblacklist_id(const char *id)
{
	struct namespace *ns = zfcp_host_subtype.namespace;
	char *fcp_id = get_fcp_id(id);

	if (ns && ns->unblacklist_id)
		ns->unblacklist_id(fcp_id);
	free(fcp_id);
}

struct namespace zfcp_lun_namespace = {
	.devname		= "zFCP LUN",
	.is_id_valid		= zfcp_lun_is_id_valid,
	.is_id_similar		= zfcp_lun_is_id_similar,
	.cmp_ids		= zfcp_lun_cmp_ids,
	.normalize_id		= zfcp_lun_normalize_id,
	.parse_id		= zfcp_lun_parse_id,
	.cmp_parsed_ids		= zfcp_lun_cmp_parsed_ids,
	.qsort_cmp		= zfcp_lun_qsort_cmp,
	.is_id_range_valid	= zfcp_lun_is_id_range_valid,
	.num_ids_in_range	= zfcp_lun_num_ids_in_range,
	.is_id_in_range		= zfcp_lun_is_id_in_range,
	.range_start		= zfcp_lun_range_start,
	.range_next		= zfcp_lun_range_next,
	.is_id_blacklisted	= zfcp_lun_is_id_blacklisted,
	.unblacklist_id		= zfcp_lun_unblacklist_id,
};

/*
 * zfcp lun device attributes.
 */

static struct attrib zfcp_lun_attr_failed = {
	.name = "failed",
	.title = "Check and restart FCP SCSI device recovery",
	.desc =
	"This attribute shows if error recovery of an FCP SCSI device has\n"
	"failed:\n"
	"  0: Error recovery has not failed or was not started\n"
	"  1: Error recovery was started and failed to complete\n"
	"     successfully\n\n"
	"Write the value 0 to this attribute to restart the error recovery\n"
	"process after resolving the root cause of the failure.\n",
	.activeonly = 1,
	.rewrite = 1,
	.unstable = 1,
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM(0)),
};

static struct attrib zfcp_lun_attr_scsi_queue_depth = {
	.name = SCSI_ATTR_PREFIX "/queue_depth",
	.title = "Modify the maximum SCSI device queue depth",
	.desc =
	"Control the upper limit on the number of outstanding SCSI commands\n"
	"of a SCSI device. Note that storage servers typically limit the\n"
	"total number of outstanding SCSI commands of all SCSI devices\n"
	"accessed from all attached hosts.\n",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM_GE(1)),
};

static struct attrib zfcp_lun_attr_scsi_queue_ramp_up_period = {
	.name = SCSI_ATTR_PREFIX "/queue_ramp_up_period",
	.title = "Modify SCSI device queue depth ramp up period",
	.desc =
	"Linux automatically reduces the queue depth for a SCSI device when\n"
	"the storage device lacks the resources to process a command. Use\n"
	"this attribute to control the time in milliseconds that Linux waits\n"
	"before increasing the queue depth again after such an event.\n",
	.defval = "120000",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM_GE(1)),
};

static struct attrib zfcp_lun_attr_scsi_rescan = {
	.name = SCSI_ATTR_PREFIX "/rescan",
	.title = "Trigger a rescan of SCSI device information",
	.desc =
	"Trigger a rescan of SCSI device information by writing 1 to this\n"
	"attribute, e.g. after having dynamically reconfigured the size or\n"
	"type of the corresponding logical unit on the storage server.\n",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM(1)),
	.activeonly = 1,
	.rewrite = 1,
};

static struct attrib zfcp_lun_attr_scsi_timeout = {
	.name = SCSI_ATTR_PREFIX "/timeout",
	.title = "Modify the SCSI command timeout value",
	.desc =
	"Control the time in seconds that the SCSI layer waits for the\n"
	"completion of a running SCSI command before considering that SCSI\n"
	"command to have failed.\n",
	.defval = "30",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM_GE(1)),
};

static struct attrib zfcp_lun_attr_scsi_state = {
	.name = SCSI_ATTR_PREFIX "/state",
	.title = "Control SCSI device state",
	.desc =
	"Set the state of a SCSI device back to 'running' after resolving\n"
	"the root cause for the failure that set the state to 'offline'.\n",
	.defval = "running",
	.accept = ACCEPT_ARRAY(ACCEPT_STR("running"), ACCEPT_STR("offline")),
	.activeonly = 1,
	.rewrite = 1,
	.newline = 1,
};

static struct attrib zfcp_lun_attr_scsi_delete = {
	.name = SCSI_ATTR_PREFIX "/delete",
	.title = "Remove SCSI device",
	.desc =
	"Temporarily remove the SCSI device by writing '1' to this attribute.\n"
	"This should only be done after quiescing the device, flushing all\n"
	"pending I/O requests and removing any virtual devices stacked on top\n"
	"of this device.\n\n"
	"Note: If automatic LUN scanning is active, the next LUN scan will\n"
	"add all available SCSI devices again, including any previously\n"
	"removed ones. To prevent removed SCSI devices from being added\n"
	"automatically, deconfigure the LUN on the storage target, or disable\n"
	"automatic LUN scanning. In case of manually configured LUNs, the\n"
	"next LUN recovery will add the corresponding SCSI device again if\n"
	"available. To permanently remove a manually configured LUN with its\n"
	"SCSI device, please deconfigure the zFCP LUN.\n",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM(1)),
};

static struct attrib zfcp_lun_attr_fc_security = {
	.name = FC_SECURITY_VATTR,
	.title = "Show FC Endpoint Security state of connection",
	.desc =
	"This read-only attribute shows the current state of Fibre Channel\n"
	"Endpoint Security of the connection between the FCP device and the\n"
	"FC remote port used to access the LUN:\n"
	"  unknown       : The Fibre Channel Endpoint Security state of the\n"
	"                  connection is not known\n"
	"  unsupported   : The FCP device does not support Fibre Channel\n"
	"                  Endpoint Security\n"
	"  none          : The connection has no Fibre Channel Endpoint\n"
	"                  Security\n"
	"  Authentication: The connection has been authenticated\n"
	"  Encryption    : The connection is encrypted\n",
	.readonly = 1,
};

/*
 * zfcp lun device methods.
 */

/* Read state of a zfcp lun device from the active configuration. */
static exit_code_t zfcp_lun_st_read_active(struct subtype *st,
					   struct device *dev,
					   read_scope_t scope)
{
	struct device_state *state = &dev->active;
	char *hctl, *fc_path;
	bool fc_exists = false, scsi_exists = false;
	struct setting *s;

	state->modified = 0;
	state->deconfigured = 0;
	state->definable = 0;

	/* Check for FC unit. */
	fc_path = path_get_zfcp_lun_dev(dev->devid);
	fc_exists = util_path_exists(fc_path);
	free(fc_path);

	/* Check for SCSI device. */
	hctl = scsi_hctl_from_zfcp_lun_devid(dev->devid);
	if (hctl)
		scsi_exists = true;

	/* Count broken devices with FC unit but no SCSI device as existing
	 * to make them visible and allow for deconfiguration. */
	if (fc_exists || scsi_exists) {
		state->exists = 1;
		device_read_active_settings(dev, scope);
	} else
		state->exists = 0;

	if (scope == scope_all) {
		/* Add special attribute values. */
		if (hctl) {
			s = setting_list_apply_actual(dev->active.settings,
						      NULL, SCSI_ATTR_PREFIX,
						      hctl);
			s->readonly = 1;
		}
	}

	free(hctl);

	return EXIT_OK;
}

static exit_code_t zfcp_lun_st_read_persistent(struct subtype *st,
					       struct device *dev,
					       read_scope_t scope)
{
	return udev_zfcp_lun_read_device(dev, false);
}

static exit_code_t zfcp_lun_st_read_autoconf(struct subtype *st,
					     struct device *dev,
					     read_scope_t scope)
{
	return udev_zfcp_lun_read_device(dev, true);
}

static exit_code_t zfcp_lun_add(struct device *dev)
{
	struct zfcp_lun_devid *devid = dev->devid;
	char *fcp_dev_id, *lunpath = NULL, *portpath = NULL, *path = NULL,
	     *lun = NULL, *failed = NULL, *hctl = NULL;
	exit_code_t rc = EXIT_OK;

	/* Check if LUN already exists. */
	fcp_dev_id = ccw_devid_to_str(&devid->fcp_dev);
	lunpath = path_get_zfcp_lun_dev(devid);
	if (util_path_is_dir(lunpath)) {
		hctl = scsi_hctl_from_zfcp_lun_devid(devid);
		if (!hctl)
			goto check_failed;
		goto out;
	}

	portpath = path_get_zfcp_port_dev(devid);
	if (!util_path_is_dir(portpath)) {
		delayed_err("Target port not found\n");
		rc = EXIT_ZFCP_WWPN_NOT_FOUND;
		goto out;
	}
	path = misc_asprintf("%s/unit_add", portpath);
	lun = misc_asprintf("0x%016" PRIx64, devid->lun);

	rc = misc_write_text_file(path, lun, err_delayed_print);
	if (rc) {
		delayed_warn("Could not add LUN %016" PRIx64 " to WWPN 0x%"
			 PRIx64 "of FCP device %s\n", devid->lun, devid->wwpn,
			 fcp_dev_id);
		goto out;
	}
	free(path);

	/* Reset failed attribute if necessary. */
check_failed:
	path = misc_asprintf("%s/failed", lunpath);
	failed = misc_read_text_file(path, 1, err_ignore);
	if (failed && strcmp(failed, "1") == 0) {
		verb("%s %s: LUN is in failed state - attempting recovery\n",
		     dev->subtype->devname, dev->id);
		/* FCP LUN is in failed state, try to recover. */
		misc_write_text_file(path, "0", err_ignore);
	}

	/* Need to wait for UDEV events here to ensure that SCSI device
	 * registration has completed. */
	udev_settle();

	/* Clear cached HCTL information. */
	scsi_reread();

	if (hctl)
		goto out;

	/* Re-check for SCSI device. */
	hctl = scsi_hctl_from_zfcp_lun_devid(devid);
	if (hctl)
		goto out;

	delayed_err("No SCSI device found - check FCP LUN ID and SAN "
		    "settings\n");
	rc = EXIT_ZFCP_SCSI_NOT_FOUND;

	if (lun && !force) {
		/* Undo failed unit_add. */
		free(path);
		path = misc_asprintf("%s/unit_remove", portpath);
		misc_write_text_file(path, lun, err_print);
	}

out:
	free(failed);
	free(lun);
	free(path);
	free(portpath);
	free(hctl);
	free(lunpath);
	free(fcp_dev_id);

	return rc;
}

/* Apply the settings of an zfcp lun to the active configuration. */
static exit_code_t zfcp_lun_st_configure_active(struct subtype *st,
						struct device *dev)
{
	return device_write_active_settings(dev);
}

static exit_code_t zfcp_lun_st_configure_persistent(struct subtype *st,
						    struct device *dev)
{
	return udev_zfcp_lun_write_device(dev, false);
}

static exit_code_t zfcp_lun_st_configure_autoconf(struct subtype *st,
						  struct device *dev)
{
	return udev_zfcp_lun_write_device(dev, true);
}

static exit_code_t zfcp_lun_st_deconfigure_active(struct subtype *st,
						  struct device *dev)
{
	/* No additional step required - LUNs are undefined using
	 * zfcp_lun_st_device_undefine */
	return EXIT_OK;
}

static exit_code_t zfcp_lun_st_deconfigure_persistent(struct subtype *st,
						      struct device *dev)
{
	return udev_zfcp_lun_remove_rule(dev->id, false);
}

static exit_code_t zfcp_lun_st_deconfigure_autoconf(struct subtype *st,
						    struct device *dev)
{
	return udev_zfcp_lun_remove_rule(dev->id, true);
}

static exit_code_t check_npiv(struct subtype *st, struct device *dev,
			      config_t config)
{
	struct zfcp_lun_devid *devid = dev->devid;
	char *fcp_dev_id;
	exit_code_t rc = EXIT_OK;
	int npiv, allow_lun_scan;

	/* Check FCP port type. */
	fcp_dev_id = ccw_devid_to_str(&devid->fcp_dev);
	if (zfcp_host_check_npiv(fcp_dev_id, &npiv)) {
		/* Could not determine NPIV setting. */
		goto out;
	}
	if (!npiv)
		goto out;

	/* Check allow_lun_scan setting. */
	if (zfcp_check_allow_lun_scan(&allow_lun_scan, config)) {
		/* Could not determine allow_lun_scan setting. */
		goto out;
	}
	if (!allow_lun_scan)
		goto out;

	if (!(dev->active.deconfigured || dev->persistent.deconfigured ||
	      dev->autoconf.deconfigured)) {
		delayed_info("Note: Auto LUN scan enabled - manual LUN "
			     "configuration is redundant for %s %s\n",
			     zfcp_host_subtype.devname, fcp_dev_id);
	} else if (dev->active.deconfigured) {
		delayed_forceable("Auto LUN scan enabled - cannot permanently "
				  "deconfigure LUN\n");
	}
	rc = EXIT_INVALID_CONFIG;

out:
	free(fcp_dev_id);

	return rc;
}

static exit_code_t zfcp_lun_st_check_pre_configure(struct subtype *st,
						   struct device *dev,
						   int prereq, config_t config)
{
	/* No need to check if device is not deconfigured. */
	if (!dev->active.deconfigured)
		return EXIT_OK;

	return check_npiv(st, dev, config);
}

static exit_code_t zfcp_lun_st_check_post_configure(struct subtype *st,
						    struct device *dev,
						    int prereq, config_t config)
{
	/* No need to check if device is deconfigured. */
	if (dev->active.deconfigured)
		return EXIT_OK;

	/* Don't show note when an attribute was modified. */
	if (setting_list_modified(dev->active.settings) ||
	    setting_list_modified(dev->persistent.settings) ||
	    setting_list_modified(dev->autoconf.settings))
		return EXIT_OK;

	/* Check for NPIV but don't route exit code to caller - we only
	 * want to show a warning. */
	check_npiv(st, dev, config);

	return EXIT_OK;
}

static exit_code_t zfcp_lun_st_device_define(struct subtype *st,
					     struct device *dev)
{
	return zfcp_lun_add(dev);
}

static exit_code_t zfcp_lun_st_device_undefine(struct subtype *st,
					       struct device *dev)
{
	struct zfcp_lun_devid *devid = dev->devid;
	char *hctl, *devpath, *path = NULL, *lun = NULL;
	exit_code_t rc = EXIT_OK;

	/* Remove SCSI device. */
	hctl = scsi_hctl_from_zfcp_lun_devid(devid);
	if (!hctl)
		goto remove_lun;
	devpath = path_get_scsi_hctl_dev(hctl);
	path = misc_asprintf("%s/delete", devpath);

	rc = misc_write_text_file(path, "\n", err_delayed_print);
	if (rc)
		goto out;
	udev_need_settle = 1;
	free(devpath);
	free(path);
	devpath = NULL;

remove_lun:
	path = path_get_zfcp_lun_dev(devid);
	if (!util_path_exists(path))
		goto out;
	free(path);
	path = NULL;

	/* Remove FCP LUN. */
	devpath = path_get_zfcp_port_dev(devid);
	if (!util_path_is_dir(devpath)) {
		rc = EXIT_ZFCP_WWPN_NOT_FOUND;
		goto out;
	}

	lun = misc_asprintf("0x%016" PRIx64, devid->lun);
	path = misc_asprintf("%s/unit_remove", devpath);

	rc = misc_write_text_file(path, lun, err_delayed_print);
	if (!rc)
		udev_need_settle = 1;

out:
	free(lun);
	free(path);
	free(devpath);
	free(hctl);

	return rc;
}

/* Add FCP device as prereqs for FCP LUN. */
static void zfcp_lun_st_add_prereqs(struct subtype *st, const char *id,
				    struct util_list *prereqs)
{
	struct zfcp_lun_devid devid;
	char *fcp_host_id;

	if (zfcp_lun_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return;

	fcp_host_id = ccw_devid_to_str(&devid.fcp_dev);
	selected_dev_list_add(prereqs, zfcp_host_subtype.devtype,
			      &zfcp_host_subtype, fcp_host_id, NULL, 0);
	free(fcp_host_id);
}

/* Return a newly allocated character string containing the absolute path to
 * the device attribute or device attribute prefix specified by @name.
 * For prefixes, @name may be specified with or without trailing slash. */
static char *zfcp_lun_st_get_active_attrib_path(struct subtype *st,
						struct device *dev,
						const char *name)
{
	char *hctl, *devpath, *path;
	size_t len = strlen(SCSI_ATTR_PREFIX);

	if (starts_with(name, SCSI_ATTR_PREFIX) &&
	    (name[len] == 0 || name[len] == '/')) {
		hctl = scsi_hctl_from_zfcp_lun_devid(dev->devid);
		if (!hctl)
			return NULL;
		devpath = path_get_scsi_hctl_dev(hctl);
		free(hctl);

		name += strlen(SCSI_ATTR_PREFIX);
	} else if (strcmp(name, FC_SECURITY_VATTR) == 0) {
		devpath = path_get_zfcp_port_dev(dev->devid);
		if (!util_path_exists(devpath)) {
			free(devpath);
			return NULL;
		}
	} else {
		devpath = path_get_zfcp_lun_dev(dev->devid);
	}

	while (*name == '/')
		name++;

	path = misc_asprintf("%s/%s", devpath, name);
	free(devpath);

	return path;
}

/* Return a newly allocated character string containing the value of the
 * specified device attribute. */
static char *zfcp_lun_st_get_active_attrib(struct subtype *st,
					   struct device *dev, const char *name)
{
	/* Special handling for "scsi_dev". */
	if (strcmp(name, SCSI_ATTR_PREFIX) == 0)
		return scsi_hctl_from_zfcp_lun_devid(dev->devid);

	/* Rest handled via default procedure. */
	return NULL;
}

static bool zfcp_lun_fc_lun_exists(const char *id)
{
	struct zfcp_lun_devid devid;
	char *path;
	bool result;

	if (zfcp_lun_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return false;
	path = path_get_zfcp_lun_dev(&devid);
	result = util_path_exists(path);
	free(path);

	return result;
}

/* Determine if a zfcp lun exists in the active configuration. */
static bool zfcp_lun_st_exists_active(struct subtype *st, const char *id)
{
	return zfcp_lun_fc_lun_exists(id) || scsi_hctl_exists(id);
}

static bool zfcp_lun_st_exists_persistent(struct subtype *st, const char *id)
{
	return udev_zfcp_lun_exists(id, false);
}

static bool zfcp_lun_st_exists_autoconf(struct subtype *st, const char *id)
{
	return udev_zfcp_lun_exists(id, true);
}

static exit_code_t zfcp_lun_st_is_definable(struct subtype *st, const char *id,
					    err_t err)
{
	struct zfcp_lun_devid devid;
	char *fcp_host_id;
	exit_code_t rc;

	rc = zfcp_lun_parse_devid(&devid, id, err);
	if (rc)
		return rc;

	fcp_host_id = ccw_devid_to_str(&devid.fcp_dev);
	if (!subtype_device_exists(&zfcp_host_subtype, fcp_host_id,
				   config_active))
		rc = EXIT_ZFCP_FCP_NOT_FOUND;
	free(fcp_host_id);

	return rc;
}

static bool filter_fcplun_cb(const char *name, void *data)
{
	return valid_hex(name);
}

static void add_fcplun_ids(struct util_list *ids, const char *fcp_device,
			   const char *wwpn)
{
	char *devpath, *path;
	struct util_list *fcpluns;
	struct strlist_node *s;

	fcpluns = strlist_new();
	devpath = path_get_ccw_device(ZFCP_CCWDRV_NAME, fcp_device);
	path = misc_asprintf("%s/%s/", devpath, wwpn);
	misc_read_dir(path, fcpluns, filter_fcplun_cb, NULL);
	free(path);
	free(devpath);

	util_list_iterate(fcpluns, s)
		strlist_add_unique(ids, "%s:%s:%s", fcp_device, wwpn, s->str);

	strlist_free(fcpluns);
}

static bool filter_wwpn_cb(const char *name, void *data)
{
	return valid_hex(name);
}

static void add_wwpn_ids(struct util_list *ids, const char *fcp_device)
{
	char *path;

	path = path_get_ccw_device(ZFCP_CCWDRV_NAME, fcp_device);
	misc_read_dir(path, ids, filter_wwpn_cb, NULL);
	free(path);
}

/* All zfcp-lun device IDs for all FCP luns registered in sysfs. */
static void zfcp_lun_add_zfcp_lun_ids(struct util_list *ids)
{
	struct util_list *fcp_devices, *wwpns;
	struct strlist_node *fcp_device, *wwpn;

	fcp_devices = strlist_new();
	/* Get list of FCP devices. */
	ccw_get_ids(ZFCP_CCWDRV_NAME, NULL, fcp_devices);
	util_list_iterate(fcp_devices, fcp_device) {
		wwpns = strlist_new();
		/* Get list of WWPNs. */
		add_wwpn_ids(wwpns, fcp_device->str);
		util_list_iterate(wwpns, wwpn) {
			/* Get list of LUNs. */
			add_fcplun_ids(ids, fcp_device->str, wwpn->str);
		}
		strlist_free(wwpns);
	}
	strlist_free(fcp_devices);
}

static void zfcp_lun_st_add_active_ids(struct subtype *st,
				       struct util_list *ids)
{
	scsi_hctl_add_zfcp_lun_ids(ids);
	zfcp_lun_add_zfcp_lun_ids(ids);
}

static void zfcp_lun_st_add_persistent_ids(struct subtype *st,
					   struct util_list *ids)
{
	udev_zfcp_lun_add_device_ids(ids, false);
}

static void zfcp_lun_st_add_autoconf_ids(struct subtype *st,
					 struct util_list *ids)
{
	udev_zfcp_lun_add_device_ids(ids, true);
}

static exit_code_t add_sg_cb(const char *path, const char *filename, void *data)
{
	struct util_list *list = data;
	struct devnode *node;
	char *devpath;

	devpath = misc_asprintf("%s/dev", path);
	node = devnode_from_devfile(devpath, filename, CHARDEV);
	free(devpath);
	if (node)
		ptrlist_add(list, node);

	return EXIT_OK;
}

static void add_sg_from_sysfs(struct util_list *list, const char *path)
{
	char *sgpath;

	sgpath = misc_asprintf("%s/scsi_generic", path);
	if (util_path_is_dir(sgpath))
		path_for_each(sgpath, add_sg_cb, list);
	free(sgpath);
}

static char *read_fcp_lun_attr(struct zfcp_lun_devid *devid, const char *name)
{
	char *lunpath, *attrpath, *attr;

	lunpath = path_get_zfcp_lun_dev(devid);
	attrpath = misc_asprintf("%s/%s", lunpath, name);
	attr = misc_read_text_file(attrpath, 1, err_ignore);
	free(attrpath);
	free(lunpath);

	return attr;
}

static char *read_scsi_dev_attr(struct zfcp_lun_devid *devid, const char *name)
{
	char *hctl, *devpath, *attrpath, *attr;

	hctl = scsi_hctl_from_zfcp_lun_devid(devid);
	if (!hctl)
		return NULL;
	devpath = path_get_scsi_hctl_dev(hctl);
	attrpath = misc_asprintf("%s/%s", devpath, name);
	attr = misc_read_text_file(attrpath, 1, err_ignore);
	free(attrpath);
	free(devpath);
	free(hctl);

	return attr;
}

static void zfcp_lun_st_add_errors(struct subtype *st, const char *id,
				   struct util_list *errors)
{
	struct zfcp_lun_devid devid;
	char *fcp_host_id, *attr;

	if (zfcp_lun_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return;

	/* Check for FCP device errors. */
	fcp_host_id = ccw_devid_to_str(&devid.fcp_dev);
	subtype_add_errors(&zfcp_host_subtype, fcp_host_id, errors);

	/* Check for FCP LUN errors. */
	attr = read_fcp_lun_attr(&devid, "failed");
	if (attr) {
		if (strcmp(attr, "0") != 0)
			strlist_add(errors, "FCP LUN is in a failed state");
		free(attr);
	}

	/* Check for SCSI device errors. */
	attr = read_scsi_dev_attr(&devid, "state");
	if (attr) {
		if (strcmp(attr, "running") != 0)
			strlist_add(errors, "SCSI device is not operational");
		free(attr);
	}

	free(fcp_host_id);
}

static void zfcp_lun_st_add_devnodes(struct subtype *st, const char *id,
				     struct util_list *devnodes)
{
	char *hctl, *path;

	hctl = scsi_hctl_from_zfcp_lun_id(id);
	if (!hctl)
		return;

	path = path_get_scsi_hctl_dev(hctl);

	/* Add block devices. */
	devnode_add_block_from_sysfs(devnodes, path);

	/* Add character devices. */
	add_sg_from_sysfs(devnodes, path);

	free(path);
	free(hctl);
}

static char *zfcp_lun_st_resolve_devnode(struct subtype *st,
					 struct devnode *devnode)
{
	char *path, *link, *hctl = NULL, *zfcp_lun_id = NULL;

	switch (devnode->type) {
	case BLOCKDEV:
		path = path_get_sys_dev_block(devnode->major, devnode->minor);
		break;
	case CHARDEV:
		path = path_get_sys_dev_char(devnode->major, devnode->minor);
		break;
	default:
		return NULL;
	}

	link = misc_readlink(path);
	if (!link)
		goto out;

	hctl = scsi_hctl_from_devpath(link);
	if (!hctl)
		goto out;

	zfcp_lun_id = scsi_hctl_to_zfcp_lun_id(hctl);

out:
	free(hctl);
	free(link);
	free(path);

	return zfcp_lun_id;
}

static exit_code_t zfcp_lun_st_detect_definable(struct subtype *st,
						struct device *dev)
{
	/* We're not doing LUN autoscanning here since we would rely on
	 * FCP devices being online. */
	dev->active.definable = 1;

	return EXIT_OK;
}

/*
 * zfcp lun subtype.
 */

struct subtype zfcp_lun_subtype = {
	.super		= &subtype_base,

	.devtype	= &zfcp_devtype,
	.name		= ZFCP_LUN_NAME,
	.title		= "zfcp-attached SCSI devices",
	.devname	= DEVNAME,
	.modules	= STRING_ARRAY(ZFCP_MOD_NAME),
	.namespace	= &zfcp_lun_namespace,

	.dev_attribs = ATTRIB_ARRAY(
		&zfcp_lun_attr_failed,
		&zfcp_lun_attr_scsi_queue_depth,
		&zfcp_lun_attr_scsi_queue_ramp_up_period,
		&zfcp_lun_attr_scsi_rescan,
		&zfcp_lun_attr_scsi_timeout,
		&zfcp_lun_attr_scsi_state,
		&zfcp_lun_attr_scsi_delete,
		&zfcp_lun_attr_fc_security,
		&internal_attr_early,
	),
	.prefixes = STRING_ARRAY(SCSI_ATTR_PREFIX),
	.unknown_dev_attribs	= 1,
	.support_definable	= 1,

	.exists_active		= &zfcp_lun_st_exists_active,
	.exists_persistent	= &zfcp_lun_st_exists_persistent,
	.exists_autoconf	= &zfcp_lun_st_exists_autoconf,

	.add_active_ids		= &zfcp_lun_st_add_active_ids,
	.add_persistent_ids	= &zfcp_lun_st_add_persistent_ids,
	.add_autoconf_ids	= &zfcp_lun_st_add_autoconf_ids,

	.read_active		= &zfcp_lun_st_read_active,
	.read_persistent	= &zfcp_lun_st_read_persistent,
	.read_autoconf		= &zfcp_lun_st_read_autoconf,

	.configure_active	= &zfcp_lun_st_configure_active,
	.configure_persistent	= &zfcp_lun_st_configure_persistent,
	.configure_autoconf	= &zfcp_lun_st_configure_autoconf,

	.deconfigure_active	= &zfcp_lun_st_deconfigure_active,
	.deconfigure_persistent	= &zfcp_lun_st_deconfigure_persistent,
	.deconfigure_autoconf	= &zfcp_lun_st_deconfigure_autoconf,

	.check_pre_configure	= &zfcp_lun_st_check_pre_configure,
	.check_post_configure	= &zfcp_lun_st_check_post_configure,

	.add_errors		= &zfcp_lun_st_add_errors,
	.add_devnodes		= &zfcp_lun_st_add_devnodes,
	.resolve_devnode	= &zfcp_lun_st_resolve_devnode,
	.add_prereqs		= &zfcp_lun_st_add_prereqs,
	.get_active_attrib_path	= &zfcp_lun_st_get_active_attrib_path,
	.get_active_attrib	= &zfcp_lun_st_get_active_attrib,

	.is_definable		= &zfcp_lun_st_is_definable,
	.detect_definable	= &zfcp_lun_st_detect_definable,
	.device_define		= &zfcp_lun_st_device_define,
	.device_undefine	= &zfcp_lun_st_device_undefine,
};
