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

#include "attrib.h"
#include "ccw.h"
#include "ccwgroup.h"
#include "device.h"
#include "devtype.h"
#include "internal.h"
#include "lcs.h"
#include "lcs_auto.h"
#include "misc.h"
#include "namespace.h"
#include "setting.h"

#define DEVNAME	"LCS device"

/*
 * LCS device ID namespace methods.
 */
static exit_code_t lcs_parse_devid(struct ccwgroup_devid *devid_ptr,
				   const char *id, err_t err)
{
	struct ccwgroup_devid devid;
	const char *reason = NULL;
	exit_code_t rc;

	rc = ccwgroup_parse_devid(&devid, id, err);
	if (rc)
		return rc;

	if (devid.num > LCS_NUM_DEVS) {
		reason = "Too many CCW device IDs specified";
		rc = EXIT_INVALID_ID;
	} else if (devid_ptr)
		*devid_ptr = devid;

	if (reason) {
		err_t_print(err, "Error in %s ID format: %s: %s\n", DEVNAME,
			    reason, id);
	}

	return rc;
}

static exit_code_t lcs_parse_devid_range(struct ccwgroup_devid *from_ptr,
					 struct ccwgroup_devid *to_ptr,
					 const char *range, err_t err)
{
	char *from_str, *to_str;
	struct ccwgroup_devid from, to;
	exit_code_t rc;
	const char *reason = NULL;

	/* Split range. */
	from_str = misc_strdup(range);
	to_str = strchr(from_str, '-');
	if (!to_str) {
		rc = EXIT_INVALID_ID;
		reason = "Missing hyphen";
		goto out;
	}
	*to_str = 0;
	to_str++;

	/* Parse range start end end ID. */
	rc = lcs_parse_devid(&from, from_str, err);
	if (rc)
		goto out;

	rc = lcs_parse_devid(&to, to_str, err);
	if (rc)
		goto out;

	/* Only allow ranges on CCWGROUP devices specified as single ID. */
	if (from.num != 1 || to.num != 1) {
		rc = EXIT_INVALID_ID;
		reason = "Ranges only supported on single CCW device IDs";
		goto out;
	}

	rc = EXIT_OK;
	if (from_ptr)
		*from_ptr = from;
	if (to_ptr)
		*to_ptr = to;

out:
	free(from_str);

	if (reason) {
		err_t_print(err, "Error in %s ID range format: %s: %s\n",
			    DEVNAME, reason, range);
	}

	return rc;
}

static bool lcs_parse_devid_range_simple(struct ccwgroup_devid *from,
					 struct ccwgroup_devid *to,
					 const char *range)
{
	if (lcs_parse_devid_range(from, to, range, err_ignore) == EXIT_OK)
		return true;

	return false;
}

static exit_code_t lcs_ns_is_id_valid(const char *id, err_t err)
{
	return lcs_parse_devid(NULL, id, err);
}

static char *lcs_ns_normalize_id(const char *id)
{
	struct ccwgroup_devid devid;

	if (lcs_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return NULL;

	return ccwgroup_devid_to_str(&devid);
}

static void *lcs_ns_parse_id(const char *id, err_t err)
{
	struct ccwgroup_devid *devid;

	devid = misc_malloc(sizeof(struct ccwgroup_devid));
	if (lcs_parse_devid(devid, id, err) != EXIT_OK) {
		free(devid);
		return NULL;
	}

	return devid;
}

static exit_code_t lcs_ns_is_id_range_valid(const char *range, err_t err)
{
	return lcs_parse_devid_range(NULL, NULL, range, err);
}

static unsigned long lcs_ns_num_ids_in_range(const char *range)
{
	struct ccwgroup_devid f, t;

	if (!lcs_parse_devid_range_simple(&f, &t, range))
		return 0;

	if (f.devid[0].cssid != t.devid[0].cssid ||
	    f.devid[0].ssid != t.devid[0].ssid)
		return 0;

	if (f.devid[0].devno > t.devid[0].devno)
		return 0;

	return t.devid[0].devno - f.devid[0].devno + 1;
}

static void lcs_ns_range_start(struct ns_range_iterator *it, const char *range)
{
	struct ccwgroup_devid from, to;

	if (!lcs_parse_devid_range_simple(&from, &to, range)) {
		memset(it, 0, sizeof(struct ns_range_iterator));
		return;
	}

	it->devid = ccwgroup_copy_devid(&from);
	it->devid_last = ccwgroup_copy_devid(&to);
	it->id = ccwgroup_devid_to_str(it->devid);
}

static bool lcs_ns_is_id_blacklisted(const char *id)
{
	struct ccwgroup_devid devid;
	char *ccw_id;
	unsigned int i;
	bool result = false;

	if (lcs_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return false;
	for (i = 0; i < devid.num; i++) {
		ccw_id = ccw_devid_to_str(&devid.devid[i]);
		result = ccw_is_id_blacklisted(ccw_id);
		free(ccw_id);
		if (result)
			break;
	}

	return result;
}

static void lcs_ns_unblacklist_id(const char *id)
{
	struct ccwgroup_devid devid;
	char *ccw_id;
	unsigned int i;

	if (lcs_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return;
	for (i = 0; i < devid.num; i++) {
		ccw_id = ccw_devid_to_str(&devid.devid[i]);
		if (ccw_is_id_blacklisted(ccw_id))
			ccw_unblacklist_id(ccw_id);
		free(ccw_id);
	}
}

/*
 * LCS device ID namespace.
 */

struct namespace lcs_namespace = {
	.devname		= DEVNAME,
	.is_id_valid		= lcs_ns_is_id_valid,
	.is_id_similar		= ccwgroup_is_id_similar,
	.cmp_ids		= ccwgroup_cmp_ids,
	.normalize_id		= lcs_ns_normalize_id,
	.parse_id		= lcs_ns_parse_id,
	.cmp_parsed_ids		= ccwgroup_cmp_parsed_ids,
	.qsort_cmp		= ccwgroup_qsort_cmp,
	.is_id_range_valid	= lcs_ns_is_id_range_valid,
	.num_ids_in_range	= lcs_ns_num_ids_in_range,
	.is_id_in_range		= ccwgroup_is_id_in_range,
	.range_start		= lcs_ns_range_start,
	.range_next		= ccwgroup_range_next,

	/* Blacklist handling. */
	.is_blacklist_active	= ccw_is_blacklist_active,
	.is_id_blacklisted	= lcs_ns_is_id_blacklisted,
	.is_id_range_blacklisted = ccw_is_id_range_blacklisted,
	.unblacklist_id		= lcs_ns_unblacklist_id,
	.unblacklist_id_range	= ccw_unblacklist_id_range,
	.blacklist_persist	= ccw_blacklist_persist,
};

/*
 * LCS device attributes.
 */

static struct attrib lcs_attr_lancmd_timeout = {
	.name = "lancmd_timeout",
	.title = "Modify LAN command timeout",
	.desc =
	"Specify the time in seconds that the LCS driver waits for a reply\n"
	"after issuing a LAN command to the LAN adapter.\n",
	.defval = "5",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM_GE(1)),
};

static struct attrib lcs_attr_recover = {
	.name = "recover",
	.title = "Trigger device recovery",
	.desc =
	"Write '1' to this attribute to restart the recovery process for the\n"
	"QETH device.\n",
	.accept = ACCEPT_ARRAY(ACCEPT_NUM(1)),
	.writeonly = 1,
	.activeonly = 1,
};

/*
 * LCS subtype methods.
 */

static exit_code_t lcs_st_is_definable(struct subtype *st, const char *id,
				       err_t err)
{
	struct ccwgroup_subtype_data *data = st->data;
	struct ccwgroup_devid devid;
	exit_code_t rc;

	rc = ccwgroup_parse_devid(&devid, id, err);
	if (rc)
		return rc;

	if (subtype_device_exists_active(st, id))
		return EXIT_OK;

	if (devid.num == data->num_devs)
		return lcs_auto_is_possible(&devid, err);

	if (devid.num == 1)
		return lcs_auto_get_devid(NULL, &devid.devid[0], err);

	err_t_print(err, "Invalid number of CCW device IDs\n");

	return EXIT_INVALID_ID;
}

/**
 * device_detect_definable - Detect configuration of definable device
 * @st: Device subtype
 * @dev: Device
 *
 * Detect the full ID and default parameters for non-existing but definable
 * device @dev and update active.definable. Return %EXIT_OK on success, or an
 * error code otherwise.
 */
static exit_code_t lcs_st_detect_definable(struct subtype *st,
					   struct device *dev)
{
	struct ccwgroup_devid *devid;
	exit_code_t rc;

	devid = dev->devid;
	if (devid->num == 1) {
		/* Detect possible group for this device. */
		rc = lcs_auto_get_devid(devid, &devid->devid[0],
					err_delayed_print);
		if (rc) {
			error("Auto-detection failed for %s %s\n"
			      "Please be sure to specify full CCWGROUP ID!\n",
			      st->devname, dev->id);
			return rc;
		}
		free(dev->id);
		dev->id = ccwgroup_devid_to_str(dev->devid);
	}

	dev->active.definable = 1;

	return EXIT_OK;
}

static void lcs_st_add_definable_ids(struct subtype *st, struct util_list *ids)
{
	lcs_auto_add_ids(ids);
}

/*
 * LCS subtype.
 */

static struct ccwgroup_subtype_data lcs_data = {
	.ccwgroupdrv	= LCS_CCWGROUPDRV_NAME,
	.ccwdrv		= LCS_CCWDRV_NAME,
	.rootdrv	= LCS_ROOTDRV_NAME,
	.mod		= LCS_MOD_NAME,
	.num_devs	= LCS_NUM_DEVS,
};

static struct subtype lcs_subtype = {
	.super		= &ccwgroup_subtype,
	.devtype	= &lcs_devtype,
	.name		= "lcs",
	.title		= "LAN-Channel-Station (LCS) network devices",
	.devname	= DEVNAME,
	.modules	= STRING_ARRAY(LCS_MOD_NAME),
	.namespace	= &lcs_namespace,
	.data		= &lcs_data,

	.dev_attribs = ATTRIB_ARRAY(
		&ccw_attr_online,
		&lcs_attr_lancmd_timeout,
		&lcs_attr_recover,
		&internal_attr_early,
	),
	.unknown_dev_attribs	= 1,
	.support_definable	= 1,

	.is_definable		= &lcs_st_is_definable,
	.detect_definable	= &lcs_st_detect_definable,
	.add_definable_ids	= &lcs_st_add_definable_ids,
};

/*
 * LCS devtype methods.
 */

/* Clean up all resources used by devtype object. */
static void lcs_devtype_exit(struct devtype *dt)
{
	setting_list_free(dt->active_settings);
	setting_list_free(dt->persistent_settings);
}

static exit_code_t lcs_devtype_read_settings(struct devtype *dt,
					     config_t config)
{
	/* No kernel or module parameters exist for the lcs device driver,
	 * but at least determine module loaded state. */
	dt->active_settings = setting_list_new();
	dt->persistent_settings = setting_list_new();

	if (SCOPE_ACTIVE(config))
		dt->active_exists = devtype_is_module_loaded(dt);

	return EXIT_OK;
}

static exit_code_t lcs_devtype_write_settings(struct devtype *dt,
					      config_t config)
{
	/* No kernel or module parameters exist for the lcs device driver. */

	return EXIT_OK;
}

/*
 * LCS devtype.
 */

struct devtype lcs_devtype = {
	.name		= "lcs",
	.title		= "", /* Only use subtypes. */
	.devname	= "LCS",

	.subtypes = SUBTYPE_ARRAY(
		&lcs_subtype,
	),

	.type_attribs = ATTRIB_ARRAY(
	),

	.exit			= &lcs_devtype_exit,

	.read_settings		= &lcs_devtype_read_settings,
	.write_settings		= &lcs_devtype_write_settings,
};
