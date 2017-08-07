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
#include "ctc.h"
#include "ctc_auto.h"
#include "device.h"
#include "devtype.h"
#include "misc.h"
#include "namespace.h"
#include "path.h"
#include "setting.h"

#define DEVNAME	"CTC device"

/*
 * CTC device ID namespace methods.
 */
static exit_code_t ctc_parse_devid(struct ccwgroup_devid *devid_ptr,
				   const char *id, err_t err)
{
	struct ccwgroup_devid devid;
	const char *reason = NULL;
	exit_code_t rc;

	rc = ccwgroup_parse_devid(&devid, id, err);
	if (rc)
		return rc;

	if (devid.num > CTC_NUM_DEVS) {
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

static exit_code_t ctc_parse_devid_range(struct ccwgroup_devid *from_ptr,
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
	rc = ctc_parse_devid(&from, from_str, err);
	if (rc)
		goto out;

	rc = ctc_parse_devid(&to, to_str, err);
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

static bool ctc_parse_devid_range_simple(struct ccwgroup_devid *from,
					 struct ccwgroup_devid *to,
					 const char *range)
{
	if (ctc_parse_devid_range(from, to, range, err_ignore) == EXIT_OK)
		return true;

	return false;
}

static exit_code_t ctc_ns_is_id_valid(const char *id, err_t err)
{
	return ctc_parse_devid(NULL, id, err);
}

static char *ctc_ns_normalize_id(const char *id)
{
	struct ccwgroup_devid devid;

	if (ctc_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return NULL;

	return ccwgroup_devid_to_str(&devid);
}

static void *ctc_ns_parse_id(const char *id, err_t err)
{
	struct ccwgroup_devid *devid;

	devid = misc_malloc(sizeof(struct ccwgroup_devid));
	if (ctc_parse_devid(devid, id, err) != EXIT_OK) {
		free(devid);
		return NULL;
	}

	return devid;
}

static exit_code_t ctc_ns_is_id_range_valid(const char *range, err_t err)
{
	return ctc_parse_devid_range(NULL, NULL, range, err);
}

static unsigned long ctc_ns_num_ids_in_range(const char *range)
{
	struct ccwgroup_devid f, t;

	if (!ctc_parse_devid_range_simple(&f, &t, range))
		return 0;

	if (f.devid[0].cssid != t.devid[0].cssid ||
	    f.devid[0].ssid != t.devid[0].ssid)
		return 0;

	if (f.devid[0].devno > t.devid[0].devno)
		return 0;

	return t.devid[0].devno - f.devid[0].devno + 1;
}

static void ctc_ns_range_start(struct ns_range_iterator *it, const char *range)
{
	struct ccwgroup_devid from, to;

	if (!ctc_parse_devid_range_simple(&from, &to, range)) {
		memset(it, 0, sizeof(struct ns_range_iterator));
		return;
	}

	it->devid = ccwgroup_copy_devid(&from);
	it->devid_last = ccwgroup_copy_devid(&to);
	it->id = ccwgroup_devid_to_str(it->devid);
}

static bool ctc_ns_is_id_blacklisted(const char *id)
{
	struct ccwgroup_devid devid;
	char *ccw_id;
	unsigned int i;
	bool result = false;

	if (ctc_parse_devid(&devid, id, err_ignore) != EXIT_OK)
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

static void ctc_ns_unblacklist_id(const char *id)
{
	struct ccwgroup_devid devid;
	char *ccw_id;
	unsigned int i;

	if (ctc_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return;
	for (i = 0; i < devid.num; i++) {
		ccw_id = ccw_devid_to_str(&devid.devid[i]);
		if (ccw_is_id_blacklisted(ccw_id))
			ccw_unblacklist_id(ccw_id);
		free(ccw_id);
	}
}

/*
 * CTC device ID namespace.
 */

struct namespace ctc_namespace = {
	.devname		= DEVNAME,
	.is_id_valid		= ctc_ns_is_id_valid,
	.is_id_similar		= ccwgroup_is_id_similar,
	.cmp_ids		= ccwgroup_cmp_ids,
	.normalize_id		= ctc_ns_normalize_id,
	.parse_id		= ctc_ns_parse_id,
	.cmp_parsed_ids		= ccwgroup_cmp_parsed_ids,
	.qsort_cmp		= ccwgroup_qsort_cmp,
	.is_id_range_valid	= ctc_ns_is_id_range_valid,
	.num_ids_in_range	= ctc_ns_num_ids_in_range,
	.is_id_in_range		= ccwgroup_is_id_in_range,
	.range_start		= ctc_ns_range_start,
	.range_next		= ccwgroup_range_next,

	/* Blacklist handling. */
	.is_blacklist_active	= ccw_is_blacklist_active,
	.is_id_blacklisted	= ctc_ns_is_id_blacklisted,
	.is_id_range_blacklisted = ccw_is_id_range_blacklisted,
	.unblacklist_id		= ctc_ns_unblacklist_id,
	.unblacklist_id_range	= ccw_unblacklist_id_range,
	.blacklist_persist	= ccw_blacklist_persist,
};

/*
 * CTC device attributes.
 */

static struct attrib ctc_attr_buffer = {
	.name = "buffer",
	.title = "Control maximum buffer size",
	.desc =
	"Specify the maximum buffer size used for a CTC interface. The value\n"
	"must be in the range of <minimum MTU + header size> to\n"
	"<maximum MTU + header size> where a header is typically 8 bytes\n"
	"long. When this attribute is set, the MTU size of the interface\n"
	"is also set accordingly.\n",
	.defval = "32768",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(584, 65535)),
	.order_cmp = ccw_online_only_order_cmp,
	.check = ccw_online_only_check,
};

static struct attrib ctc_attr_protocol = {
	.name = "protocol",
	.title = "Specify CTC interface protocol",
	.desc =
	"Specify the protocol to use for a CTC interface. The correct\n"
	"protocol depends on the CTC connection peer:\n"
	" 0: Non-z/OS peer such as a z/VM TCP service machine\n"
	" 1: Linux peer\n"
	" 3: z/OS peer\n"
	" 4: MPC connection to VTAM\n",
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1), ACCEPT_RANGE(3, 4)),
	.order_cmp = ccw_offline_only_order_cmp,
	.check = ccw_offline_only_check,
};

/*
 * CTC subtype methods.
 */

/* Check if user attempts to modify an attribute of an online CTC device
 * which can only be set while device is offline. */
static exit_code_t check_online_conflict(struct device *dev, config_t config)
{
	struct attrib *attribs[] = {
		&ctc_attr_protocol,
	};
	struct setting *online, *s;
	unsigned int i;
	exit_code_t rc;

	/* All is well if:
	 * 1. We're not configuring the active configuration
	 * 2. online->actual == 0 or we don't know the actual value
	 * 3. online->modified && online->value == 0*/
	if (!SCOPE_ACTIVE(config) || dev->active.deconfigured)
		return EXIT_OK;
	online = setting_list_find(dev->active.settings, ccw_attr_online.name);
	if (!online)
		return EXIT_OK;
	if (!online->actual_value || atoi(online->actual_value) == 0)
		return EXIT_OK;
	if (online->modified && atoi(online->value) == 0)
		return EXIT_OK;

	rc = EXIT_OK;
	for (i = 0; i < ARRAY_SIZE(attribs); i++) {
		s = setting_list_find(dev->active.settings, attribs[i]->name);
		if (!s || !s->modified)
			continue;
		delayed_warn("Attribute '%s' can only be changed while device "
			     "is offline\n", s->name);
		rc = EXIT_INVALID_CONFIG;
	}

	return rc;
}

static exit_code_t ctc_st_check_pre_configure(struct subtype *st,
					      struct device *dev,
					      int prereq, config_t config)
{
	exit_code_t rc;

	rc = check_online_conflict(dev, config);
	if (rc)
		return rc;

	return EXIT_OK;
}

static exit_code_t ctc_st_is_definable(struct subtype *st, const char *id,
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
		return ctc_auto_is_possible(&devid, err);

	if (devid.num == 1)
		return ctc_auto_get_devid(NULL, &devid.devid[0], err);

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
static exit_code_t ctc_st_detect_definable(struct subtype *st,
					   struct device *dev)
{
	struct ccwgroup_devid *devid;
	exit_code_t rc;

	devid = dev->devid;
	if (devid->num == 1) {
		/* Detect possible group for this device. */
		rc = ctc_auto_get_devid(devid, &devid->devid[0],
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

static void ctc_st_add_definable_ids(struct subtype *st, struct util_list *ids)
{
	ctc_auto_add_ids(ids);
}

/*
 * CTC subtype.
 */

static struct ccwgroup_subtype_data ctc_data = {
	.ccwgroupdrv	= CTC_CCWGROUPDRV_NAME,
	.ccwdrv		= CTC_CCWDRV_NAME,
	.rootdrv	= CTC_ROOTDRV_NAME,
	.mod		= CTC_MOD_NAME,
	.num_devs	= CTC_NUM_DEVS,
};

static struct subtype ctc_subtype = {
	.super		= &ccwgroup_subtype,
	.devtype	= &ctc_devtype,
	.name		= "ctc",
	.title		= "Channel-To-Channel (CTC) and CTC-MPC network "
			  "devices",
	.devname	= DEVNAME,
	.modules	= STRING_ARRAY(CTC_MOD_NAME),
	.namespace	= &ctc_namespace,
	.data		= &ctc_data,

	.dev_attribs = ATTRIB_ARRAY(
		&ccw_attr_online,
		&ctc_attr_buffer,
		&ctc_attr_protocol,
	),
	.unknown_dev_attribs	= 1,
	.support_definable	= 1,

	.check_pre_configure	= &ctc_st_check_pre_configure,

	.is_definable		= &ctc_st_is_definable,
	.detect_definable	= &ctc_st_detect_definable,
	.add_definable_ids	= &ctc_st_add_definable_ids,
};

/*
 * CTC devtype methods.
 */

/* Clean up all resources used by devtype object. */
static void ctc_devtype_exit(struct devtype *dt)
{
	setting_list_free(dt->active_settings);
	setting_list_free(dt->persistent_settings);
}

static exit_code_t ctc_devtype_read_settings(struct devtype *dt,
					     config_t config)
{
	/* No kernel or module parameters exist for the ctc device driver,
	 * but at least determine module loaded state. */
	dt->active_settings = setting_list_new();
	dt->persistent_settings = setting_list_new();

	if (SCOPE_ACTIVE(config))
		dt->active_exists = devtype_is_module_loaded(dt);

	return EXIT_OK;
}

static exit_code_t ctc_devtype_write_settings(struct devtype *dt,
					      config_t config)
{
	/* No kernel or module parameters exist for the ctc device driver. */

	return EXIT_OK;
}

/*
 * CTC devtype.
 */

struct devtype ctc_devtype = {
	.name		= "ctc",
	.title		= "", /* Only use subtypes. */
	.devname	= "CTC",

	.subtypes = SUBTYPE_ARRAY(
		&ctc_subtype,
	),

	.type_attribs = ATTRIB_ARRAY(
	),

	.exit			= &ctc_devtype_exit,

	.read_settings		= &ctc_devtype_read_settings,
	.write_settings		= &ctc_devtype_write_settings,
};

/*
 * Helper functions.
 */

static struct util_list *ctc_list;

static void add_query(struct util_list *list, const char *cmd)
{
	char *vmcp, *curr, *next, **argv;
	int argc;
	struct ccw_devid devid;

	/* Query real CTC adapters. */
	vmcp = misc_read_cmd_output(cmd, 0, 1);
	if (!vmcp)
		return;

	next = vmcp;
	while ((curr = strsep(&next, "\n"))) {
		line_split(curr, &argc, &argv);
		if (argc >= 2 && ccw_parse_devid_simple(&devid, argv[1]))
			ptrlist_add(list, ccw_copy_devid(&devid));
		line_free(argc, argv);
	}

	free(vmcp);
}

/* Perform a CP QUERY CTCA ALL command and return a ptrlist of CCW device IDs
 * for all found CTC devices. */
static struct util_list *query_ctc(void)
{
	struct util_list *list;
	char *cmd;

	list = ptrlist_new();

	/* Query real CTC adapters. */
	cmd = misc_asprintf("%s query ctca all 2>/dev/null", PATH_VMCP);
	add_query(list, cmd);
	free(cmd);

	/* Query virtual CTC adapters. */
	cmd = misc_asprintf("%s query virtual ctca 2>/dev/null", PATH_VMCP);
	add_query(list, cmd);
	free(cmd);

	return list;
}

/* Release all allocated resources. */
void ctc_exit(void)
{
	ptrlist_free(ctc_list, 1);
}

/* Try to confirm that the specified CCW device ID refers to CTC device.
 * Return %true it is a CTC device, %false if it cannot be confirmed. */
bool ctc_confirm(struct ccw_devid *devid)
{
	struct ptrlist_node *p;
	struct ccw_devid *d;

	if (devid->cssid != 0 || devid->ssid != 0 || !is_zvm())
		return false;

	if (!ctc_list)
		ctc_list = query_ctc();

	util_list_iterate(ctc_list, p) {
		d = p->ptr;
		if (ccw_cmp_devids(devid, d) == 0)
			return true;
	}

	return false;
}
