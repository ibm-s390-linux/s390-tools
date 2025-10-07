/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_path.h"

#include "attrib.h"
#include "ccw.h"
#include "ccwgroup.h"
#include "device.h"
#include "devnode.h"
#include "devtype.h"
#include "iscsi.h"
#include "misc.h"
#include "module.h"
#include "namespace.h"
#include "path.h"
#include "select.h"
#include "setting.h"
#include "subtype.h"
#include "udev.h"
#include "udev_ccwgroup.h"

#define DEVNAME		"CCWGROUP device"

/*
 * Common CCWGROUP device attributes.
 */

struct attrib ccwgroup_attr_online = {
	.name = "online",
	.title = "Activate a device",
	.desc = "Control the activation of a device:\n"
		"  0: Device is disabled and cannot be used\n"
		"  1: Device is enabled\n",
	.mandatory = 1,
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
};

/*
 * CCWGROUP device methods.
 */

/**
 * ccwgroup_parse_devid - Parse a string into a ccwgroup_devid
 * @devid_ptr: Target ccwgroup_devid or NULL
 * @id: String to parse
 * @err: Specify what to do with errors (ignore, print, delayed_print)
 *
 * Return %EXIT_OK on success, a corresponding error exit code otherwise.
 */
exit_code_t ccwgroup_parse_devid(struct ccwgroup_devid *devid_ptr,
				 const char *id, err_t err)
{
	struct ccwgroup_devid devid;
	char *copy, *curr, *next;
	unsigned int i, j;
	exit_code_t rc;
	char *reason = NULL;

	memset(&devid, 0, sizeof(struct ccwgroup_devid));
	copy = misc_strdup(id);
	next = copy;
	for (i = 0; i < CCWGROUP_MAX_DEVIDS; i++) {
		curr = strsep(&next, ":");
		if (!curr)
			break;
		rc = ccw_parse_devid(&devid.devid[i], curr, err);
		if (rc)
			goto out;
	}
	devid.num = i;
	rc = EXIT_INVALID_ID;

	if (i == 0) {
		reason = "No CCW device ID specified\n";
		goto out;
	}
	if (next && *next) {
		reason = "Too many CCW device IDs specified\n";
		goto out;
	}
	for (i = 1; i < devid.num; i++) {
		for (j = 0; j < i; j++) {
			if (ccw_cmp_devids(&devid.devid[j],
					   &devid.devid[i]) == 0) {
				reason = "Duplicate CCW device ID specified";
				goto out;
			}
		}
	}

	rc = EXIT_OK;
	if (devid_ptr)
		*devid_ptr = devid;

out:
	free(copy);

	if (reason) {
		err_t_print(err, "Error in %s ID format: %s: %s\n", DEVNAME,
			    reason, id);
	}

	return rc;
}

bool ccwgroup_parse_devid_simple(struct ccwgroup_devid *devid, const char *id)
{
	if (ccwgroup_parse_devid(devid, id, err_ignore) == EXIT_OK)
		return true;

	return false;
}

static exit_code_t ccwgroup_is_id_valid(const char *id, err_t err)
{
	return ccwgroup_parse_devid(NULL, id, err);
}

bool ccwgroup_is_id_similar(const char *id)
{
	char *copy, *start, *end;
	bool result = false;

	copy = misc_strdup(id);
	start = copy;

	/* ccwid:ccwid:ccwid */
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
	if (!ccw_is_id_similar(start))
		goto out;
	start = end + 1;

	if (ccw_is_id_similar(start))
		result = true;

out:
	free(copy);

	return result;
}

int ccwgroup_cmp_parsed_ids(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct ccwgroup_devid));
}

int ccwgroup_cmp_ids(const char *a_str, const char *b_str)
{
	struct ccwgroup_devid a, b;

	if (!ccwgroup_parse_devid_simple(&a, a_str) ||
	    !ccwgroup_parse_devid_simple(&b, b_str))
		return -1;

	if (a.num == b.num)
		return ccwgroup_cmp_parsed_ids(&a, &b);

	/* ccwid vs ccwid */
	if (a.num == 1 || b.num == 1)
		return ccw_cmp_devids(&a.devid[0], &b.devid[0]);

	return -1;
}

char *ccwgroup_devid_to_str(struct ccwgroup_devid *devid)
{
	char *last = NULL, *result = NULL;
	unsigned int i;

	for (i = 0; i < devid->num; i++) {
		if (last) {
			result = misc_asprintf("%s:%x.%x.%04x", last,
					       devid->devid[i].cssid,
					       devid->devid[i].ssid,
					       devid->devid[i].devno);
		} else {
			result = misc_asprintf("%x.%x.%04x",
					       devid->devid[i].cssid,
					       devid->devid[i].ssid,
					       devid->devid[i].devno);
		}
		free(last);
		last = result;
	}

	return result;
}

static char *ccwgroup_normalize_id(const char *id)
{
	struct ccwgroup_devid devid;

	if (!ccwgroup_parse_devid_simple(&devid, id))
		return NULL;

	return ccwgroup_devid_to_str(&devid);
}

static exit_code_t ccwgroup_parse_devid_range(struct ccwgroup_devid *from_ptr,
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
	rc = ccwgroup_parse_devid(&from, from_str, err);
	if (rc)
		goto out;

	rc = ccwgroup_parse_devid(&to, to_str, err);
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

static bool ccwgroup_parse_devid_range_simple(struct ccwgroup_devid *from,
					      struct ccwgroup_devid *to,
					      const char *range)
{
	if (ccwgroup_parse_devid_range(from, to, range, err_ignore) == EXIT_OK)
		return true;

	return false;
}

static exit_code_t ccwgroup_is_id_range_valid(const char *range, err_t err)
{
	return ccwgroup_parse_devid_range(NULL, NULL, range, err);
}

static unsigned long ccwgroup_num_ids_in_range(const char *range)
{
	struct ccwgroup_devid f, t;

	if (!ccwgroup_parse_devid_range_simple(&f, &t, range))
		return 0;

	if (f.devid[0].cssid != t.devid[0].cssid ||
	    f.devid[0].ssid != t.devid[0].ssid)
		return 0;

	if (f.devid[0].devno > t.devid[0].devno)
		return 0;

	return t.devid[0].devno - f.devid[0].devno + 1;
}

bool ccwgroup_is_id_in_range(const char *id, const char *range)
{
	struct ccwgroup_devid devid, from, to;

	if (!ccwgroup_parse_devid_simple(&devid, id))
		return false;
	if (!ccwgroup_parse_devid_range_simple(&from, &to, range))
		return false;

	return ccw_devid_in_range(&devid.devid[0], &from.devid[0],
				  &to.devid[0]);
}

struct ccwgroup_devid *ccwgroup_copy_devid(struct ccwgroup_devid *devid)
{
	struct ccwgroup_devid *result;

	result = misc_malloc(sizeof(struct ccwgroup_devid));
	*result = *devid;

	return result;
}

/* Initialize the range iterator object IT with the specified range and
 * set it->id to the first ID in the range or NULL if the range is not valid.
 * All used fields in IT must be objects allocated using alloc().  */
static void ccwgroup_range_start(struct ns_range_iterator *it,
				 const char *range)
{
	struct ccwgroup_devid from, to;

	if (!ccwgroup_parse_devid_range_simple(&from, &to, range)) {
		memset(it, 0, sizeof(struct ns_range_iterator));
		return;
	}

	it->devid = ccwgroup_copy_devid(&from);
	it->devid_last = ccwgroup_copy_devid(&to);
	it->id = ccwgroup_devid_to_str(it->devid);
}

/* Set it->id to the next ID in the range or NULL if the end of the range
 * was reached. */
void ccwgroup_range_next(struct ns_range_iterator *it)
{
	struct ccwgroup_devid *curr, *last;

	if (!it->id)
		return;
	free(it->id);
	curr = it->devid;
	last = it->devid_last;
	if (curr->devid[0].devno < last->devid[0].devno) {
		curr->devid[0].devno++;
		it->id = ccwgroup_devid_to_str(curr);
	} else
		it->id = NULL;
}

static void *ccwgroup_parse_id(const char *id, err_t err)
{
	struct ccwgroup_devid *devid;

	devid = misc_malloc(sizeof(struct ccwgroup_devid));
	if (ccwgroup_parse_devid(devid, id, err) != EXIT_OK) {
		free(devid);
		return NULL;
	}
	return devid;
}

static int ccwgroup_cmp_devids(struct ccwgroup_devid *a,
			       struct ccwgroup_devid *b)
{
	return ccwgroup_cmp_parsed_ids(a, b);
}

static void ccwgroup_get_online_attrib(struct attrib **attribs, int online,
				       config_t config, struct attrib **a_ptr,
				       const char **name_ptr,
				       const char **value_ptr)
{
	const char *name;
	const char *value = online ? "1" : "0";
	struct attrib *a;

	a = attrib_find(attribs, "online");

	if (a)
		name = a->name;
	else
		name = "online";

	*a_ptr = a;
	*name_ptr = name;
	*value_ptr = value;
}

/* Modify the online attribute of the specified device. */
static void ccwgroup_st_online_set(struct subtype *st, struct device *dev,
				   int online, config_t config)
{
	struct attrib *a;
	const char *name, *value;

	ccwgroup_get_online_attrib(st->dev_attribs, online, config, &a, &name,
				   &value);

	if (SCOPE_ACTIVE(config)) {
		if (online)
			setting_list_apply(dev->active.settings, a, name,
					   value);
		else {
			/* CCWGROUP devices should be deconfigured in
			 * offline state. */
			dev->active.deconfigured = 1;
			dev->active.modified = 1;
		}
	}
	if (SCOPE_PERSISTENT(config))
		setting_list_apply(dev->persistent.settings, a, name, value);
	if (SCOPE_AUTOCONF(config))
		setting_list_apply(dev->autoconf.settings, a, name, value);
}

static int get_online(struct setting_list *list)
{
	struct setting *s;

	if (!list)
		return -1;

	s = setting_list_find(list, "online");
	if (!s)
		return -1;

	if (atoi(s->value) != 0)
		return 1;

	return 0;
}

/* Return -1 if online state is not configured, 0 for offline and 1 for online.
 * If multiple configurations are specified, return the minimum of all. */
static int ccwgroup_st_online_get(struct subtype *st, struct device *dev,
				  config_t config)
{
	int act_online = 1, pers_online = 1, auto_online = 1;

	if (SCOPE_ACTIVE(config))
		act_online = get_online(dev->active.settings);
	if (SCOPE_PERSISTENT(config))
		pers_online = get_online(dev->persistent.settings);
	if (SCOPE_AUTOCONF(config))
		auto_online = get_online(dev->autoconf.settings);

	return MIN(MIN(act_online, pers_online), auto_online);
}

/* Determine if the online state of the specified device was modified. */
static bool ccwgroup_st_online_specified(struct subtype *st,
					 struct device *dev, config_t config)
{
	struct setting *s;

	if (SCOPE_ACTIVE(config) && dev->active.settings) {
		s = setting_list_find(dev->active.settings, "online");
		if (s && s->specified)
			return true;
	}
	if (SCOPE_PERSISTENT(config) && dev->persistent.settings) {
		s = setting_list_find(dev->persistent.settings, "online");
		if (s && s->specified)
			return true;
	}
	if (SCOPE_AUTOCONF(config) && dev->autoconf.settings) {
		s = setting_list_find(dev->autoconf.settings, "online");
		if (s && s->specified)
			return true;
	}

	return false;
}

/* Add summary descriptions of operational problems with CCWGROUP device @id to
 * strlist @errors. */
static void ccwgroup_st_add_errors(struct subtype *st, const char *id,
				   struct util_list *errors)
{
	struct ccwgroup_devid devid;
	char *ccwid;
	unsigned int i;

	if (!ccwgroup_parse_devid_simple(&devid, id))
		return;

	/* Add errors for each associated CCW device. */
	for (i = 0; i < devid.num; i++) {
		ccwid = ccw_devid_to_str(&devid.devid[i]);
		subtype_add_errors(&ccw_subtype, ccwid, errors);
		free(ccwid);
	}
}

char *ccwgroup_get_partial_id(const char *id)
{
	struct ccwgroup_devid devid;

	if (!ccwgroup_parse_devid_simple(&devid, id))
		return NULL;

	return ccw_devid_to_str(&devid.devid[0]);
}

static char *ccwgroup_get_dev_path(const char *drv, const char *id)
{
	char *partial_id, *path;

	partial_id = ccwgroup_get_partial_id(id);
	if (!partial_id)
		return NULL;

	path = path_get_ccwgroup_device(drv, partial_id);
	free(partial_id);

	return path;
}

static char *ccwgroup_get_dev_path_by_devid(const char *drv,
					    struct ccwgroup_devid *devid)
{
	char *partial_id, *path;

	partial_id = ccw_devid_to_str(&devid->devid[0]);
	path = path_get_ccwgroup_device(drv, partial_id);
	free(partial_id);

	return path;
}

static void ccwgroup_st_add_devnodes(struct subtype *st, const char *id,
				     struct util_list *devnodes)
{
	struct ccwgroup_subtype_data *data = st->data;
	char *path;

	path = ccwgroup_get_dev_path(data->ccwgroupdrv, id);
	if (path)
		devnode_add_net_from_sysfs(devnodes, path);
	free(path);
}

/* Read the full CCWGROUP device ID from the main CCW device ID. */
static bool read_full_id(struct ccwgroup_devid *devid_ptr, const char *drv,
			 const char *id)
{
	char *path, *link_path, *link, *base;
	unsigned int i;
	struct ccwgroup_devid devid;
	bool result = false;

	path = path_get_ccwgroup_device(drv, id);
	if (!util_path_is_dir(path))
		goto out;

	memset(&devid, 0, sizeof(struct ccwgroup_devid));
	for (i = 0; i < CCWGROUP_MAX_DEVIDS; i++) {
		/* Read cdev<n> link target. */
		link_path = misc_asprintf("%s/cdev%u", path, i);
		link = misc_readlink(link_path);
		free(link_path);
		if (!link) {
			result = false;
			break;
		}

		/* Parse as CCW device ID. */
		base = basename(link);
		result = ccw_parse_devid_simple(&devid.devid[i], base);
		free(link);
		if (!result)
			goto out;
		devid.num++;
	}
	if (devid.num > 0) {
		result = true;
		*devid_ptr = devid;
	}
out:
	free(path);

	return result;
}

struct get_ids_cb_data {
	const char *drv;
	struct util_list *ids;
};

static exit_code_t get_ids_cb(const char *path, const char *file, void *data)
{
	struct get_ids_cb_data *cb_data = data;
	struct ccwgroup_devid devid;
	char *id;

	if (strchr(file, '.') && read_full_id(&devid, cb_data->drv, file)) {
		id = ccwgroup_devid_to_str(&devid);
		strlist_add(cb_data->ids, id);
		free(id);
	}

	return EXIT_OK;
}

/* Add all existing CCWGROUP devices attached to driver DRV to strlist LIST.
 * If DRV is NULL add all CCWGROUP device IDs. */
static void ccwgroup_add_ids(const char *drv, const char *mod,
			     struct util_list *list)
{
	struct get_ids_cb_data cb_data;
	char *path;

	cb_data.drv = drv;
	cb_data.ids = list;

	cio_settle(0);

	path = path_get_ccwgroup_devices(drv);
	if (mod)
		module_try_load_once(mod, path);
	if (util_path_is_dir(path))
		path_for_each(path, get_ids_cb, &cb_data);
	free(path);
}

static void expand_id(const char *ccwgroupdrv, struct device *dev)
{
	struct ccwgroup_devid *devid = dev->devid;

	if (devid->num != 1 || !ccwgroupdrv)
		return;

	if (read_full_id(devid, ccwgroupdrv, dev->id)) {
		free(dev->id);
		dev->id = ccwgroup_devid_to_str(devid);
	}
}

static exit_code_t ccwgroup_st_read_active(struct subtype *st,
					   struct device *dev,
					   read_scope_t scope)
{
	struct ccwgroup_subtype_data *data = st->data;
	const char *drv = data->ccwgroupdrv;
	struct ccwgroup_devid *devid;
	struct device_state *state = &dev->active;
	char *path;

	cio_settle(0);

	expand_id(drv, dev);
	devid = dev->devid;

	state->modified = 0;
	state->deconfigured = 0;
	state->definable = 0;

	path = ccwgroup_get_dev_path_by_devid(drv, devid);
	if (util_path_exists(path)) {
		state->exists = 1;
		device_read_active_settings(dev, scope);
	} else
		state->exists = 0;
	free(path);

	return EXIT_OK;
}

static exit_code_t ccwgroup_st_read_persistent(struct subtype *st,
					       struct device *dev,
					       read_scope_t scope)
{
	struct ccwgroup_subtype_data *data = st->data;

	expand_id(data->ccwgroupdrv, dev);

	return udev_ccwgroup_read_device(dev, false);
}

static exit_code_t ccwgroup_st_read_autoconf(struct subtype *st,
					     struct device *dev,
					     read_scope_t scope)
{
	struct ccwgroup_subtype_data *data = st->data;

	expand_id(data->ccwgroupdrv, dev);

	return udev_ccwgroup_read_device(dev, true);
}

static exit_code_t ccwgroup_st_configure_active(struct subtype *st,
						struct device *dev)
{
	cio_settle(0);

	return device_write_active_settings(dev);
}

static exit_code_t _ccwgroup_st_configure_persistent(struct subtype *st,
						     struct device *dev,
						     bool autoconf)
{
	struct ccwgroup_subtype_data *data = st->data;
	struct ccwgroup_devid *devid = dev->devid;

	if (devid->num != data->num_devs) {
		delayed_err("Incomplete device ID specified\n");
		return EXIT_INCOMPLETE_ID;
	}
	return udev_ccwgroup_write_device(dev, autoconf);
}

static exit_code_t ccwgroup_st_configure_persistent(struct subtype *st,
						    struct device *dev)
{
	return _ccwgroup_st_configure_persistent(st, dev, false);
}

static exit_code_t ccwgroup_st_configure_autoconf(struct subtype *st,
						    struct device *dev)
{
	return _ccwgroup_st_configure_persistent(st, dev, true);
}


static char *ccwgroup_st_get_active_attrib_path(struct subtype *,
						struct device *, const char *);

/* Set the specified CCWGROUP device offline. */
static exit_code_t ccwgroup_st_deconfigure_active(struct subtype *st,
						  struct device *dev)
{
	struct setting *s;
	char *path;
	exit_code_t rc;

	if (get_online(dev->active.settings) != 1)
		return EXIT_OK;

	/* Set the online attribute to 0. */
	s = setting_list_apply(dev->active.settings, &ccwgroup_attr_online,
			       ccwgroup_attr_online.name, "0");
	path = ccwgroup_st_get_active_attrib_path(st, dev, s->name);
	rc = setting_write(path, s);
	free(path);

	return rc;
}

static exit_code_t ccwgroup_st_deconfigure_persistent(struct subtype *st,
						      struct device *dev)
{
	return udev_ccwgroup_remove_rule(st->name, dev->id, false);
}

static exit_code_t ccwgroup_st_deconfigure_autoconf(struct subtype *st,
						    struct device *dev)
{
	return udev_ccwgroup_remove_rule(st->name, dev->id, true);
}

/* Check if a CCWGROUP device with the specified ID exists. */
static bool ccwgroup_is_grouped(const char *drv, const char *id)
{
	struct ccwgroup_devid devid, full_devid;
	char *ccw_id;
	bool result;

	cio_settle(0);

	if (!ccwgroup_parse_devid_simple(&devid, id))
		return false;

	ccw_id = ccw_devid_to_str(&devid.devid[0]);
	result = read_full_id(&full_devid, drv, ccw_id);
	free(ccw_id);
	if (!result)
		return false;

	if (devid.num == 1) {
		/* CCWGROUP device ID specified as single CCW device ID. */
		return result;
	}

	if (ccwgroup_cmp_devids(&devid, &full_devid) == 0)
		return true;

	return false;
}

static bool ccwgroup_st_exists_active(struct subtype *st, const char *id)
{
	struct ccwgroup_subtype_data *data = st->data;

	return ccwgroup_is_grouped(data->ccwgroupdrv, id);
}

static bool ccwgroup_st_exists_persistent(struct subtype *st, const char *id)
{
	return udev_ccwgroup_exists(st->name, id, false);
}

static bool ccwgroup_st_exists_autoconf(struct subtype *st, const char *id)
{
	return udev_ccwgroup_exists(st->name, id, true);
}

int ccwgroup_qsort_cmp(const void *a_ptr, const void *b_ptr)
{
	const char *a = *((const char **) a_ptr);
	const char *b = *((const char **) b_ptr);

	return ccwgroup_cmp_ids(a, b);
}

static void ccwgroup_st_add_active_ids(struct subtype *st,
				       struct util_list *ids)
{
	struct ccwgroup_subtype_data *data = st->data;

	ccwgroup_add_ids(data->ccwgroupdrv, data->mod, ids);
}

static void ccwgroup_st_add_persistent_ids(struct subtype *st,
					   struct util_list *ids)
{
	udev_ccwgroup_add_device_ids(st->name, ids, false);
}

static void ccwgroup_st_add_autoconf_ids(struct subtype *st,
					 struct util_list *ids)
{
	udev_ccwgroup_add_device_ids(st->name, ids, true);
}

/* Check if CCW device ID @b is part of CCW group device ID @a. */
static bool id_contains(struct ccwgroup_devid *a, struct ccw_devid *b)
{
	unsigned int i;

	for (i = 0; i < a->num; i++) {
		if (ccw_cmp_devids(&a->devid[i], b) == 0)
			return true;
	}

	return false;
}

/* Check if there are common CCW device IDs in @a and @b. */
static bool id_overlap(struct ccwgroup_devid *a, struct ccwgroup_devid *b)
{
	unsigned int i;

	for (i = 0; i < a->num; i++) {
		if (id_contains(b, &a->devid[i]))
			return true;
	}

	return false;
}

/* Remove all CCW device IDs which are part of CCW group device %dev from
 * %list. */
static void ccwgroup_st_rem_combined(struct subtype *st, struct device *dev,
				     struct selected_dev_node *curr,
				     struct util_list *list)
{
	struct selected_dev_node *p, *n;
	struct ccw_devid devid;
	struct ccwgroup_devid groupid, *gdevid;

	gdevid = dev->devid;
	util_list_iterate_safe(list, p, n) {
		if (curr) {
			/* Skip all entries before and including %curr. */
			if (p == curr)
				curr = NULL;
			continue;
		}
		if (p->st != st)
			continue;
		if (ccw_parse_devid_simple(&devid, p->id)) {
			if (id_contains(gdevid, &devid))
				goto remove;
		} else if (ccwgroup_parse_devid_simple(&groupid, p->id)) {
			if (id_overlap(gdevid, &groupid))
				goto remove;
		}
		continue;

remove:
		util_list_remove(list, p);
		selected_dev_free(p);
	}
}

/* Return a newly allocated character string containing the path to the file
 * that implements a device attribute of the specified @name or %NULL if
 * such an attribute is not allowed. */
static char *ccwgroup_st_get_active_attrib_path(struct subtype *st,
						struct device *dev,
						const char *name)
{
	struct ccwgroup_subtype_data *data = st->data;
	char *devpath, *path;

	devpath = ccwgroup_get_dev_path_by_devid(data->ccwgroupdrv, dev->devid);
	path = misc_asprintf("%s/%s", devpath, name);
	free(devpath);

	return path;
}

/* Return a newly allocated character string containing the value of the
 * specified device attribute. */
static char *ccwgroup_st_get_active_attrib(struct subtype *st,
					   struct device *dev,
					   const char *name)
{
	struct ccwgroup_subtype_data *data = st->data;

	/* Special handling for "online": if device is not grouped, device
	 * is offline. This is needed to prevent incorrect conflict messages
	 * in setting_list_check_conflict(). */
	if (strcmp(name, ccwgroup_attr_online.name) == 0 &&
	    !ccwgroup_is_grouped(data->ccwgroupdrv, dev->id))
		return misc_strdup("0");

	/* Rest handled via default procedure. */
	return NULL;
}

/* Check if a CCWGROUP device with the specified ID can be grouped. */
static exit_code_t ccwgroup_can_group(struct ccwgroup_devid *devid)
{
	struct ccw_devinfo *devinfo;
	unsigned int i;
	const char *err = NULL;
	char *ccwid;
	exit_code_t rc = EXIT_OK;

	cio_settle(0);

	for (i = 0; i < devid->num && rc == EXIT_OK; i++) {
		devinfo = ccw_devinfo_get(&devid->devid[i], 1);
		if (!devinfo->exists) {
			err = "CCW device %s not found\n";
			rc = EXIT_GROUP_NOT_FOUND;
		} else if (devinfo->grouped) {
			err = "CCW device %s already grouped\n";
			rc = EXIT_GROUP_ALREADY;
		}
		free(devinfo);
		if (!err)
			continue;
		ccwid = ccw_devid_to_str(&devid->devid[i]);
		delayed_err(err, ccwid);
		free(ccwid);
	}

	return rc;
}

static exit_code_t rebind_devices(struct ccwgroup_devid *devid, const char *drv)
{
	unsigned int i;
	char *curr_drv, *ccwid;
	exit_code_t rc = EXIT_OK;

	for (i = 0; i < devid->num && rc == EXIT_OK; i++) {
		/* Determine CCW device driver to which device is bound. */
		curr_drv = ccw_get_driver(&devid->devid[i]);

		if (curr_drv) {
			if (strcmp(curr_drv, drv) == 0)
				goto next;
			rc = ccw_unbind_device(&devid->devid[i]);
			if (rc)
				goto next;
		} else {
			ccwid = ccw_devid_to_str(&devid->devid[i]);
			delayed_err("Could not determine driver of CCW "
				    "device %s\n", ccwid);
			free(ccwid);
		}

		rc = ccw_bind_device(&devid->devid[i], drv);

next:
		free(curr_drv);
	}

	return rc;
}

/* Create a CCWGROUP device with the specified driver @drv and device ID
 * @ID. Only fully specified IDs are valid. Return %EXIT_OK on success,
 * another exit code on error. */
static exit_code_t ccwgroup_group(const char *drv, const char *ccwdrv,
				  const char *id)
{
	struct ccwgroup_devid devid;
	char *path, *group_path, *value, *delim;
	exit_code_t rc = EXIT_OK;

	cio_settle(0);

	if (!ccwgroup_parse_devid_simple(&devid, id)) {
		delayed_err("Unrecognized device ID format: %s\n", id);
		return EXIT_INVALID_ID;
	}

	if (devid.num == 1) {
		delayed_err("Incomplete CCWGROUP device ID specified\n");
		return EXIT_INCOMPLETE_ID;
	}

	rc = ccwgroup_can_group(&devid);
	if (rc)
		return rc;

	rc = rebind_devices(&devid, ccwdrv);
	if (rc)
		return rc;

	path = path_get_sys_bus_drv(CCWGROUP_BUS, drv);
	group_path = misc_asprintf("%s/group", path);

	value = ccwgroup_devid_to_str(&devid);

	delim = value;
	while ((delim = strchr(delim, ':')))
		*delim = ',';

	rc = misc_write_text_file(group_path, value, err_delayed_print);
	if (rc)
		rc = EXIT_GROUP_FAILED;

	/* Wait until any asynchronous ccwgroup processing has finished. */
	cio_settle(1);

	free(value);
	free(path);
	free(group_path);

	return rc;
}

static exit_code_t ccwgroup_st_device_define(struct subtype *st,
					     struct device *dev)
{
	struct ccwgroup_subtype_data *data = st->data;

	return ccwgroup_group(data->ccwgroupdrv, data->ccwdrv, dev->id);
}

/* Ungroup a CCWGROUP device. */
static exit_code_t ccwgroup_ungroup(const char *drv, const char *id)
{
	char *path, *file;
	exit_code_t rc = EXIT_OK;

	cio_settle(0);

	path = ccwgroup_get_dev_path(drv, id);
	if (!path)
		return EXIT_INVALID_ID;

	file = misc_asprintf("%s/ungroup", path);
	rc = misc_write_text_file(file, "\n", err_delayed_print);
	if (rc)
		rc = EXIT_UNGROUP_FAILED;

	free(path);
	free(file);

	return rc;
}

static exit_code_t ccwgroup_st_device_undefine(struct subtype *st,
					       struct device *dev)
{
	struct ccwgroup_subtype_data *data = st->data;

	return ccwgroup_ungroup(data->ccwgroupdrv, dev->id);
}

static char *ccwgroup_st_resolve_devnode(struct subtype *st,
					 struct devnode *devnode)
{
	struct ccwgroup_subtype_data *data = st->data;
	char *link = NULL, *pattern = NULL, *id = NULL, *curr, dummy;
	unsigned int cssid, ssid, devno;
	struct ccwgroup_devid devid;
	struct devnode *netdev = NULL;

	if (devnode->type == BLOCKDEV) {
		netdev = iscsi_get_net_devnode(devnode);
		if (!netdev)
			return NULL;
		devnode = netdev;
	}

	if (devnode->type != NETDEV)
		goto out;

	link = devnode_readlink(devnode);
	if (!link)
		goto out;

	/* ../../devices/qeth/0.0.f503/net/enccw0.0.f503/ */
	curr = strstr(link, "/devices/");
	if (!curr)
		goto out;

	pattern = misc_asprintf("/devices/%s/%%x.%%x.%%x/net%%c",
				data->rootdrv);

	/* /devices/qeth/0.0.f503/net/enccw0.0.f503/ */
	if (sscanf(curr, pattern, &cssid, &ssid, &devno, &dummy) != 4 ||
	    dummy != '/')
		goto out;

	id = misc_asprintf("%x.%x.%04x", cssid, ssid, devno);
	if (read_full_id(&devid, data->ccwgroupdrv, id)) {
		free(id);
		id = ccwgroup_devid_to_str(&devid);
	}

out:
	free(netdev);
	free(pattern);
	free(link);

	return id;
}

static bool ccwgroup_is_id_blacklisted(const char *id)
{
	struct ccwgroup_devid devid;
	char *ccw_id;
	unsigned int i;
	bool result = false;

	if (!ccwgroup_parse_devid_simple(&devid, id))
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

static void ccwgroup_unblacklist_id(const char *id)
{
	struct ccwgroup_devid devid;
	char *ccw_id;
	unsigned int i;

	if (!ccwgroup_parse_devid_simple(&devid, id))
		return;
	for (i = 0; i < devid.num; i++) {
		ccw_id = ccw_devid_to_str(&devid.devid[i]);
		if (ccw_is_id_blacklisted(ccw_id))
			ccw_unblacklist_id(ccw_id);
		free(ccw_id);
	}
}

/* Determine if the specified namespace is compatible with the CCWGROUP
 * namespace. */
bool ccwgroup_compatible_namespace(struct namespace *ns)
{
	if ((void *) ns->cmp_parsed_ids == (void *) &ccwgroup_cmp_parsed_ids)
		return true;

	return false;
}

/*
 * CCWGROUP device ID namespace.
 */

struct namespace ccwgroup_namespace = {
	.devname		= DEVNAME,
	.is_id_valid		= ccwgroup_is_id_valid,
	.cmp_ids		= ccwgroup_cmp_ids,
	.normalize_id		= ccwgroup_normalize_id,
	.parse_id		= ccwgroup_parse_id,
	.cmp_parsed_ids		= ccwgroup_cmp_parsed_ids,
	.qsort_cmp		= ccwgroup_qsort_cmp,
	.is_id_range_valid	= ccwgroup_is_id_range_valid,
	.num_ids_in_range	= ccwgroup_num_ids_in_range,
	.is_id_in_range		= ccwgroup_is_id_in_range,
	.range_start		= ccwgroup_range_start,
	.range_next		= ccwgroup_range_next,

	/* Blacklist handling. */
	.is_blacklist_active	= ccw_is_blacklist_active,
	.is_id_blacklisted	= ccwgroup_is_id_blacklisted,
	.is_id_range_blacklisted = ccw_is_id_range_blacklisted,
	.unblacklist_id		= ccwgroup_unblacklist_id,
	.unblacklist_id_range	= ccw_unblacklist_id_range,
	.blacklist_persist	= ccw_blacklist_persist,
};

/*
 * CCWGROUP device subtype.
 */

/* The methods of this subtype assume that @data points to a
 * struct ccwgroup_subtype_data. */
struct subtype ccwgroup_subtype = {
	.super			= &subtype_base,

	.exists_active		= &ccwgroup_st_exists_active,
	.exists_persistent	= &ccwgroup_st_exists_persistent,
	.exists_autoconf	= &ccwgroup_st_exists_autoconf,

	.add_active_ids		= &ccwgroup_st_add_active_ids,
	.add_persistent_ids	= &ccwgroup_st_add_persistent_ids,
	.add_autoconf_ids	= &ccwgroup_st_add_autoconf_ids,

	.read_active		= &ccwgroup_st_read_active,
	.read_persistent	= &ccwgroup_st_read_persistent,
	.read_autoconf		= &ccwgroup_st_read_autoconf,

	.configure_active	= &ccwgroup_st_configure_active,
	.configure_persistent	= &ccwgroup_st_configure_persistent,
	.configure_autoconf	= &ccwgroup_st_configure_autoconf,

	.deconfigure_active	= &ccwgroup_st_deconfigure_active,
	.deconfigure_persistent	= &ccwgroup_st_deconfigure_persistent,
	.deconfigure_autoconf	= &ccwgroup_st_deconfigure_autoconf,

	.online_set		= &ccwgroup_st_online_set,
	.online_get		= &ccwgroup_st_online_get,
	.online_specified	= &ccwgroup_st_online_specified,

	.add_errors		= &ccwgroup_st_add_errors,

	.add_devnodes		= &ccwgroup_st_add_devnodes,
	.resolve_devnode	= &ccwgroup_st_resolve_devnode,
	.rem_combined		= &ccwgroup_st_rem_combined,
	.get_active_attrib_path	= &ccwgroup_st_get_active_attrib_path,
	.get_active_attrib	= &ccwgroup_st_get_active_attrib,

	.device_define		= &ccwgroup_st_device_define,
	.device_undefine	= &ccwgroup_st_device_undefine,
};
