/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>

#include "lib/util_path.h"

#include "ccw.h"
#include "ccwgroup.h"
#include "ctc.h"
#include "ctc_auto.h"
#include "device.h"
#include "lcs.h"
#include "module.h"
#include "path.h"

struct cutype {
	unsigned int cutype:16;
	unsigned int cumodel:8;
};

static struct cutype ctc_cutypes[] = {
	{ .cutype = 0x3088, .cumodel = 0x08, },
	{ .cutype = 0x3088, .cumodel = 0x1e, },
	{ .cutype = 0x3088, .cumodel = 0x1f, },
};

/*
 * CTC autodetection
 *
 * A CTC device must be grouped before it can be used. The following
 * rules apply to grouping:
 *
 * 1. A CTC device can be grouped from 2 CCW devices
 *    a) Read device
 *    b) Write device
 * 2. All CCW devices must be bound to the CTC CCW device driver. Note that
 *    due to an overlap in CU-Types, CCW device could also be bound to
 *    the LCS device driver.
 * 3. The subchannel of all CCW devices must be defined with the same CHPID
 * 4. None of the CCW devices is part of an existing CCWGROUP device
 */

/* Compare by: 1. CHPID, 2. CUTYPE, 3. DEVTYPE, 4. CCW device ID
 * -1 = a < b    1 = a > b    0 = a == b. */
static int info_cmp(void *a, void *b, void *data)
{
	struct ptrlist_node *pa = a, *pb = b;
	struct ccw_devinfo *ia = pa->ptr, *ib = pb->ptr;
	int r;

	r = ccw_devinfo_chpids_cmp(ia, ib);
	if (r)
		return r;

	r = ccw_devinfo_cutype_cmp(ia, ib);
	if (r)
		return r;

	r = ccw_devinfo_devtype_cmp(ia, ib);
	if (r)
		return r;

	return ccw_cmp_devids(&ia->devid, &ib->devid);
}

static bool is_compatible(struct ccw_devinfo *a, struct ccw_devinfo *b)
{
	if (ccw_devinfo_chpids_cmp(a, b) == 0 &&
	    ccw_devinfo_cutype_cmp(a, b) == 0 &&
	    ccw_devinfo_devtype_cmp(a, b) == 0)
		return true;

	return false;
}

static bool is_ctc(struct ccw_devinfo *info)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ctc_cutypes); i++) {
		if (info->cutype == ctc_cutypes[i].cutype &&
		    info->cumodel == ctc_cutypes[i].cumodel)
			return true;
	}

	return false;
}

/* Add device info for all CTC CCW devices to ptrlist in data. */
static exit_code_t add_cb(const char *path, const char *filename, void *data)
{
	struct ccw_devid devid;
	struct util_list *infos = data;
	struct ccw_devinfo *devinfo;

	if (!strchr(filename, '.'))
		return EXIT_OK;
	if (ccw_parse_devid(&devid, filename, err_ignore) != EXIT_OK)
		return EXIT_OK;
	devinfo = ccw_devinfo_get(&devid, 0);
	if (devinfo->exists && !devinfo->grouped && is_ctc(devinfo))
		ptrlist_add(infos, devinfo);
	else
		free(devinfo);

	return EXIT_OK;
}

/* Return a sorted ptrlist of struct ccw_devinfos for all CCW devices
 * bound to the ctc or lcs CCW device driver with matching CUTYPE.
 * The result must be freed using ptrlist_free(,1); */
static struct util_list *read_sorted_ctc_devinfos(void)
{
	struct util_list *infos;
	char *path;

	/* Get CHPID information for all devices handled by the CTC driver. */
	infos = ptrlist_new();

	/* Add CCW devices bound to the CTC CCW device driver. */
	module_try_load_once(CTC_MOD_NAME, NULL);
	path = path_get_sys_bus_drv(CCW_BUS_NAME, CTC_CCWDRV_NAME);
	if (util_path_is_dir(path))
		path_for_each(path, add_cb, infos);
	free(path);

	/* Add CCW devices bound to the LCS CCW device driver. */
	path = path_get_sys_bus_drv(CCW_BUS_NAME, LCS_CCWDRV_NAME);
	if (util_path_is_dir(path))
		path_for_each(path, add_cb, infos);
	free(path);

	/* For each CHPID: Find groups. Add to result list. */
	util_list_sort(infos, info_cmp, NULL);

	return infos;
}

static void add_ccwgroup_devid(struct util_list *devids, struct ccw_devid *read,
			       struct ccw_devid *write)
{
	struct ccwgroup_devid devid;

	devid.devid[0] = *read;
	devid.devid[1] = *write;
	devid.num = CTC_NUM_DEVS;

	ptrlist_add(devids, ccwgroup_copy_devid(&devid));
}

static void add_groupable_devids(struct util_list *devids,
				 struct util_list *infos)
{
	struct ptrlist_node *curr, *next;
	struct ccw_devinfo *r, *w;

	/* For each CHPID: Find groups. Add to result list. */
	curr = util_list_start(infos);
	while (curr) {
		next = util_list_next(infos, curr);
		if (!next)
			break;
		r = curr->ptr;
		w = next->ptr;
		if (is_compatible(r, w)) {
			add_ccwgroup_devid(devids, &r->devid, &w->devid);
			curr = util_list_next(infos, next);
		} else
			curr = next;
	}
}

/* Add CCWGROUP IDs of ctc devices that can be grouped to strlist @ids. */
void ctc_auto_add_ids(struct util_list *ids)
{
	struct util_list *infos, *devids;
	struct ptrlist_node *p;
	char *id;

	infos = read_sorted_ctc_devinfos();
	devids = ptrlist_new();
	add_groupable_devids(devids, infos);

	util_list_iterate(devids, p) {
		id = ccwgroup_devid_to_str(p->ptr);
		strlist_add(ids, id);
		free(id);
	}

	ptrlist_free(devids, 1);
	ptrlist_free(infos, 1);
}

exit_code_t ctc_auto_get_devid(struct ccwgroup_devid *devid_ptr,
			       struct ccw_devid *ccw_devid, err_t err)
{
	struct util_list *devids, *infos;
	struct ptrlist_node *p, *read, *write;
	struct ccw_devinfo *r, *w;
	struct ccwgroup_devid *devid;
	exit_code_t rc;

	infos = read_sorted_ctc_devinfos();

	/* Try to find an ID from the canonical auto-generated list. */
	devids = ptrlist_new();
	add_groupable_devids(devids, infos);

	util_list_iterate(devids, p) {
		devid = p->ptr;
		if (ccw_cmp_devids(ccw_devid, &devid->devid[0]) != 0)
			continue;
		rc = EXIT_OK;
		if (devid_ptr)
			*devid_ptr = *devid;
		goto out;
	}

	/* Try to create a CCWGROUP ID with the specified ID as read device. */

	/* Get CCW device info for read device. */
	util_list_iterate(infos, read) {
		r = read->ptr;
		if (ccw_cmp_devids(&r->devid, ccw_devid) == 0)
			break;
	}
	if (!read) {
		err_t_print(err, "Read CCW device not found\n");
		rc = EXIT_GROUP_NOT_FOUND;
		goto out;
	}

	/* Get CCW device ID for write device. */
	write = util_list_next(infos, read);
	if (!write) {
		err_t_print(err, "Write CCW device not found\n");
		rc = EXIT_GROUP_NOT_FOUND;
		goto out;
	}
	w = write->ptr;
	if (!is_compatible(r, w)) {
		err_t_print(err, "No compatible write CCW device found\n");
		rc = EXIT_GROUP_INVALID;
		goto out;
	}

	rc = EXIT_OK;
	if (devid_ptr) {
		devid_ptr->devid[0] = r->devid;
		devid_ptr->devid[1] = w->devid;
		devid_ptr->num = CTC_NUM_DEVS;
	}

out:
	ptrlist_free(devids, 1);
	ptrlist_free(infos, 1);

	return rc;
}

exit_code_t ctc_auto_is_possible(struct ccwgroup_devid *devid, err_t err)
{
	struct ccw_devinfo *info[CTC_NUM_DEVS];
	unsigned int i;
	char *ccwid;
	const char *msg;
	exit_code_t rc;

	if (devid->num < CTC_NUM_DEVS) {
		err_t_print(err, "Not enough CCW device IDs in CTC device "
			    "ID\n");
		return EXIT_INCOMPLETE_ID;
	}
	if (devid->num > CTC_NUM_DEVS) {
		err_t_print(err, "CTC device ID contains too many CCW device "
			    "IDs\n");
		return EXIT_INVALID_ID;
	}

	for (i = 0; i < ARRAY_SIZE(info); i++)
		info[i] = ccw_devinfo_get(&devid->devid[i], 1);

	rc = EXIT_OK;
	msg = NULL;
	for (i = 0; i < ARRAY_SIZE(info); i++) {
		if (!info[i]->exists) {
			msg = "CCW device %s does not exist\n";
			rc = EXIT_GROUP_NOT_FOUND;
		} else if (info[i]->grouped) {
			msg = "CCW device %s is in another group device\n";
			rc = EXIT_GROUP_ALREADY;
		} else if (i > 0 &&
			   ccw_devinfo_chpids_cmp(info[i - 1], info[i]) != 0) {
			msg = "CCW device %s is not on the same CHPID\n";
			rc = EXIT_GROUP_INVALID;
		} else if (i > 0 &&
			   ccw_devinfo_cutype_cmp(info[i - 1], info[i]) != 0) {
			msg = "CUTYPE of CCW device %s differs\n";
			rc = EXIT_GROUP_INVALID;
		} else if (i > 0 &&
			   ccw_devinfo_devtype_cmp(info[i - 1], info[i]) != 0) {
			msg = "DEVTYPE of CCW device %s differs\n";
			rc = EXIT_GROUP_INVALID;
		}
		if (!msg)
			continue;
		ccwid = ccw_devid_to_str(&devid->devid[i]);
		err_t_print(err, msg, ccwid);
		free(ccwid);
		break;
	}

	for (i = 0; i < ARRAY_SIZE(info); i++)
		free(info[i]);

	return rc;
}
