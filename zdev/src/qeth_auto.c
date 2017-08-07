/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "ccw.h"
#include "ccwgroup.h"
#include "device.h"
#include "misc.h"
#include "path.h"
#include "qeth.h"
#include "qeth_auto.h"

/*
 * QETH autodetection
 *
 * A QETH device must be grouped before it can be used. The following
 * rules apply to grouping:
 *
 * 1. A QETH device can be grouped from 3 CCW devices
 *    a) Read device
 *    b) Write device
 *    c) Data device
 * 2. All CCW devices must be bound to the QETH CCW device driver
 * 3. The subchannel of all CCW devices must be defined with the same
 *    CHPID
 * 4. The CCW devices must have the same CUTYPE
 * 5. The CCW devices must have the same DEVTYPE
 * 6. The write device ID must be the read device ID plus one
 * 7. None of the CCW devices is part of an existing CCWGROUP device
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

/* Return the number of consecutive ptrlist_nodes pointing to ccw_devinfos
 * which are compatible with each other. */
static unsigned int count_compatible(struct util_list *infos,
				     struct ptrlist_node *start)
{
	struct ptrlist_node *curr;
	unsigned int num;

	num = 0;
	for (curr = start; curr && is_compatible(start->ptr, curr->ptr);
	     curr = util_list_next(infos, curr))
		num++;

	return num;
}

/* Check if sequential fill is possible without holes. */
static bool check_seq(struct util_list *infos, struct ptrlist_node *start,
		      unsigned int num)
{
	struct ptrlist_node *curr;
	struct ccw_devinfo *read = NULL, *write = NULL;
	unsigned int i;

	curr = start;
	for (i = 0; i < num; i++) {
		if (write) {
			/* Expect data. */
			read = NULL;
			write = NULL;
		} else if (read) {
			/* Expect write. */
			write = curr->ptr;
			if (ccw_devid_distance(&read->devid,
					       &write->devid) != 1)
				return false;
		} else {
			/* Expect read. */
			read = curr->ptr;
		}
		curr = util_list_next(infos, curr);
	}

	return true;
}

static void add_ccwgroup_devid(struct util_list *devids, struct ccw_devid *read,
			       struct ccw_devid *write, struct ccw_devid *data)
{
	struct ccwgroup_devid devid;

	devid.devid[0] = *read;
	devid.devid[1] = *write;
	devid.devid[2] = *data;
	devid.num = QETH_NUM_DEVS;

	ptrlist_add(devids, ccwgroup_copy_devid(&devid));
}

static struct ptrlist_node *add_seq(struct util_list *devids,
				    struct util_list *infos,
				    struct ptrlist_node *start,
				    unsigned int num)
{
	struct ptrlist_node *curr;
	struct ccw_devinfo *read = NULL, *write = NULL, *data;
	unsigned int i;

	curr = start;
	for (i = 0; i < num; i++) {
		if (write) {
			/* Expect data. */
			data = curr->ptr;
			add_ccwgroup_devid(devids, &read->devid, &write->devid,
					   &data->devid);
			read = NULL;
			write = NULL;
			data = NULL;
		} else if (read) {
			/* Expect write. */
			write = curr->ptr;
		} else {
			/* Expect read. */
			read = curr->ptr;
		}
		curr = util_list_next(infos, curr);
	}

	return curr;
}

/* Create IDs by searching for consecutive pairs of CCW device IDs first. */
static struct ptrlist_node *add_pairs_first(struct util_list *devids,
					    struct util_list *infos,
					    struct ptrlist_node *start,
					    unsigned int num)
{
	struct util_list *pairs, *all;
	struct ptrlist_node *curr, *next, *read, *data, *cont;
	struct ccw_devinfo *r, *w, *d;
	unsigned int i, max_pairs, num_pairs;

	all = ptrlist_new();
	pairs = ptrlist_new();

	/* Copy devinfos to all list. */
	curr = start;
	for (i = 0; i < num; i++) {
		ptrlist_add(all, curr->ptr);
		curr = util_list_next(infos, curr);
	}
	cont = curr;

	/* Move valid read-write pairs to pairs list. */
	max_pairs = num / QETH_NUM_DEVS;
	num_pairs = 0;
	read = NULL;
	util_list_iterate_safe(all, curr, next) {
		if (read) {
			r = read->ptr;
			w = curr->ptr;
			/* Check for write = read + 1. */
			if (ccw_devid_distance(&r->devid, &w->devid) == 1) {
				ptrlist_move(pairs, all, read);
				ptrlist_move(pairs, all, curr);
				num_pairs++;
				if (num_pairs >= max_pairs)
					break;
				read = NULL;
			} else
				read = curr;
		} else
			read = curr;
	}

	/* Create full groups by combining pairs + remaining IDs. */
	read = NULL;
	util_list_iterate(pairs, curr) {
		if (read) {
			/* Got read and write - check for data. */
			data = util_list_start(all);
			if (!data)
				break;
			util_list_remove(all, data);
			r = read->ptr;
			w = curr->ptr;
			d = data->ptr;
			add_ccwgroup_devid(devids, &r->devid, &w->devid,
					   &d->devid);
			read = NULL;
		} else
			read = curr;
	}

	ptrlist_free(all, 0);
	ptrlist_free(pairs, 0);

	return cont;
}

static struct ptrlist_node *add_groups(struct util_list *devids,
				       struct util_list *infos,
				       struct ptrlist_node *start,
				       unsigned int num)
{
	struct ptrlist_node *next;

	if (check_seq(infos, start, num))
		next = add_seq(devids, infos, start, num);
	else
		next = add_pairs_first(devids, infos, start, num);

	return next;
}

/* Add device info for all QETH CCW devices to ptrlist in data. */
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
	if (devinfo->exists && !devinfo->grouped)
		ptrlist_add(infos, devinfo);
	else
		free(devinfo);

	return EXIT_OK;
}

/* Return a sorted ptrlist of struct ccw_devinfos for all CCW devices
 * bound to the qeth CCW device driver. The result must be freed using
 * ptrlist_free(,1); */
static struct util_list *read_sorted_qeth_devinfos(void)
{
	struct util_list *infos;
	char *path;

	/* Get CHPID information for all devices bound to the QETH driver. */
	infos = ptrlist_new();
	path = path_get_sys_bus_drv(CCW_BUS_NAME, QETH_CCWDRV_NAME);
	if (dir_exists(path))
		path_for_each(path, add_cb, infos);
	free(path);

	/* For each CHPID: Find groups. Add to result list. */
	util_list_sort(infos, info_cmp, NULL);

	return infos;
}

static void add_groupable_devids(struct util_list *devids,
				 struct util_list *infos)
{
	struct ptrlist_node *curr;
	unsigned int num;

	/* For each group of compatible devices: Find valid CCWGROUPs.
	 * Add to result list. */
	curr = util_list_start(infos);
	while (curr) {
		num = count_compatible(infos, curr);
		curr = add_groups(devids, infos, curr, num);
	}
}

/* Add CCWGROUP IDs of qeth devices that can be grouped to strlist IDs.*/
void qeth_auto_add_ids(struct util_list *ids)
{
	struct util_list *infos, *devids;
	struct ptrlist_node *p;
	char *id;

	infos = read_sorted_qeth_devinfos();
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

/* Determine the CCWGROUP ID of the qeth device that can be grouped with the
 * specified CCW device ID as first ID. */
exit_code_t qeth_auto_get_devid(struct ccwgroup_devid *devid_ptr,
				struct ccw_devid *ccw_devid, err_t err)
{
	struct util_list *devids, *infos;
	struct ptrlist_node *p, *read, *write, *data;
	struct ccw_devinfo *r, *w, *d;
	struct ccwgroup_devid *devid;
	exit_code_t rc;

	infos = read_sorted_qeth_devinfos();

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
	if (ccw_devid_distance(&r->devid, &w->devid) != 1) {
		err_t_print(err, "Write CCW device ID must be read plus one\n");
		rc = EXIT_GROUP_INVALID;
		goto out;
	}

	/* Get CCW device ID for data device. */

	/* 1. Prefer ID after the write ID. */
	data = util_list_next(infos, write);
	if (!data || !is_compatible(r, data->ptr)) {
		/* Try ID before read ID. */
		data = util_list_prev(infos, read);
	}
	if (!data) {
		err_t_print(err, "Data CCW device not found\n");
		rc = EXIT_GROUP_NOT_FOUND;
		goto out;
	}
	if (!is_compatible(r, data->ptr)) {
		err_t_print(err, "No compatible data CCW device found\n");
		rc = EXIT_GROUP_INVALID;
		goto out;
	}
	d = data->ptr;

	rc = EXIT_OK;
	if (devid_ptr) {
		devid_ptr->devid[0] = r->devid;
		devid_ptr->devid[1] = w->devid;
		devid_ptr->devid[2] = d->devid;
		devid_ptr->num = QETH_NUM_DEVS;
	}

out:
	ptrlist_free(devids, 1);
	ptrlist_free(infos, 1);

	return rc;
}

/* Check if the specified QETH device can be grouped .*/
exit_code_t qeth_auto_is_possible(struct ccwgroup_devid *devid, err_t err)
{
	struct ccw_devinfo *info[QETH_NUM_DEVS];
	unsigned int i;
	char *ccwid;
	const char *msg;
	exit_code_t rc;

	if (devid->num < QETH_NUM_DEVS) {
		err_t_print(err, "Not enough CCW device IDs in QETH device "
			    "ID\n");
		return EXIT_INCOMPLETE_ID;
	}
	if (devid->num > QETH_NUM_DEVS) {
		err_t_print(err, "QETH device ID contains too many CCW device "
			    "IDs\n");
		return EXIT_INVALID_ID;
	}
	if (ccw_devid_distance(&devid->devid[0], &devid->devid[1]) != 1) {
		err_t_print(err, "Write device ID must be read plus one\n");
		return EXIT_GROUP_INVALID;
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
