/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_base.h"
#include "lib/util_path.h"

#include "attrib.h"
#include "ccw.h"
#include "ccwgroup.h"
#include "device.h"
#include "devnode.h"
#include "devtype.h"
#include "misc.h"
#include "module.h"
#include "namespace.h"
#include "path.h"
#include "setting.h"
#include "udev.h"
#include "udev_ccw.h"

#define DEVNAME			"CCW device"
#define CSSID_MAX		255
#define	SSID_MAX		15
#define DEVNO_MAX		65535
#define CCW_HASH_BUCKETS	256

/*
 * Common CCW device attributes and related functions.
 */

struct attrib ccw_attr_online = {
	.name = "online",
	.title = "Activate a device",
	.desc = "Control the activation of a device:\n"
		"  0: Device is disabled and cannot be used\n"
		"  1: Device is enabled\n",
	.mandatory = 1,
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
};

struct attrib ccw_attr_online_force = {
	.name = "online",
	.title = "Activate a device",
	.desc = "Control the activation of a device:\n"
		"  0:     Device is disabled and cannot be used\n"
		"  1:     Device is enabled\n"
		"  force: Release an existing reservation for this device\n"
		"         before trying to enable it\n",
	.mandatory = 1,
	.defval = "0",
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1), ACCEPT_STR("force")),
};

struct attrib ccw_attr_cmb_enable = {
	.name = "cmb_enable",
	.title = "Enable the Channel measurement facility",
	.desc =
	"Control the channel measurement facility setting for a device:\n"
	"  0: Data collection is disabled\n"
	"  1: Data collection is enabled (rewrite 1 to reset data)\n",
	.rewrite = 1,
	.defval = "0",
	.order_cmp = ccw_offline_only_order_cmp,
	.accept = ACCEPT_ARRAY(ACCEPT_RANGE(0, 1)),
};

static bool is_online(const char *value)
{
	if (!value)
		return false;
	if (strcmp(value, "force") == 0 || atoi(value) == 1)
		return true;

	return false;
}

static bool is_offline(const char *value)
{
	if (!value)
		return false;
	if (atoi(value) == 0)
		return true;

	return false;
}

/* Function to be used as order_cmp callback for attributes that can only be
 * set while a CCW device is online. @a is the attribute in question, while
 * @b can be any other setting, including the online attribute. */
int ccw_online_only_order_cmp(struct setting *a, struct setting *b)
{
	if (b->attrib != &ccw_attr_online &&
	    b->attrib != &ccw_attr_online_force)
		return 0;

	/* This setting should be applied before online=0 (assuming it
	 * started online) or after online=1. */
	if (is_online(b->value))
		return 1;

	return -1;
}

/* Function to be used as check callback for attributes that can only be
 * set while a CCW device is online. @a is the attribute in question, while
 * @b can be any other setting, including the online attribute. Return
 * %false in case there is a conflict, %true otherwise. */
bool ccw_online_only_check(struct setting *a, struct setting *b,
			   config_t config)
{
	if (b->attrib != &ccw_attr_online &&
	    b->attrib != &ccw_attr_online_force)
		return true;

	/* No conflict if:
	 *  - online=1: setting can be applied
	 *  - online is changed to 1: setting can be applied after change
	 *  - online is changed from 1 to 0 in the active configuration:
	 *    setting can be applied before change */
	if (is_online(b->value) ||
	    (SCOPE_ACTIVE(config) && is_online(b->actual_value)))
		return true;

	return false;
}

/* Function to be used as order_cmp callback for attributes that can only be
 * set while a CCW device is offline. @a is the attribute in question, while
 * @b can be any other setting, including the online attribute. */
int ccw_offline_only_order_cmp(struct setting *a, struct setting *b)
{
	if (b->attrib != &ccw_attr_online &&
	    b->attrib != &ccw_attr_online_force)
		return 0;

	/* This setting should be applied before online=1 (assuming it
	 * started offline) or after online=0. */
	if (is_online(b->value))
		return -1;

	return 1;
}

/* Function to be used as check callback for attributes that can only be
 * set while a CCW device is offline. @a is the attribute in question, while
 * @b can be any other setting, including the online attribute. Return
 * %false in case there is a conflict, %true otherwise. */
bool ccw_offline_only_check(struct setting *a, struct setting *b,
			    config_t config)
{
	if (b->attrib != &ccw_attr_online &&
	    b->attrib != &ccw_attr_online_force)
		return true;

	if (!SCOPE_ACTIVE(config)) {
		/* CCW devices start in offline mode so no conflict. */
		return true;
	}

	/* No conflict if:
	 *  - online=0: setting can be applied
	 *  - online is changed to 0: setting can be applied after change
	 *  - online is changed from 0 to 1: setting can be applied before
	 *    change */
	if (is_offline(b->value) || is_offline(b->actual_value))
		return true;

	return false;
}


/*
 * CCW device methods.
 */

/**
 * ccw_parse_devid - Parse a string into a ccw_devid
 * @devid_ptr: Target ccw_devid or NULL
 * @id: String to parse
 * @err: Specify what to do with errors (ignore, print, delayed_print)
 *
 * Return %EXIT_OK on success, a corresponding error exit code otherwise.
 */
exit_code_t ccw_parse_devid(struct ccw_devid *devid_ptr, const char *id,
			    err_t err)
{
	unsigned int cssid, ssid, devno;
	char d;
	char *reason = NULL;
	exit_code_t rc = EXIT_INVALID_ID;

	if (sscanf(id, "%8x %c", &devno, &d) == 1) {
		if (strcasecmp(id, "0x") == 0) {
			reason = "Incomplete hexadecimal number";
			goto out;
		}
		cssid = 0;
		ssid = 0;
	} else if (sscanf(id, "%8x.%8x.%8x %c", &cssid, &ssid, &devno,
			  &d) != 3) {
		reason = "Invalid format";
		goto out;
	}

	if (cssid > CSSID_MAX) {
		reason = "CSSID out of bounds";
		goto out;
	}
	if (ssid > SSID_MAX) {
		reason = "SSID out of bounds";
		goto out;
	}
	if (devno > DEVNO_MAX) {
		reason = "DEVNO out of bounds";
		goto out;
	}

	rc = EXIT_OK;
	if (devid_ptr) {
		devid_ptr->cssid = cssid;
		devid_ptr->ssid = ssid;
		devid_ptr->devno = devno;
	}

out:
	if (reason) {
		err_t_print(err, "Error in %s ID format: %s: %s\n", DEVNAME,
			    reason, id);
	}

	return rc;
}

bool ccw_parse_devid_simple(struct ccw_devid *devid, const char *id)
{
	if (ccw_parse_devid(devid, id, err_ignore) == EXIT_OK)
		return true;

	return false;
}

static exit_code_t ccw_is_id_valid(const char *id, err_t err)
{
	return ccw_parse_devid(NULL, id, err);
}

bool ccw_is_id_similar(const char *id)
{
	char *copy, *start, *end;
	bool result = false;

	copy = misc_strdup(id);
	start = copy;

	if (strchr(start, ':'))
		goto out;
	/* xx.xx.xxxx or xxxx or 0xxxxx */
	end = strchr(start, '.');
	if (end) {
		/* Check for a list of 2 dot-separated hexadecimal numbers. */
		*end = 0;
		if (!valid_hex(start) || strlen(start) > 8)
			goto out;
		start = end + 1;

		end = strchr(start, '.');
		if (!end)
			goto out;
		*end = 0;
		if (!valid_hex(start) || strlen(start) > 8)
			goto out;
		start = end + 1;
	}

	/* Check if this is a valid hexadecimal number. */
	if (valid_hex(start) && strlen(start) <= 8)
		result = true;

out:
	free(copy);

	return result;
}

static int ccw_cmp_parsed_ids(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct ccw_devid));
}

static int ccw_cmp_ids(const char *a_str, const char *b_str)
{
	struct ccw_devid a, b;

	if (!ccw_parse_devid_simple(&a, a_str) ||
	    !ccw_parse_devid_simple(&b, b_str))
		return -1;

	return ccw_cmp_parsed_ids(&a, &b);
}

static int ccw_qsort_cmp(const void *a_ptr, const void *b_ptr)
{
	const char *a = *((const char **) a_ptr);
	const char *b = *((const char **) b_ptr);

	return ccw_cmp_ids(a, b);
}

static int ccw_hash_by_parsed_id(const void *devid_ptr)
{
	const struct ccw_devid *devid = devid_ptr;

	return devid->devno & 0xff;
}

/* Return distance between CCW device IDs %a and %b in number of CCW device
 * IDs or INT_MAX if both IDs are not in the same CSS/SS. */
int ccw_devid_distance(struct ccw_devid *a, struct ccw_devid *b)
{
	if (a->cssid != b->cssid)
		return INT_MAX;
	if (a->ssid != b->ssid)
		return INT_MAX;

	return (int) b->devno - (int) a->devno;
}

char *ccw_devid_to_str(struct ccw_devid *devid)
{
	return misc_asprintf("%x.%x.%04x", devid->cssid, devid->ssid,
			     devid->devno);
}

char *ccw_normalize_id(const char *id)
{
	struct ccw_devid devid;

	if (!ccw_parse_devid_simple(&devid, id))
		return NULL;

	return ccw_devid_to_str(&devid);
}

static exit_code_t ccw_parse_devid_range(struct ccw_devid *from_ptr,
					 struct ccw_devid *to_ptr,
					 const char *range, err_t err)
{
	char *from_str, *to_str;
	struct ccw_devid from, to;
	exit_code_t rc = EXIT_INVALID_ID;
	const char *reason = NULL;

	/* Split range. */
	from_str = misc_strdup(range);
	to_str = strchr(from_str, '-');
	if (!to_str) {
		reason = "Missing hyphen";
		goto out;
	}
	*to_str = 0;
	to_str++;

	/* Parse range start end end ID. */
	rc = ccw_parse_devid(&from, from_str, err);
	if (rc)
		goto out;

	rc = ccw_parse_devid(&to, to_str, err);
	if (rc)
		goto out;

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

static bool ccw_parse_devid_range_simple(struct ccw_devid *from,
					 struct ccw_devid *to,
					 const char *range)
{
	if (ccw_parse_devid_range(from, to, range, err_ignore) == EXIT_OK)
		return true;

	return false;
}

static exit_code_t ccw_is_id_range_valid(const char *range, err_t err)
{
	return ccw_parse_devid_range(NULL, NULL, range, err);
}

static unsigned long ccw_num_ids_in_range(const char *range)
{
	struct ccw_devid f, t;

	if (!ccw_parse_devid_range_simple(&f, &t, range))
		return 0;

	if (f.cssid != t.cssid || f.ssid != t.ssid)
		return 0;

	if (f.devno > t.devno)
		return 0;

	return t.devno - f.devno + 1;
}

static struct ccw_devid *copy_devid(struct ccw_devid *devid)
{
	struct ccw_devid *result;

	result = misc_malloc(sizeof(struct ccw_devid));
	*result = *devid;

	return result;
}

/* Initialize the range iterator object IT with the specified range and
 * set it->id to the first ID in the range or NULL if the range is not valid.
 * All used fields in IT must be objects allocated using alloc().  */
static void ccw_range_start(struct ns_range_iterator *it, const char *range)
{
	struct ccw_devid from, to;

	if (!ccw_parse_devid_range_simple(&from, &to, range)) {
		memset(it, 0, sizeof(struct ns_range_iterator));
		return;
	}

	it->devid = copy_devid(&from);
	it->devid_last = copy_devid(&to);
	it->id = ccw_devid_to_str(it->devid);
}

/* Set it->id to the next ID in the range or NULL if the end of the range
 * was reached. */
static void ccw_range_next(struct ns_range_iterator *it)
{
	struct ccw_devid *curr, *last;

	if (!it->id)
		return;
	free(it->id);
	curr = it->devid;
	last = it->devid_last;
	if (curr->devno < last->devno) {
		curr->devno++;
		it->id = ccw_devid_to_str(curr);
	} else
		it->id = NULL;
}

static void *ccw_parse_id(const char *id, err_t err)
{
	struct ccw_devid *devid;

	devid = misc_malloc(sizeof(struct ccw_devid));
	if (ccw_parse_devid(devid, id, err) != EXIT_OK) {
		free(devid);
		return NULL;
	}
	return devid;
}

int ccw_cmp_devids(struct ccw_devid *a, struct ccw_devid *b)
{
	return ccw_cmp_parsed_ids(a, b);
}

/*
 * cio_ignore handling.
 */

static char *proc_cio_ignore;
static struct util_list *ignore_once_list;
static struct util_list *devinfos;

/* Release memory used by CCW module. */
void ccw_exit(void)
{
	free(proc_cio_ignore);
	strlist_free(ignore_once_list);
	ptrlist_free(devinfos, 1);
}

/* Before accessing a CCW device, ensure that the common I/O layer has finished
 * processing all events. This is done only once unless FORCE is set to a
 * non-zero value. */
void cio_settle(int force)
{
	static int done;
	char *path;

	if (done && !force)
		return;

	path = path_get_proc("cio_settle");
	misc_write_text_file(path, "\n", err_ignore);
	free(path);
	done = 1;
}

/* Determine the name of the CCW driver associated with the specified device. */
char *ccw_get_driver(struct ccw_devid *devid)
{
	char *id, *path, *driver_path, *link, *drv = NULL;

	id = ccw_devid_to_str(devid);
	path = path_get_ccw_device(NULL, id);
	driver_path = misc_asprintf("%s/driver", path);
	link = misc_readlink(driver_path);
	if (link)
		drv = misc_strdup(basename(link));
	free(link);
	free(driver_path);
	free(path);
	free(id);

	return drv;
}

/* Return the name of the kernel module associated with the specified device. */
static char *ccw_get_module(struct ccw_devid *devid)
{
	char *id, *path, *driver_path, *link, *module = NULL;

	id = ccw_devid_to_str(devid);
	path = path_get_ccw_device(NULL, id);
	driver_path = misc_asprintf("%s/driver/module", path);
	link = misc_readlink(driver_path);
	if (link)
		module = misc_strdup(basename(link));
	free(link);
	free(driver_path);
	free(path);
	free(id);

	return module;

}

/* Unbind a CCW device from its driver. */
exit_code_t ccw_unbind_device(struct ccw_devid *devid)
{
	char *id, *path, *unbind_path;
	exit_code_t rc;

	id = ccw_devid_to_str(devid);
	path = path_get_ccw_device(NULL, id);
	unbind_path = misc_asprintf("%s/driver/unbind", path);
	rc = misc_write_text_file(unbind_path, id, err_delayed_print);
	if (rc)
		delayed_err("Could not unbind CCW device %s from driver\n", id);

	free(unbind_path);
	free(path);
	free(id);

	return rc;
}

/* Bind a CCW device to a driver. */
exit_code_t ccw_bind_device(struct ccw_devid *devid, const char *drv)
{
	char *id, *path, *bind_path;
	exit_code_t rc;

	id = ccw_devid_to_str(devid);
	path = path_get_sys_bus_drv(CCW_BUS_NAME, drv);
	bind_path = misc_asprintf("%s/bind", path);
	rc = misc_write_text_file(bind_path, id, err_delayed_print);
	if (rc) {
		delayed_err("Could not bind CCW device %s to driver %s\n",
			    id, drv);
	}
	free(bind_path);
	free(path);
	free(id);

	return rc;
}

/* Check if the specified device ID is within the range specified by FROM
 * and TO. */
bool ccw_devid_in_range(struct ccw_devid *id, struct ccw_devid *from,
			struct ccw_devid *to)
{
	if (ccw_cmp_parsed_ids(id, from) < 0 || ccw_cmp_parsed_ids(id, to) > 0)
		return false;

	return true;
}

/* Check if @id is in @range. */
static bool ccw_is_id_in_range(const char *id, const char *range)
{
	struct ccw_devid devid, from, to;

	if (!ccw_parse_devid_range_simple(&from, &to, range))
		return false;
	if (!ccw_parse_devid_simple(&devid, id))
		return false;

	return ccw_devid_in_range(&devid, &from, &to);
}

/* Return a newly allocated copy of @devid. */
struct ccw_devid *ccw_copy_devid(struct ccw_devid *devid)
{
	struct ccw_devid *result;

	result = misc_malloc(sizeof(struct ccw_devid));
	*result = *devid;

	return result;
}

static char *read_cio_ignore(void)
{
	static int warned;
	char *path;

	if (proc_cio_ignore)
		return proc_cio_ignore;
	path = path_get_proc("cio_ignore");
	proc_cio_ignore = misc_read_text_file(path, 0, err_ignore);
	if (!proc_cio_ignore) {
		if (!warned) {
			warn("Failed to read %s: Could not access CIO "
			     "blacklist\n", path);
		}
		warned = 1;
	}
	free(path);

	return proc_cio_ignore;
}

/* Check if there is a CCW device blacklist active. */
bool ccw_is_blacklist_active(void)
{
	read_cio_ignore();
	if (!proc_cio_ignore || !*proc_cio_ignore)
		return false;

	return true;
}

static bool is_ignored(const char *str, int is_range)
{
	char *copy, *next, *curr;
	bool rc = false;
	struct ccw_devid id, id2, from, to;

	if (is_range) {
		if (!ccw_parse_devid_range_simple(&id, &id2, str))
			return false;
	} else {
		if (!ccw_parse_devid_simple(&id, str))
			return false;
	}

	/* Read /proc/cio_ignore. */
	if (!read_cio_ignore())
		return false;

	/* Iterate over each line. */
	copy = misc_strdup(proc_cio_ignore);
	next = copy;
	while ((curr = strsep(&next, "\n"))) {
		if (*curr == 0)
			break;
		if (ccw_parse_devid_simple(&from, curr)) {
			/* Single ID: xx.y.zzzz */
			if (is_range) {
				/* Is FROM within ID-ID2? */
				if (!ccw_devid_in_range(&from, &id, &id2))
					continue;
			} else {
				/* Is FROM the same as ID? */
				if (ccw_cmp_parsed_ids(&id, &from) != 0)
					continue;
			}
			goto found;
		}
		if (!ccw_parse_devid_range_simple(&from, &to, curr))
			continue;

		/* ID range: xx.y.zzzz-xx.y.zzzz */
		if (is_range) {
			/* Does FROM-TO intersect with ID-ID2 ? */
			if (ccw_cmp_parsed_ids(&to, &id) < 0 ||
			    ccw_cmp_parsed_ids(&from, &id2) > 0)
				continue;
		} else {
			/* Is ID inside FROM-TO? */
			if (!ccw_devid_in_range(&id, &from, &to))
				continue;
		}

found:
		rc = true;
		break;
	}
	free(copy);

	return rc;
}

/* Determine if the specified CCW device ID is on the cio_ignore blacklist. */
bool ccw_is_id_blacklisted(const char *id)
{
	return is_ignored(id, 0);
}

/* Determine if a device ID in the specified CCW device ID range is on the
 * cio_ignore blacklist. */
bool ccw_is_id_range_blacklisted(const char *range)
{
	return is_ignored(range, 1);
}

/* Remove a CCW device ID from the CIO blacklist. Ensure that this is done
 * only once. */
void ccw_unblacklist_id(const char *id)
{
	char *normid, *path, *line;

	/* Ensure that this is only attempted once. */
	normid = ccw_normalize_id(id);
	if (!normid)
		return;
	if (!ignore_once_list)
		ignore_once_list = strlist_new();
	if (strlist_find(ignore_once_list, normid)) {
		free(normid);
		return;
	}

	verb("Removing CCW device %s from the CIO blacklist\n", normid);
	strlist_add(ignore_once_list, normid);
	free(normid);

	path = path_get_proc("cio_ignore");
	line = misc_asprintf("free %s", id);
	if (misc_write_text_file(path, line, err_ignore))
		warn("Could not remove %s from the CIO blacklist\n", id);
	cio_settle(1);
	free(line);
	free(path);
	free(proc_cio_ignore);

	/* Ensure that cio_ignore file is re-read. */
	proc_cio_ignore = NULL;
}

/* Remove a CCW device ID range from the CIO blacklist. */
void ccw_unblacklist_id_range(const char *range)
{
	char *path, *line;

	verb("Removing CCW device ID range %s from the CIO blacklist\n", range);

	path = path_get_proc("cio_ignore");
	line = misc_asprintf("free %s", range);
	if (misc_write_text_file(path, line, err_ignore))
		warn("Could not remove %s from the CIO blacklist\n", range);
	cio_settle(1);
	/* Need to wait for udev or persistent changes might accidentally
	 * become activated due to delayed register events. */
	udev_settle();
	free(line);
	free(path);
	free(proc_cio_ignore);

	/* Ensure that cio_ignore file is re-read. */
	proc_cio_ignore = NULL;
}

static char ***id_bitmap_new(void)
{
	return misc_malloc(sizeof(char **) * (CSSID_MAX + 1));
}

static void id_bitmap_free(char ***id_bitmap)
{
	unsigned int cssid, ssid;

	for (cssid = 0; cssid <= CSSID_MAX; cssid++) {
		if (!id_bitmap[cssid])
			continue;
		for (ssid = 0; ssid <= SSID_MAX; ssid++)
			free(id_bitmap[cssid][ssid]);
		free(id_bitmap[cssid]);
	}

	free(id_bitmap);
}

#define BITS_PER_CHAR	8

static void id_bitmap_set(char ***id_bitmap, unsigned int cssid,
			  unsigned int ssid, unsigned int devno)
{
	unsigned int offset, bit;

	if (!id_bitmap[cssid])
		id_bitmap[cssid] = misc_malloc(sizeof(char *) * (SSID_MAX + 1));
	if (!id_bitmap[cssid][ssid]) {
		id_bitmap[cssid][ssid] = misc_malloc(sizeof(char) *
						     (DEVNO_MAX + 1) /
						     BITS_PER_CHAR);
	}

	offset = devno / BITS_PER_CHAR;
	bit = devno % BITS_PER_CHAR;

	id_bitmap[cssid][ssid][offset] |= 1 << bit;
}

static bool id_bitmap_get(char ***id_bitmap, unsigned int cssid,
			  unsigned int ssid, unsigned int devno)
{
	unsigned int offset, bit;

	if (!id_bitmap[cssid])
		return false;
	if (!id_bitmap[cssid][ssid])
		return false;

	offset = devno / BITS_PER_CHAR;
	bit = devno % BITS_PER_CHAR;

	if (id_bitmap[cssid][ssid][offset] & 1 << bit)
		return true;

	return false;
}

static exit_code_t collect_cb(struct subtype *st, const char *id,
			      config_t config, void *data)
{
	char ***id_bitmap = data;
	struct ccw_devid devid;

	if (ccw_parse_devid_simple(&devid, id))
		id_bitmap_set(id_bitmap, devid.cssid, devid.ssid, devid.devno);

	return EXIT_OK;
}

static exit_code_t collect_group_cb(struct subtype *st, const char *id,
				    config_t config, void *data)
{
	char ***id_bitmap = data;
	struct ccwgroup_devid devid;
	unsigned int i;

	if (ccwgroup_parse_devid_simple(&devid, id)) {
		for (i = 0; i < devid.num; i++) {
			id_bitmap_set(id_bitmap, devid.devid[i].cssid,
				      devid.devid[i].ssid,
				      devid.devid[i].devno);
		}
	}

	return EXIT_OK;
}

/* Set bits for all persistently configured CCW devices. */
static char ***id_bitmap_collect(bool autoconf)
{
	char ***id_bitmap;
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	config_t config = autoconf ? config_autoconf : config_persistent;

	id_bitmap = id_bitmap_new();

	/* Search all subtypes. */
	for (i = 0; (dt = devtypes[i]); i++) {
		for (j = 0; (st = dt->subtypes[j]); j++) {
			/* Collect CCW device IDs. */
			if (st->namespace == &ccw_namespace) {
				subtype_for_each_id(st, config,
						    collect_cb, id_bitmap);
			}
			/* Collect CCWGROUP device IDs. Since there may be
			 * multiple namespaces, we need to make use of this
			 * hack. */
			if (ccwgroup_compatible_namespace(st->namespace)) {
				subtype_for_each_id(st, config,
						    collect_group_cb,
						    id_bitmap);
			}
		}
	}

	return id_bitmap;
}

struct ccw_devid_range {
	struct ccw_devid from;
	struct ccw_devid to;
};

static void range_add(struct util_list *list, struct ccw_devid *from,
		      struct ccw_devid *to)
{
	char *f_str, *fs_str, *t_str = NULL, *ts_str;

	f_str = ccw_devid_to_str(from);
	if (from->cssid == 0 && from->ssid == 0)
		fs_str = f_str + 4;
	else
		fs_str = f_str;
	if (to) {
		t_str = ccw_devid_to_str(to);
		if (to->cssid == 0 && to->ssid == 0)
			ts_str = t_str + 4;
		else
			ts_str = t_str;
		strlist_add(list, "%s-%s", fs_str, ts_str);
	} else
		strlist_add(list, "%s", fs_str);

	free(t_str);
	free(f_str);
}

static struct util_list *cio_ignore_get_ranges(bool autoconf)
{
	char ***id_bitmap;
	unsigned int cssid, ssid, devno;
	struct util_list *ranges;
	struct ccw_devid a, b;
	struct ccw_devid *first, *last;

	ranges = strlist_new();

	id_bitmap = id_bitmap_collect(autoconf);
	for (cssid = 0; cssid <= CSSID_MAX; cssid++) {
		if (!id_bitmap[cssid])
			continue;
		for (ssid = 0; ssid <= SSID_MAX; ssid++) {
			if (!id_bitmap[cssid][ssid])
				continue;
			first = NULL;
			last = NULL;
			for (devno = 0; devno <= DEVNO_MAX; devno++) {
				if (!id_bitmap_get(id_bitmap, cssid, ssid,
						   devno)) {
					if (first) {
						range_add(ranges, first, last);
						first = NULL;
						last = NULL;
					}
					continue;
				}
				if (first) {
					last = &b;
					last->cssid = cssid;
					last->ssid = ssid;
					last->devno = devno;
				} else {
					first = &a;
					first->cssid = cssid;
					first->ssid = ssid;
					first->devno = devno;
				}
			}
			if (first)
				range_add(ranges, first, last);
		}
	}
	id_bitmap_free(id_bitmap);

	return ranges;
}

/* Persistently configure cio_ignore. */
static exit_code_t _ccw_blacklist_persist(bool autoconf)
{
	struct util_list *ranges;
	char *id_list;
	exit_code_t rc;

	/* Get string to write to /proc/cio_ignore. */
	ranges = cio_ignore_get_ranges(autoconf);
	id_list = strlist_flatten(ranges, ",");
	strlist_free(ranges);

	/* Write udev rule to automatically write cio_ignore. */
	rc = udev_ccw_write_cio_ignore(id_list, autoconf);
	free(id_list);

	return rc;
}

exit_code_t ccw_blacklist_persist(void)
{
	exit_code_t rc1, rc2;

	rc1 = _ccw_blacklist_persist(false);
	rc2 = _ccw_blacklist_persist(true);

	return rc1 ? rc1 : rc2;
}

/*
 * CCW device ID namespace.
 */

struct namespace ccw_namespace = {
	.devname		= DEVNAME,

	/* IDs. */
	.is_id_valid		= ccw_is_id_valid,
	.is_id_similar		= ccw_is_id_similar,
	.cmp_ids		= ccw_cmp_ids,
	.normalize_id		= ccw_normalize_id,
	.parse_id		= ccw_parse_id,
	.cmp_parsed_ids		= ccw_cmp_parsed_ids,
	.qsort_cmp		= ccw_qsort_cmp,

	/* ID Hash. */
	.hash_buckets		= CCW_HASH_BUCKETS,
	.hash_parsed_id		= ccw_hash_by_parsed_id,

	/* Ranges. */
	.is_id_range_valid	= ccw_is_id_range_valid,
	.num_ids_in_range	= ccw_num_ids_in_range,
	.is_id_in_range		= ccw_is_id_in_range,
	.range_start		= ccw_range_start,
	.range_next		= ccw_range_next,

	/* Blacklist handling. */
	.is_blacklist_active	= ccw_is_blacklist_active,
	.is_id_blacklisted	= ccw_is_id_blacklisted,
	.is_id_range_blacklisted = ccw_is_id_range_blacklisted,
	.unblacklist_id		= ccw_unblacklist_id,
	.unblacklist_id_range	= ccw_unblacklist_id_range,
	.blacklist_persist	= ccw_blacklist_persist,
};

/*
 * CCW device info handling.
 */

/* Used for debugging. */
void ccw_devinfo_print(struct ccw_devinfo *d, int level)
{
	char *id;
	int i;

	printf("%*sdevinfo at %p\n", level, "", (void *) d);
	if (!d)
		return;
	level += 2;
	id = ccw_devid_to_str(&d->devid);
	printf("%*sdevid=%s\n", level, "", id);
	printf("%*scutype=%04x/%02x\n", level, "", d->cutype, d->cumodel);
	printf("%*sdevtype=%04x/%02x\n", level, "", d->devtype, d->devmodel);
	printf("%*schpids=", level, "");
	for (i = 0; i < CCW_CHPID_NUM; i++) {
		printf("%" PRIx8 ".%02" PRIx8 " ", d->chpids[i].cssid,
		       d->chpids[i].id);
	}
	printf("\n");
	printf("%*spim=%02x\n", level, "", d->pim);
	printf("%*sexists=%d\n", level, "", d->exists);
	printf("%*sgrouped=%d\n", level, "", d->grouped);
}

static struct ccw_devinfo *ccw_devinfo_find(struct ccw_devid *devid)
{
	struct ccw_devinfo *info;
	struct ptrlist_node *p;

	if (!devinfos)
		return NULL;

	util_list_iterate(devinfos, p) {
		info = p->ptr;
		if (ccw_cmp_devids(devid, &info->devid) == 0)
			return info;
	}

	return NULL;
}

static bool read_pim(struct ccw_devinfo *info, const char *path)
{
	char *file_path, *text;
	bool result = false;
	uint8_t pim;

	file_path = misc_asprintf("%s/../pimpampom", path);
	text = misc_read_text_file(file_path, 1, err_ignore);
	if (!text)
		goto out;

	if (sscanf(text, "%" SCNx8, &pim) != 1)
		goto out;

	info->pim = pim;
	result = true;

out:
	free(text);
	free(file_path);

	return result;
}

static bool read_chpids(struct ccw_devinfo *info, unsigned int cssid,
			unsigned int pim, const char *path)
{
	char *file_path, *text;
	bool result = false;
	struct ccw_chpid ids[CCW_CHPID_NUM];
	int i;

	file_path = misc_asprintf("%s/../chpids", path);
	text = misc_read_text_file(file_path, 1, err_ignore);
	if (!text)
		goto out;

	if (sscanf(text, "%" SCNx8 " %" SCNx8 " %" SCNx8 " %" SCNx8
		   "%" SCNx8 " %" SCNx8 " %" SCNx8 " %" SCNx8,
		   &ids[0].id, &ids[1].id, &ids[2].id, &ids[3].id,
		   &ids[4].id, &ids[5].id, &ids[6].id, &ids[7].id) != 8)
		goto out;

	/* Apply CSS-ID to CHPIDs. */
	for (i = 0; i < CCW_CHPID_NUM; i++) {
		if (pim & CCW_CHPID_MASK(i))
			ids[i].cssid = cssid;
		else
			ids[i].cssid = 0;
	}

	memcpy(&info->chpids, ids, sizeof(ids));
	result = true;

out:
	free(text);
	free(file_path);

	return result;
}

static void read_grouped(struct ccw_devinfo *info, const char *path)
{
	if (util_path_exists("%s/group_device", path))
		info->grouped = 1;
	else
		info->grouped = 0;
}

static void read_cutype(struct ccw_devinfo *info, const char *path)
{
	char *file_path, *text;
	unsigned int cutype = 0, cumodel = 0;

	file_path = misc_asprintf("%s/cutype", path);
	text = misc_read_text_file(file_path, 1, err_ignore);
	if (!text)
		goto out;

	if (sscanf(text, "%04x/%02x", &cutype, &cumodel) != 2)
		goto out;

out:
	info->cutype = cutype;
	info->cumodel = cumodel;

	free(text);
	free(file_path);
}

static void read_devtype(struct ccw_devinfo *info, const char *path)
{
	char *file_path, *text;
	unsigned int devtype = 0, devmodel = 0;

	file_path = misc_asprintf("%s/devtype", path);
	text = misc_read_text_file(file_path, 1, err_ignore);
	if (!text)
		goto out;

	if (sscanf(text, "%04x/%02x", &devtype, &devmodel) != 2)
		goto out;

out:
	info->devtype = devtype;
	info->devmodel = devmodel;

	free(text);
	free(file_path);
}

/* Read device information from sysfs. */
static struct ccw_devinfo *ccw_devinfo_read(struct ccw_devid *devid)
{
	struct ccw_devinfo *info;
	char *id, *path;

	info = misc_malloc(sizeof(struct ccw_devinfo));
	info->devid = *devid;

	id = ccw_devid_to_str(devid);
	path = path_get_ccw_device(NULL, id);
	if (!util_path_is_dir(path))
		goto out;

	info->exists = 1;

	if (read_pim(info, path))
		read_chpids(info, devid->cssid, info->pim, path);
	read_grouped(info, path);
	read_cutype(info, path);
	read_devtype(info, path);

out:
	free(path);
	free(id);

	return info;
}

static struct ccw_devinfo *ccw_devinfo_copy(struct ccw_devinfo *info)
{
	struct ccw_devinfo *result;

	result = misc_malloc(sizeof(struct ccw_devinfo));
	memcpy(result, info, sizeof(struct ccw_devinfo));

	return result;
}

/* Return a newly allocated copy of a struct ccw_devinfo describing the
 * CCW device with the specified CCW device ID. */
struct ccw_devinfo *ccw_devinfo_get(struct ccw_devid *devid, int reload)
{
	struct ccw_devinfo *info = NULL;

	if (reload)
		return ccw_devinfo_read(devid);

	info = ccw_devinfo_find(devid);
	if (!info) {
		info = ccw_devinfo_read(devid);
		if (!devinfos)
			devinfos = ptrlist_new();
		ptrlist_add(devinfos, info);
	}

	return ccw_devinfo_copy(info);
}

/* Compare two ccw_devinfos by CHPID. */
int ccw_devinfo_chpids_cmp(struct ccw_devinfo *a, struct ccw_devinfo *b)
{
	if (a->pim > b->pim)
		return 1;
	if (a->pim < b->pim)
		return -1;

	return memcmp(&a->chpids, &b->chpids, sizeof(a->chpids));
}

/* Compare two ccw_devinfos by CUTYPE. */
int ccw_devinfo_cutype_cmp(struct ccw_devinfo *a, struct ccw_devinfo *b)
{
	if (a->cutype > b->cutype)
		return 1;
	if (a->cutype < b->cutype)
		return -1;
	if (a->cumodel > b->cumodel)
		return 1;
	if (a->cumodel < b->cumodel)
		return -1;

	return 0;
}

/* Compare two ccw_devinfos by DEVYPE. */
int ccw_devinfo_devtype_cmp(struct ccw_devinfo *a, struct ccw_devinfo *b)
{
	if (a->devtype > b->devtype)
		return 1;
	if (a->devtype < b->devtype)
		return -1;
	if (a->devmodel > b->devmodel)
		return 1;
	if (a->devmodel < b->devmodel)
		return -1;

	return 0;
}

/*
 * CCW device base subtype.
 */

static char *ccw_get_dev_path(const char *drv, const char *id)
{
	char *normid, *path;

	normid = ccw_normalize_id(id);
	if (!normid)
		return NULL;

	path = path_get_ccw_device(drv, normid);
	free(normid);

	return path;
}

/* Check if a CCW device with the given ID exists. If DRV is non-null,
 * only check for devices attached to the specified driver. */
bool ccw_exists(const char *drv, const char *mod, const char *id)
{
	char *path;
	bool rc;

	cio_settle(0);

	path = path_get_ccw_devices(drv);
	if (mod)
		module_try_load_once(mod, path);
	free(path);

	path = ccw_get_dev_path(drv, id);
	if (!path)
		return false;

	rc = util_path_is_dir(path);
	free(path);

	return rc;
}

/* Check if a CCW device with the specified @id exists in the active
 * configuration. */
static bool ccw_st_exists_active(struct subtype *st, const char *id)
{
	struct ccw_subtype_data *data = st->data;

	return ccw_exists(data->ccwdrv, data->mod, id);
}

/* Check if a configuration exists for a CCW device with the specified @id. */
static bool ccw_st_exists_persistent(struct subtype *st, const char *id)
{
	return udev_ccw_exists(st->name, id, false);
}

/* Check if a configuration exists for a CCW device with the specified @id. */
static bool ccw_st_exists_autoconf(struct subtype *st, const char *id)
{
	return udev_ccw_exists(st->name, id, true);
}

static bool get_ids_cb(const char *file, void *data)
{
	return ccw_is_id_valid(file, err_ignore) == EXIT_OK ? true : false;
}

/* Add all existing CCW devices attached to driver DRV to strlist LIST. If DRV
 * is NULL add all CCW device IDs. */
void ccw_get_ids(const char *drv, const char *mod, struct util_list *list)
{
	char *path;

	cio_settle(0);

	path = path_get_ccw_devices(drv);
	if (mod)
		module_try_load_once(mod, path);
	misc_read_dir(path, list, get_ids_cb, NULL);
	free(path);
}

/* Add the IDs of all CCW devices existing in the active configuration to
 * strlist @ids. */
static void ccw_st_add_active_ids(struct subtype *st, struct util_list *ids)
{
	struct ccw_subtype_data *data = st->data;

	ccw_get_ids(data->ccwdrv, data->mod, ids);
}

/* Add the IDs of all CCW devices for which a persistent configuration exists
 * to strlist @ids. */
static void ccw_st_add_persistent_ids(struct subtype *st, struct util_list *ids)
{
	udev_get_device_ids(st->name, ids, false);
}

/* Add the IDs of all CCW devices for which a autoconf configuration exists
 * to strlist @ids. */
static void ccw_st_add_autoconf_ids(struct subtype *st, struct util_list *ids)
{
	udev_get_device_ids(st->name, ids, true);
}

/* Read the configuration of the CCW device with the specified @id from the
 * active configuration and add the resulting data to @dev. */
static exit_code_t ccw_st_read_active(struct subtype *st, struct device *dev,
				      read_scope_t scope)
{
	struct ccw_subtype_data *data = st->data;
	const char *drv = data->ccwdrv, *id = dev->id;
	struct device_state *state = &dev->active;
	char *path;

	cio_settle(0);

	state->modified = 0;
	state->deconfigured = 0;
	state->definable = 0;

	path = path_get_ccw_device(drv, id);
	if (util_path_exists(path)) {
		state->exists = 1;
		device_read_active_settings(dev, scope);
	} else
		state->exists = 0;
	free(path);

	return EXIT_OK;
}

/* Read the configuration of the CCW device with the specified @id from the
 * persistent configuration and add the resulting data to @dev. */
static exit_code_t ccw_st_read_persistent(struct subtype *st,
					  struct device *dev,
					  read_scope_t scope)
{
	return udev_ccw_read_device(dev, false);
}

/* Read the configuration of the CCW device with the specified @id from the
 * autoconf configuration and add the resulting data to @dev. */
static exit_code_t ccw_st_read_autoconf(struct subtype *st,
					  struct device *dev,
					  read_scope_t scope)
{
	return udev_ccw_read_device(dev, true);
}

static int get_online(struct setting_list *list)
{
	struct setting *s;

	if (!list)
		return -1;

	s = setting_list_find(list, "online");
	if (!s)
		return -1;

	/* "force" cannot be read from online attribute but might be
	 * in active list. */
	if (strcmp(s->value, "force") == 0 || atoi(s->value) != 0)
		return 1;

	return 0;
}

static void ccw_get_online_attrib(struct attrib **attribs, int online,
				  config_t config, struct attrib **a_ptr,
				  const char **name_ptr, const char **value_ptr)
{
	const char *name;
	const char *value = online ? "1" : "0";
	struct attrib *a = NULL;

	/* Use safe_offline if available. */
	if (!online && !force && config == config_active) {
		a = attrib_find(attribs, "safe_offline");
		if (a)
			name = "safe_offline";
	}

	/* Fall back to normal online. */
	if (!a)
		a = attrib_find(attribs, "online");

	if (a)
		name = a->name;
	else
		name = "online";

	*a_ptr = a;
	*name_ptr = name;
	*value_ptr = value;
}

/* Apply the configuration found in @dev to the active configuration of the
 * corresponding device. */
static exit_code_t ccw_st_configure_active(struct subtype *st,
					   struct device *dev)
{
	cio_settle(0);

	return device_write_active_settings(dev);
}

/* Create a persistent configuration for the specified device @dev. */
static exit_code_t ccw_st_configure_persistent(struct subtype *st,
					       struct device *dev)
{
	return udev_ccw_write_device(dev, false);
}

/* Create a autoconf configuration for the specified device @dev. */
static exit_code_t ccw_st_configure_autoconf(struct subtype *st,
					       struct device *dev)
{
	return udev_ccw_write_device(dev, true);
}


static char *ccw_st_get_active_attrib_path(struct subtype *, struct device *,
					   const char *);

/**
 * ccw_st_deconfigure_active - Deconfigure device in active configuration set
 * @st: Subtype of target device
 * @dev: Target device
 *
 * Deconfigure device @dev in the active configuration set. Return %EXIT_OK on
 * success, an error code otherwise.
 */
static exit_code_t ccw_st_deconfigure_active(struct subtype *st,
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
	path = ccw_st_get_active_attrib_path(st, dev, s->name);
	rc = setting_write(path, s);
	free(path);

	return rc;
}

/**
 * ccw_st_deconfigure_persistent - Deconfigure device in persistent
 *                                 configuration set
 * @st: Subtype of target device
 * @dev: Target device
 *
 * Deconfigure device @dev in the persistent configuration set. Return %EXIT_OK
 * on success, an error code otherwise.
 */
static exit_code_t ccw_st_deconfigure_persistent(struct subtype *st,
						 struct device *dev)
{
	return ccw_st_configure_persistent(st, dev);
}

/**
 * ccw_st_deconfigure_autoconf - Deconfigure device in autoconf
 *                               configuration set
 * @st: Subtype of target device
 * @dev: Target device
 *
 * Deconfigure device @dev in the autoconf configuration set. Return %EXIT_OK
 * on success, an error code otherwise.
 */
static exit_code_t ccw_st_deconfigure_autoconf(struct subtype *st,
						 struct device *dev)
{
	return udev_remove_rule(st->name, dev->id, true);
}

/* Perform basic sanity checks. */
static exit_code_t ccw_st_check_pre_configure(struct subtype *st,
					      struct device *dev, int prereq,
					      config_t config)
{
	char *drv;

	if (!SCOPE_ACTIVE(config) || dev->active.deconfigured)
		return EXIT_OK;

	drv = ccw_get_driver(dev->devid);
	if (!drv) {
		delayed_err("CCW device is not bound to a driver\n");
		return EXIT_INVALID_CONFIG;
	}
	free(drv);

	return EXIT_OK;
}

/* Adjust the online state of the specified device @dev. */
static void ccw_st_online_set(struct subtype *st, struct device *dev,
			      int online, config_t config)
{
	struct attrib *a;
	const char *name, *value;

	ccw_get_online_attrib(st->dev_attribs, online, config, &a, &name,
			      &value);

	if (SCOPE_ACTIVE(config))
		setting_list_apply(dev->active.settings, a, name, value);
	if (SCOPE_PERSISTENT(config))
		setting_list_apply(dev->persistent.settings, a, name, value);
	if (SCOPE_AUTOCONF(config))
		setting_list_apply(dev->autoconf.settings, a, name, value);
}

/* Determine the online state of the specified CCW device (0=offline, 1=online,
 * -1=not set). */
static int ccw_st_online_get(struct subtype *st, struct device *dev,
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

/* Determine if the online state of the specified CCW device was specified */
static bool ccw_st_online_specified(struct subtype *st, struct device *dev,
				    config_t config)
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

/* Add summary descriptions of operational problems with CCW device @id to
 * strlist @errors. */
static void ccw_st_add_errors(struct subtype *st, const char *id,
			      struct util_list *errors)
{
	char *path, *apath = NULL, *avail = NULL;

	path = ccw_get_dev_path(NULL, id);
	if (!path)
		return;

	if (!util_path_exists(path)) {
		strlist_add(errors, "CCW device %s does not exist", id);
		goto out;
	}
	apath = misc_asprintf("%s/availability", path);
	avail = misc_read_text_file(apath, 1, err_ignore);
	if (!avail) {
		strlist_add(errors, "CCW device %s is missing SysFS attributes",
			    id);
		goto out;
	}
	if (strcmp(avail, "no device") == 0) {
		strlist_add(errors, "CCW device %s has been detached or "
			    "removed", id);
		goto out;
	}
	if (strcmp(avail, "no path") == 0) {
		strlist_add(errors, "CCW device %s does not have any usable "
			    "paths", id);
		goto out;
	}
	if (!util_path_exists("%s/driver", path)) {
		strlist_add(errors, "CCW device %s is not bound to a driver",
			    id);
		goto out;
	}
	/* No known problem. */

out:
	free(avail);
	free(apath);
	free(path);
}

/* Add names of required kernel modules to strlist @modules. */
static void ccw_st_add_modules(struct subtype *st, struct device *dev,
			       struct util_list *modules)
{
	char *module;

	module = ccw_get_module(dev->devid);
	if (module)
		strlist_add_unique(modules, module);
	free(module);
}

/* Add struct devnodes to ptrlist @devnodes for each Linux device that is
 * provided by the CCW device with the specified ID. */
static void ccw_st_add_devnodes(struct subtype *st, const char *id,
				struct util_list *devnodes)
{
	struct ccw_subtype_data *data = st->data;
	char *path;

	path = ccw_get_dev_path(data->ccwdrv, id);
	if (path) {
		devnode_add_block_from_sysfs(devnodes, path);
		devnode_add_net_from_sysfs(devnodes, path);
	}
	free(path);
}

/* Return a newly allocated CCW device ID of the device that provides the
 * specified @devnode. Return %NULL if no CCW device ID could be determined. */
static char *ccw_st_resolve_devnode(struct subtype *st, struct devnode *devnode)
{
	char *link, *id = NULL, *curr, dummy;
	unsigned int cssid, sch_cssid, sch_ssid, sch_devno, dev_cssid,
		     dev_ssid, dev_devno;

	if (devnode->type == NETDEV)
		return NULL;

	link = devnode_readlink(devnode);
	if (!link)
		return NULL;

	/* ../../devices/css0/0.0.0024/0.0.8000/block/dasdg/dasdg1/ */
	curr = strstr(link, "/devices/");
	if (!curr)
		goto out;

	/* /devices/css0/0.0.0024/0.0.8000/block/dasdg/dasdg1/ */
	if (devnode->type == BLOCKDEV &&
	    sscanf(curr, "/devices/css%x/%x.%x.%x/%x.%x.%x/block%c",
		   &cssid, &sch_cssid, &sch_ssid, &sch_devno, &dev_cssid,
		   &dev_ssid, &dev_devno, &dummy) == 8 && dummy == '/')
		goto found;
	if (devnode->type == CHARDEV &&
	    sscanf(curr, "/devices/css%x/%x.%x.%x/%x.%x.%x/char%c",
		   &cssid, &sch_cssid, &sch_ssid, &sch_devno, &dev_cssid,
		   &dev_ssid, &dev_devno, &dummy) == 8 && dummy == '/')
		goto found;

	goto out;

found:
	id = misc_asprintf("%x.%x.%04x", dev_cssid, dev_ssid, dev_devno);
	if (!subtype_device_exists_active(st, id)) {
		/* Subtype of CCW device doesn't match. */
		free(id);
		id = NULL;
	}

out:
	free(link);

	return id;
}

/* Return a newly allocated character string containing the path to the file
 * that implements a device attribute of the specified @name or %NULL if
 * such an attribute is not allowed. */
static char *ccw_st_get_active_attrib_path(struct subtype *st,
					   struct device *dev,
					   const char *name)
{
	struct ccw_subtype_data *data = st->data;
	char *devpath, *path;

	devpath = path_get_ccw_device(data->ccwdrv, dev->id);
	path = misc_asprintf("%s/%s", devpath, name);
	free(devpath);

	return path;
}

/* Return a newly allocated character string containing the IPL device ID in
 * case of CCW IPL. */
static char *ccw_st_get_ipldev_id(struct subtype *st)
{
	char *type, *id = NULL;

	type = path_read_text_file(1, err_ignore, PATH_IPL "/ipl_type");
	if (strcmp(type, "ccw") != 0)
		goto out;

	id = path_read_text_file(1, err_ignore, PATH_IPL "/device");
	if (!ccw_st_exists_active(st, id)) {
		free(id);
		id = NULL;
	}
out:
	free(type);

	return id;
}

/* The methods of this subtype assume that @data points to a
 * struct ccw_subtype_data. */
struct subtype ccw_subtype = {
	.super			= &subtype_base,

	.exists_active		= &ccw_st_exists_active,
	.exists_persistent	= &ccw_st_exists_persistent,
	.exists_autoconf	= &ccw_st_exists_autoconf,

	.add_active_ids		= &ccw_st_add_active_ids,
	.add_persistent_ids	= &ccw_st_add_persistent_ids,
	.add_autoconf_ids	= &ccw_st_add_autoconf_ids,

	.read_active		= &ccw_st_read_active,
	.read_persistent	= &ccw_st_read_persistent,
	.read_autoconf		= &ccw_st_read_autoconf,

	.configure_active	= &ccw_st_configure_active,
	.configure_persistent	= &ccw_st_configure_persistent,
	.configure_autoconf	= &ccw_st_configure_autoconf,

	.deconfigure_active	= &ccw_st_deconfigure_active,
	.deconfigure_persistent	= &ccw_st_deconfigure_persistent,
	.deconfigure_autoconf	= &ccw_st_deconfigure_autoconf,

	.check_pre_configure	= &ccw_st_check_pre_configure,

	.online_set		= &ccw_st_online_set,
	.online_get		= &ccw_st_online_get,
	.online_specified	= &ccw_st_online_specified,

	.add_errors		= &ccw_st_add_errors,

	.add_modules		= &ccw_st_add_modules,
	.add_devnodes		= &ccw_st_add_devnodes,
	.resolve_devnode	= &ccw_st_resolve_devnode,
	.get_active_attrib_path	= &ccw_st_get_active_attrib_path,

	.get_ipldev_id		= &ccw_st_get_ipldev_id,
};
