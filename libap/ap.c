/*
 * libap - A collection of tools for ap/vfio-ap management
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_JSONC
#include <json-c/json.h>
#endif /* HAVE_JSONC */

#ifdef HAVE_LOCKFILE
#include <lockfile.h>
#endif /* HAVE_LOCKFILE */

#include "lib/ap.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_udev.h"

/*
 * Return sysfs path to a bus attribute
 * Note: caller is responsible for freeing the returned string
 */
static char *path_get_bus_attr(const char *bus, const char *attr)
{
	return util_path_sysfs("bus/%s/%s", bus, attr);
}

/*
 * Compare two vfio_ap nodes based upon their id value. Return:
 * -1: a < b
 *  1: a > b
 *  0: a == b
 */
static int vfio_ap_node_cmp(void *a, void *b, void *UNUSED(data))
{
	struct vfio_ap_node *a_node = a, *b_node = b;

	if (a_node->id < b_node->id)
		return -1;
	return (a_node->id > b_node->id);
}

static void vfio_ap_node_add_tail(struct util_list *list, unsigned int val)
{
	struct vfio_ap_node *node = util_zalloc(sizeof(struct vfio_ap_node));

	node->id = val;
	util_list_add_tail(list, node);
}

/* Remove duplicate entries from a sorted vfio_ap_node list */
static void vfio_ap_node_remove_dupes(struct util_list *list)
{
	struct vfio_ap_node *node, *check, *next;

	util_list_iterate(list, node) {
		/* Remove any subsequent duplicates */
		check = util_list_next(list, node);

		while (check) {
			next = util_list_next(list, check);
			if (node->id == check->id) {
				util_list_remove(list, check);
				free(check);
			}
			check = next;
		}
	}
}

static bool starts_with(const char *str, const char *s)
{
	size_t len = strlen(s);

	return (strncmp(str, s, len) == 0);
}

/*
 * Pass a comma-delimited string of IDs (adapter, domains or control domains)
 * and add these IDs to the input list.  The resulting list will be sorted
 * and duplicates removed before returning.
 */
static void modify_device_attr(struct util_list *list, char *value)
{
	unsigned int val;
	char *curr;

	curr = strtok(value, ",");
	if (curr == NULL)
		return;

	/* Create list from input setting */
	while (curr != NULL) {
		val = strtol(curr, NULL, 0);
		vfio_ap_node_add_tail(list, val);
		curr = strtok(NULL, ",");
	}

	/* Cleanup the list */
	util_list_sort(list, vfio_ap_node_cmp, NULL);
	vfio_ap_node_remove_dupes(list);
}

static void load_attr_to_device(struct vfio_ap_device *dev, char *attr,
				const char *value)
{
	char *v = util_strdup(value);

	if (strcmp(attr, "assign_adapter") == 0)
		modify_device_attr(dev->adapters, v);
	else if (strcmp(attr, "assign_domain") == 0)
		modify_device_attr(dev->domains, v);
	else if (strcmp(attr, "assign_control_domain") == 0)
		modify_device_attr(dev->controls, v);

	free(v);
}

/**
 * Print the contents of the vfio-ap device struct to stderr. Used for
 * debugging.
 *
 * @param[in]      dev        vfio-ap device strcucture to print
 */
void print_ap_device(struct vfio_ap_device *dev)
{
	struct vfio_ap_node *node;

	warnx("Device %s:", dev->uuid);
	warnx("Type: %s", dev->type);
	if (dev->manual)
		warnx("Start: MANUAL");
	else
		warnx("Start: AUTO");
	if (util_list_is_empty(dev->adapters)) {
		warnx("Adapters: (none)");
	} else {
		warnx("Adapters:");
		util_list_iterate(dev->adapters, node) {
			warnx("  %u", node->id);
		}
	}
	if (util_list_is_empty(dev->domains)) {
		warnx("Domains: (none)");
	} else {
		warnx("Domains:");
		util_list_iterate(dev->domains, node) {
			warnx("  %u", node->id);
		}
	}
	if (util_list_is_empty(dev->controls)) {
		warnx("Controls: (none)");
	} else {
		warnx("Controls:");
		util_list_iterate(dev->controls, node) {
			warnx("  %u", node->id);
		}
	}
}

/**
 * Determine if the input string is a valid Universally Unique Identifier
 *
 * @param[in]      uuid       Character string to inspect
 *
 * @retval         true       Specified string is a valid UUID
 * @retval         false      Specified string is not a valid UUID
 */
bool is_valid_uuid(const char *uuid)
{
	uint32_t s1, s2, s3, s4;
	uint64_t s5;
	char d;

	return (strlen(uuid) == 36 && sscanf(uuid, "%8x-%4x-%4x-%4x-%12x %c",
					     &s1, &s2, &s3, &s4,
					     (unsigned int *) &s5, &d) == 5);
}

/*
 * For an input string of hex characters, find the nth character and return its
 * numeric value to the caller.
 */
static int get_hexbyte_value(int n, const char *hexbytestr)
{
	int i = 0, v = 0;
	char c;

	if (strncmp(hexbytestr, "0x", 2) == 0)
		i = 2;

	/*
	 * The specified mask is only valid if it includes at least 64 hex
	 * digits.  The specified mask may optionally include a leading '0x'
	 */
	util_assert((strlen(hexbytestr) >= (size_t)(AP_MASK_SIZE - i - 1)),
		    "Invalid hex string provided for mask: %s", hexbytestr);

	c = hexbytestr[i + n / 4];
	if (c >= '0' && c <= '9')
		v = c - '0';
	else if (c >= 'a' && c <= 'f')
		v = 10 + c - 'a';
	else if (c >= 'A' && c <= 'F')
		v = 10 + c - 'A';
	else
		util_assert(false, "Could not parse hex digit '%c'", c);

	return v;
}

/**
 * For an input hex string, determine if the specified nth bit is ON or OFF.
 *
 * @param[in]      n          Bit number to test
 * @param[in, out] hexbytestr Character string of hex characters
 *
 * @retval         0          Specified bit is OFF
 * @retval         != 0       Specified bit is ON
 */
int ap_test_bit(int n, const char *hexbytestr)
{
	int v;

	v = get_hexbyte_value(n, hexbytestr);

	return v & (1 << (3 - (n % 4)));
}

/**
 * For an input hex string, set the nth bit true/false
 *
 * @param[in]      n          Bit number to set
 * @param[in, out] hexbytestr Character string of hex characters
 * @param[in]      val        Bit is to be set ON (true) or OFF (false)
 */
void ap_set_bit(int n, char *hexbytestr, bool val)
{
	char c = 0;
	int v, m, i = 0;

	v = get_hexbyte_value(n, hexbytestr);

	/* Calculate the bit mask */
	m = (1 << (3 - (n % 4)));

	/* Return if bit already at correct value */
	if (((val) && ((v & m) != 0)) || (!val && ((v & m) == 0)))
		return;

	if (val)
		v = v + m;
	else
		v = v - m;

	if (v < 10)
		c = '0' + v;
	else if (v >= 10 && v <= 15)
		c = 'a' + (v - 10);
	else
		util_assert(false, "Could not set bit value '%d'", v);

	if (strncmp(hexbytestr, "0x", 2) == 0)
		i = 2;

	/* Set the new value */
	hexbytestr[i + n / 4] = c;
}

/**
 * Return sysfs path to vfio_ap mdev
 * Note: caller is responsible for freeing the returned string
 *
 * @param[in]      uuid       Character string containing an mdev UUID
 *
 * @retval         != 0       sysfs path for a vfio-ap device with this UUID
 */
char *path_get_vfio_ap_mdev(const char *uuid)
{
	return util_path_sysfs("%s/%s", VFIO_AP_PARENT_PATH, uuid);
}

/**
 * Return path to mdevctl config file for specified UUID
 * Note: caller is responsible for freeing the returned string
 *
 * @param[in]      uuid       Character string containing an mdev UUID
 *
 * @retval         != 0       config file path for vfio-ap device with this UUID
 */
char *path_get_vfio_ap_mdev_config(const char *uuid)
{
	char *path;

	util_asprintf(&path, "%s/%s", VFIO_AP_CONFIG_PATH, uuid);
	return path;
}

/**
 * Return sysfs path to vfio_ap mdev attribute (matrix, remove, ...)
 * Note: caller is responsible for freeing the returned string
 *
 * @param[in]      uuid       Character string containing an mdev UUID
 * @param[in]      attr       Character string containing device attribute name
 *
 * @retval         != 0       sysfs path to specified attribute for this device
 */
char *path_get_vfio_ap_attr(const char *uuid, const char *attr)
{
	return util_path_sysfs("%s/%s/%s", VFIO_AP_PARENT_PATH, uuid, attr);
}

/**
 * Return path to ap udev config file
 * Note: caller is responsible for freeing the returned string
 *
 * @retval         != 0       path to the ap udev config file
 */
char *path_get_ap_udev(void)
{
	char *path;

	util_asprintf(&path, "%s", AP_UDEV_FILE);
	return path;
}

/**
 * Take one line from the active 'matrix' attribute and parse it
 * into a list of adapters and domains.  Each line of the 'matrix'
 * attribute is presented as a "adapter.domain" (e.g. "03.0005") where the
 * numeric values are always hexadecimal.
 * In a case where no adapters are assigned, a valid string might be ".0005"
 * In a case where no domains are assigned, a valid string might be "03."
 *
 * @param[in, out] dev        Vfio-ap struct that will be updated
 * @param[in]      matrix     Character string to parse
 */
void vfio_ap_parse_matrix(struct vfio_ap_device *dev, char *matrix)
{
	char *curr;
	int val;

	if (!matrix)
		return;

	if (*matrix != '.') {
		/* Handle a device with adapters */
		curr = strtok(matrix, ".");
		val = strtol(curr, NULL, 16);
		vfio_ap_node_add_tail(dev->adapters, val);
		curr = strtok(NULL, "\n");
	} else {
		/* Handle a device with no adapters */
		curr = strtok(matrix + 1, "\n");
	}

	/* Leave now if the device has no domains */
	if (!curr)
		return;
	/* Get the domain */
	val = strtol(curr, NULL, 16);
	vfio_ap_node_add_tail(dev->domains, val);
}

/**
 * Function to sort the results of repeated vfio_ap_parse_matrix calls
 *
 * @param[in, out] dev        Vfio-ap struct whose lists will be sorted
 */
void vfio_ap_sort_matrix_results(struct vfio_ap_device *dev)
{
	/* Sort the lists for later use */
	util_list_sort(dev->adapters, vfio_ap_node_cmp, NULL);
	util_list_sort(dev->domains, vfio_ap_node_cmp, NULL);

	/* Run the lists and delete duplicates */
	vfio_ap_node_remove_dupes(dev->adapters);
	vfio_ap_node_remove_dupes(dev->domains);
}

/**
 * Take the string provided by the active 'control_domains' attribute and
 * parse it into a list of control domains
 *
 * @param[in, out] dev        Vfio-ap struct that will be updated
 * @param[in]      control    Character string to parse
 */
void vfio_ap_parse_control(struct vfio_ap_device *dev, char *control)
{
	char *curr;
	int val;

	curr = strtok(control, "\n");

	while (curr != NULL) {
		val = strtol(curr, NULL, 16);
		vfio_ap_node_add_tail(dev->controls, val);
		curr = strtok(NULL, "\n");
	}
}

#ifdef HAVE_JSONC

/**
 * For a given path, read in the contents.  If no path is provided, get the
 * input from stdin instead.
 *
 * @param[in]      path       Path to mdevctl config file
 * @param[in, out] dev        Vfio-ap struct that will be updated
 *
 * @retval         0          Config read successfully, dev updated
 * @retval         -1         Failed to read config, dev may have partial info
 */
int vfio_ap_read_device_config(const char *path, struct vfio_ap_device *dev)
{
	json_object *root, *type, *start, *attrs, *attr;
	int i, len, rc = 0;
	const char *val;

	if (path == NULL)
		root = json_object_from_fd(STDIN_FILENO);
	else
		root = json_object_from_file(path);
	if (root == NULL)
		return -1;

	if (json_object_object_get_ex(root, "mdev_type", &type)) {
		val = json_object_get_string(type);
		if (!val)
			goto err;
		dev->type = util_strdup(val);
		if (strcmp(val, "vfio_ap-passthrough") != 0)
			goto err;
	}

	if (json_object_object_get_ex(root, "start", &start)) {
		val = json_object_get_string(start);
		if (!val)
			goto err;
		if (strcmp(val, "auto") == 0)
			dev->manual = false;
		else if (strcmp(val, "manual") == 0)
			dev->manual = true;
		else
			goto err;
	}

	if (json_object_object_get_ex(root, "attrs", &attrs)) {
		len = json_object_array_length(attrs);
		for (i = 0; i < len; i++) {
			attr = json_object_array_get_idx(attrs, i);
			json_object_object_foreach(attr, key, setting) {
				val = json_object_get_string(setting);
				load_attr_to_device(dev, key, val);
			}
		}
	}

out:
	json_object_put(root);
	return rc;

err:
	rc = -1;
	goto out;
}

#else
int vfio_ap_read_device_config(const char *path, struct vfio_ap_device *dev)
{
	return -1;
}
#endif /* HAVE_JSONC */

/**
 * Allocate and initialize a vfio-ap device structure.
 *
 * @retval         !=0        Address of the new vfio-ap device structure
 */
struct vfio_ap_device *vfio_ap_device_new(void)
{
	struct vfio_ap_device *dev;

	dev = util_zalloc(sizeof(struct vfio_ap_device));

	dev->manual = false;
	dev->type = NULL;
	dev->uuid = NULL;

	dev->adapters = util_list_new(struct vfio_ap_node, node);
	dev->domains = util_list_new(struct vfio_ap_node, node);
	dev->controls = util_list_new(struct vfio_ap_node, node);

	return dev;
}

/**
 * Re-initialize a vfio-ap device structure, leaving the structure allocated.
 *
 * @param[in, out] dev        Vfio-ap struct that will be re-initialized
 */
void vfio_ap_device_clear(struct vfio_ap_device *dev)
{
	if (dev == NULL)
		return;

	dev->manual = false;
	if (dev->type) {
		free(dev->type);
		dev->type = NULL;
	}
	if (dev->uuid) {
		free(dev->uuid);
		dev->uuid = NULL;
	}

	ap_list_remove_all(dev->adapters);
	ap_list_remove_all(dev->domains);
	ap_list_remove_all(dev->controls);
}

/**
 * Clear and release a vfio-ap device structure.
 *
 * @param[in, out] dev        Vfio-ap struct that will be freed
 */
void vfio_ap_device_free(struct vfio_ap_device *dev)
{
	if (dev == NULL)
		return;

	vfio_ap_device_clear(dev);
	util_list_free(dev->adapters);
	util_list_free(dev->domains);
	util_list_free(dev->controls);
	free(dev);
}

static int read_sysfs_mask(const char *path, char *mask, int size)
{
	return util_file_read_line(mask, size, "%s", path);
}

/**
 * Get the apmask and aqmask from sysfs
 *
 * @param[in, out] ap         Buffer to hold apmask contents
 * @param[in, out] aq         Buffer to hold aqmask contents
 * @param[in]      size       Size of the mask buffers
 *
 * @retval         0          Both mask values read successfully
 * @retval         != 0       Failed to read one or both mask values
 */
int ap_read_sysfs_masks(char *ap, char *aq, int size)
{
	char *path;
	int rc = 0;

	path = path_get_bus_attr("ap", "apmask");
	rc = read_sysfs_mask(path, ap, size);
	free(path);
	if (rc != 0)
		goto out;
	path = path_get_bus_attr("ap", "aqmask");
	rc = read_sysfs_mask(path, aq, size);
	free(path);

out:
	return rc;
}

/**
 * Get the apmask and aqmask from udev, falling back to sysfs if a udev rule
 * is not available or does not provide values for both masks.
 * The values in read_ap and read_aq tell the caller whether each mask was
 * successfully loaded from udev or if the sysfs value was substituted
 * Note: both ap and aq must point to a string that is at least AP_MASK_SIZE
 * in length.
 *
 * @param[in]      path       Path to the ap udev file
 * @param[in, out] ap         Buffer to hold apmask contents
 * @param[in, out] aq         Buffer to hold aqmask contents
 * @param[out]     read_ap    Specifies if an apmask value was read from udev
 * @param[out]     read_aq    Specifies if an aqmask value was read from udev
 *
 * @retval         true       Udev file read successfully or did not exist
 * @retval         false      Udev file exists but error was encountered
 */
bool ap_read_udev_masks(char *path, char *ap, char *aq, bool *read_ap,
			bool *read_aq)
{
	struct util_udev_entry_node *entry;
	struct util_udev_file *file = NULL;
	struct util_udev_line_node *line;
	char sysap[AP_MASK_SIZE];
	char sysaq[AP_MASK_SIZE];
	int rc;

	/* Assume we fail to read both masks */
	*read_ap = *read_aq = false;

	/* If a udev file doesn't exist, quietly use the active masks */
	if (!util_path_exists(path))
		goto out;

	rc = util_udev_read_file(path, &file);

	/* If errors were encountered reading the udev file, exit now */
	if (rc)
		return false;

	util_list_iterate(&file->lines, line) {
		entry = util_list_start(&line->entries);

		/* Skip comments and empty lines. */
		if (!entry)
			continue;

		if (starts_with(entry->key, "ATTR{")) {
			if (strstr(entry->key, "apmask")) {
				util_strlcpy(ap, entry->value, AP_MASK_SIZE);
				*read_ap = true;
			} else if (strstr(entry->key, "aqmask")) {
				util_strlcpy(aq, entry->value, AP_MASK_SIZE);
				*read_aq = true;
			}
		}
	}

	util_udev_free_file(file);

out:
	/* If we didn't read in masks, use current sysfs values */
	if ((!*read_ap) || (!*read_aq)) {
		rc = ap_read_sysfs_masks(sysap, sysaq, AP_MASK_SIZE);
		if (rc != 0)
			return false;
		if (!*read_ap)
			strcpy(ap, sysap);
		if (!*read_aq)
			strcpy(aq, sysaq);
	}

	return true;
}

/**
 * For a given bitmask, create a list of vfio_ap_node entries corresponding
 * to the ON bits in the mask.
 *
 * @param[in]      mask       Character string of hex characters
 * @param[in, out] list       List to be updated with entries for each ON bit
 */
void ap_mask_to_list(char *mask, struct util_list *list)
{
	int i;

	if (mask == NULL || list == NULL)
		return;

	for (i = 0; i <= AP_MAX_MASK_VALUE; i++) {
		if (ap_test_bit(i, mask))
			vfio_ap_node_add_tail(list, i);
	}

	/* Could have duplicates if the input list was not empty */
	util_list_sort(list, vfio_ap_node_cmp, NULL);
	vfio_ap_node_remove_dupes(list);
}

/**
 * For the specified list, remove all elements and free each node
 *
 * @param[in, out] list       List that will have all entries removed
 */
void ap_list_remove_all(struct util_list *list)
{
	struct ap_node *node;

	while (!util_list_is_empty(list)) {
		node = util_list_start(list);
		util_list_remove(list, node);
		free(node);
	}
}

#ifdef HAVE_LOCKFILE
static int ap_lockfile_create(int flags)
{
	return lockfile_create(AP_LOCKFILE, AP_LOCK_RETRIES, flags);
}

/**
 * Acquire the ap config lock using this process PID (L_PID)
 *
 * @retval         0          Lock successfully acquired on behalf of L_PID
 * @retval         != 0       Error, lock was not obtained
 */
int ap_get_lock(void)
{
	return ap_lockfile_create(L_PID);
}

/**
 * Acquire the ap config lock using the parent process PID (L_PPID) -- intended
 * for use by the mdevctl callout ap-check utility
 *
 * @retval         0          Lock successfully acquired on behalf of L_PPID
 * @retval         != 0       Error, lock was not obtained
 */
int ap_get_lock_callout(void)
{
	return ap_lockfile_create(L_PPID);
}

/**
 * Release the ap config lock
 *
 * @retval         0          Lock successfully released or file didn't exist
 * @retval         != 0       Error removing the lockfile
 */
int ap_release_lock(void)
{
	return lockfile_remove(AP_LOCKFILE);
}
#else
/* If no liblockfile, actions are performed without acquiring the file lock */
int ap_get_lock(void)
{
	return 0;
}

int ap_get_lock_callout(void)
{
	return 0;
}

int ap_release_lock(void)
{
	return 0;
}

#endif /* HAVE_LOCKFILE */
