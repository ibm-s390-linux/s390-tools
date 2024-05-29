/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "lib/util_libc.h"
#include "lib/util_path.h"
#include "lib/util_list.h"
#include "lib/ap.h"

#include "attrib.h"
#include "ccw.h"
#include "device.h"
#include "devtype.h"
#include "internal.h"
#include "misc.h"
#include "namespace.h"
#include "path.h"
#include "ap.h"
#include "setting.h"
#include "udev.h"

#define DEVNAME			"AP device"

static const char default_mask[AP_MASK_SIZE] =
	"0x0000000000000000000000000000000000000000000000000000000000000000";

static char apmask[AP_MASK_SIZE] = {0};
static char aqmask[AP_MASK_SIZE] = {0};
static char p_apmask[AP_MASK_SIZE] = {0};
static char p_aqmask[AP_MASK_SIZE] = {0};
static bool valid_p_apmask = false, valid_p_aqmask = false;

/*
 * For 2 input masks (source and target), generate a list of all bits that are
 * on in target and off in source (adds) as well as a list of all bits that are
 * on in source but off in target (subs).
 */
static void ap_mask_list_changes(const char *source, const char *target,
				 struct util_list *adds, struct util_list *subs)
{
	int i;
	struct vfio_ap_node *node;

	for (i = 0; i <= AP_MAX_MASK_VALUE; i++) {
		if (ap_test_bit(i, source)) {
			if (!ap_test_bit(i, target)) {
				node = misc_malloc(sizeof(struct vfio_ap_node));
				node->id = i;
				util_list_add_tail(subs, node);
			}
		} else {
			if (ap_test_bit(i, target)) {
				node = misc_malloc(sizeof(struct vfio_ap_node));
				node->id = i;
				util_list_add_tail(adds, node);
			}
		}
	}
}

/*
 * For a given character string, convert to unsigned long and validate that
 * it is within range.
 */
static bool parse_mask_entry_single(char *entry, unsigned long *val)
{
	char *end;

	*val = strtoul(entry, &end, 0);
	if (*val > AP_MAX_MASK_VALUE || *end != '\0')
		return false;
	return true;
}

/*
 * For a given character string, split it into 2 entries delimited by a '-'
 * character and parse each half of the range.
 */
static bool parse_mask_entry_range(char *entry, unsigned long *val,
				   unsigned long *val2)
{
	char *entry2;

	/* Find range delimeter, convert to 2 null-terminated entries */
	entry2 = strchr(entry, '-');
	*entry2 = '\0';
	entry2++;

	/* Handle invalid range where there is no 2nd number */
	if (*entry2 == '\0')
		return false;

	if (!parse_mask_entry_single(entry, val))
		return false;
	if (!parse_mask_entry_single(entry2, val2))
		return false;
	if (val > val2)
		return false;
	return true;
}

/*
 * For a given string, parse its contents and modify the provided mask.
 * For assignment operations, valid strings are of the format:
 * # or #-#
 * Otherwise, for modification operations, valid strings are of the format:
 * +# or +#-#
 * -# or -#-#
 */
static bool parse_mask_entry(char *entry, bool assign, char *mask)
{
	unsigned long val, val2;
	bool is_add = true;

	/*
	 * Modifications must begin with a +/- and assignments cannot begin
	 * with a +/-
	 */
	if ((!assign && (*entry != '+' && *entry != '-')) ||
	    (assign && (*entry == '+' || *entry == '-')))
		return false;

	/*
	 * An assignment is now treated the same as a + modification.
	 * But for modification operations, skip past the +/- and remember if
	 * we are doing removal.
	 */
	if (!assign) {
		if (*entry == '-')
			is_add = false;
		entry++;
		/* Handle the case where there's nothing after the +/- */
		if (*entry == '\0')
			return false;
	}

	/* Next, parse either a single element or a range */
	if (strchr(entry, '-')) {
		if (!parse_mask_entry_range(entry, &val, &val2))
			return false;
	} else {
		if (!parse_mask_entry_single(entry, &val))
			return false;
		val2 = val;
	}

	/* Set the specified bit(s) accordingly */
	while (val <= val2) {
		ap_set_bit(val, mask, is_add);
		val++;
	}

	return true;
}

/*
 * For an input string, validate that the format of the input is valid, then
 * generate the new mask string as well as a list of bits that were added
 * for later validation.  If all looks valid, change the mask in memory based
 * upon the provided input
 */
static bool ap_validate_mask_input(char *mask, const char *input,
				   struct util_list *adds,
				   struct util_list *subs)
{
	bool is_assign = false, rc = true;
	char *incopy = misc_strdup(input);
	char newmask[AP_MASK_SIZE] = {0};
	char *curr, *next;

	/* If we aren't starting with +/-, it's an assignment */
	if (*incopy != '+' && *incopy != '-') {
		is_assign = true;
		/* Start with all bits OFF */
		strcpy(newmask, default_mask);
	} else {
		/* Otherwise, input is a list of changes */
		strcpy(newmask, mask);
	}

	/* Get the first entry to start -- if there are none, exit on error */
	curr = strtok(incopy, ",");
	if (curr == NULL)
		goto err_out;

	/* Run the comma-delimited list of entries, updating the mask value */
	do {
		/* Ensure we null-terminate the current entry */
		next = strtok(NULL, ",");
		if (!parse_mask_entry(curr, is_assign, newmask))
			goto err_out;
		curr = next;
	} while (curr != NULL);

	/*
	 * Translate the mask value into a list of additions/removals for later
	 * conflict analysis.
	 */
	util_list_init(adds, struct vfio_ap_node, node);
	ap_mask_list_changes(mask, newmask, adds, subs);
	strcpy(mask, newmask);
	goto out;

err_out:
	error("Invalid input string %s\n", input);
	rc = false;

out:
	free(incopy);
	return rc;
}

static int write_sysfs_mask(const char *path, char *mask)
{
	int rc = 0;
	FILE *f;

	f = fopen(path, "w");
	if (!f) {
		rc = -1;
		goto out;
	}
	fputs(mask, f);
	fclose(f);

out:
	return rc;
}

static bool ap_read_type_udev(char *ap, char *aq, bool autoconf)
{
	bool retval = false;
	char *path = path_get_udev_rule(AP_NAME, NULL, autoconf);

	if (ap_read_udev_masks(path, ap, aq, &valid_p_apmask, &valid_p_aqmask))
		retval = true;

	free(path);
	return retval;
}

static exit_code_t ap_write_type_udev(char *ap, char *aq, bool autoconf)
{
	FILE *fd;
	exit_code_t rc;
	char *path = path_get_udev_rule(AP_NAME, NULL, autoconf);

	/* Remove if already exists */
	if (util_path_is_reg_file(path)) {
		rc = remove_file(path);
		if (rc) {
			error("Could not remove file %s\n", path);
			goto out;
		}
	}

	/* If there's no masks, no need for a udev file */
	if (!(valid_p_apmask || valid_p_aqmask))
		return EXIT_OK;

	debug("Writing udev rule file %s\n", path);
	rc = path_create(path);
	if (rc)
		goto out;

	fd = misc_fopen(path, "w");
	if (!fd) {
		error("Could not write to file %s: %s\n", path,
		      strerror(errno));
		rc = EXIT_RUNTIME_ERROR;
		goto out;
	}

	/* Write udev rule prolog. */
	fprintf(fd, "# Generated by chzdev\n");

	/* Triggers. */
	fprintf(fd, "ACTION==\"change\", SUBSYSTEM==\"ap\", "
		"DEVPATH==\"/devices/ap\", ENV{BINDINGS}==\"complete\", "
		"ENV{COMPLETECOUNT}==\"1\", GOTO=\"cfg_ap\"\n");
	fprintf(fd, "GOTO=\"end_ap\"\n\n");

	/* Begin Configuration */
	fprintf(fd, "LABEL=\"cfg_ap\"\n\n");
	if (valid_p_apmask)
		fprintf(fd, "ATTR{../../bus/ap/apmask}=\"%s\"\n", ap);
	if (valid_p_aqmask)
		fprintf(fd, "ATTR{../../bus/ap/aqmask}=\"%s\"\n", aq);
	fprintf(fd, "RUN{builtin}+=\"kmod load %s\"\n", VFIO_AP_MOD_NAME);

	/* Write udev rule epilog. */
	fprintf(fd, "\nLABEL=\"end_ap\"\n");

	fclose(fd);

out:
	free(path);
	return rc;
}

/*
 * AP namespace
 */
static exit_code_t ap_is_id_valid(const char *id, err_t err)
{
	/* AP device doesn't support an ID */
	err_t_print(err, "Error: %s management is not supported\n",
		    DEVNAME);

	return EXIT_INVALID_ID;
}

static int ap_cmp_ids(const char *a_str, const char *b_str)
{
	/* AP device doesn't support an ID */
	return EXIT_OK;
}

static char *ap_normalize_id(const char *id)
{
	/* AP device doesn't support an ID, just return a copy of input */
	return util_strdup(id);
}

static void *ap_parse_id(const char *id, err_t err)
{
	/* Nothing to be parsed, just use normalized string */
	return ap_normalize_id(id);
}

static int ap_cmp_parsed_ids(const void *a, const void *b)
{
	return ap_cmp_ids((const char *)a, (const char *)b);
}

static int ap_qsort_cmp(const void *a_ptr, const void *b_ptr)
{
	const char *a = *((const char **) a_ptr);
	const char *b = *((const char **) b_ptr);

	return ap_cmp_ids(a, b);
}

static exit_code_t ap_is_id_range_valid(const char *range, err_t err)
{
	/* AP device doesn't support an ID */
	err_t_print(err, "Error: %s management is not supported\n",
		    DEVNAME);

	return EXIT_INVALID_ID;
}

static unsigned long ap_num_ids_in_range(const char *range)
{
	/* AP device doesn't support an ID */
	return 0;
}

static bool ap_is_id_in_range(const char *id, const char *range)
{
	/* AP device doesn't support an ID */
	return false;
}

static void ap_range_start(struct ns_range_iterator *it,
			   const char *range)
{
	/* AP device doesn't support an ID */
	memset(it, 0, sizeof(struct ns_range_iterator));
}

static void ap_range_next(struct ns_range_iterator *it)
{
	/* AP device doesn't support an ID */
}

struct namespace ap_namespace = {
	.devname		= DEVNAME,
	.is_id_valid		= ap_is_id_valid,
	.cmp_ids		= ap_cmp_ids,
	.normalize_id		= ap_normalize_id,
	.parse_id		= ap_parse_id,
	.cmp_parsed_ids		= ap_cmp_parsed_ids,
	.qsort_cmp		= ap_qsort_cmp,
	.is_id_range_valid	= ap_is_id_range_valid,
	.num_ids_in_range	= ap_num_ids_in_range,
	.is_id_in_range		= ap_is_id_in_range,
	.range_start		= ap_range_start,
	.range_next		= ap_range_next,
};

/*
 * AP type attributes
 */
static struct attrib ap_tattr_apmask = {
	.name = "apmask",
	.title = "Configure Cryptographic Adapter ID availability",
	.desc =
	"Specify the set of Cryptographic Adapters that will be available\n"
	"for host usage.  Any bits not enabled for host usage indicate\n"
	"adapters that are available for guest passthrough.\n"
	"Input can be in the form of a comma-delimited list of adapters\n"
	"such as:\n"
	"  3,5-10,0x25\n"
	"where the listed adapters are set for host usage and the unlisted\n"
	"adapters are set for guest passthrough.  A range indicates that all\n"
	"adapters in this range should be set for host usage.\n\n"
	"Alternatively, this attribute can also be specified as a\n"
	"comma-delimited list of changes to the current mask such as:\n"
	"  +0-4,-0xf0\n"
	"where each number or range preceded by a '+' will change the current\n"
	"mask to set the specified adapters for host usage and each number\n"
	"or range preceded by a '-' will set the specified adapters for guest\n"
	"passthrough.\n"
	"Adapters can be specified in both decimal and hexadecimal.",
};

static struct attrib ap_tattr_aqmask = {
	.name = "aqmask",
	.title = "Configure Cryptographic Queue Index availability",
	.desc =
	"Specify the set of Cryptographic Queue Indices that will be\n"
	"available for host usage.  Any bits not enabled for host usage\n"
	"indicate a queue index that is available for guest passthrough.\n"
	"Input can be in the form of a comma-delimited list of indices\n"
	"such as:\n"
	"  3,5-10,0x25\n"
	"where the listed queue indices are set for host usage and the\n"
	"unlisted indices are set for guest passthrough.  A range indicates\n"
	"that all indices in this range should be set for host usage.\n\n"
	"Alternatively, this attribute can also be specified as a\n"
	"comma-delimited list of changes to the current mask such as:\n"
	"  +0-4,-0xf0\n"
	"where each number or range preceded by a '+' will change the current\n"
	"mask to set the specified indices for host usage and each number\n"
	"or range preceded by a '-' will set the specified indices for guest\n"
	"passthrough.\n"
	"Queue indices can be specified in both decimal and hexadecimal.",
};

/*
 * AP device attributes - there are currently none.
 */

/*
 * AP subtype methods
 */

static void ap_st_init(struct subtype *st)
{
	st->devices = device_list_new(st);
}

static void ap_st_exit(struct subtype *st)
{
	device_list_free(st->devices);
}

/* Determine if an AP device exists in the active configuration. */
static bool ap_st_exists_active(struct subtype *st, const char *id)
{
	return false;
}

static bool ap_st_exists_persistent(struct subtype *st, const char *id)
{
	return false;
}

static bool ap_st_exists_autoconf(struct subtype *st, const char *id)
{
	return false;
}

static void ap_st_add_active_ids(struct subtype *st, struct util_list *ids)
{
}

static void ap_st_add_persistent_ids(struct subtype *st, struct util_list *ids)
{
}

static void ap_st_add_autoconf_ids(struct subtype *st, struct util_list *ids)
{
}

/* Read state of an AP device from the active configuration. */
static exit_code_t ap_st_read_active(struct subtype *st,
				     struct device *dev,
				     read_scope_t scope)
{
	return EXIT_OK;
}

static exit_code_t ap_st_read_persistent(struct subtype *st,
					 struct device *dev,
					 read_scope_t scope)
{
	return EXIT_OK;
}

static exit_code_t ap_st_read_autoconf(struct subtype *st,
				       struct device *dev,
				       read_scope_t scope)
{
	return EXIT_OK;
}

/* Apply the settings of an AP device to the active configuration. */
static exit_code_t ap_st_configure_active(struct subtype *st,
					  struct device *dev)
{
	return device_write_active_settings(dev);
}

static exit_code_t ap_st_configure_persistent(struct subtype *st,
					      struct device *dev)
{
	return EXIT_OK;
}

static exit_code_t ap_st_configure_autoconf(struct subtype *st,
					    struct device *dev)
{
	return EXIT_OK;
}

static exit_code_t ap_st_deconfigure_active(struct subtype *st,
					    struct device *dev)
{
	/* No additional step required */
	return EXIT_OK;
}

static exit_code_t ap_st_deconfigure_persistent(struct subtype *st,
						struct device *dev)
{
	/* No additional step required */
	return EXIT_OK;
}

static exit_code_t ap_st_deconfigure_autoconf(struct subtype *st,
					      struct device *dev)
{
	/* No additional step required */
	return EXIT_OK;
}

/*
 * AP subtype
 */
struct subtype ap_subtype = {
	.super		= &subtype_base,
	.devtype	= &ap_devtype,
	.name		= AP_NAME,
	.title		= "Cryptographic Adjunct Processor (AP) device",

	.devname	= DEVNAME,
	.modules	= STRING_ARRAY(AP_MOD_NAME),
	.namespace	= &ap_namespace,

	.dev_attribs = ATTRIB_ARRAY(),

	.unknown_dev_attribs	= 0,
	.support_definable	= 0,

	.init			= &ap_st_init,
	.exit			= &ap_st_exit,

	.exists_active		= &ap_st_exists_active,
	.exists_persistent	= &ap_st_exists_persistent,
	.exists_autoconf	= &ap_st_exists_autoconf,

	.add_active_ids		= &ap_st_add_active_ids,
	.add_persistent_ids	= &ap_st_add_persistent_ids,
	.add_autoconf_ids	= &ap_st_add_autoconf_ids,

	.read_active		= &ap_st_read_active,
	.read_persistent	= &ap_st_read_persistent,
	.read_autoconf		= &ap_st_read_autoconf,

	.configure_active	= &ap_st_configure_active,
	.configure_persistent	= &ap_st_configure_persistent,
	.configure_autoconf	= &ap_st_configure_autoconf,

	.deconfigure_active	= &ap_st_deconfigure_active,
	.deconfigure_persistent	= &ap_st_deconfigure_persistent,
	.deconfigure_autoconf	= &ap_st_deconfigure_autoconf,
};

/*
 * AP devtype methods
 */
/* Clean up all resources used by devtype object. */
static void ap_devtype_exit(struct devtype *dt)
{
	setting_list_free(dt->active_settings);
	setting_list_free(dt->persistent_settings);
}

/*
 * Turn a full ap/aqmask bitmap into a comma-delimited list of bits
 *
 * Use a worst-case string size for the setting, which would be a string size
 * for a string that has every other bit on, with up to 3 digits per bit plus
 * commas.
 */
static char *ap_mask_to_setting(char *value)
{
	int size = ((AP_MAX_MASK_VALUE / 2) + 1)  * 4;
	char *sval = misc_malloc(size);
	char *curr = sval;
	bool found_one = false;
	int i, rc, start = -1, stop = -1;

	for (i = 0; i <= AP_MAX_MASK_VALUE; i++) {
		if (ap_test_bit(i, value)) {
			found_one = true;
			if (start < 0) {
				start = stop = i;
			} else if (stop == i - 1) {
				stop++;
			} else {
				/* Write the old range, we have a new one */
				if (start == stop)
					/* print a single bit */
					rc = snprintf(curr, size, "%d,", start);
				else
					/* print a range */
					rc = snprintf(curr, size, "%d-%d,",
						      start, stop);
				curr += rc;
				start = stop = i;
			}
		}
	}

	if (found_one) {
		/* Print the final entry in the list */
		if (start == stop)
			/* print a single bit */
			rc = snprintf(curr, size, "%d", start);
		else
			/* print a range */
			rc = snprintf(curr, size, "%d-%d", start, stop);
	} else {
		/* If no bits are on, return an empty string */
		curr[0] = '\0';
	}

	return sval;
}

static void ap_create_type_setting(struct devtype *dt,
				   struct setting_list *slist, char *name,
				   char *value)
{
	struct attrib *a;
	struct setting *s;
	char *c;

	a = attrib_find(dt->type_attribs, name);
	if (a != NULL) {
		s = setting_list_find(slist, name);
		if (s != NULL) {
			free(s->value);
			s->value = ap_mask_to_setting(value);
		} else {
			c = ap_mask_to_setting(value);
			s = setting_new(a, NULL, c);
			setting_list_add(slist, s);
			free(c);
		}
	}
}

static exit_code_t ap_devtype_read_settings(struct devtype *dt, config_t config)
{
	exit_code_t rc = EXIT_OK;

	dt->active_settings = setting_list_new();
	dt->persistent_settings = setting_list_new();

	rc = ap_get_lock();
	if (rc != 0) {
		rc = EXIT_RUNTIME_ERROR;
		goto out2;
	}

	if (SCOPE_ACTIVE(config)) {
		/* read apmask and aqmask */
		if (ap_read_sysfs_masks(apmask, aqmask, AP_MASK_SIZE) != 0) {
			rc = EXIT_RUNTIME_ERROR;
			goto out;
		}
		dt->active_exists = 1;
	}
	if (SCOPE_PERSISTENT(config)) {
		/* read apmask and aqmask udev */
		if (ap_read_type_udev(p_apmask, p_aqmask, false))
			dt->persistent_exists = 1;
	} else if (SCOPE_AUTOCONF(config)) {
		/* read apmask and aqmask udev */
		if (ap_read_type_udev(p_apmask, p_aqmask, true))
			dt->persistent_exists = 1;
	}

	if (dt->active_exists) {
		ap_create_type_setting(dt, dt->active_settings, "apmask",
				       apmask);
		ap_create_type_setting(dt, dt->active_settings, "aqmask",
				       aqmask);
	}

	if (dt->persistent_exists) {
		if (valid_p_apmask)
			ap_create_type_setting(dt, dt->persistent_settings,
					       "apmask", p_apmask);
		if (valid_p_aqmask)
			ap_create_type_setting(dt, dt->persistent_settings,
					       "aqmask", p_aqmask);
	}

out:
	ap_release_lock();
out2:
	return rc;
}

/*
 * Report an error message when the specified configuration will conflict
 * with an existing device
 */
static void conflict_error(const char *uuid, unsigned int a, unsigned int d,
			   bool typeap, bool persistent)
{
	if (persistent) {
		if (typeap) {
			warnx("persistent apmask conflicts with defined "
			      "autostart mdev %s APQN %u.%u", uuid, a, d);
		} else {
			warnx("persistent aqmask conflicts with defined "
			      "autostart mdev %s APQN %u.%u",
			      uuid, a, d);
		}
	} else {
		if (typeap) {
			warnx("apmask conflicts with mdev %s APQN %u.%u",
			      uuid, a, d);
		} else {
			warnx("aqmask conflicts with mdev %s APQN %u.%u",
			      uuid, a, d);
		}
	}
}

/*
 * Compare the list of adapters and domains for the system and a vfio-ap
 * device, reporting error messages for any conflicts that occur
 */
static int find_apqn_conflicts(const char *uuid,
			       struct util_list *adapters,
			       struct util_list *domains,
			       struct util_list *adapters2,
			       struct util_list *domains2,
			       bool typeap,
			       bool persistent)
{
	struct vfio_ap_node *a, *a2, *d, *d2;
	int rc = 0;

	/* Checks for conflicts with the device */
	a = util_list_start(adapters);
	a2 = util_list_start(adapters2);
	while ((a != NULL) && (a2 != NULL)) {
		if (a->id == a2->id) {
			d = util_list_start(domains);
			d2 = util_list_start(domains2);
			while ((d != NULL) && (d2 != NULL)) {
				if (d->id == d2->id) {
					/* Report error, look for more */
					conflict_error(uuid, a->id, d->id,
						       typeap, persistent);
					rc = -1;
					d = util_list_next(domains, d);
					d2 = util_list_next(domains2, d2);
				} else if (d->id > d2->id) {
					d2 = util_list_next(domains2, d2);
				} else {
					d = util_list_next(domains, d);
				}
			}
			a = util_list_next(adapters, a);
			a2 = util_list_next(adapters2, a2);
		} else if (a->id > a2->id) {
			a2 = util_list_next(adapters2, a2);
		} else {
			a = util_list_next(adapters, a);
		}
	}

	return rc;
}

static exit_code_t check_mask_cfg_cb(const char *path,
				     const char *filename,
				     void *data)
{
	struct mdev_cb_data *cb_data = data;
	struct vfio_ap_device *dev = NULL;
	int rc = 0;

	/* Skip anything that isn't an mdev config */
	if (!is_valid_uuid(filename))
		goto out;

	/* Read the device config */
	dev = vfio_ap_device_new();
	if (vfio_ap_read_device_config(path, dev) != 0)
		goto out;

	/* If wrong device type, skip */
	if (strcmp(dev->type, VFIO_AP_TYPE) != 0)
		goto out;

	/* If not AUTO device, skip */
	if (dev->manual)
		goto out;

	/* Perform mdev-to-system apqn conflict analysis */
	rc = find_apqn_conflicts(filename, cb_data->adapters, cb_data->domains,
				 dev->adapters, dev->domains, cb_data->typeap,
				 true);

	if (rc != 0)
		cb_data->found_conflict = true;

out:
	if (dev != NULL)
		vfio_ap_device_free(dev);
	/* Always return 0 so we continue looking for further conflicts */
	return 0;
}

static exit_code_t check_mask_sysfs_cb(const char *path,
				       const char *filename,
				       void *data)
{
	struct mdev_cb_data *cb_data = data;
	char *matrix_path;
	FILE *f;
	char buf[80];
	struct vfio_ap_device *dev;
	int rc = 0;

	if (!is_valid_uuid(filename))
		return 0;

	dev = vfio_ap_device_new();
	matrix_path = path_get_vfio_ap_attr(filename, "matrix");
	f = fopen(matrix_path, "r");
	while (fgets(buf, sizeof(buf), f))
		vfio_ap_parse_matrix(dev, buf);
	vfio_ap_sort_matrix_results(dev);
	fclose(f);
	free(matrix_path);

	/* Look for conflicts between the system and this device */
	rc = find_apqn_conflicts(filename, cb_data->adapters, cb_data->domains,
				 dev->adapters, dev->domains, cb_data->typeap,
				 false);

	if (rc != 0)
		cb_data->found_conflict = true;

	vfio_ap_device_free(dev);

	/* Always return 0 so we continue looking for further conflicts */
	return 0;
}

/*
 * We enter this function to check for mask changes under all circumstances.
 * 'persistent' determines whether we are looking at sysfs or config files
 * 'adapters' is used for error reporting (adapters vs domains)
 */
static exit_code_t check_mask_changes(struct util_list *a,
				      struct util_list *d,
				      bool persistent,
				      bool typeap,
				      bool autoconf)
{
	exit_code_t rc = EXIT_OK;
	struct mdev_cb_data cb_data;
	char *root;

	cb_data.adapters = a;
	cb_data.domains = d;
	cb_data.found_conflict = false;
	cb_data.typeap = typeap;

	if (persistent) {
		/* Validate udev changes against mdevctl AUTO configs */
		root = path_get(VFIO_AP_CONFIG_PATH);
		if (util_path_is_dir(root))
			rc = path_for_each(root, check_mask_cfg_cb, &cb_data);
	} else {
		/* Validate immediate changes against active devices */
		root = path_get_vfio_ap_mdev("");
		if (util_path_is_dir(root))
			rc = path_for_each(root, check_mask_sysfs_cb, &cb_data);
	}

	if (cb_data.found_conflict)
		rc = EXIT_INVALID_CONFIG;

	free(root);

	return rc;
}

/* To validate changes to the system masks, consider the following set of
 * APQNs:
 * To validate apmask changes:  new_apmask_bits * aqmask
 * To validate aqmask changes:  apmask * new_aqmask_bits
 */
static exit_code_t ap_check_mask_changes(config_t config,
					 struct util_list *add_ap,
					 struct util_list *add_aq,
					 struct util_list *add_p_ap,
					 struct util_list *add_p_aq)
{
	int rc = EXIT_OK, rc2 = EXIT_OK, rc3;
	struct util_list all_ap;
	struct util_list all_aq;

	util_list_init(&all_ap, struct vfio_ap_node, node);
	util_list_init(&all_aq, struct vfio_ap_node, node);

	/* Validate the mask changes against existing vfio-ap devices */
	if (SCOPE_ACTIVE(config) && (!util_list_is_empty(add_ap) ||
				     !util_list_is_empty(add_aq))) {
		ap_mask_to_list(apmask, &all_ap);
		ap_mask_to_list(aqmask, &all_aq);
		rc = check_mask_changes(add_ap, &all_aq, false, true, false);
		rc2 = check_mask_changes(&all_ap, add_aq, false, false, false);
		ap_list_remove_all(&all_ap);
		ap_list_remove_all(&all_aq);
		rc = rc == EXIT_OK ? rc2 : rc;
	}
	if (SCOPE_PERSISTENT(config) && (!util_list_is_empty(add_p_ap) ||
					 !util_list_is_empty(add_p_aq))) {
		ap_mask_to_list(p_apmask, &all_ap);
		ap_mask_to_list(p_aqmask, &all_aq);
		rc2 = check_mask_changes(add_p_ap, &all_aq, true, true, false);
		rc3 = check_mask_changes(&all_ap, add_p_aq, true, false, false);
		ap_list_remove_all(&all_ap);
		ap_list_remove_all(&all_aq);
		rc2 = rc2 == EXIT_OK ? rc3 : rc2;
	} else if (SCOPE_AUTOCONF(config) && (!util_list_is_empty(add_p_ap) ||
					      !util_list_is_empty(add_p_aq))) {
		ap_mask_to_list(p_apmask, &all_ap);
		ap_mask_to_list(p_aqmask, &all_aq);
		rc2 = check_mask_changes(add_p_ap, &all_aq, true, true, true);
		rc3 = check_mask_changes(&all_ap, add_p_aq, true, false, true);
		ap_list_remove_all(&all_ap);
		ap_list_remove_all(&all_aq);
		rc2 = rc2 == EXIT_OK ? rc3 : rc2;
	}

	return rc == EXIT_OK ? rc2 : rc;
}

static exit_code_t ap_devtype_write_settings(struct devtype *dt,
					     config_t config)
{
	struct setting *s;
	char *path;
	bool write_ap, write_aq, write_udev;
	struct util_list add_ap, add_aq, sub_ap, sub_aq;
	struct util_list add_p_ap, add_p_aq, sub_p_ap, sub_p_aq;
	exit_code_t rc = EXIT_OK;
	/* No kernel or module parameters exist for AP device driver. */

	util_list_init(&add_ap, struct vfio_ap_node, node);
	util_list_init(&add_aq, struct vfio_ap_node, node);
	util_list_init(&sub_ap, struct vfio_ap_node, node);
	util_list_init(&sub_aq, struct vfio_ap_node, node);
	util_list_init(&add_p_ap, struct vfio_ap_node, node);
	util_list_init(&add_p_aq, struct vfio_ap_node, node);
	util_list_init(&sub_p_ap, struct vfio_ap_node, node);
	util_list_init(&sub_p_aq, struct vfio_ap_node, node);
	write_ap = write_aq = write_udev = false;

	rc = ap_get_lock();
	if (rc != 0) {
		rc = EXIT_RUNTIME_ERROR;
		goto out2;
	}

	/* Determine what was specified and if its valid */
	if (SCOPE_ACTIVE(config) && dt->active_settings) {
		s = setting_list_find(dt->active_settings, "apmask");
		if (s != NULL && s->specified) {
			if (!ap_validate_mask_input(apmask, s->value,
						    &add_ap, &sub_ap)) {
				rc = EXIT_INVALID_SETTING;
				goto out;
			}
			write_ap = true;
		}
		s = setting_list_find(dt->active_settings, "aqmask");
		if (s != NULL && s->specified) {
			if (!ap_validate_mask_input(aqmask, s->value,
						    &add_aq, &sub_aq)) {
				rc = EXIT_INVALID_SETTING;
				goto out;
			}
			write_aq = true;
		}
	}

	if ((SCOPE_PERSISTENT(config) || SCOPE_AUTOCONF(config)) &&
	     dt->persistent_settings) {
		s = setting_list_find(dt->persistent_settings, "apmask");
		if (s != NULL && s->specified) {
			if (!ap_validate_mask_input(p_apmask, s->value,
						    &add_p_ap, &sub_p_ap)) {
				rc = EXIT_INVALID_SETTING;
				goto out;
			}
			write_udev = true;
			valid_p_apmask = true;
		} else if (s != NULL && s->removed) {
			write_udev = true;
			valid_p_apmask = false;
		}
		s = setting_list_find(dt->persistent_settings, "aqmask");
		if (s != NULL && s->specified) {
			if (!ap_validate_mask_input(p_aqmask, s->value,
						    &add_p_aq, &sub_p_aq)) {
				rc = EXIT_INVALID_SETTING;
				goto out;
			}
			write_udev = true;
			valid_p_aqmask = true;
		} else if (s != NULL && s->removed) {
			write_udev = true;
			valid_p_aqmask = false;
		}
	}

	/* Check for conflicts with existing devices */
	rc = ap_check_mask_changes(config, &add_ap, &add_aq, &add_p_ap,
				   &add_p_aq);
	if (rc != EXIT_OK)
		goto out;

	/* Commit the changes to sysfs/udev */
	if (write_ap) {
		path = path_get_bus_attr(AP_MOD_NAME, "apmask");
		write_sysfs_mask(path, apmask);
		free(path);
	}
	if (write_aq) {
		path = path_get_bus_attr(AP_MOD_NAME, "aqmask");
		write_sysfs_mask(path, aqmask);
		free(path);
	}
	if (write_udev) {
		if (SCOPE_PERSISTENT(config))
			ap_write_type_udev(p_apmask, p_aqmask, false);
		else if (SCOPE_AUTOCONF(config))
			ap_write_type_udev(p_apmask, p_aqmask, true);
	}

out:
	ap_list_remove_all(&add_ap);
	ap_list_remove_all(&add_aq);
	ap_list_remove_all(&sub_ap);
	ap_list_remove_all(&sub_aq);
	ap_list_remove_all(&add_p_ap);
	ap_list_remove_all(&add_p_aq);
	ap_list_remove_all(&sub_p_ap);
	ap_list_remove_all(&sub_p_aq);
	ap_release_lock();
out2:
	return rc;
}

/*
 * AP devtype.
 */

struct devtype ap_devtype = {
	.name		= "ap",
	.title		= "", /* Only use subtypes. */
	.devname	= "AP",

	.subtypes = SUBTYPE_ARRAY(
		&ap_subtype,
	),

	.type_attribs = ATTRIB_ARRAY(
		&ap_tattr_apmask,
		&ap_tattr_aqmask,
	),

	.exit			= &ap_devtype_exit,

	.read_settings		= &ap_devtype_read_settings,
	.write_settings		= &ap_devtype_write_settings,
};
