/*
 * ap-check - Validate vfio-ap mediated device configuration changes
 *
 * This tool in intended to be driven via the callout API of the mdevctl
 * utility (https://github.com/mdevctl/mdevctl/)
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "lib/ap.h"
#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"

#include "ap-check.h"

static const struct mdevctl_action mdevctl_action_table[NUM_MDEVCTL_ACTIONS] = {
	{MDEVCTL_ACTION_DEFINE, "define"},
	{MDEVCTL_ACTION_LIST, "list"},
	{MDEVCTL_ACTION_MODIFY, "modify"},
	{MDEVCTL_ACTION_START, "start"},
	{MDEVCTL_ACTION_STOP, "stop"},
	{MDEVCTL_ACTION_TYPES, "types"},
	{MDEVCTL_ACTION_UNDEFINE, "undefine"},
	{MDEVCTL_ACTION_ATTRIBUTES, "attributes"}
};

static const struct mdevctl_event mdevctl_event_table[NUM_MDEVCTL_EVENTS] = {
	{MDEVCTL_EVENT_PRE, "pre"},
	{MDEVCTL_EVENT_POST, "post"},
	{MDEVCTL_EVENT_GET, "get"}
};

/*
 * Convert mdevctl action string to an enumerated value
 */
static enum mdevctl_action_id validate_action(char *action)
{
	int i;

	for (i = 0; i < NUM_MDEVCTL_ACTIONS; i++) {
		if (strcmp(action, mdevctl_action_table[i].action) == 0)
			return mdevctl_action_table[i].id;
	}

	return MDEVCTL_ACTION_UNKNOWN;
}

/*
 * Convert mdevctl event string to an enumerated value
 */
static enum mdevctl_event_id validate_event(char *event)
{
	int i;

	for (i = 0; i < NUM_MDEVCTL_EVENTS; i++) {
		if (strcmp(event, mdevctl_event_table[i].event) == 0)
			return mdevctl_event_table[i].id;
	}

	return MDEVCTL_EVENT_UNKNOWN;
}

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("DEVICE"),
	{
		.option = { "e", required_argument, NULL, 'e' },
		.argument = "EVENT",
		.desc = "The type of callout being issued",
	},
	{
		.option = { "a", required_argument, NULL, 'a' },
		.argument = "ACTION",
		.desc = "The action being performed on the specified device",
	},
	{
		.option = { "s", required_argument, NULL, 's' },
		.argument = "STATE",
		.desc = "The state of the associated mdevctl command",
	},
	{
		.option = { "u", required_argument, NULL, 'u' },
		.argument = "UUID",
		.desc = "Universally Unique ID for the mediated device",
	},
	{
		.option = { "p", required_argument, NULL, 'p' },
		.argument = "PDEV",
		.desc = "Parent device name, e.g. matrix",
	},
	{
		.option = { "t", required_argument, NULL, 't' },
		.argument = "TYPE",
		.desc = "Mediated device type, e.g. vfio_ap-passthrough",
	},
	UTIL_OPT_END
};

/*
 * Initialize the ap_check anchor struct.
 */
static void ap_check_init(struct ap_check_anchor *anc)
{
	anc->uuid = anc->parent = anc->type = NULL;
	anc->dev = vfio_ap_device_new();
	anc->cleanup_lock = false;
}

/*
 * Free memory of ap_check anchor struct.
 */
static void ap_check_cleanup(struct ap_check_anchor *anc)
{
	if (anc->uuid)
		free(anc->uuid);
	if (anc->parent)
		free(anc->parent);
	if (anc->type)
		free(anc->type);
	if (anc->dev)
		vfio_ap_device_free(anc->dev);
	if (anc->cleanup_lock)
		ap_release_lock_callout();
}

/*
 * Exit ap_check
 */
static void __noreturn ap_check_exit(struct ap_check_anchor *anc, int rc)
{
	ap_check_cleanup(anc);
	exit(rc);
}

/*
 * parses the command line
 */
static void ap_check_parse(struct ap_check_anchor *anc,
			   int argc, char *argv[])
{
	bool action = false, event = false, state = false, bad_opts = false;
	int opt;

	util_opt_init(opt_vec, NULL);

	while (1) {
		opt = util_opt_getopt_long(argc, argv);
		if (opt == -1)
			break;
		switch (opt) {
		case 'e':
			if (event) {
				bad_opts = true;
			} else {
				anc->event = validate_event(optarg);
				event = true;
			}
			break;
		case 'a':
			if (action) {
				bad_opts = true;
			} else {
				anc->action = validate_action(optarg);
				action = true;
			}
			break;
		case 's':
			if (state) {
				bad_opts = true;
			} else {
				/* Ignore the state */
				state = true;
			}
			break;
		case 'u':
			if (anc->uuid)
				bad_opts = true;
			else
				anc->uuid = util_strdup(optarg);
			break;
		case 'p':
			if (anc->parent)
				bad_opts = true;
			else
				anc->parent = util_strdup(optarg);
			break;
		case 't':
			if (anc->type)
				bad_opts = true;
			else
				anc->type = util_strdup(optarg);
			break;
		default:
			fprintf(stderr, "Unknown operand\n");
			ap_check_exit(anc, EXIT_FAILURE);
		}
	}

	/* Make sure we got all expected input values */
	if (!(action && event && state && anc->uuid && anc->parent &&
	      anc->type) || bad_opts) {
		fprintf(stderr, "Duplicate or missing operand\n");
		ap_check_exit(anc, EXIT_FAILURE);
	}

	/* Check for invalid UUID */
	if (!is_valid_uuid(anc->uuid)) {
		fprintf(stderr, "Invalid UUID specified\n");
		ap_check_exit(anc, EXIT_FAILURE);
	}
	anc->dev->uuid = util_strdup(anc->uuid);

	/* Check for valid type */
	if (strcmp(anc->type, VFIO_AP_TYPE) != 0)
		ap_check_exit(anc, APC_EXIT_UNKNOWN_TYPE);

	/* Check for invalid parent - currently only 'matrix' supported */
	if (strcmp(anc->parent, "matrix") != 0) {
		fprintf(stderr, "Invalid parent specified\n");
		ap_check_exit(anc, EXIT_FAILURE);
	}
}

/*
 * Call a function for each entry in a directory:
 * int callback(const char *abs_path, const char *rel_path, void *data)
 * Continues for all entries in the directory regardless of callback return
 * code.  Will return 0 or, if one or more callbacks failed, the first nonzero
 * rc received.
 */
static int path_for_each(const char *path,
			 int (*callback)(const char *, const char *, void *),
			 void *data)
{
	struct dirent *de;
	int rc = 0;
	int r = 0;
	DIR *dir;
	char *p;

	dir = opendir(path);
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		util_asprintf(&p, "%s/%s", path, de->d_name);
		r = callback(p, de->d_name, data);
		/* Save first nonzero return code for caller */
		if (rc == 0 && r != 0)
			rc = r;
		free(p);
	}

	closedir(dir);

	return rc;
}

/*
 * Report an error message when the specified configuration will conflict
 * with an existing device
 */
static void conflict_error(const char *uuid, unsigned int a, unsigned int d,
			   bool persistent)
{
	if (uuid) {
		if (persistent) {
			fprintf(stderr,
				"APQN %u.%u is defined for autostart by %s\n",
				a, d, uuid);
		} else {
			fprintf(stderr, "APQN %u.%u already in use by %s\n",
				a, d, uuid);
		}
	} else {
		if (persistent) {
			fprintf(stderr, "AQPN %u.%u is not defined for "
				"vfio_ap-passthrough use by the persistent "
				"ap bus mask settings\n", a, d);
		} else {
			fprintf(stderr, "AQPN %u.%u is not allowed for "
				"vfio_ap-passthrough use by the active ap "
				"bus mask settings\n", a, d);
		}
	}
}

/*
 * Compare the list of adapters and domains for two devices, reporting error
 * messages for any conflicts that occur.  A conflict occurs when both devices
 * have the same adapter + domain pair.
 * The function below takes advantage of the fact that the lists are known to
 * be sorted in numeric order; therefore we can use this information to run
 * the lists in parallel rather than always starting from the beginning.
 */
static int find_apqn_conflicts(const char *uuid,
			       struct util_list *adapters,
			       struct util_list *domains,
			       struct util_list *adapters2,
			       struct util_list *domains2,
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
						       persistent);
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

/*
 * If the provided path maps to a valid vfio-ap device configuration,
 * determine if its current configuration will conflict with the proposed
 * changes.
 */
static int check_other_mdev_cfg_cb(const char *path,
				   const char *filename,
				   void *data)
{
	struct other_mdev_cb_data *cbdata = data;
	struct vfio_ap_device *dev = cbdata->dev;
	struct vfio_ap_device *dev2 = NULL;
	int rc = 0;

	/* Skip anything that isn't an mdev config */
	if (!is_valid_uuid(filename))
		goto out;

	/* Skip if this is the input device */
	if (strcasecmp(cbdata->uuid, filename) == 0)
		goto out;

	/* Read the device config */
	dev2 = vfio_ap_device_new();
	if (vfio_ap_read_device_config(path, dev2) != 0)
		goto out;

	/* If wrong device type, skip */
	if (strcmp(dev2->type, VFIO_AP_TYPE) != 0)
		goto out;

	/* If not AUTO device, skip */
	if (dev2->manual)
		goto out;

	/* Perform mdev-to-mdev apqn conflict analysis */
	rc = find_apqn_conflicts(filename, dev->adapters, dev->domains,
				 dev2->adapters, dev2->domains, true);

out:
	if (dev2 != NULL)
		vfio_ap_device_free(dev2);
	return rc;
}

/*
 * Perform conflict analysis against all other vfio-ap persistent
 * configurations.
 */
int check_other_mdevs_cfg(struct ap_check_anchor *anc)
{
	struct other_mdev_cb_data cb_data;

	if (!util_path_is_dir(VFIO_AP_CONFIG_PATH))
		return 0;

	cb_data.uuid = anc->uuid;
	cb_data.dev = anc->dev;

	return path_for_each(VFIO_AP_CONFIG_PATH, check_other_mdev_cfg_cb,
			     &cb_data);
}

/*
 * If the provided path maps to a valid device, determine if its current
 * configuration will conflict with the proposed changes.
 */
static int check_other_mdev_sysfs_cb(const char *path, const char *filename,
				     void *data)
{
	struct other_mdev_cb_data *cbdata = data;
	struct vfio_ap_device *dev = cbdata->dev;
	struct vfio_ap_device *dev2;
	char *matrix_path;
	char buf[80];
	int rc = 0;
	FILE *f;

	if (!is_valid_uuid(filename) || path == NULL ||
	    strcasecmp(filename, cbdata->uuid) == 0)
		return 0;

	dev2 = vfio_ap_device_new();
	matrix_path = path_get_vfio_ap_attr(filename, "matrix");
	f = fopen(matrix_path, "r");
	while (fgets(buf, sizeof(buf), f))
		vfio_ap_parse_matrix(dev2, buf);
	vfio_ap_sort_matrix_results(dev2);
	fclose(f);
	free(matrix_path);

	/* Look for conflicts between target device and this device */
	rc = find_apqn_conflicts(filename, dev->adapters, dev->domains,
				 dev2->adapters, dev2->domains, false);

	vfio_ap_device_free(dev2);

	return rc;
}

/* Run conflict analysis against all other active vfio-ap devices */
static int check_other_mdevs_sysfs(struct ap_check_anchor *anc)
{
	struct other_mdev_cb_data cb_data;
	char *root;
	int rc = 0;

	cb_data.uuid = anc->uuid;
	cb_data.dev = anc->dev;

	root = path_get_vfio_ap_mdev("");
	if (util_path_is_dir(root))
		rc = path_for_each(root, check_other_mdev_sysfs_cb, &cb_data);

	free(root);
	return rc;
}

/*
 * Determine if there are any conflicts between the specified device and
 * the active apmask/aqmask settings.  This is done by treating the masks
 * as a temporary vfio_ap_device with all of the associated APQNs owned by
 * the system.
 */
static int check_sysfs_mask_conflicts(struct ap_check_anchor *anc)
{
	struct vfio_ap_device *sysdev = vfio_ap_device_new();
	char *apmask = util_zalloc(AP_MASK_SIZE);
	char *aqmask = util_zalloc(AP_MASK_SIZE);
	int rc = 0;

	if (ap_read_sysfs_masks(apmask, aqmask, AP_MASK_SIZE) != 0) {
		fprintf(stderr, "Error reading system AP settings\n");
		rc = -1;
		goto out;
	}

	/* Convert the masks to a device with the associated APQNs */
	ap_mask_to_list(apmask, sysdev->adapters);
	ap_mask_to_list(aqmask, sysdev->domains);

	/* Perform conflict analysis */
	rc = find_apqn_conflicts(NULL, anc->dev->adapters,
				 anc->dev->domains, sysdev->adapters,
				 sysdev->domains, false);
out:
	free(apmask);
	free(aqmask);
	vfio_ap_device_free(sysdev);

	return rc;
}

/*
 * Determine if there are any conflicts between the specified device and
 * the apmask/aqmask settings stored in udev.  This is done by treating
 * the masks as a temporary vfio_ap_device with all of the associated
 * AQPNs owned by the system.
 */
static int check_cfg_mask_conflicts(struct ap_check_anchor *anc)
{
	struct vfio_ap_device *sysdev = vfio_ap_device_new();
	char *apmask = util_zalloc(AP_MASK_SIZE);
	char *aqmask = util_zalloc(AP_MASK_SIZE);
	bool read_ap = false, read_aq = false;
	char *path;
	int rc = 0;

	path = path_get_ap_udev();
	if (!ap_read_udev_masks(path, apmask, aqmask, &read_ap, &read_aq)) {
		fprintf(stderr, "Error reading system AP settings\n");
		rc = -1;
		goto out;
	}

	/* Convert the masks to a device with the associated APQNs */
	ap_mask_to_list(apmask, sysdev->adapters);
	ap_mask_to_list(aqmask, sysdev->domains);

	/* Perform conflict analysis */
	rc = find_apqn_conflicts(NULL, anc->dev->adapters,
				 anc->dev->domains, sysdev->adapters,
				 sysdev->domains, true);
out:
	free(apmask);
	free(aqmask);
	free(path);
	vfio_ap_device_free(sysdev);

	return rc;
}

/* Subroutine to handle checking shared between DEFINE and MODIFY actions. */
static int ap_check_changes(struct ap_check_anchor *anc)
{
	int rc = 0, rc2;

	rc = ap_get_lock_callout();
	if (rc) {
		fprintf(stderr, "Failed to acquire configuration lock %d\n",
			rc);
		rc = -1;
		goto out;
	}
	anc->cleanup_lock = true;

	if (vfio_ap_read_device_config(NULL, anc->dev) != 0) {
		fprintf(stderr, "Failed to read device config\n");
		rc = -1;
		goto out;
	}

	if (strcmp(anc->dev->type, anc->type) != 0) {
		fprintf(stderr, "Invalid mdev_type: %s\n", anc->dev->type);
		rc = -1;
		goto out;
	}

	if (!anc->dev->manual) {
		/* Check against all other AUTO config files */
		rc = check_other_mdevs_cfg(anc);
		/* Check against the system UDEV rule for apmask/aqmask */
		rc2 = check_cfg_mask_conflicts(anc);
		/* If either hit an error, reflect this */
		rc = rc != 0 ? rc : rc2;
	}

	/* If successful, lock must remain held until post callout */
	if (rc == 0)
		anc->cleanup_lock = false;

out:
	return rc;
}

/*
 * Determine if defining the specified device is a valid operation.
 * mdevctl can reach us for a DEFINE under the following circumstances:
 * 1) the device does not exist
 * 2) the device is active but does not have a config file, so this action
 *    would be to generate a config file based upon the active device.
 * DEFINE has no effect on an active device (if one exists) it only creates
 * the configuration file.  The config file might be empty or may have various
 * attributes if being fed by --jsonfile or an active device.
 */
static int ap_check_handle_define(struct ap_check_anchor *anc)
{
	char *path = path_get_vfio_ap_mdev_config(anc->uuid);

	if (util_path_is_readable(path)) {
		fprintf(stderr, "Config already exists\n");
		free(path);
		return -1;
	}

	free(path);

	return ap_check_changes(anc);
}

/*
 * Determine if modifying the specified device is a valid operation.
 * mdevctl can reach us for a MODIFY under the following circumstances:
 * 1) Modifying a MANUAL device
 * 2) Modifying an AUTO device
 * In the case of MANUAL, we don't take any action because changes made via
 * MODIFY don't take affect on the active mdev until a STOP/START cycle.
 * In the case of AUTO, we must compare the contents of the proposed device
 * with the contents of stashed AUTO mdev configurations + the system.
 */
static int ap_check_handle_modify(struct ap_check_anchor *anc)
{
	char *path = path_get_vfio_ap_mdev_config(anc->uuid);
	FILE *fd = fopen(path, "r");

	/* Determine if a base config file already exists for UUID */
	free(path);
	if (fd == NULL) {
		fprintf(stderr, "Config doesn't exist\n");
		return -1;
	}
	fclose(fd);

	return ap_check_changes(anc);
}

/*
 * Determine if starting the specified device is a valid operation.
 * mdevctl can reach us for a START under the following circumstances:
 * 1) STARTing a MANUAL device
 *    1a) Where the MANUAL device is defined (has a config file)
 *    1b) Where the MANUAL device is NOT defined (no config file).
 *        For vfio-ap this case provides an mdev with no adapters/domains.
 *    1c) Where the MANUAL device is NOT defined but a full configuration is
 *        provided via --jsonfile
 * 2) STARTing an AUTO device
 *    2a) Where the AUTO device is defined (has a config file)
 *    2b) Where the AUTO device is NOT defined but a full configuration is
 *        provided via --jsonfile
 * In each case, we must compare the proposed device with the contents of
 * active mdevs + the system.
 */
static int ap_check_handle_start(struct ap_check_anchor *anc)
{
	int rc = 0, rc2;

	/* Can only start a device if vfio_ap is built-in or loaded */
	if (!util_path_is_dir(VFIO_AP_PATH)) {
		fprintf(stderr, "vfio_ap module is not loaded\n");
		ap_check_exit(anc, EXIT_FAILURE);
	}

	rc = ap_get_lock_callout();
	if (rc) {
		fprintf(stderr, "Failed to acquire configuration lock %d\n",
			rc);
		rc = -1;
		goto out;
	}
	anc->cleanup_lock = true;

	if (vfio_ap_read_device_config(NULL, anc->dev) != 0) {
		fprintf(stderr, "Failed to read device config\n");
		rc = -1;
		goto out;
	}

	if (strcmp(anc->dev->type, anc->type) != 0) {
		fprintf(stderr, "Invalid mdev_type: %s\n", anc->dev->type);
		rc = -1;
		goto out;
	}

	/* Ensure device with control domains also has usage domains */
	if (util_list_is_empty(anc->dev->domains) &&
	    !util_list_is_empty(anc->dev->controls)) {
		fprintf(stderr, "At least one usage domain must be specified\n");
		rc = -1;
		goto out;
	}

	/* Check against all other active vfio-ap devices */
	rc = check_other_mdevs_sysfs(anc);
	/* Check against the system sysfs values for apmask/aqmask */
	rc2 = check_sysfs_mask_conflicts(anc);
	/* If either hit an error, reflect this */
	rc = rc != 0 ? rc : rc2;

	/* If successful, lock must remain held until post callout */
	if (rc == 0)
		anc->cleanup_lock = false;

out:
	return rc;
}

/*
 * Acquire the appropriate serialization so that the specified device can be
 * STOPped.
 */
static int ap_check_handle_stop(void)
{
	int rc;

	rc = ap_get_lock_callout();
	if (rc) {
		fprintf(stderr, "Failed to acquire configuration lock %d\n",
			rc);
		return -1;
	}

	/* The lock must remain held until post callout */
	return 0;
}

/*
 * Determine if UNDEFINEing the specified device is a valid operation.
 * mdevctl can reach us for an UNDEFINE under the following circumstances:
 * 1) UNDEFINEing an active device
 * 2) UNDEFINEing an inactive device
 * UNDEFINE has no effect on the active device, it only removes the config
 * file.
 */
static int ap_check_handle_undefine(struct ap_check_anchor *anc)
{
	char *path = path_get_vfio_ap_mdev_config(anc->uuid);
	int rc = 0;

	rc = ap_get_lock_callout();
	if (rc) {
		fprintf(stderr, "Failed to acquire configuration lock %d\n",
			rc);
		rc = -1;
		goto out;
	}
	anc->cleanup_lock = true;

	if (vfio_ap_read_device_config(path, anc->dev) != 0) {
		fprintf(stderr, "Failed to read device config\n");
		rc = -1;
		goto out;
	}

	if (strcmp(anc->dev->type, anc->type) != 0) {
		fprintf(stderr, "Invalid mdev_type: %s\n", anc->dev->type);
		rc = -1;
		goto out;
	}

	/* Success: lock must remain held until post callout */
	anc->cleanup_lock = false;

out:
	free(path);
	return rc;
}

/*
 * For callouts where the "pre" callout would have acquired the lock, it is
 * now safe to remove the lock as all changes have been committed.
 */
static int ap_check_handle_post(void)
{
	return ap_release_lock_callout();
}

/* For the specified device, print the attributes to stdout in JSON format */
static int ap_check_handle_get_attributes(struct ap_check_anchor *anc)
{
	struct vfio_ap_device *dev = anc->dev;
	struct vfio_ap_node *node;
	bool has_attr = false;
	char buf[80];
	char *path;
	FILE *f;
	int rc;

	rc = ap_get_lock_callout();
	if (rc) {
		fprintf(stderr, "Failed to acquire configuration lock %d\n", rc);
		return -1;
	}
	anc->cleanup_lock = true;

	path = path_get_vfio_ap_attr(anc->uuid, "matrix");
	f = fopen(path, "r");
	while (fgets(buf, sizeof(buf), f))
		vfio_ap_parse_matrix(dev, buf);
	vfio_ap_sort_matrix_results(dev);
	fclose(f);
	free(path);

	path = path_get_vfio_ap_attr(anc->uuid, "control_domains");
	f = fopen(path, "r");
	while (fgets(buf, sizeof(buf), f))
		vfio_ap_parse_control(dev, buf);
	fclose(f);
	free(path);

	printf("[{");

	if (!util_list_is_empty(dev->adapters)) {
		util_list_iterate(dev->adapters, node) {
			if (has_attr)
				printf("},{");
			printf("\"assign_adapter\": \"%u\"", node->id);
			has_attr = true;
		}
	}

	if (!util_list_is_empty(dev->domains)) {
		util_list_iterate(dev->domains, node) {
			if (has_attr)
				printf("},{");
			printf("\"assign_domain\": \"%u\"", node->id);
			has_attr = true;
		}
	}

	if (!util_list_is_empty(dev->controls)) {
		util_list_iterate(dev->controls, node) {
			if (has_attr)
				printf("},{");
			printf("\"assign_control_domain\": \"%u\"", node->id);
			has_attr = true;
		}
	}

	printf("}]\n");

	return 0;
}

/*
 * Determine which mdevctl action is being checked and handle accordingly.
 */
static int ap_check_handle_action(struct ap_check_anchor *anc)
{
	int rc = 0;

	switch (anc->event) {
	case MDEVCTL_EVENT_PRE:
		switch (anc->action) {
		case MDEVCTL_ACTION_DEFINE:
			rc = ap_check_handle_define(anc);
			break;
		case MDEVCTL_ACTION_MODIFY:
			rc = ap_check_handle_modify(anc);
			break;
		case MDEVCTL_ACTION_START:
			rc = ap_check_handle_start(anc);
			break;
		case MDEVCTL_ACTION_STOP:
			rc = ap_check_handle_stop();
			break;
		case MDEVCTL_ACTION_UNDEFINE:
			rc = ap_check_handle_undefine(anc);
			break;
		case MDEVCTL_ACTION_LIST:
		case MDEVCTL_ACTION_TYPES:
		default:
			/* Ignore some actions including unknown ones */
			break;
		}
		break;
	case MDEVCTL_EVENT_POST:
		switch (anc->action) {
		case MDEVCTL_ACTION_DEFINE:
		case MDEVCTL_ACTION_MODIFY:
		case MDEVCTL_ACTION_START:
		case MDEVCTL_ACTION_STOP:
		case MDEVCTL_ACTION_UNDEFINE:
			ap_check_handle_post();
			break;
		default:
			/* Ignore other post events */
			break;
		}
		break;
	case MDEVCTL_EVENT_GET:
		switch (anc->action) {
		case MDEVCTL_ACTION_ATTRIBUTES:
			rc = ap_check_handle_get_attributes(anc);
			break;
		default:
			/* Ignore some actions including unknown ones */
			break;
		}
		break;
	default:
		/* Ignore any unknown events */
		break;
	}

	return rc;
}

/*
 *
 */
int main(int argc, char *argv[])
{
	struct ap_check_anchor anchor;
	int rc;

	ap_check_init(&anchor);

	ap_check_parse(&anchor, argc, argv);

	rc = ap_check_handle_action(&anchor);

	ap_check_exit(&anchor, rc);
}
