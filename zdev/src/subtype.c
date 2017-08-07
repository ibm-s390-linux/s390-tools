/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "lib/util_base.h"

#include "attrib.h"
#include "device.h"
#include "devnode.h"
#include "devtype.h"
#include "misc.h"
#include "namespace.h"
#include "setting.h"
#include "subtype.h"
#include "udev.h"

/*
 * Generic subtype helper functions.
 */

/* Return struct subtype associated with NAME or NULL if type could not
 * be found. */
struct subtype *subtype_find(const char *name)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;

	for (i = 0; devtypes[i]; i++) {
		dt = devtypes[i];
		for (j = 0; dt->subtypes[j]; j++) {
			st = dt->subtypes[j];
			if (strcasecmp(st->name, name) == 0)
				return st;
		}
	}

	return NULL;
}

/* Search for a device attribute named STR. */
struct attrib *subtype_find_dev_attrib(struct subtype *st, const char *str)
{
	struct attrib *a;
	int i;

	for (i = 0; (a = st->dev_attribs[i]); i++) {
		if (strcmp(str, a->name) == 0)
			return a;
	}
	return NULL;
}

struct devnode_cb_data_t {
	struct devnode *devnode;
	struct subtype **st_ptr;
	char **id_ptr;
};

static exit_code_t devnode_cb(struct subtype *st, const char *id,
			      config_t config, void *data)
{
	struct devnode_cb_data_t *cb_data = data;
	struct devnode *devnode;
	struct ptrlist_node *p, *n;
	struct util_list *devnodes;
	exit_code_t rc = EXIT_OK;

	devnodes = subtype_get_devnodes(st, id);
	if (!devnodes)
		return EXIT_OK;
	util_list_iterate_safe(devnodes, p, n) {
		util_list_remove(devnodes, p);
		devnode = p->ptr;
		if (!rc && devnode_cmp(devnode, cb_data->devnode) == 0) {
			*cb_data->st_ptr = st;
			*cb_data->id_ptr = misc_strdup(id);
			/* Not an error but aborts the loop. */
			rc = EXIT_ABORTED;
		}
		free(devnode);
		free(p);
	}
	free(devnodes);

	return rc;
}

/* Find a device which provides the specified devnode. Note that id_ptr will
 * point to a newly allocated string on success. */
bool subtypes_find_by_devnode(struct devnode *devnode, struct subtype **st_ptr,
			      char **id_ptr)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	struct devnode_cb_data_t cb_data;
	char *id;

	/* Try direct resolution if available. */
	for (i = 0; (dt = devtypes[i]); i++) {
		for (j = 0; (st = dt->subtypes[j]); j++) {
			id = subtype_resolve_devnode(st, devnode);
			if (id) {
				*st_ptr = st;
				*id_ptr = id;

				return true;
			}
		}
	}

	/* Search list of provided devnodes. */
	cb_data.devnode = devnode;
	cb_data.st_ptr = st_ptr;
	cb_data.id_ptr = id_ptr;
	for (i = 0; (dt = devtypes[i]); i++) {
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (subtype_for_each_id(st, config_active, devnode_cb,
						&cb_data))
				return true;
		}
	}

	return false;
}

/*
 * Subtype method acessor functions. These functions run the subtype's
 * method or, if non was defined, the method of its super-subtype.
 */

/* Follow curr->super until curr->method is non-zero or curr is NULL. */
static void *_super_get(void *curr, size_t method_off, size_t super_off,
			int mandatory)
{
	void **addr;

	while (curr) {
		addr = (void *) ((unsigned long) curr + method_off);
		if (*addr)
			break;
		addr = (void *) ((unsigned long) curr + super_off);
		curr = *addr;
	}

	if (!curr && mandatory)
		internal("Missing method implementation");

	return curr;
}

#define super_get(obj, method, mand) \
	_super_get((obj), offsetof(__typeof__(*(obj)), method), \
		   offsetof(__typeof__(*(obj)), super), \
		   (mand))

void subtype_init(struct subtype *st)
{
	struct subtype *super = super_get(st, init, 0);

	if (super)
		super->init(st);
}

void subtype_exit(struct subtype *st)
{
	struct subtype *super = super_get(st, exit, 0);

	if (super)
		super->exit(st);
}

bool subtype_device_exists_active(struct subtype *st, const char *id)
{
	struct subtype *super = super_get(st, exists_active, 1);

	return super->exists_active(st, id);
}

bool subtype_device_exists_persistent(struct subtype *st, const char *id)
{
	struct subtype *super = super_get(st, exists_persistent, 1);

	return super->exists_persistent(st, id);
}

void subtype_add_active_ids(struct subtype *st, struct util_list *ids)
{
	struct subtype *super = super_get(st, add_active_ids, 1);

	super->add_active_ids(st, ids);
}

void subtype_add_persistent_ids(struct subtype *st, struct util_list *ids)
{
	struct subtype *super = super_get(st, add_persistent_ids, 1);

	super->add_persistent_ids(st, ids);
}

exit_code_t subtype_device_read_active(struct subtype *st, struct device *dev,
				       read_scope_t scope)
{
	struct subtype *super = super_get(st, read_active, 1);

	return super->read_active(st, dev, scope);
}

exit_code_t subtype_device_read_persistent(struct subtype *st,
					   struct device *dev,
					   read_scope_t scope)
{
	struct subtype *super = super_get(st, read_persistent, 1);

	return super->read_persistent(st, dev, scope);
}

exit_code_t subtype_device_configure_active(struct subtype *st,
					    struct device *dev)
{
	struct subtype *super = super_get(st, configure_active, 1);

	return super->configure_active(st, dev);
}

exit_code_t subtype_device_configure_persistent(struct subtype *st,
						struct device *dev)
{
	struct subtype *super = super_get(st, configure_persistent, 1);

	return super->configure_persistent(st, dev);
}

exit_code_t subtype_device_deconfigure_active(struct subtype *st,
					      struct device *dev)
{
	struct subtype *super = super_get(st, deconfigure_active, 1);

	return super->deconfigure_active(st, dev);
}

exit_code_t subtype_device_deconfigure_persistent(struct subtype *st,
						  struct device *dev)
{
	struct subtype *super = super_get(st, deconfigure_persistent, 1);

	return super->deconfigure_persistent(st, dev);
}

exit_code_t subtype_check_pre_configure(struct subtype *st, struct device *dev,
					int prereq, config_t config)
{
	struct subtype *super = super_get(st, check_pre_configure, 0);
	exit_code_t rc;

	/* Generic checking. */
	rc = device_check_settings(dev, config, err_delayed_forceable);
	if (rc)
		return rc;

	/* Type-specific checking. */
	if (super)
		return super->check_pre_configure(st, dev, prereq, config);

	return EXIT_OK;
}

exit_code_t subtype_check_post_configure(struct subtype *st, struct device *dev,
					 int prereq, config_t config)
{
	struct subtype *super = super_get(st, check_post_configure, 0);

	if (super)
		return super->check_post_configure(st, dev, prereq, config);

	return EXIT_OK;
}

void subtype_online_set(struct subtype *st, struct device *dev, int online,
			config_t config)
{
	struct subtype *super = super_get(st, online_set, 0);

	if (super)
		super->online_set(st, dev, online, config);
}

int subtype_online_get(struct subtype *st, struct device *dev, config_t config)
{
	struct subtype *super = super_get(st, online_get, 0);
	int act_online = 1, pers_online = 1;

	if (super)
		return super->online_get(st, dev, config);

	/* Devices that do not support online setting are online when they
	 * exist. */
	if (SCOPE_ACTIVE(config))
		act_online = dev->active.exists;
	if (SCOPE_PERSISTENT(config))
		pers_online = dev->persistent.exists;

	return MIN(act_online, pers_online);
}

bool subtype_online_specified(struct subtype *st, struct device *dev,
			      config_t config)
{
	struct subtype *super = super_get(st, online_specified, 0);

	if (super)
		return super->online_specified(st, dev, config);

	return false;
}

void subtype_add_errors(struct subtype *st, const char *id,
			struct util_list *errors)
{
	struct subtype *super = super_get(st, add_errors, 0);

	if (super)
		super->add_errors(st, id, errors);
}

void subtype_add_modules(struct subtype *st, struct device *dev,
			 struct util_list *modules)
{
	struct subtype *super = super_get(st, add_modules, 0);

	if (super)
		super->add_modules(st, dev, modules);
}

void subtype_add_devnodes(struct subtype *st, const char *id,
			  struct util_list *devnodes)
{
	struct subtype *super = super_get(st, add_devnodes, 0);

	if (super)
		super->add_devnodes(st, id, devnodes);
}

char *subtype_resolve_devnode(struct subtype *st, struct devnode *devnode)
{
	struct subtype *super = super_get(st, resolve_devnode, 0);

	if (super)
		return super->resolve_devnode(st, devnode);

	return NULL;
}

void subtype_add_prereqs(struct subtype *st, const char *id,
			 struct util_list *selected)
{
	struct subtype *super = super_get(st, add_prereqs, 0);

	if (super)
		super->add_prereqs(st, id, selected);
}

void subtype_rem_combined(struct subtype *st, struct device *dev,
			  struct selected_dev_node *curr,
			  struct util_list *selected)
{
	struct subtype *super = super_get(st, rem_combined, 0);

	if (super)
		super->rem_combined(st, dev, curr, selected);
}

char *subtype_get_active_attrib_path(struct subtype *st, struct device *dev,
				     const char *name)
{
	struct subtype *super = super_get(st, get_active_attrib_path, 0);

	if (super)
		return super->get_active_attrib_path(st, dev, name);

	return NULL;
}

char *subtype_get_active_attrib(struct subtype *st, struct device *dev,
				const char *name)
{
	struct subtype *super = super_get(st, get_active_attrib, 0);

	if (super)
		return super->get_active_attrib(st, dev, name);

	return NULL;
}

exit_code_t subtype_device_is_definable(struct subtype *st, const char *id,
					err_t err)
{
	struct subtype *super = super_get(st, is_definable, 0);

	if (super)
		return super->is_definable(st, id, err);

	return EXIT_GROUP_NOT_FOUND;
}

exit_code_t subtype_detect_definable(struct subtype *st, struct device *dev)
{
	struct subtype *super = super_get(st, detect_definable, 0);

	if (super)
		return super->detect_definable(st, dev);

	return EXIT_OK;
}

exit_code_t subtype_device_define(struct subtype *st, struct device *dev)
{
	struct subtype *super = super_get(st, device_define, 0);
	exit_code_t rc;
	int proc;
	struct setting_list *settings;

	if (super) {
		rc = super->device_define(st, dev);
		if (rc)
			return rc;

		/* After device was defined, udev might have already applied
		 * existing persistent settings. Need to wait for udev and
		 * reread active configuration. */
		udev_settle();

		proc = dev->processed;
		settings = dev->active.settings;
		dev->active.settings = setting_list_new();

		if (subtype_reread_device(st, dev->id, config_active,
					  scope_known, &dev) == EXIT_OK)
			dev->active.modified = 1;

		/* Re-apply settings. */
		setting_list_merge(dev->active.settings, settings, true, true);
		setting_list_free(settings);

		/* Need to restore dev->proc since it might have been cleared
		 * by subtype_reread_device() . */
		dev->processed = proc;
	}

	return EXIT_OK;
}

exit_code_t subtype_device_undefine(struct subtype *st, struct device *dev)
{
	struct subtype *super = super_get(st, device_undefine, 0);

	if (super)
		return super->device_undefine(st, dev);

	return EXIT_OK;
}

void subtype_add_definable_ids(struct subtype *st, struct util_list *ids)
{
	struct subtype *super = super_get(st, add_definable_ids, 0);

	if (super)
		super->add_definable_ids(st, ids);
}

/*
 * Subtype helpers. These functions combine some of the subtype methods
 * to implement more complex functions.
 */

bool subtype_device_exists(struct subtype *st, const char *id, config_t config)
{
	if (SCOPE_ACTIVE(config)) {
		if (!subtype_device_exists_active(st, id) &&
		    subtype_device_is_definable(st, id, err_ignore) != EXIT_OK)
			return false;
	}
	if (SCOPE_PERSISTENT(config)) {
		if (!subtype_device_exists_persistent(st, id))
			return false;
	}

	return true;
}

static struct util_list *get_ids(struct subtype *st, config_t config)
{
	struct util_list *ids;

	ids = strlist_new();

	/* Get IDs from each configuration. */
	if (SCOPE_ACTIVE(config)) {
		subtype_add_active_ids(st, ids);
		subtype_add_definable_ids(st, ids);
	}
	if (SCOPE_PERSISTENT(config))
		subtype_add_persistent_ids(st, ids);

	/* Provide a sorted view. */
	strlist_sort_unique(ids, st->namespace->qsort_cmp);

	return ids;
}

unsigned long subtype_count_ids(struct subtype *st, config_t config)
{
	struct util_list *ids;
	unsigned long num;

	ids = get_ids(st, config);
	num = util_list_len(ids);
	strlist_free(ids);

	return num;
}

exit_code_t subtype_for_each_id(struct subtype *st, config_t config,
				subtype_cb_t cb, void *data)
{
	struct util_list *ids;
	struct strlist_node *s;
	exit_code_t rc;

	ids = get_ids(st, config);

	rc = EXIT_OK;
	util_list_iterate(ids, s) {
		rc = cb(st, s->str, config, data);
		if (rc)
			break;
	}

	strlist_free(ids);

	return rc;
}

struct util_list *subtype_get_devnodes(struct subtype *st, const char *id)
{
	struct util_list *devnodes;

	devnodes = ptrlist_new();
	subtype_add_devnodes(st, id, devnodes);
	if (util_list_is_empty(devnodes)) {
		ptrlist_free(devnodes, 1);
		devnodes = NULL;
	}

	return devnodes;
}

/* Return a space-separated list of device names provided by device with
 * subtype @st and @id. */
char *subtype_get_devnodes_str(struct subtype *st, const char *id, int bdev,
			       int bdev_part, int cdev, int netdev)
{
	struct util_list *devnodes, *names;
	struct ptrlist_node *p;
	struct devnode *d;
	char *str;
	int first_bdev = 1;

	devnodes = ptrlist_new();
	subtype_add_devnodes(st, id, devnodes);

	names = strlist_new();
	util_list_iterate(devnodes, p) {
		d = p->ptr;
		switch (d->type) {
		case BLOCKDEV:
			if (bdev_part || (bdev && first_bdev))
				strlist_add(names, "%s", d->name);
			first_bdev = 0;
			break;
		case CHARDEV:
			if (cdev)
				strlist_add(names, "%s", d->name);
			break;
		case NETDEV:
			if (netdev)
				strlist_add(names, "%s", d->name);
			break;
		}
	}

	str = strlist_flatten(names, " ");

	strlist_free(names);
	ptrlist_free(devnodes, 1);

	return str;

}

struct util_list *subtype_get_errors(struct subtype *st, const char *id)
{
	struct util_list *errors;

	errors = strlist_new();
	subtype_add_errors(st, id, errors);
	if (util_list_is_empty(errors)) {
		strlist_free(errors);
		errors = NULL;
	}

	return errors;
}

static exit_code_t read_device(struct subtype *st, const char *id,
			       config_t config, struct device **dev_ptr,
			       int reread, read_scope_t scope)
{
	struct device *dev;
	exit_code_t rc = EXIT_OK;
	int add, defined;

	dev = device_list_find(st->devices, id, NULL);
	if (dev) {
		if (!reread) {
			if (SCOPE_ACTIVE(config) && dev->active.blacklisted) {
				/* Reread active device information because
				 * device might have been removed from
				 * blacklist. . */
				config = config_active;
			} else
				goto out;
		}
		add = 0;
		device_reset(dev, config);
	} else {
		dev = device_new(st, id);
		if (!dev)
			return EXIT_INVALID_ID;
		add = 1;
	}

	defined = 0;
	if (SCOPE_ACTIVE(config)) {
		if (subtype_device_exists_active(st, id))
			rc = subtype_device_read_active(st, dev, scope);
		else if (subtype_device_is_definable(st, id,
						     err_ignore) == EXIT_OK) {
			rc = subtype_detect_definable(st, dev);
			defined = 1;
		}
		if (rc)
			goto out;
		/* Apply attribute value mapping. */
		setting_list_map_values(dev->active.settings);
		/* Add blacklisted flag. */
		if (st->namespace->is_id_blacklisted &&
		    st->namespace->is_id_blacklisted(id))
			dev->active.blacklisted = 1;
	}

	if (SCOPE_PERSISTENT(config)) {
		if (subtype_device_exists_persistent(st, id))
			rc = subtype_device_read_persistent(st, dev, scope);
		else if (defined) {
			/* Need to copy detected settings to persistent
			 * config. */
			setting_list_merge(dev->persistent.settings,
					   dev->active.settings, false, false);
		}
		if (rc)
			goto out;
	}

	if (add)
		device_list_add(st->devices, dev);

out:
	if (rc)
		device_free(dev);
	else if (dev_ptr)
		*dev_ptr = dev;

	return rc;
}

exit_code_t subtype_read_device(struct subtype *st, const char *id,
				config_t config, read_scope_t scope,
				struct device **dev_ptr)
{
	return read_device(st, id, config, dev_ptr, 0, scope);
}

exit_code_t subtype_reread_device(struct subtype *st, const char *id,
				  config_t config, read_scope_t scope,
				  struct device **dev_ptr)
{
	return read_device(st, id, config, dev_ptr, 1, scope);
}

/* Apply device configuration %dev to the configuration sets %config. */
exit_code_t subtype_write_device(struct subtype *st, struct device *dev,
				 config_t config)
{
	exit_code_t rc = EXIT_OK;

	if (SCOPE_ACTIVE(config)) {
		if (dev->active.deconfigured) {
			/* Deconfigure device. */
			if (dev->active.exists) {
				rc = subtype_device_deconfigure_active(st, dev);
				if (rc)
					return rc;
				rc = subtype_device_undefine(st, dev);
				if (rc)
					return rc;
			}
		} else if (dev->active.exists || dev->active.definable) {
			/* Configure device. */
			if (dev->active.definable) {
				rc = subtype_device_define(st, dev);
				if (rc)
					return rc;
			}
			rc = subtype_device_configure_active(st, dev);
			if (rc)
				return rc;
		}
	}
	if (SCOPE_PERSISTENT(config)) {
		if (dev->persistent.deconfigured) {
			/* Deconfigure device. */
			if (dev->persistent.exists) {
				rc = subtype_device_deconfigure_persistent(st,
									   dev);
				if (rc)
					return rc;
			}
		} else if (dev->persistent.exists) {
			/* Configure device. */
			rc = subtype_device_configure_persistent(st, dev);
			if (rc)
				return rc;
		}
		if (!rc)
			namespace_set_modified(dev->subtype->namespace);
	}

	return EXIT_OK;
}

/* Used for debugging. */
void subtype_devices_print_all(void)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;

	for (i = 0; devtypes[i]; i++) {
		dt = devtypes[i];
		for (j = 0; dt->subtypes[j]; j++) {
			st = dt->subtypes[j];
			device_list_print(st->devices, 0);
		}
	}
}

/* Add name of all modules required by subtype @st to strlist @modules. */
void subtype_add_static_modules(struct util_list *modules, struct subtype *st)
{
	const char **mod = st->modules;
	int i;

	if (!mod)
		return;

	for (i = 0; mod[i]; i++)
		strlist_add_unique(modules, "%s", mod[i]);
}

void subtype_print(struct subtype *st, int indent)
{
	printf("%*ssubtype at %p\n", indent, "", (void *) st);
	if (!st)
		return;
	indent += 2;
	printf("%*sname=%s\n", indent, "", st->name);
	printf("%*sdevices:\n", indent, "");
	device_list_print(st->devices, indent + 2);
}

static void base_st_init(struct subtype *st)
{
	st->devices = device_list_new(st);
}

static void base_st_exit(struct subtype *st)
{
	device_list_free(st->devices);
}

struct subtype subtype_base = {
	.init		= &base_st_init,
	.exit		= &base_st_exit,
};
