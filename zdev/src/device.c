/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "lib/util_path.h"

#include "attrib.h"
#include "device.h"
#include "devtype.h"
#include "internal.h"
#include "misc.h"
#include "namespace.h"
#include "setting.h"
#include "subtype.h"
#include "udev.h"

/* Create and initialize a new device. */
struct device *device_new(struct subtype *st, const char *id)
{
	struct device *dev;
	struct namespace *ns = st->namespace;

	dev = misc_malloc(sizeof(struct device));
	dev->subtype = st;

	dev->id = ns->normalize_id(id);
	dev->devid = ns->parse_id(id, 0);
	if (!dev->id || !dev->devid) {
		device_free(dev);
		return NULL;
	}

	dev->active.settings = setting_list_new();
	dev->persistent.settings = setting_list_new();
	dev->autoconf.settings = setting_list_new();

	return dev;
}

/* Release all resources associated with the specified device. */
void device_free(struct device *dev)
{
	if (!dev)
		return;
	free(dev->id);
	free(dev->devid);
	setting_list_free(dev->active.settings);
	setting_list_free(dev->persistent.settings);
	setting_list_free(dev->autoconf.settings);
	free(dev);
}

/* Used for debugging. */
void device_print(struct device *dev, int level)
{
	printf("%*sdevice at %p:\n", level, "", (void *) dev);
	if (!dev)
		return;
	printf("%*stype=%s id=%s devid=%p proc=%d\n", level + 4, "",
	       dev->subtype->name, dev->id, dev->devid, dev->processed);

	printf("%*sactive:\n", level + 4, "");
	printf("%*sexists=%d mod=%d deconf=%d def=%d blacklisted=%d\n",
	       level + 8, "", dev->active.exists, dev->active.modified,
	       dev->active.deconfigured, dev->active.definable,
	       dev->active.blacklisted);
	if (dev->active.settings)
		setting_list_print(dev->active.settings, level + 8);
	else
		printf("%*s<none>\n", level + 8, "");

	printf("%*spersistent:\n", level + 4, "");
	printf("%*sexists=%d mod=%d deconf=%d\n",
	       level + 8, "", dev->persistent.exists, dev->persistent.modified,
	       dev->persistent.deconfigured);
	if (dev->persistent.settings)
		setting_list_print(dev->persistent.settings, level + 8);
	else
		printf("%*s<none>\n", level + 8, "");

	printf("%*sautoconf:\n", level + 4, "");
	printf("%*sexists=%d mod=%d deconf=%d\n",
	       level + 8, "", dev->autoconf.exists, dev->autoconf.modified,
	       dev->autoconf.deconfigured);
	if (dev->autoconf.settings)
		setting_list_print(dev->autoconf.settings, level + 8);
	else
		printf("%*s<none>\n", level + 8, "");
}

static const void *device_hash_get_id(void *dev_ptr)
{
	struct device *dev = dev_ptr;

	return dev->devid;
}

/* Create and initialize a new device_list. */
struct device_list *device_list_new(struct subtype *st)
{
	struct device_list *list;
	struct namespace *ns = st->namespace;

	list = misc_malloc(sizeof(struct device_list));
	hash_init(&list->hash, ns->hash_buckets, device_hash_get_id,
		  ns->cmp_parsed_ids, ns->hash_parsed_id,
		  struct device, node);

	return list;
}

/* Release resources used by list and enlisted devices. */
void device_list_free(struct device_list *list)
{
	if (!list)
		return;
	hash_clear(&list->hash, (void (*)(void *)) device_free);
	free(list);
}

/* Add a new element to a list and mark the list as modified. */
void device_list_add(struct device_list *list, struct device *device)
{
	hash_add(&list->hash, device);
	list->modified = 1;
}

/* Find an element in the list. */
struct device *device_list_find(struct device_list *list, const char *id,
				struct device *start)
{
	struct device *dev;
	struct namespace *ns;
	void *devid;

	if (!list)
		return NULL;

	dev = start ? start : util_list_start(&list->hash.list);
	if (!dev)
		return NULL;

	ns = dev->subtype->namespace;
	devid = ns->parse_id(id, err_ignore);
	if (!devid)
		goto out;

	/* Try to find using hashed ID data. */
	if (!start && list->hash.get_hash) {
		dev = hash_find_by_id(&list->hash, devid);
		goto out;
	}

	/* Find the slow way. */
	while (dev) {
		if (ns->cmp_parsed_ids(dev->devid, devid) == 0)
			goto out;
		dev = util_list_next(&list->hash.list, dev);
	}

out:
	free(devid);

	return dev;
}

/* Used for debugging. */
void device_list_print(struct device_list *list, int level)
{
	struct device *dev;

	printf("%*sdevice list at %p:\n", level, "", (void *) list);
	util_list_iterate(&list->hash.list, dev)
		device_print(dev, level + 4);
}

/* Check if a device configuration needs to be written. */
bool device_needs_writing(struct device *dev, config_t config)
{
	if (SCOPE_ACTIVE(config) &&
	    (dev->active.modified || dev->active.deconfigured ||
	     setting_list_modified(dev->active.settings)))
		return true;
	if (SCOPE_PERSISTENT(config) &&
	    (dev->persistent.modified || dev->persistent.deconfigured ||
	     setting_list_modified(dev->persistent.settings)))
		return true;
	if (SCOPE_AUTOCONF(config) &&
	    (dev->autoconf.modified || dev->autoconf.deconfigured ||
	     setting_list_modified(dev->autoconf.settings)))
		return true;

	return false;
}

static exit_code_t apply_setting(struct device *dev, config_t config,
				 const char *key, const char *value,
				 struct util_list *processed)
{
	struct subtype *st = dev->subtype;
	struct attrib *a;
	struct setting *s;
	bool warn_readonly = false;

	/* Check for known attribute. */
	a = subtype_find_dev_attrib(st, key);
	if (a) {
		/* Check for read-only attribute. */
		if (a->readonly)
			goto err_readonly;
		/* Check for acceptable value of known attribute. */
		if (!force && !attrib_check_value(a, value))
			goto err_invalid_forceable;
		/* Check for activeonly. */
		if (!force && SCOPE_PERSISTENT(config) && a->activeonly)
			goto err_activeonly_forceable;
		if (!force && SCOPE_AUTOCONF(config) && a->activeonly)
			goto err_activeonly_forceable;
		/* Check for internal. */
		if (config == config_active && a->internal)
			goto err_int_noactive;
		/* Check for multiple values. */
		if (!force && !a->multi && strlist_find(processed, key))
			goto err_multi_forceable;
	} else {
		/* Handle unknown attribute. */
		if (!st->unknown_dev_attribs)
			goto err_unknown;
		if (!force)
			goto err_unknown_forceable;
		/* Check for internal. */
		if (config == config_active && internal_by_name(key))
			goto err_int_noactive;
	}

	strlist_add(processed, "%s", key);

	/* Apply to active config. */
	if (SCOPE_ACTIVE(config)) {
		s = setting_list_apply_specified(dev->active.settings, a,
						 key, value);
		if (s->readonly)
			warn_readonly = true;
	}

	/* Apply to persistent config. */
	if (SCOPE_PERSISTENT(config)) {
		setting_list_apply_specified(dev->persistent.settings,
					     a, key, value);
	}

	/* Apply to autoconf config. */
	if (SCOPE_AUTOCONF(config)) {
		setting_list_apply_specified(dev->autoconf.settings,
					     a, key, value);
	}

	/* Additional warning when trying to persist read-only setting. */
	if (!SCOPE_ACTIVE(config) && (SCOPE_PERSISTENT(config) ||
				      SCOPE_AUTOCONF(config))) {
		s = setting_list_find(dev->active.settings, key);
		if (s && s->readonly)
			warn_readonly = true;
	}

	if (warn_readonly)
		delayed_warn("Modifying read-only attribute: %s\n", key);

	return EXIT_OK;

err_invalid_forceable:
	delayed_forceable("Invalid value for %s attribute: %s=%s\n",
			  dev->subtype->name, key, value);
	delayed_info("Acceptable values:\n");
	attrib_print_acceptable(a, -1);
	delayed_info("Use '%s %s --help-attribute %s' for more "
		     "information\n", toolname, dev->subtype->name, key);
	return EXIT_INVALID_SETTING;

err_multi_forceable:
	delayed_forceable("Cannot specify multiple values for attribute '%s'\n",
			  key);
	return EXIT_INVALID_SETTING;

err_unknown:
	delayed_err("Unknown %s attribute specified: %s\n", st->devname, key);
	return EXIT_ATTRIB_NOT_FOUND;

err_unknown_forceable:
	delayed_forceable("Unknown %s attribute specified: %s\n",
			  st->devname, key);
	return EXIT_ATTRIB_NOT_FOUND;

err_activeonly_forceable:
	delayed_forceable("Attribute '%s' should only be changed in the active "
			  "config\n", a->name);
	return EXIT_INVALID_SETTING;

err_int_noactive:
	delayed_err("Internal attribute '%s' cannot be set in the active config\n",
		    key);
	return EXIT_INVALID_SETTING;

err_readonly:
	delayed_err("Cannot modify read-only attribute: %s\n", key);
	return EXIT_INVALID_SETTING;
}

/* Apply device settings from strlist to device. */
exit_code_t device_apply_strlist(struct device *dev, config_t config,
				 struct util_list *settings)
{
	struct util_list *processed;
	struct strlist_node *s;
	exit_code_t rc;
	char *key, *value;

	/* Apply settings. */
	processed = strlist_new();
	rc = EXIT_OK;
	util_list_iterate(settings, s) {
		key = misc_strdup(s->str);
		value = strchr(key, '=');
		*value = 0;
		value++;

		rc = apply_setting(dev, config, key, value, processed);
		free(key);

		if (rc)
			break;
	}

	strlist_free(processed);

	return rc;
}

/* Apply device settings from setting_list to device. */
exit_code_t device_apply_settings(struct device *dev, config_t config,
				  struct util_list *settings)
{
	struct util_list *processed;
	struct setting *s;
	exit_code_t rc;

	/* Apply settings. */
	processed = strlist_new();
	rc = EXIT_OK;
	util_list_iterate(settings, s) {
		rc = apply_setting(dev, config, s->name, s->value, processed);
		if (rc)
			break;
	}

	strlist_free(processed);

	return rc;
}

static void reset_device_state(struct device_state *state)
{
	setting_list_free(state->settings);
	state->settings = setting_list_new();
	state->exists = 0;
	state->modified = 0;
	state->deconfigured = 0;
	state->definable = 0;
	state->blacklisted = 0;
}

void device_reset(struct device *dev, config_t config)
{
	if (SCOPE_ACTIVE(config))
		reset_device_state(&dev->active);
	if (SCOPE_PERSISTENT(config))
		reset_device_state(&dev->persistent);
	if (SCOPE_AUTOCONF(config))
		reset_device_state(&dev->autoconf);
	dev->processed = 0;
}

void device_add_modules(struct util_list *modules, struct device *dev)
{
	struct subtype *st = dev->subtype;

	/* Add dynamic module info. */
	subtype_add_modules(st, dev, modules);

	/* Add static subtype module info. */
	subtype_add_static_modules(modules, st);

	/* Add static devtype module info. */
	devtype_add_modules(modules, st->devtype, 0);
}

char *device_read_active_attrib(struct device *dev, const char *name)
{
	struct subtype *st = dev->subtype;
	char *path, *value, *link;

	/* Try direct approach. */
	value = subtype_get_active_attrib(st, dev, name);
	if (value)
		return value;

	/* Try reading from path. */
	path = subtype_get_active_attrib_path(st, dev, name);
	if (!path)
		return NULL;
	value = misc_read_text_file(path, 1, err_ignore);
	if (!value) {
		/* Symbolic links count as read-only attributes. */
		link = misc_readlink(path);
		if (link) {
			value = misc_strdup(basename(link));
			free(link);
		}
	}
	free(path);

	return value;
}

/* Return a newly allocated strlist of attribute names for @dev based on
 * @scope. */
static struct util_list *get_attrib_names(struct device *dev,
					  read_scope_t scope)
{
	struct subtype *st = dev->subtype;
	struct util_list *names, *files;
	struct strlist_node *s;
	int i;
	struct attrib *a;
	const char *prefix;
	char *path;

	names = strlist_new();

	/* Start with known and mandatory attributes. */
	for (i = 0; (a = st->dev_attribs[i]); i++) {
		if (scope != scope_mandatory || a->mandatory)
			strlist_add(names, a->name);
	}
	if (scope != scope_all)
		goto out;

	/* Add attributes based on readable files in any of the prefix
	 * directories. */
	prefix = "";
	i = 0;
	do {
		path = subtype_get_active_attrib_path(st, dev, prefix);
		if (!path)
			continue;

		/* Add attribute name for each file in path. */
		files = strlist_new();
		misc_read_dir(path, files, NULL, NULL);
		util_list_iterate(files, s) {
			if (*prefix) {
				strlist_add_unique(names, "%s/%s", prefix,
						   s->str);
			} else
				strlist_add_unique(names, s->str);
		}
		strlist_free(files);

		free(path);
	} while (st->prefixes && (prefix = st->prefixes[i++]));

out:
	return names;
}

/* Read settings according to @scope for device @dev from active
 * configuration and add them to dev->active.settings. */
void device_read_active_settings(struct device *dev, read_scope_t scope)
{
	struct subtype *st = dev->subtype;
	struct util_list *names;
	struct strlist_node *str;
	char *path, *name, *value, *link;
	struct attrib *a;
	struct setting *s;

	/* Expand scope. */
	names = get_attrib_names(dev, scope);

	util_list_iterate(names, str) {
		name = str->str;

		/* Don't add uevent attribute. */
		if (strcmp(name, "uevent") == 0 || ends_with(name, "/uevent"))
			continue;

		/* Determine full attribute path. */
		path = subtype_get_active_attrib_path(st, dev, name);
		if (!path)
			continue;

		/* Get attribute value. */
		link = NULL;
		value = misc_read_text_file(path, 1, err_ignore);
		if (!value) {
			if (scope != scope_all)
				goto next;

			/* Register symbolic links as readonly attributes. */
			link = misc_readlink(path);
			if (!link)
				goto next;

			value = basename(link);
		}

		/* Apply setting to list. */
		a = attrib_find(st->dev_attribs, name);
		s = setting_list_apply_actual(dev->active.settings, a, name,
					      value);
		if ((a && a->readonly) || link || (scope == scope_all &&
			     util_path_is_readonly_file("%s", path)))
			s->readonly = 1;
		if (link)
			free(link);
		else
			free(value);
next:
		free(path);
	}

	strlist_free(names);
}

/* Apply modified settings in @dev->active.settings to active configuration.
 * Abort on first error. This requires that @dev defines
 * get_active_attrib_path. */
exit_code_t device_write_active_settings(struct device *dev)
{
	struct subtype *st = dev->subtype;
	struct util_list *list;
	struct ptrlist_node *p;
	struct setting *s;
	char *path;
	exit_code_t rc = EXIT_OK;

	/* Get order of applying attributes. */
	list = setting_list_get_sorted(dev->active.settings);

	/* Apply settings in order. */
	util_list_iterate(list, p) {
		s = p->ptr;
		if (!s->modified || s->removed)
			continue;
		if ((s->attrib && s->attrib->internal) ||
		    internal_by_name(s->name))
			continue;

		path = subtype_get_active_attrib_path(st, dev, s->name);
		if (!path) {
			delayed_err("Could not determine path for attribute "
				    "'%s'\n", s->name);
			rc = EXIT_SETTING_NOT_FOUND;
			break;
		}
		rc = setting_write(path, s);
		free(path);
		if (rc)
			break;
	}

	ptrlist_free(list, 0);

	/* Changing device configuration could generate uevents. */
	udev_need_settle = 1;

	return rc;
}

/* Check if there are any conflicts in the settings list of @dev for the
 * specified configuration. */
exit_code_t device_check_settings(struct device *dev, config_t config,
				  err_t err)
{
	struct setting *s;

	if (SCOPE_ACTIVE(config)) {
		/* Ensure that actual values are available or we might
		 * report false positives. */
		util_list_iterate(&dev->active.settings->list, s) {
			if (s->actual_value || s->removed ||
			    (!s->modified && !s->specified))
				continue;
			s->actual_value =
				device_read_active_attrib(dev, s->name);
		}

		if (!setting_list_check_conflict(dev->active.settings,
						 config_active,
						 err))
			return EXIT_INVALID_CONFIG;
	}
	if (SCOPE_PERSISTENT(config)) {
		if (!setting_list_check_conflict(dev->persistent.settings,
						 config_persistent,
						 err))
			return EXIT_INVALID_CONFIG;
	}
	if (SCOPE_AUTOCONF(config)) {
		if (!setting_list_check_conflict(dev->autoconf.settings,
						 config_autoconf,
						 err))
			return EXIT_INVALID_CONFIG;
	}

	return EXIT_OK;
}

struct setting_list *device_get_setting_list(struct device *dev,
					     config_t config)
{
	struct setting_list *settings = NULL;

	if (config == config_active)
		settings = dev->active.settings;
	else if (config == config_persistent)
		settings = dev->persistent.settings;
	else if (config == config_autoconf)
		settings = dev->autoconf.settings;

	return settings;
}

/* Return configuration set in which device exists. */
config_t device_get_config(struct device *dev)
{
	config_t config = 0;

	if (dev->active.exists || dev->active.definable)
		config |= config_active;

	if (dev->persistent.exists)
		config |= config_persistent;

	if (dev->autoconf.exists)
		config |= config_autoconf;

	return config;
}
