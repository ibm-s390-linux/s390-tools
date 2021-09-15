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
#include <strings.h>

#include "attrib.h"
#include "ctc.h"
#include "dasd.h"
#include "device.h"
#include "devnode.h"
#include "devtype.h"
#include "generic_ccw.h"
#include "lcs.h"
#include "misc.h"
#include "module.h"
#include "namespace.h"
#include "qeth.h"
#include "select.h"
#include "setting.h"
#include "subtype.h"
#include "zfcp.h"
#include "ap.h"

/* Array of pointers to known device types. */
struct devtype *devtypes[] = {
	&dasd_devtype,
	&zfcp_devtype,
	&qeth_devtype,
	&ctc_devtype,
	&lcs_devtype,
	&ap_devtype,
	&generic_ccw_devtype,	/* Generic types should come last. */
	NULL
};

/* Call the init() function of each registered devtype and subtype. */
void devtypes_init(void)
{
	struct devtype *dt;
	struct subtype *st;
	int i, j;

	for (i = 0; (dt = devtypes[i]); i++) {
		if (dt->init)
			dt->init(dt);
		for (j = 0; (st = dt->subtypes[j]); j++)
			subtype_init(st);
	}
}

/* Call the exit() function of each registered devtype and subtype. */
void devtypes_exit(void)
{
	struct devtype *dt;
	struct subtype *st;
	int i, j;

	for (i = 0; (dt = devtypes[i]); i++) {
		if (dt->exit)
			dt->exit(dt);
		for (j = 0; (st = dt->subtypes[j]); j++)
			subtype_exit(st);
	}
}

/* Return struct devtype associated with NAME or NULL if type could not
 * be found. */
struct devtype *devtype_find(const char *name)
{
	int i;
	struct devtype *dt;

	for (i = 0; (dt = devtypes[i]); i++) {
		if (strcasecmp(dt->name, name) == 0)
			return dt;
	}

	return NULL;
}

/* Search for a device type attribute named STR. */
struct attrib *devtype_find_type_attrib(struct devtype *devtype,
					const char *str)
{
	struct attrib *a;
	int i;

	for (i = 0; (a = devtype->type_attribs[i]); i++) {
		if (strcmp(str, a->name) == 0)
			return a;
	}
	return NULL;
}

/* Search for a device attribute named STR in any subtype of DT. */
struct attrib *devtype_find_dev_attrib(struct devtype *dt, const char *str)
{
	struct attrib *a;
	struct subtype *st;
	int i, j;

	for (i = 0; (st = dt->subtypes[i]); i++) {
		for (j = 0; (a = st->dev_attribs[j]); j++) {
			if (strcmp(str, a->name) == 0)
				return a;
		}
	}
	return NULL;
}

/* Apply device type settings string list to settings list. */
static exit_code_t apply_setting(struct devtype *dt, config_t config,
				 const char *key, const char *value,
				 struct util_list *processed)
{
	struct attrib *a;

	/* Check for known attribute. */
	a = devtype_find_type_attrib(dt, key);
	if (a) {
		/* Check for acceptable value of known attribute. */
		if (!force && !attrib_check_value(a, value))
			goto err_invalid_forceable;
		/* Check for activeonly. */
		if (!force && SCOPE_PERSISTENT(config) && a->activeonly)
			goto err_activeonly_forceable;
		/* Check for multiple values. */
		if (!force && !a->multi && strlist_find(processed, key))
			goto err_multi_forceable;
	} else {
		/* Handle unknown attribute. */
		if (!dt->unknown_type_attribs)
			goto err_unknown;
		if (!force)
			goto err_unknown_forceable;
	}

	strlist_add(processed, "%s", key);

	/* Apply to active config. */
	if (SCOPE_ACTIVE(config)) {
		setting_list_apply_specified(dt->active_settings, a, key,
					     value);
	}

	/* Apply to persistent config. */
	if (SCOPE_PERSISTENT(config)) {
		setting_list_apply_specified(dt->persistent_settings, a, key,
					     value);
	}

	return EXIT_OK;

err_invalid_forceable:
	delayed_forceable("Invalid value for attribute '%s': %s\n", key, value);
	return EXIT_INVALID_SETTING;

err_multi_forceable:
	delayed_forceable("Cannot specify multiple values for attribute '%s'\n",
			  key);
	return EXIT_INVALID_SETTING;

err_unknown:
	delayed_err("Unknown device type attribute specified: %s\n", key);
	return EXIT_ATTRIB_NOT_FOUND;

err_unknown_forceable:
	delayed_forceable("Unknown device type attribute specified: %s\n", key);
	return EXIT_ATTRIB_NOT_FOUND;

err_activeonly_forceable:
	delayed_forceable("Device type attribute should only be changed in the "
			  "active configuration: %s\n", a->name);
	return EXIT_INVALID_SETTING;
}

/* Apply device type settings from strlist to devtype. */
exit_code_t devtype_apply_strlist(struct devtype *dt, config_t config,
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

		rc = apply_setting(dt, config, key, value, processed);
		free(key);

		if (rc)
			break;
	}

	strlist_free(processed);

	return rc;
}

/* Apply device type settings from setting_list to devtype. */
exit_code_t devtype_apply_settings(struct devtype *dt, config_t config,
				   struct util_list *settings)
{
	struct util_list *processed;
	struct setting *s;
	exit_code_t rc;

	/* Apply settings. */
	processed = strlist_new();
	rc = EXIT_OK;
	util_list_iterate(settings, s) {
		rc = apply_setting(dt, config, s->name, s->value, processed);
		if (rc)
			break;
	}

	strlist_free(processed);

	return rc;
}

/* Check if a device ID is valid for a subtype of the specified devtype. */
bool devtype_is_id_valid(struct devtype *dt, const char *id)
{
	int i;
	struct subtype *st;

	for (i = 0; (st = dt->subtypes[i]); i++) {
		if (ns_is_id_valid(st->namespace, id))
			return true;
	}

	return false;
}

/* Check if a device ID range is valid for a subtype of the specified
 * devtype. */
bool devtype_is_id_range_valid(struct devtype *dt, const char *id)
{
	int i;
	struct subtype *st;

	for (i = 0; (st = dt->subtypes[i]); i++) {
		if (st->namespace->is_id_range_valid(id, err_ignore) == EXIT_OK)
			return true;
	}

	return false;
}

/* Check if a device type configuration needs to be written. */
bool devtype_needs_writing(struct devtype *dt, config_t config)
{
	if (SCOPE_ACTIVE(config) && dt->active_settings &&
	    setting_list_modified(dt->active_settings))
		return true;
	if (SCOPE_PERSISTENT(config) && dt->persistent_settings &&
	    setting_list_modified(dt->persistent_settings))
		return true;

	return false;
}

void devtype_print(struct devtype *dt, int indent)
{
	int i;
	struct subtype *st;

	printf("%*sdevtype at %p\n", indent, "", (void *) dt);
	if (!dt)
		return;
	indent += 2;
	printf("%*sname=%s proc=%d\n", indent, "", dt->name, dt->processed);
	printf("%*sactive_settings exists=%d:\n", indent, "",
	       dt->active_exists);
	setting_list_print(dt->active_settings, indent + 2);
	printf("%*spersistent_settings exists=%d:\n", indent, "",
	       dt->persistent_exists);
	setting_list_print(dt->persistent_settings, indent + 2);
	printf("%*ssubtypes:\n", indent, "");
	for (i = 0; (st = dt->subtypes[i]); i++)
		subtype_print(st, indent + 2);
}

/* Add name of all modules required by devtype @dt to strlist @modules.
 * If @subtypes is set, also add modules required by all subtypes. */
void devtype_add_modules(struct util_list *modules, struct devtype *dt,
			 int subtypes)
{
	const char **mod = dt->modules;
	int i;
	struct subtype *st;

	if (!mod)
		goto out;

	for (i = 0; mod[i]; i++)
		strlist_add_unique(modules, "%s", mod[i]);

out:
	if (subtypes) {
		for (i = 0; (st = dt->subtypes[i]); i++)
			subtype_add_static_modules(modules, st);
	}
}

/* Check if any of the kernel modules used by devtype @dt is loaded. */
bool devtype_is_module_loaded(struct devtype *dt)
{
	struct util_list *modules;
	struct strlist_node *s;
	bool result = false;

	modules = strlist_new();
	devtype_add_modules(modules, dt, 1);
	util_list_iterate(modules, s) {
		if (module_loaded(s->str)) {
			result = true;
			break;
		}
	}
	strlist_free(modules);

	return result;
}

/* Return the number of different namespaces found in subtypes of @dt. */
int devtype_count_namespaces(struct devtype *dt)
{
	int found[NUM_NAMESPACES];
	int i, j, num;
	struct subtype *st;

	/* Reset array. */
	for (i = 0; i < NUM_NAMESPACES; i++)
		found[i] = 0;

	/* Set array entries for namespaces found. */
	for (i = 0; (st = dt->subtypes[i]); i++) {
		j = namespaces_index(st->namespace);
		if (j < 0)
			continue;
		found[j] = 1;
	}

	/* Count namespaces. */
	num = 0;
	for (i = 0; i < NUM_NAMESPACES; i++) {
		if (found[i])
			num++;
	}

	return num;
}

/* Return the number of subtypes defined for devtype @dt. */
int devtype_count_subtypes(struct devtype *dt)
{
	int i;

	for (i = 0; dt->subtypes[i]; i++) ;

	return i;
}

/* Try to find namespace in which @ID is could be an ID. Return %NULL if no
 * namespace or more than one namespace was found. */
struct namespace *devtype_most_similar_namespace(struct devtype *only_dt,
						 struct subtype *only_st,
						 const char *id)
{
	struct namespace *match = NULL;
	struct devtype *dt;
	struct subtype *st;
	int i, j;

	for (i = 0; (dt = devtypes[i]); i++) {
		if (only_dt && dt != only_dt)
			continue;
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (only_st && st != only_st)
				continue;

			if (ns_is_id_valid(st->namespace, id))
				goto found;
			if (!st->namespace->is_id_similar ||
			    !st->namespace->is_id_similar(id))
				continue;
found:
			if (match && match != st->namespace) {
				/* Multiple matches. */
				return NULL;
			}
			match = st->namespace;
		}
	}

	return match;
}
