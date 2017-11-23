/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "lib/util_path.h"

#include "attrib.h"
#include "misc.h"
#include "module.h"
#include "path.h"
#include "setting.h"
#include "udev.h"

static struct util_list *tried_loading;
static int suppress_module_load;

/* Allow suppression of module loading. */
void module_load_suppress(int state)
{
	suppress_module_load = 1;
}

/* Check if a module is currently loaded. */
bool module_loaded(const char *mod)
{
	char *path = path_get_sys_module(mod);
	bool rc;

	rc = util_path_is_dir(path);
	free(path);

	return rc;
}

static int module_get_refcnt(const char *mod)
{
	char *path, *refcnt_path, *text;
	int refcnt = 0;

	path = path_get_sys_module(mod);
	refcnt_path = misc_asprintf("%s/refcnt", path);
	text = misc_read_text_file(refcnt_path, 1, err_delayed_print);
	if (text)
		refcnt = atoi(text);
	free(refcnt_path);
	free(path);

	return refcnt;
}

/* Attempt to unload specified kernel module. */
static exit_code_t module_unload(const char *mod, err_t err)
{
	char *mp;
	int rc;

	if (!dryrun && module_get_refcnt(mod) > 0) {
		err_t_print(err, "Cannot unload module %s: Module is in use\n",
			    mod);
		return EXIT_MOD_BUSY;
	}

	mp = path_get_modprobe();
	rc = misc_system(err, "%s -r %s", mp, mod);
	free(mp);
	if (rc != 0)
		return EXIT_MOD_UNLOAD_FAILED;

	return EXIT_OK;
}

/* Attempt to load kernel module with specified parameters. PARAMS may be
 * NULL to load the module with default parameters. */
static exit_code_t do_load(const char *mod, char *params, err_t err)
{
	char *empty_file;
	char *mp;
	exit_code_t rc;

	rc = EXIT_OK;
	mp = path_get_modprobe();
	if (params) {
		/* Note: We need to pass an empty configuration file to
		 * modprobe or the persistent parameters in /etc/modprobe.d
		 * would always overwrite the specified parameters. */
		rc = misc_mktemp(&empty_file, NULL);
		if (rc)
			goto out;
		if (misc_system(err, "%s %s %s -C %s %s", mp, mod, params,
				empty_file,
				err == err_ignore ? " 2>/dev/null" : ""))
			rc = EXIT_MOD_LOAD_FAILED;
		remove_file(empty_file);
		free(empty_file);
	} else {
		if (misc_system(err, "%s %s %s", mp, mod,
				err == err_ignore ? " 2>/dev/null" : ""))
			rc = EXIT_MOD_LOAD_FAILED;
	}

out:
	free(mp);

	return rc;
}

/* Apply kernel module parameters. */
exit_code_t module_load(const char *mod, const char **deps,
			struct setting_list *settings, err_t err)
{
	char *params;
	struct util_list *unloaded = NULL;
	struct strlist_node *s;
	exit_code_t rc;
	int i;

	if (suppress_module_load)
		return EXIT_OK;

	/* Unload modules depending on mod. */
	if (deps) {
		unloaded = strlist_new();
		for (i = 0; deps[i]; i++) {
			if (!module_loaded(deps[i]) && !dryrun)
				continue;
			rc = module_unload(deps[i], err);
			if (rc)
				goto out;
			strlist_add(unloaded, "%s", deps[i]);
		}
	}

	if (module_loaded(mod) || dryrun) {
		rc = module_unload(mod, err);
		if (rc)
			goto out;
	}

	params = settings ? setting_list_flatten(settings) : NULL;
	rc = do_load(mod, params, err);
	free(params);

	if (rc == EXIT_OK && unloaded) {
		/* Re-load modules depending on mod. */
		util_list_iterate(unloaded, s) {
			rc = do_load(s->str, "", err);
			if (rc)
				break;
		}
	}
out:
	strlist_free(unloaded);

	return rc;
}

struct add_setting_data {
	struct setting_list *list;
	struct attrib **attribs;
};

/* Add all attribute values to settings list. */
static exit_code_t add_setting(const char *path, const char *name, void *data)
{
	struct add_setting_data *sdata = data;
	struct setting_list *list = sdata->list;
	struct attrib **attribs = sdata->attribs;
	struct attrib *a;
	char *value;

	value = misc_read_text_file(path, 1, err_print);
	if (!value)
		return EXIT_RUNTIME_ERROR;
	if (strcmp(value, "(null)") == 0)
		goto out;
	a = attrib_find(attribs, name);
	setting_list_apply_actual(list, a, name, value);
out:
	free(value);

	return EXIT_OK;
}

/* Retrieve currently active module parameters. */
exit_code_t module_get_params(const char *mod, struct attrib **attribs,
			      struct setting_list **settings)
{
	struct add_setting_data data;
	struct setting_list *list = NULL;
	char *path;
	exit_code_t rc = EXIT_OK;

	if (!module_loaded(mod))
		goto out;
	list = setting_list_new();

	path = path_get_sys_module_param(mod, NULL);
	data.list = list;
	data.attribs = attribs;
	rc = path_for_each(path, add_setting, &data);
	free(path);

out:
	if (rc == EXIT_OK)
		*settings = list;
	else
		setting_list_free(list);

	return rc;
}

/* Try to load a kernel module once. If @path is not %NULL, don't try loading
 * the module if @path exists. */
void module_try_load_once(const char *mod, const char *path)
{
	if (suppress_module_load)
		return;
	if (tried_loading) {
		if (strlist_find(tried_loading, mod))
			return;
	} else
		tried_loading = strlist_new();
	strlist_add(tried_loading, mod);
	if (path && util_path_exists(path))
		return;
	if (module_loaded(mod))
		return;

	verb("Loading required kernel module: %s\n", mod);
	if (module_load(mod, NULL, NULL, err_ignore))
		verb("Failed to load kernel module: %s\n", mod);
	else {
		/* Let udev rules apply. */
		udev_settle();
	}
}

/* Release any global memory. */
void module_exit(void)
{
	strlist_free(tried_loading);
}

/* Apply module parameters for kernel module @mod found in @settings via
 * /sys/module/../parameters. Return %true if all modified settings
 * could be set via this method. */
bool module_set_params(const char *mod, struct setting_list *settings)
{
	struct setting *s;
	char *path;
	const char *value;
	bool result;
	exit_code_t rc;

	/* First check if all modified settings can be applied this way. */
	util_list_iterate(&settings->list, s) {
		if (!s->modified && !s->removed) {
			/* Nothing to do. */
			continue;
		}
		if (!s->attrib || !s->attrib->nounload) {
			/* Attribute does not support setting via Sysfs. */
			return false;
		}
		if (s->removed && !s->attrib->defval) {
			/* Cannot remove setting with no default value. */
			return false;
		}
		path = path_get_sys_module_param(mod, s->name);
		result = util_path_is_writable(path);
		free(path);
		if (!result) {
			/* Sysfs file is not writable. */
			return false;
		}
	}

	/* Apply settings. */
	util_list_iterate(&settings->list, s) {
		if (s->removed)
			value = s->attrib->defval;
		else if (s->modified)
			value = s->value;
		else {
			/* Nothing to do. */
			continue;
		}

		path = path_get_sys_module_param(mod, s->name);
		rc = misc_write_text_file(path, value, err_ignore);
		free(path);
		if (rc)
			return false;
	}

	return true;
}
