/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_path.h"

#include "attrib.h"
#include "ccwgroup.h"
#include "device.h"
#include "internal.h"
#include "misc.h"
#include "path.h"
#include "setting.h"
#include "udev.h"
#include "udev_ccwgroup.h"

static char *get_rule_path_by_devid(const char *type,
				    struct ccwgroup_devid *devid, bool autoconf)
{
	char *ccw_id, *path;

	ccw_id = ccw_devid_to_str(&devid->devid[0]);
	path = path_get_udev_rule(type, ccw_id, autoconf);
	free(ccw_id);

	return path;
}

static char *get_rule_path(const char *type, const char *id, bool autoconf)
{
	struct ccwgroup_devid devid;

	if (ccwgroup_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return NULL;

	return get_rule_path_by_devid(type, &devid, autoconf);
}

/* Check if a udev rule for the specified CCWGROUP device exists. */
bool udev_ccwgroup_exists(const char *type, const char *id, bool autoconf)
{
	char *path;
	bool rc;

	path = get_rule_path(type, id, autoconf);
	if (!path)
		return false;
	rc = util_path_is_reg_file(path);
	free(path);

	return rc;
}

static void add_setting_from_entry(struct setting_list *list,
				   struct udev_entry_node *entry,
				   struct attrib **attribs)
{
	char *copy, *name, *end;
	struct attrib *a;

	/* ENV{zdev_var}="1" */
	if (starts_with(entry->key, "ENV{zdev_") &&
	    strcmp(entry->op, "=") == 0) {
		udev_add_internal_from_entry(list, entry, attribs);
		return;
	}
	/* ATTR{[ccwgroup/0.0.f5f0]online}=1 */
	if (strncmp(entry->key, "ATTR{[ccwgroup/", 10) != 0 ||
	    strcmp(entry->op, "=") != 0)
		return;
	copy = misc_strdup(entry->key);
	name = copy;

	/* Find attribute name start. */
	name = strchr(entry->key, ']');
	end = strrchr(entry->key, '}');
	if (!name || !end)
		goto out;
	*end = 0;
	name++;

	a = attrib_find(attribs, name);
	setting_list_apply_actual(list, a, name, entry->value);

out:
	free(copy);
}

/* Extract CCWGROUP device settings from a CCWGROUP device udev rule file. */
static void udev_file_get_settings(struct udev_file *file,
				   struct attrib **attribs,
				   struct setting_list *list)
{
	struct udev_line_node *line;
	struct udev_entry_node *entry;

	util_list_iterate(&file->lines, line) {
		entry = util_list_start(&line->entries);
		if (!entry)
			continue;
		add_setting_from_entry(list, entry, attribs);
	}
}

/* Determine full CCWGROUP from data in udev rule file. */
static void expand_id(struct device *dev, struct udev_file *file)
{
	struct ccwgroup_devid devid;
	struct ccwgroup_devid *devid_ptr = dev->devid;
	struct udev_line_node *line;
	struct udev_entry_node *entry;
	char *id;
	int i;

	if (devid_ptr->num != 1)
		return;

	util_list_iterate(&file->lines, line) {
		entry = util_list_start(&line->entries);
		if (!entry)
			continue;
		if (!starts_with(entry->key, "ATTR{[drivers/ccwgroup:") ||
		    !ends_with(entry->key, "]group}"))
			continue;
		/* Extract CCWGROUP ID from comma-separated list of CCW
		 * device IDs. */
		id = misc_strdup(entry->value);
		for (i = 0; id[i]; i++) {
			if (id[i] == ',')
				id[i] = ':';
		}
		if (ccwgroup_parse_devid(&devid, id, err_ignore) == EXIT_OK)
			*devid_ptr = devid;
		free(dev->id);
		dev->id = ccwgroup_devid_to_str(&devid);
		free(id);
		break;
	}
}

/* Read the persistent configuration of a CCWGROUP device from a udev rule. */
exit_code_t udev_ccwgroup_read_device(struct device *dev, bool autoconf)
{
	struct subtype *st = dev->subtype;
	struct device_state *state = autoconf ? &dev->autoconf :
						&dev->persistent;
	struct udev_file *file = NULL;
	exit_code_t rc;
	char *path;

	path = get_rule_path_by_devid(st->name, dev->devid, autoconf);
	rc = udev_read_file(path, &file);
	if (rc)
		goto out;
	if (udev_file_is_empty(file)) {
		warn_once("Warning: Invalid udev rule: %s\n", path);
		state->exists = 0;
	} else {
		udev_file_get_settings(file, st->dev_attribs, state->settings);
		expand_id(dev, file);
		state->exists = 1;
	}
	udev_free_file(file);

out:
	free(path);

	return rc;
}

/* Return an ID suitable for use as udev label. */
static char *get_label_id(const char *prefix, const char *type,
			  const char *dev_id)
{
	char *id;
	int i;

	id = misc_asprintf("%s_%s_%s", prefix, type, dev_id);
	for (i = 0; id[i]; i++) {
		if (isalnum(id[i]) || id[i] == '_' || id[i] == '.')
			continue;
		id[i] = '_';
	}

	return id;
}

/* Write the persistent configuration of a CCWGROUP device to a udev rule. */
exit_code_t udev_ccwgroup_write_device(struct device *dev, bool autoconf)
{
	struct subtype *st = dev->subtype;
	struct device_state *state = autoconf ? &dev->autoconf :
						&dev->persistent;
	struct ccwgroup_subtype_data *data = st->data;
	const char *type = st->name, *drv = data->ccwgroupdrv, *id = dev->id;
	struct ccwgroup_devid devid;
	char *path, *cfg_label = NULL, *group_label = NULL, *end_label = NULL,
	     *ccw_id, *chan_id;
	struct util_list *list;
	struct ptrlist_node *p;
	struct setting *s;
	struct strlist_node *str;
	exit_code_t rc = EXIT_OK;
	FILE *fd;
	unsigned int i;

	if (!state->exists)
		return udev_ccwgroup_remove_rule(type, id, autoconf);

	if (ccwgroup_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return EXIT_INVALID_ID;

	ccw_id = ccw_devid_to_str(&devid.devid[0]);
	path = get_rule_path(type, ccw_id, autoconf);

	group_label = get_label_id("group", type, ccw_id);
	cfg_label = get_label_id("cfg", type, ccw_id);
	end_label = get_label_id("end", type, ccw_id);

	/* Apply attributes in correct order. */
	list = setting_list_get_sorted(state->settings);

	debug("Writing %s udev rule file %s\n", type, path);
	if (!util_path_exists(path)) {
		rc = path_create(path);
		if (rc)
			goto out;
	}

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
	fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"drivers\", "
		"KERNEL==\"%s\", GOTO=\"%s\"\n", drv, group_label);
	for (i = 0; i < devid.num; i++) {
		chan_id = ccw_devid_to_str(&devid.devid[i]);
		fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"ccw\", "
			"KERNEL==\"%s\", DRIVER==\"%s\", "
			"GOTO=\"%s\"\n", chan_id, drv, group_label);
		free(chan_id);
	}
	fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"ccwgroup\", "
		"KERNEL==\"%s\", DRIVER==\"%s\", GOTO=\"%s\"\n", ccw_id,
		drv, cfg_label);
	fprintf(fd, "GOTO=\"%s\"\n\n", end_label);

	/* Group. */
	fprintf(fd, "LABEL=\"%s\"\n", group_label);
	fprintf(fd, "TEST==\"[ccwgroup/%s]\", GOTO=\"%s\"\n", ccw_id,
		end_label);
	for (i = 0; i < devid.num; i++) {
		chan_id = ccw_devid_to_str(&devid.devid[i]);
		fprintf(fd, "TEST!=\"[ccw/%s]\", GOTO=\"%s\"\n", chan_id,
			end_label);
		free(chan_id);
	}
	fprintf(fd, "ATTR{[drivers/ccwgroup:%s]group}=\"", drv);
	for (i = 0; i < devid.num; i++) {
		chan_id = ccw_devid_to_str(&devid.devid[i]);
		fprintf(fd, "%s%s", i > 0 ? "," : "", chan_id);
		free(chan_id);
	}
	fprintf(fd, "\"\n");
	fprintf(fd, "GOTO=\"%s\"\n\n", end_label);

	/* Configure. */
	fprintf(fd, "LABEL=\"%s\"\n", cfg_label);
	util_list_iterate(list, p) {
		s = p->ptr;
		if (s->removed)
			continue;
		if (s->values) {
			util_list_iterate(s->values, str) {
				fprintf(fd, "ATTR{[ccwgroup/%s]%s}=\"%s\"\n",
					ccw_id, s->name, str->str);
			}
		} else if ((s->attrib && s->attrib->internal) ||
			   internal_by_name(s->name)) {
			fprintf(fd, "ENV{zdev_%s}=\"%s\"\n",
				internal_get_name(s->name), s->value);
		} else {
			fprintf(fd, "ATTR{[ccwgroup/%s]%s}=\"%s\"\n", ccw_id,
				s->name, s->value);
		}
	}

	/* Write udev rule epilog. */
	fprintf(fd, "\n");
	fprintf(fd, "LABEL=\"%s\"\n", end_label);

	if (misc_fclose(fd))
		warn("Could not close file %s: %s\n", path, strerror(errno));

out:
	ptrlist_free(list, 0);
	free(end_label);
	free(cfg_label);
	free(group_label);
	free(path);
	free(ccw_id);

	return rc;
}

static char *read_full_id(const char *path)
{
	char *text, *start, *end, *id = NULL;

	text = misc_read_text_file(path, 0, err_ignore);
	if (!text)
		return NULL;
	start = strstr(text, "ATTR{[drivers/ccwgroup:");
	if (!start)
		goto out;
	start = strchr(start, '"');
	if (!start)
		goto out;
	start++;
	end = strchr(start, '"');
	if (!end)
		goto out;
	*end = 0;
	id = misc_strdup(start);

	start = id;
	while ((start = strchr(start, ',')))
		*start = ':';

out:
	free(text);

	if (!id)
		warn_once("Warning: Invalid udev rule: %s\n", path);

	return id;
}

struct get_ids_cb_data {
	char *prefix;
	struct util_list *ids;
};

static exit_code_t get_ids_cb(const char *path, const char *filename,
			      void *data)
{
	struct get_ids_cb_data *cb_data = data;
	char *id;

	if (!starts_with(filename, cb_data->prefix))
		return EXIT_OK;
	id = read_full_id(path);
	if (!id)
		return EXIT_OK;
	strlist_add(cb_data->ids, id);
	free(id);

	return EXIT_OK;
}

/* Add the IDs for all devices of the specified subtype name for which a
 * udev rule exists to strlist LIST. */
void udev_ccwgroup_add_device_ids(const char *type, struct util_list *list,
				  bool autoconf)
{
	struct get_ids_cb_data cb_data;
	char *path;

	path = path_get_udev_rules(autoconf);
	cb_data.prefix = misc_asprintf("%s-%s-", UDEV_PREFIX, type);
	cb_data.ids = list;

	if (util_path_is_dir(path))
		path_for_each(path, get_ids_cb, &cb_data);

	free(cb_data.prefix);
	free(path);
}

/* Remove UDEV rule for CCWGROUP device. */
exit_code_t udev_ccwgroup_remove_rule(const char *type, const char *id,
				      bool autoconf)
{
	char *partial_id, *path;
	exit_code_t rc = EXIT_OK;

	partial_id = ccwgroup_get_partial_id(id);
	if (!partial_id)
		return EXIT_INVALID_ID;

	path = path_get_udev_rule(type, partial_id, autoconf);
	if (util_path_is_reg_file(path))
		rc = remove_file(path);
	free(path);
	free(partial_id);

	return rc;
}
