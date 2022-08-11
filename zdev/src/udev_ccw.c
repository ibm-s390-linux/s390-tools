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
#include "lib/util_udev.h"

#include "attrib.h"
#include "ccw.h"
#include "device.h"
#include "internal.h"
#include "misc.h"
#include "path.h"
#include "setting.h"
#include "udev.h"
#include "udev_ccw.h"

#define SITE_FALLBACK_SUFFIX	"fb"

/* Check if a udev rule for the specified ccw device exists. */
bool udev_ccw_exists(const char *type, const char *id, bool autoconf)
{
	char *path, *normid;
	bool rc;

	normid = ccw_normalize_id(id);
	if (!normid)
		return false;

	path = path_get_udev_rule(type, normid, autoconf);
	rc = util_path_is_reg_file(path);
	free(path);
	free(normid);

	return rc;
}

static void add_setting_from_entry(struct setting_list *list,
				   struct util_udev_entry_node *entry,
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
	/* ATTR{[ccw/0.0.37bf]online}=1 */
	if (strncmp(entry->key, "ATTR{[ccw/", 10) != 0 ||
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

static void get_site_from_line(char *line, int *site, bool *in_site)
{
	char site_str[2];

	if (starts_with(line, SITE_BLOCK_START)) {
		memcpy(site_str, line + sizeof(SITE_BLOCK_START), 2);
		if (strcmp(site_str, "fb") != 0)
			*site = atoi(site_str);
		else
			*site = SITE_FALLBACK;
		*in_site = true;
	} else if (starts_with(line, SITE_BLOCK_END)) {
		memcpy(site_str, line + sizeof(SITE_BLOCK_END), 2);
		if (strcmp(site_str, "fb") != 0)
			*site = atoi(site_str);
		else
			*site = SITE_FALLBACK;
		*in_site = false;
	}
}

static void dev_state_copy(struct device_state *dst, struct device_state *src)
{
	setting_list_free(dst->settings);
	dst->settings = setting_list_copy(src->settings);
	dst->exists = src->exists;
	dst->modified = src->modified;
	dst->deconfigured = src->deconfigured;
	dst->blacklisted = src->blacklisted;
	dst->definable = src->definable;
}

/* Extract per-site CCW device settings from a CCW device udev rule file. */
static void _udev_file_get_settings_new(struct util_udev_file *file,
					struct attrib **attribs,
					struct device *dev)
{
	struct util_udev_line_node *line;
	struct util_udev_entry_node *entry;
	int site_id = SITE_FALLBACK;
	struct setting_list *list;
	bool in_site = false;

	util_list_iterate(&file->lines, line) {
		get_site_from_line(line->line, &site_id, &in_site);
		if (!in_site || site_id >= NUM_SITES || site_id < 0)
			continue;
		entry = util_list_start(&line->entries);
		if (!entry)
			continue;
		list = dev->site_specific[site_id].settings;
		add_setting_from_entry(list, entry, attribs);
		dev->site_specific[site_id].exists = 1;
		if (site_id == global_site_id)
			dev_state_copy(&dev->persistent, &dev->site_specific[site_id]);
	}
}

/* Extract CCW device settings from a CCW device udev rule file. */
static void _udev_file_get_settings_legacy(struct util_udev_file *file,
					   struct attrib **attribs,
					   struct setting_list *list)
{
	struct util_udev_line_node *line;
	struct util_udev_entry_node *entry;

	util_list_iterate(&file->lines, line) {
		entry = util_list_start(&line->entries);
		if (!entry)
			continue;
		add_setting_from_entry(list, entry, attribs);
	}
}

static void udev_file_get_settings(struct util_udev_file *file,
				   struct attrib **attribs,
				   struct device *dev,
				   bool autoconf)
{
	struct device_state *state = autoconf ? &dev->autoconf :
		&dev->persistent;

	if (is_legacy_rule(file) || autoconf) {
		_udev_file_get_settings_legacy(file, attribs, state->settings);
		state->exists = 1;
	} else {
		_udev_file_get_settings_new(file, attribs, dev);
	}
}

/* Read the persistent configuration of a CCW device from a udev rule. */
exit_code_t udev_ccw_read_device(struct device *dev, bool autoconf)
{
	struct subtype *st = dev->subtype;
	struct device_state *state = autoconf ? &dev->autoconf :
						&dev->persistent;
	struct util_udev_file *file = NULL;
	exit_code_t rc;
	char *path;

	path = path_get_udev_rule(st->name, dev->id, autoconf);
	rc = (exit_code_t) util_udev_read_file(path, &file);
	if (rc)
		goto out;
	if (udev_file_is_empty(file)) {
		warn_once("Warning: Invalid udev rule: %s\n", path);
		state->exists = 0;
	} else {
		udev_file_get_settings(file, st->dev_attribs, dev, autoconf);
	}
	util_udev_free_file(file);

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

static void write_attr_to_file(FILE *fd, struct device_state *state, const char *id)
{
	struct ptrlist_node *p;
	struct setting *s;
	struct util_list *list = NULL;
	struct strlist_node *str;

	/* Apply attributes in correct order. */
	list = setting_list_get_sorted(state->settings);

	util_list_iterate(list, p) {
		s = p->ptr;
		if (s->removed)
			continue;
		if (s->values) {
			util_list_iterate(s->values, str) {
				fprintf(fd, "ATTR{[ccw/%s]%s}=\"%s\"\n",
					id, s->name, str->str);
			}
		} else if ((s->attrib && s->attrib->internal) ||
			   internal_by_name(s->name)) {
			fprintf(fd, "ENV{zdev_%s}=\"%s\"\n",
				internal_get_name(s->name), s->value);
		} else {
			fprintf(fd, "ATTR{[ccw/%s]%s}=\"%s\"\n", id, s->name,
				s->value);
		}
	}
	ptrlist_free(list, 0);
}

static exit_code_t udev_ccw_write_device_legacy(struct device *dev, bool autoconf)
{
	struct subtype *st = dev->subtype;
	struct ccw_subtype_data *data = st->data;
	const char *type = st->name, *drv = data->any_driver ? "*" : data->ccwdrv, *id = dev->id;
	struct device_state *state = autoconf ? &dev->autoconf :
						&dev->persistent;
	char *path, *cfg_label = NULL, *end_label = NULL;
	exit_code_t rc = EXIT_OK;
	FILE *fd;

	if (!state->exists)
		return udev_remove_rule(type, id, true);

	cfg_label = get_label_id("cfg", type, id);
	end_label = get_label_id("end", type, id);

	path = path_get_udev_rule(type, id, true);
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
	if (drv) {
		fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"ccw\", "
			"KERNEL==\"%s\", DRIVER==\"%s\", GOTO=\"%s\"\n", id,
			drv, cfg_label);
		fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"drivers\", "
			"KERNEL==\"%s\", TEST==\"[ccw/%s]\", "
			"GOTO=\"%s\"\n", drv, id, cfg_label);
	} else {
		fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"ccw\", "
			"KERNEL==\"%s\", GOTO=\"%s\"\n", id, cfg_label);
	}
	fprintf(fd, "GOTO=\"%s\"\n", end_label);
	fprintf(fd, "\n");

	write_attr_to_file(fd, state, id);

	/* Write udev rule epilog. */
	fprintf(fd, "\n");
	fprintf(fd, "LABEL=\"%s\"\n", end_label);

	if (misc_fclose(fd))
		warn("Could not close file %s: %s\n", path, strerror(errno));

out:
	free(end_label);
	free(cfg_label);
	free(path);

	return rc;
}

/* Write the persistent configuration of a CCW device to a udev rule. */
static exit_code_t udev_ccw_write_device_new(struct device *dev)
{
	struct subtype *st = dev->subtype;
	struct ccw_subtype_data *data = st->data;
	const char *type = st->name, *drv = data->any_driver ? "*" : data->ccwdrv, *id = dev->id;
	char *path, *cfg_label = NULL, *end_label = NULL;
	exit_code_t rc = EXIT_OK;
	FILE *fd;
	int i, configured = 0;

	/*
	 * Remove the previous file; The new udev rule will be created based on the
	 * current configuration settings
	 */
	udev_remove_rule(type, id, 0);

	/*
	 * Copy the dev->persistent to the site_specific array; While writing the new
	 * udev-rule we consider the site_specific array only
	 */

	dev_state_copy(&dev->site_specific[global_site_id], &dev->persistent);
	for (i = 0; i < NUM_SITES; i++) {
		configured += dev->site_specific[i].exists;
		configured -= dev->site_specific[i].deconfigured;
	}

	/*
	 * If there is no configuration settings available, do not create the new
	 * udev-rule file; exit here
	 */
	if (!configured)
		return rc;

	cfg_label = get_label_id("cfg", type, id);
	end_label = get_label_id("end", type, id);

	path = path_get_udev_rule(type, id, false);
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

	if (drv) {
		fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"ccw\", "
			"KERNEL==\"%s\", DRIVER==\"%s\", GOTO=\"%s\"\n", id,
			drv, cfg_label);
		fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"drivers\", "
			"KERNEL==\"%s\", TEST==\"[ccw/%s]\", "
			"GOTO=\"%s\"\n", drv, id, cfg_label);
	} else {
		fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"ccw\", "
			"KERNEL==\"%s\", GOTO=\"%s\"\n", id, cfg_label);
	}
	fprintf(fd, "GOTO=\"%s\"\n", end_label);
	fprintf(fd, "\n");

	fprintf(fd, "LABEL=\"%s\"\n", cfg_label);
	/* site comparison block */
	for (i = 0; i < NUM_USER_SITES; i++) {
		if (dev->site_specific[i].exists &&
		    !dev->site_specific[i].deconfigured) {
			fprintf(fd, "ENV{ZDEV_SITE_ID}==\"%d\",GOTO=\"%s_site%d\"\n", i,
				cfg_label, i);
		}
	}

	/*
	 * If we have a generic configuration available, then use that setting as a
	 * fail-over incase of no site-id information in LOADPARM
	 */
	if (dev->site_specific[SITE_FALLBACK].exists &&
	    !dev->site_specific[SITE_FALLBACK].deconfigured)
		fprintf(fd, "GOTO=\"%s_site_fb\"\n", cfg_label);
	else
		fprintf(fd, "GOTO=\"%s\"\n", end_label);
	fprintf(fd, "\n");

	/* Write the site blocks for all the available configurations */
	for (i = 0; i < NUM_USER_SITES; i++) {
		if (dev->site_specific[i].exists &&
		    !dev->site_specific[i].deconfigured) {
			fprintf(fd, "# site_start_%d\n", i);
			fprintf(fd, "LABEL=\"%s_site%d\"\n", cfg_label, i);

			write_attr_to_file(fd, &dev->site_specific[i], id);
			/* Write udev rule epilog. */
			fprintf(fd, "GOTO=\"%s\"\n", end_label);
			fprintf(fd, "# site_end_%d\n", i);
			fprintf(fd, "\n");
		}
	}
	if (dev->site_specific[SITE_FALLBACK].exists &&
	    !dev->site_specific[SITE_FALLBACK].deconfigured) {
		fprintf(fd, "# site_start_fb\n");
		fprintf(fd, "LABEL=\"%s_site_fb\"\n", cfg_label);

		write_attr_to_file(fd, &dev->site_specific[i], id);
		/* Write udev rule epilog. */
		fprintf(fd, "GOTO=\"%s\"\n", end_label);
		fprintf(fd, "# site_end_fb\n");
		fprintf(fd, "\n");
	}

	/* Write udev rule epilog. */
	fprintf(fd, "\n");
	fprintf(fd, "LABEL=\"%s\"\n", end_label);

	if (misc_fclose(fd))
		warn("Could not close file %s: %s\n", path, strerror(errno));

	rc = udev_write_site_rule();
	if (rc)
		goto out;
out:
	free(end_label);
	free(cfg_label);
	free(path);

	return rc;
}

exit_code_t udev_ccw_write_device(struct device *dev, bool autoconf)
{
	if (autoconf)
		return udev_ccw_write_device_legacy(dev, autoconf);
	else
		return udev_ccw_write_device_new(dev);
}

#define MARKER	"echo free "

static char *read_cio_ignore(const char *path)
{
	char *text, *start, *end, *result = NULL;

	text = misc_read_text_file(path, 0, err_ignore);
	if (!text)
		goto out;

	start = strstr(text, MARKER);
	if (!start)
		goto out;
	start += strlen(MARKER);
	end = strchr(start, ' ');
	if (!end)
		goto out;
	*end = 0;
	result = misc_strdup(start);

out:
	free(text);

	return result;
}

/* Write a udev rule to free devices from the cio-ignore blacklist. */
exit_code_t udev_ccw_write_cio_ignore(const char *id_list, bool autoconf)
{
	char *path, *prefix, *curr = NULL;
	FILE *fd;
	exit_code_t rc = EXIT_OK;

	/* Ensure that autoconf version of cio-ignore is not masked
	 * by normal one. */
	prefix = autoconf ? "cio-ignore-autoconf" : "cio-ignore";

	/* Create file. */
	path = path_get_udev_rule(prefix, NULL, autoconf);

	if (!*id_list) {
		/* Empty id_list string - remove file. */
		if (!util_path_is_reg_file(path)) {
			/* Already removed. */
			goto out;
		}
		rc = remove_file(path);
		goto out;
	}

	curr = read_cio_ignore(path);
	if (curr && strcmp(curr, id_list) == 0)
		goto out;

	debug("Writing cio-ignore udev rule file %s\n", path);
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

	/* Write udev rule. */
	fprintf(fd, "# Generated by chzdev\n");

	fprintf(fd, "ACTION==\"add\", SUBSYSTEM==\"subsystem\", "
		"KERNEL==\"ccw\", RUN{program}+=\"/bin/sh -c "
		"'echo free %s > /proc/cio_ignore'\"\n", id_list);

	/* Close file. */
	if (misc_fclose(fd))
		warn("Could not close file %s: %s\n", path, strerror(errno));

out:
	free(curr);
	free(path);

	return rc;
}
