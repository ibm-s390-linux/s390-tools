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
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_path.h"
#include "lib/util_udev.h"

#include "attrib.h"
#include "device.h"
#include "internal.h"
#include "misc.h"
#include "path.h"
#include "scsi.h"
#include "setting.h"
#include "udev.h"
#include "udev_zfcp_lun.h"
#include "zfcp_lun.h"

#define LABEL_START	"start_zfcp_lun_"
#define LABEL_END	"end_zfcp_lun_"
#define LABEL_FC	"cfg_fc_"
#define LABEL_SCSI	"cfg_scsi_"

struct zfcp_lun_node {
	struct util_list_node node;
	struct zfcp_lun_devid id;
	struct setting_list *fc_settings;
	struct setting_list *scsi_settings;
};

static void zfcp_lun_node_print(struct zfcp_lun_node *node, int indent)
{
	char *id;

	printf("%*szfcp_lun_node at %p\n", indent, "", (void *) node);
	if (!node)
		return;
	indent += 2;
	id = zfcp_lun_devid_to_str(&node->id);
	printf("%*sid=%s\n", indent, "", id);
	free(id);
	printf("%*sfc_settings:\n", indent, "");
	setting_list_print(node->fc_settings, indent + 2);
	printf("%*sscsi_settings:\n", indent, "");
	setting_list_print(node->scsi_settings, indent + 2);
}

static struct zfcp_lun_node *zfcp_lun_node_new(struct zfcp_lun_devid *id)
{
	struct zfcp_lun_node *node;

	node = misc_malloc(sizeof(struct zfcp_lun_node));
	node->id = *id;
	node->fc_settings = setting_list_new();
	node->scsi_settings = setting_list_new();

	return node;
}

static void zfcp_lun_node_free(struct zfcp_lun_node *node)
{
	if (!node)
		return;
	setting_list_free(node->fc_settings);
	setting_list_free(node->scsi_settings);
	free(node);
}

static struct zfcp_lun_node *zfcp_lun_node_find(struct util_list *list,
						struct zfcp_lun_devid *id)
{
	struct zfcp_lun_node *node;

	util_list_iterate(list, node) {
		if (zfcp_lun_cmp_devids(&node->id, id) == 0)
			return node;
	}

	return NULL;
}

static struct util_list *zfcp_lun_node_list_new(void)
{
	struct util_list *list;

	list = misc_malloc(sizeof(struct util_list));
	util_list_init(list, struct zfcp_lun_node, node);

	return list;
}

static void zfcp_lun_node_list_free(struct util_list *list)
{
	struct zfcp_lun_node *n, *p;

	if (!list)
		return;
	util_list_iterate_safe(list, n, p) {
		util_list_remove(list, n);
		zfcp_lun_node_free(n);
	}
	free(list);
}

/* Used for debugging. */
void zfcp_lun_node_list_print(struct util_list *list, int indent)
{
	struct zfcp_lun_node *n;

	printf("%*szfcp_lun_node_list at %p\n", indent, "", (void *) list);
	if (!list)
		return;
	util_list_iterate(list, n)
		zfcp_lun_node_print(n, indent + 2);
}

static bool zfcp_lun_devid_from_entry(struct zfcp_lun_devid *id_ptr,
				      struct util_udev_entry_node *entry)
{
	struct zfcp_lun_devid id;
	char *copy = NULL, *s, *e, *u;
	int i;
	bool rc = false;

	/* LABEL="cfg_scsi_0.0.1941_0x500507630510c1ae_0x402340d400000000" */
	if (strcmp(entry->key, "LABEL") == 0 &&
	    starts_with(entry->value, LABEL_SCSI)) {
		copy = misc_strdup(entry->value);
		s = copy + strlen(LABEL_SCSI);
		for (i = 0; s[i]; i++) {
			if (s[i] == '_')
				s[i] = ':';
		}
		rc = zfcp_lun_parse_devid(&id, s, err_ignore) == EXIT_OK ?
			true : false;
		goto out;
	}

	/*ATTR{[ccw/0.0.1941]0x500507630510c1ae/unit_add}="0x402340d400000000"*/
	if (starts_with(entry->key, "ATTR{[ccw/") &&
	    ends_with(entry->key, "/unit_add}")) {
		copy = misc_asprintf("%s%s", entry->key, entry->value);
		s = copy + strlen("ATTR{[ccw/");
		for (i = 0; s[i]; i++) {
			if (s[i] == ']')
				s[i] = ':';
			else if (s[i] == '/')
				break;
		}
		if (s[i] != '/')
			goto out;
		s[i] = ':';
		strcpy(s + i + 1, entry->value);
		rc = zfcp_lun_parse_devid(&id, s, err_ignore) == EXIT_OK ?
			true : false;
		goto out;
	}

	/*ATTR{[ccw/0.0.1941]0x500507630510c1ae/0x402340d400000000/failed}="0"*/
	if (starts_with(entry->key, "ATTR{[ccw/")) {
		copy = misc_strdup(entry->key);
		s = strrchr(copy, '/');
		if (s)
			*s = 0;
		s = copy + strlen("ATTR{[ccw/");
		for (i = 0; s[i]; i++) {
			if (s[i] == ']' || s[i] == '/')
				s[i] = ':';
		}
		rc = zfcp_lun_parse_devid(&id, s, err_ignore) == EXIT_OK ?
			true : false;
		goto out;
	}

	/*ENV{zdev_var__0_0_1941_0x500507630510c1ae_0x402340d400000000}="1"*/
	if (starts_with(entry->key, "ENV{zdev_")) {
		copy = misc_strdup(entry->key);

		/* Find ID start (last __) and end (last }). */
		s = misc_strrstr(copy, "__");
		e = strrchr(copy, '}');
		if (!s || !e)
			goto out;
		*e = 0;
		s += 2;
		/* Convert variable name to ID format. */
		for (i = 0, u = s; (u = strchr(u, '_')); i++, u++) {
			if (i < 2)
				*u = '.';
			else
				*u = ':';
		}
		rc = zfcp_lun_parse_devid(&id, s, err_ignore) == EXIT_OK ?
			true : false;
	}

out:
	free(copy);
	if (rc)
		*id_ptr = id;

	return rc;
}

static struct zfcp_lun_node *zfcp_lun_node_from_entry(
					struct util_udev_entry_node *entry,
					struct zfcp_lun_node *old,
					struct util_list *list)
{
	struct zfcp_lun_devid id;
	struct zfcp_lun_node *node;

	if (!zfcp_lun_devid_from_entry(&id, entry))
		return old;
	if (old && zfcp_lun_cmp_devids(&old->id, &id) == 0)
		return old;
	node = zfcp_lun_node_find(list, &id);
	if (!node) {
		node = zfcp_lun_node_new(&id);
		util_list_add_tail(list, node);
	}

	return node;
}

static void add_internal_setting_from_entry(struct util_udev_entry_node *entry,
					    struct zfcp_lun_node *node)
{
	char *copy, *name, *end, *u;
	struct attrib *a;

	/*ENV{zdev_var__0_0_1941_0x500507630510c1ae_0x402340d400000000}="1"*/
	copy = misc_strdup(entry->key);

	/* Find attribute name start and end. */
	name = strchr(copy, '{');
	end = misc_strrstr(copy, "__");
	if (!name || !end)
		goto out;
	*end = 0;
	name++;

	/* zdev_ => zdev: */
	u = strchr(name, '_');
	if (u)
		*u = ':';

	a = attrib_find(zfcp_lun_subtype.dev_attribs, name);
	setting_list_apply_actual(node->fc_settings, a, name, entry->value);

out:
	free(copy);
}

static void add_fc_setting_from_entry(struct util_udev_entry_node *entry,
				      struct zfcp_lun_node *node)
{
	char *copy, *s, *e;

	/*ENV{zdev_var__0_0_1941_0x500507630510c1ae_0x402340d400000000}="1"*/
	if (starts_with(entry->key, "ENV{zdev_") &&
	    strcmp(entry->op, "=") == 0) {
		add_internal_setting_from_entry(entry, node);
		return;
	}
	/*ATTR{[ccw/0.0.1941]0x500507630510c1ae/0x402340d400000000/failed}="0"*/
	if (!starts_with(entry->key, "ATTR{[ccw/"))
		return;
	if (strstr(entry->key, "unit_add"))
		return;
	copy = misc_strdup(entry->key);
	s = strrchr(copy, '/');
	if (!s)
		goto out;
	s++;
	e = strchr(s, '}');
	if (!e)
		goto out;
	*e = 0;
	setting_list_add(node->fc_settings, setting_new(NULL, s, entry->value));

out:
	free(copy);
}

static void add_scsi_setting_from_entry(struct util_udev_entry_node *entry,
					struct zfcp_lun_node *node)
{
	char *copy, *s, *e;

	/* ATTR{queue_depth}="64" */
	if (!starts_with(entry->key, "ATTR{"))
		return;
	copy = misc_strdup(entry->key);
	s = strchr(copy, '{');
	if (!s)
		goto out;
	s++;
	e = strchr(s, '}');
	if (!e)
		goto out;
	*e = 0;
	setting_list_add(node->scsi_settings,
			 setting_new(NULL, s, entry->value));

out:
	free(copy);
}

static int zfcp_lun_node_cmp(void *a, void *b, void *data)
{
	struct zfcp_lun_node *a_node = a, *b_node = b;

	return zfcp_lun_cmp_devids(&a_node->id, &b_node->id);
}

static void sort_zfcp_lun_list(struct util_list *list)
{
	util_list_sort(list, zfcp_lun_node_cmp, NULL);
}

/* Read udev rule from FILENAME and extract all LUN settings as zfcp_lun_node
 * to list. Note: List entries will be sorted by ID. */
static exit_code_t udev_read_zfcp_lun_rule(const char *filename,
					   struct util_list *list)
{
	exit_code_t rc;
	struct util_udev_file *file = NULL;
	struct util_udev_line_node *line;
	struct util_udev_entry_node *entry;
	struct zfcp_lun_node *node = NULL;
	enum {
		none,
		in_fc,
		in_scsi,
	} state = none;
	bool empty_rule = true;

	rc = (exit_code_t) util_udev_read_file(filename, &file);
	if (rc)
		goto out;

	util_list_iterate(&file->lines, line) {
		entry = util_list_start(&line->entries);

		/* Skip comments and empty lines. */
		if (!entry)
			continue;

		/* GOTO resets current state. */
		if (strcmp(entry->key, "GOTO") == 0) {
			node = NULL;
			state = none;
			continue;
		}

		switch (state) {
		case none:
			if (strcmp(entry->key, "LABEL") != 0)
				continue;
			if (starts_with(entry->value, LABEL_FC))
				state = in_fc;
			else if (starts_with(entry->value, LABEL_SCSI)) {
				state = in_scsi;
				node = zfcp_lun_node_from_entry(entry, node,
								list);
				if (node)
					empty_rule = false;
			}
			break;
		case in_fc:
			node = zfcp_lun_node_from_entry(entry, node, list);
			if (node) {
				add_fc_setting_from_entry(entry, node);
				empty_rule = false;
			}
			break;
		case in_scsi:
			if (node) {
				add_scsi_setting_from_entry(entry, node);
				empty_rule = false;
			}
			break;
		}
	}

	sort_zfcp_lun_list(list);

out:
	util_udev_free_file(file);

	if (empty_rule)
		warn_once("Warning: Invalid udev rule: %s\n", filename);

	return rc;
}

struct lun_cb_data {
	char *prefix;
	struct util_list *list;
};

static exit_code_t lun_cb(const char *path, const char *name, void *data)
{
	struct lun_cb_data *cb_data = data;
	struct util_list *luns;
	struct zfcp_lun_node *node;
	char *id;

	if (!starts_with(name, cb_data->prefix))
		return EXIT_OK;

	luns = zfcp_lun_node_list_new();
	udev_read_zfcp_lun_rule(path, luns);

	util_list_iterate(luns, node) {
		id = zfcp_lun_devid_to_str(&node->id);
		strlist_add(cb_data->list, id);
		free(id);
	}

	zfcp_lun_node_list_free(luns);

	return EXIT_OK;
}

/* Add the IDs for all zfcp lun devices for which a configuration exists to
 * LIST. */
void udev_zfcp_lun_add_device_ids(struct util_list *list, bool autoconf)
{
	struct lun_cb_data cb_data;
	char *path;

	cb_data.prefix = misc_asprintf("%s-%s-", UDEV_PREFIX, ZFCP_LUN_NAME);
	cb_data.list = list;
	path = path_get_udev_rules(autoconf);

	if (util_path_is_dir(path))
		path_for_each(path, lun_cb, &cb_data);

	free(path);
	free(cb_data.prefix);
}

/* Return path to zfcp lun udev rule file containing configuration data for
 * all LUNs of a zfcp device. */
static char *get_zfcp_lun_path(const char *id, bool autoconf)
{
	char *copy, *e, *path;

	copy = misc_strdup(id);
	e = strchr(copy, ':');
	if (e)
		*e = 0;
	path = path_get_udev_rule(ZFCP_LUN_NAME, copy, autoconf);
	free(copy);

	return path;
}

/* Return path to zfcp lun udev rule file containing configuration data for
 * a single LUN. */
static char *get_single_zfcp_lun_path(const char *id, bool autoconf)
{
	return path_get_udev_rule(ZFCP_LUN_NAME, id, autoconf);
}

/* Apply the settings found in NODE to STATE. */
static void zfcp_lun_node_to_state(struct zfcp_lun_node *node,
				   struct attrib **attribs,
				   struct device_state *state)
{
	struct setting *s;
	struct attrib *a;
	char *name;

	state->modified = 0;
	state->deconfigured = 0;
	state->definable = 0;

	if (!node) {
		state->exists = 0;
		return;
	}

	state->exists = 1;

	util_list_iterate(&node->fc_settings->list, s) {
		a = attrib_find(attribs, s->name);
		setting_list_add(state->settings,
				 setting_new(a, s->name, s->value));
	}
	util_list_iterate(&node->scsi_settings->list, s) {
		name = misc_asprintf("%s/%s", SCSI_ATTR_PREFIX, s->name);
		a = attrib_find(attribs, name);
		setting_list_add(state->settings,
				 setting_new(a, name, s->value));
		free(name);
	}
}

/* Read the persistent configuration of a zfcp lun from a udev rule. */
exit_code_t udev_zfcp_lun_read_device(struct device *dev, bool autoconf)
{
	struct subtype *st = dev->subtype;
	struct device_state *state = autoconf ? &dev->autoconf :
						&dev->persistent;
	struct util_list *luns;
	struct zfcp_lun_node *node;
	exit_code_t rc = EXIT_OK;
	char *path;

	/* Check for single lun file first then try multi lun file. */
	path = get_single_zfcp_lun_path(dev->id, autoconf);
	if (!util_path_exists(path)) {
		free(path);
		path = get_zfcp_lun_path(dev->id, autoconf);
	}

	/* Get previous rule data. */
	luns = zfcp_lun_node_list_new();
	rc = udev_read_zfcp_lun_rule(path, luns);
	if (rc)
		goto out;

	node = zfcp_lun_node_find(luns, dev->devid);
	zfcp_lun_node_to_state(node, st->dev_attribs, state);

out:
	zfcp_lun_node_list_free(luns);
	free(path);

	return rc;
}

static struct zfcp_lun_node *state_to_zfcp_lun_node(struct zfcp_lun_devid *id,
						    struct device_state *state)
{
	struct zfcp_lun_node *node;
	struct setting *s, *n;

	node = zfcp_lun_node_new(id);
	util_list_iterate(&state->settings->list, s) {
		if (s->removed)
			continue;
		if (attrib_match_prefix(s->name, SCSI_ATTR_PREFIX)) {
			n = setting_new(NULL,
					attrib_rem_prefix(s->name,
							  SCSI_ATTR_PREFIX),
					s->value);
			setting_list_add(node->scsi_settings, n);
		} else {
			n = setting_new(s->attrib, s->name, s->value);
			setting_list_add(node->fc_settings, n);
		}
	}

	return node;
}

/* Write udev rule as defined by LIST of struct zfcp_lun_nodes to PATH. */
static exit_code_t write_luns_rule(const char *path, struct util_list *list)
{
	FILE *fd;
	exit_code_t rc = EXIT_OK;
	struct zfcp_lun_node *node, *last_node;
	char *hba_id;
	struct setting *s;

	sort_zfcp_lun_list(list);

	node = util_list_start(list);
	if (!node)
		return EXIT_INTERNAL_ERROR;
	hba_id = ccw_devid_to_str(&node->id.fcp_dev);
	debug("Writing FCP LUN udev rule file %s\n", path);
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

	fprintf(fd, "# Generated by chzdev\n");
	fprintf(fd, "ACTION==\"add\", SUBSYSTEMS==\"ccw\", KERNELS==\"%s\", "
		"GOTO=\"%s%s\"\n", hba_id, LABEL_START, hba_id);
	fprintf(fd, "GOTO=\"%s%s\"\n", LABEL_END, hba_id);
	fprintf(fd, "\nLABEL=\"%s%s\"\n", LABEL_START, hba_id);

	/* Emit FC port triggers. */
	last_node = NULL;
	util_list_iterate(list, node) {
		if (last_node && last_node->id.wwpn == node->id.wwpn) {
			/* Only one trigger per WWPN required. */
			continue;
		}
		fprintf(fd, "SUBSYSTEM==\"fc_remote_ports\", "
			"ATTR{port_name}==\"0x%016" PRIx64 "\", "
			"GOTO=\"%s%s_0x%016" PRIx64 "\"\n",
			node->id.wwpn, LABEL_FC, hba_id, node->id.wwpn);
		last_node = node;
	}

	/* Emit SCSI unit triggers. */
	util_list_iterate(list, node) {
		if (util_list_is_empty(&node->scsi_settings->list))
			continue;
		fprintf(fd, "SUBSYSTEM==\"scsi\", "
			"ENV{DEVTYPE}==\"scsi_device\", "
			"KERNEL==\"*:%" PRIu64 "\", "
			"KERNELS==\"rport-*\", "
			"ATTRS{fc_remote_ports/$id/port_name}==\"0x%016" PRIx64
			"\", GOTO=\"%s%s_0x%016" PRIx64 "_0x%016" PRIx64 "\"\n",
			scsi_lun_from_fcp_lun(node->id.lun), node->id.wwpn,
			LABEL_SCSI, hba_id, node->id.wwpn, node->id.lun);
	}

	fprintf(fd, "GOTO=\"%s%s\"\n", LABEL_END, hba_id);

	/* Emit FC port sections. */
	last_node = NULL;
	util_list_iterate(list, node) {
		if (!last_node || last_node->id.wwpn != node->id.wwpn) {
			if (last_node) {
				fprintf(fd, "GOTO=\"end_zfcp_lun_%s\"\n",
					hba_id);
			}
			fprintf(fd, "\nLABEL=\"%s%s_0x%016" PRIx64 "\"\n",
				LABEL_FC, hba_id, node->id.wwpn);
		}
		fprintf(fd, "ATTR{[ccw/%s]0x%016" PRIx64 "/unit_add}="
			"\"0x%016" PRIx64 "\"\n", hba_id, node->id.wwpn,
			node->id.lun);

		util_list_iterate(&node->fc_settings->list, s) {
			if ((s->attrib && s->attrib->internal) ||
			    internal_by_name(s->name)) {
				fprintf(fd, "ENV{zdev_%s__%x_%x_%04x_0x%016"
					PRIx64 "_0x%016" PRIx64 "}=\"%s\"\n",
					internal_get_name(s->name),
					node->id.fcp_dev.cssid,
					node->id.fcp_dev.ssid,
					node->id.fcp_dev.devno, node->id.wwpn,
					node->id.lun, s->value);
			} else {
				fprintf(fd, "ATTR{[ccw/%s]0x%016" PRIx64
					"/0x%016" PRIx64 "/%s}=\"%s\"\n",
					hba_id, node->id.wwpn, node->id.lun,
					s->name, s->value);
			}
		}
		last_node = node;
	}
	if (last_node)
		fprintf(fd, "GOTO=\"%s%s\"\n", LABEL_END, hba_id);

	/* Emit SCSI unit sections. */
	util_list_iterate(list, node) {
		if (util_list_is_empty(&node->scsi_settings->list))
			continue;
		fprintf(fd, "\nLABEL=\"%s%s_0x%016" PRIx64 "_0x%016"
			PRIx64 "\"\n", LABEL_SCSI, hba_id, node->id.wwpn,
			node->id.lun);
		util_list_iterate(&node->scsi_settings->list, s)
			fprintf(fd, "ATTR{%s}=\"%s\"\n", s->name, s->value);
		fprintf(fd, "GOTO=\"%s%s\"\n", LABEL_END, hba_id);
	}

	fprintf(fd, "\nLABEL=\"%s%s\"\n", LABEL_END, hba_id);

	if (misc_fclose(fd))
		warn("Could not close file %s: %s\n", path, strerror(errno));

out:
	free(hba_id);

	return rc;
}

/* Update the udev rule file that configures the zfcp lun with the specified
 * ID. If @state is %NULL, remove the rule, otherwise create a rule that
 * applies the corresponding parameters. If @single is set, update a single
 * lun rule file, otherwise update a multi lun rule file. */
static exit_code_t update_lun_rule(const char *id, struct device_state *state,
				   bool single, bool autoconf)
{
	struct zfcp_lun_devid devid;
	struct util_list *luns;
	struct zfcp_lun_node *node;
	exit_code_t rc = EXIT_OK;
	char *path;
	bool exists;

	rc = zfcp_lun_parse_devid(&devid, id, err_delayed_print);
	if (rc)
		return rc;
	path = single ? get_single_zfcp_lun_path(id, autoconf) :
			get_zfcp_lun_path(id, autoconf);

	/* Get previous rule data. */
	luns = zfcp_lun_node_list_new();
	exists = util_path_is_reg_file(path);
	if (exists)
		udev_read_zfcp_lun_rule(path, luns);

	/* Replace previous rule data for this ID. */
	node = zfcp_lun_node_find(luns, &devid);
	if (node) {
		util_list_remove(luns, node);
		zfcp_lun_node_free(node);
	}
	if (state && state->exists) {
		node = state_to_zfcp_lun_node(&devid, state);
		util_list_add_tail(luns, node);
	}

	if (util_list_is_empty(luns)) {
		/* Remove empty file. */
		if (exists)
			rc = remove_file(path);
	} else {
		/* Write updated rules file. */
		rc = write_luns_rule(path, luns);
	}

	zfcp_lun_node_list_free(luns);
	free(path);

	return rc;
}

/* Write a udev-rule to configure the specified zfcp lun and associated
 * device state. */
exit_code_t udev_zfcp_lun_write_device(struct device *dev, bool autoconf)
{
	exit_code_t rc;
	struct device_state *state = autoconf ? &dev->autoconf :
						&dev->persistent;

	rc = update_lun_rule(dev->id, state, true, autoconf);

	/* We only want single lun rule files so remove any remaining
	 * references in multi lun rule files. */
	update_lun_rule(dev->id, NULL, false, autoconf);

	return rc;
}

/* Remove the UDEV rule used to configure the zfcp lun with the specified ID. */
exit_code_t udev_zfcp_lun_remove_rule(const char *id, bool autoconf)
{
	exit_code_t rc, rc2;

	rc = update_lun_rule(id, NULL, true, autoconf);
	rc2 = update_lun_rule(id, NULL, false, autoconf);

	if (rc)
		return rc;

	return rc2;
}

/* Determine if a udev rule exists for configuring the specified zfcp lun. */
bool udev_zfcp_lun_exists(const char *id, bool autoconf)
{
	struct zfcp_lun_devid devid;
	char *path, *rule = NULL, *pattern = NULL;
	bool rc = false;

	if (zfcp_lun_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return false;

	/* Check for single lun rule file first. */
	path = get_single_zfcp_lun_path(id, autoconf);
	if (util_path_exists(path)) {
		rc = true;
		goto out;
	}
	free(path);

	/* Check multi lun rule file next. */
	path = get_zfcp_lun_path(id, autoconf);
	rule = misc_read_text_file(path, 1, err_ignore);
	if (!rule)
		goto out;

	pattern = misc_asprintf("ATTR{[ccw/%x.%x.%04x]0x%016" PRIx64
				"/unit_add}=\"0x%016" PRIx64 "\"\n",
				devid.fcp_dev.cssid, devid.fcp_dev.ssid,
				devid.fcp_dev.devno, devid.wwpn, devid.lun);
	if (strstr(rule, pattern))
		rc = true;

out:
	free(pattern);
	free(rule);
	free(path);

	return rc;
}
