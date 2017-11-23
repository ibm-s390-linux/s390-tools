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

#include "lib/util_path.h"

#include "blkinfo.h"
#include "ccw.h"
#include "device.h"
#include "devnode.h"
#include "findmnt.h"
#include "iscsi.h"
#include "misc.h"
#include "namespace.h"
#include "net.h"
#include "select.h"
#include "udev.h"

/* Create and initialize selection options. */
struct select_opts *select_opts_new(void)
{
	struct select_opts *select;

	select = misc_malloc(sizeof(struct select_opts));
	util_list_init(&select->devids, struct strlist_node, node);
	util_list_init(&select->by_path, struct strlist_node, node);
	util_list_init(&select->by_node, struct strlist_node, node);
	util_list_init(&select->by_if, struct strlist_node, node);
	util_list_init(&select->by_attr, struct strlist_node, node);

	return select;
}

/* Free selection options. */
void select_opts_free(struct select_opts *select)
{
	void *next, *this;

	if (!select)
		return;
	util_list_iterate_safe(&select->devids, this, next)
		free(this);
	util_list_iterate_safe(&select->by_path, this, next)
		free(this);
	util_list_iterate_safe(&select->by_node, this, next)
		free(this);
	util_list_iterate_safe(&select->by_if, this, next)
		free(this);
	util_list_iterate_safe(&select->by_attr, this, next)
		free(this);

	free(select);
}

/* Check if devices are specified in the options structure. */
bool select_opts_dev_specified(struct select_opts *select)
{
	if (!util_list_is_empty(&select->devids) ||
	    !util_list_is_empty(&select->by_path) ||
	    !util_list_is_empty(&select->by_node) ||
	    !util_list_is_empty(&select->by_if) ||
	    !util_list_is_empty(&select->by_attr) ||
	    select->all || select->configured || select->existing ||
	    select->online || select->offline || select->failed)
		return true;

	return false;
}

/* Allocated and initialize a new list of selected_dev objects. */
struct util_list *selected_dev_list_new(void)
{
	struct util_list *list;

	list = misc_malloc(sizeof(struct util_list));
	util_list_init(list, struct selected_dev_node, node);

	return list;
}

/* Free resources associated with specified selected_dev_node. */
void selected_dev_free(struct selected_dev_node *dev)
{
	free(dev->id);
	free(dev->param);
	free(dev);
}

/* Release all resources associated with the specified list. */
void selected_dev_list_free(struct util_list *list)
{
	struct selected_dev_node *p, *n;

	if (!list)
		return;
	util_list_iterate_safe(list, p, n) {
		util_list_remove(list, p);
		selected_dev_free(p);
	}
	free(list);
}

/* Used for debugging purpose. */
void selected_dev_list_print(struct util_list *list, int i)
{
	struct selected_dev_node *sel;

	indent(i, "selected_dev_list at %p:\n", (void *) list);
	if (!list)
		return;
	util_list_iterate(list, sel)
		selected_dev_print(sel, i + 2);
}

static struct selected_dev_node *selected_dev_node_new(struct devtype *dt,
						       struct subtype *st,
						       const char *id,
						       const char *param,
						       exit_code_t rc)
{
	struct selected_dev_node *sel;

	sel = misc_malloc(sizeof(struct selected_dev_node));
	sel->dt = dt;
	sel->st = st;
	if (st)
		sel->id = st->namespace->normalize_id(id);
	if (!sel->id)
		sel->id = misc_strdup(id);
	sel->param = param ? misc_strdup(param) : NULL;
	sel->rc = rc;

	return sel;
}

/* Add a new selected_dev object to the list. */
struct selected_dev_node *selected_dev_list_add(struct util_list *list,
						struct devtype *dt,
						struct subtype *st,
						const char *id,
						const char *param,
						exit_code_t rc)
{
	struct selected_dev_node *sel;

	sel = selected_dev_node_new(dt, st, id, param, rc);
	util_list_add_tail(list, sel);

	return sel;
}

/* Used for debugging. */
void selected_dev_print(struct selected_dev_node *sel, int indent)
{
	printf("%*sselected_dev_node at %p\n", indent, "", (void *) sel);
	indent += 2;
	printf("%*sdt=%p (%s)\n", indent, "", (void *) sel->dt,
	       sel->dt ? sel->dt->name : "<none>");
	printf("%*sst=%p (%s)\n", indent, "", (void *) sel->st,
	       sel->st ? sel->st->name : "<none>");
	printf("%*sid=%s\n", indent, "", sel->id);
	printf("%*sparam=%s\n", indent, "", sel->param);
	printf("%*src=%d\n", indent, "", sel->rc);
}

#define is_range(x)	(strchr((x), '-'))

/**
 * devid_spec - Device ID specification
 * @spec: Device ID or range as specified on the command line
 * @match: The resulting selected_dev_node
 * @exists: A hint that this spec matched an existing device
 */
struct devid_spec {
	const char *spec;
	struct selected_dev_node *match;
	int exists;
};

/* Make sure that all devices specified by ID are available. */
static void unblacklist_devices(struct select_opts *select)
{
	struct devtype *dt, *only_dt = select->devtype;
	struct subtype *st, *only_st = select->subtype;
	struct namespace *ns;
	struct strlist_node *s;
	int ns_done[NUM_NAMESPACES];
	int i, j, nsi, need_wait;

	/* Reset done array. */
	for (i = 0; i < NUM_NAMESPACES; i++)
		ns_done[i] = 0;

	/* Process all selected namespaces. */
	need_wait = 0;
	for (i = 0; (dt = devtypes[i]); i++) {
		if (only_dt && dt != only_dt)
			continue;
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (only_st && st != only_st)
				continue;
			ns = st->namespace;

			/* Ensure that each namespace is handled only once. */
			nsi = namespaces_index(ns);
			if (nsi < 0)
				continue;
			if (ns_done[nsi])
				continue;
			ns_done[nsi] = 1;

			/* Check if blacklist is supported. */
			if (!ns->unblacklist_id && !ns->unblacklist_id_range)
				continue;

			/* Unblacklist all specified IDs. */
			util_list_iterate(&select->devids, s) {
				if (ns_is_id_valid(ns, s->str) &&
				    ns->is_id_blacklisted(s->str) &&
				    ns->unblacklist_id) {
					ns->unblacklist_id(s->str);
					need_wait = 1;
				} else if (ns_is_id_range_valid(ns, s->str) &&
					ns->is_id_range_blacklisted(s->str) &&
					ns->unblacklist_id_range) {
					ns->unblacklist_id_range(s->str);
					need_wait = 1;
				}
			}
		}
	}

	/* Devices may have become available which trigger udev rules.
	 * Wait for udev to settle before reading device state. */
	if (need_wait)
		udev_settle();
}

/* Check if @dev matches state selection parameters in @select. */
bool select_match_state(struct device *dev, struct select_opts *select)
{
	struct subtype *st = dev->subtype;
	int exists, configured, online;
	struct util_list *errors;

	exists = dev->active.exists || dev->active.definable;
	configured = dev->persistent.exists;
	if (select->all && !(exists || configured))
		return false;
	if (select->existing && !exists)
		return false;
	if (select->configured && !configured)
		return false;

	online = subtype_online_get(st, dev, config_active);
	if (select->online && online != 1)
		return false;
	if (select->offline && online == 1)
		return false;

	errors = subtype_get_errors(st, dev->id);
	if (select->failed && !errors)
		return false;
	strlist_free(errors);

	return true;
}

/* If device @ID of subtype @st matches state selection specified in @select,
 * add it to @selected. */
static exit_code_t match_state_and_add(struct select_opts *select,
				       struct util_list *selected,
				       config_t config,
				       read_scope_t scope,
				       struct subtype *st,
				       const char *id, const char *param,
				       struct selected_dev_node **match_ptr)
{
	struct device *dev;
	struct selected_dev_node *sel;
	struct devtype *dt = st->devtype;
	exit_code_t rc;
	config_t c;

	/* Online information must be obtained from active config. */
	c = SCOPE_ACTIVE(config) ? config : config_all;

	/* Heavy-weight, but we may need device online information. */
	rc = subtype_read_device(st, id, c, scope, &dev);
	if (rc)
		return rc;

	if (!select_match_state(dev, select))
		return EXIT_OK;

	sel = selected_dev_list_add(selected, dt, st, dev->id, param, 0);

	if (match_ptr && !*match_ptr)
		*match_ptr = sel;

	return EXIT_OK;
}

/* Ask for confirmation when the number of devices addressed by range exceeds
 * RANGE_LIMIT. */
static bool check_range_size(struct namespace *ns, const char *range)
{
	static int warned;
	unsigned long num;

	if (force || warned)
		return true;

	num = ns->num_ids_in_range(range);
	if (num <= RANGE_LIMIT)
		return true;

	/* Warn only once. */
	warned = 1;

	return confirm("Note: This will attempt to select more than %d "
		       "devices (at least %u)\nContinue?", RANGE_LIMIT, num);
}

/* Check if device is matched by list of device IDs and ranges in @specs. */
static struct devid_spec *match_id(struct namespace *ns, const char *id,
				   struct util_list *specs)
{
	struct ptrlist_node *p;
	struct devid_spec *spec;

	util_list_iterate(specs, p) {
		spec = p->ptr;
		if (ns_is_id_range_valid(ns, spec->spec)) {
			if (ns->is_id_in_range(id, spec->spec))
				return spec;
		} else if (ns->cmp_ids(id, spec->spec) == 0)
			return spec;
	}

	return NULL;
}

/* Set spec->match of all matching spec entries in @specs to @match. */
static void set_match(struct namespace *ns, const char *id,
		      struct util_list *specs, struct selected_dev_node *match)
{
	struct ptrlist_node *p;
	struct devid_spec *spec;

	util_list_iterate(specs, p) {
		spec = p->ptr;
		if (spec->match)
			continue;
		if (ns_is_id_range_valid(ns, spec->spec)) {
			if (ns->is_id_in_range(id, spec->spec))
				spec->match = match;
		} else if (ns->cmp_ids(id, spec->spec) == 0)
			spec->match = match;
	}
}

struct select_cb_data {
	struct select_opts *select;
	struct util_list *selected;
	config_t config;
	read_scope_t scope;
	struct util_list *specs;
};

/* Check if this existing device matches any of the devices specified.
 * If so, add a selected_dev_node to data->selected. */
static exit_code_t select_cb(struct subtype *st, const char *id,
			     config_t config, void *data)
{
	struct select_cb_data *cb_data = data;
	struct devid_spec *spec;
	const char *param;
	struct selected_dev_node **match, *old_match = NULL;
	exit_code_t rc;

	longrun_current++;
	if (!cb_data->specs) {
		/* No devids provided on command line. */
		param = NULL;
		match = NULL;
		goto add;
	}
	spec = match_id(st->namespace, id, cb_data->specs);
	if (!spec)
		return EXIT_OK;
	param = spec->spec;
	match = &spec->match;
	old_match = spec->match;

	/* Note that ID matched existing device to generate a more fitting
	 * exit code. */
	spec->exists = 1;

add:
	rc = match_state_and_add(cb_data->select, cb_data->selected,
				 cb_data->config, cb_data->scope,
				 st, id, param, match);

	if (rc || !match || !*match || old_match)
		return rc;

	/* At this point the following is true:
	 * - device IDs were specified
	 * - the current device ID spec matched
	 * - this is the first match.
	 * To prevent "Device not found" error messages on multiple
	 * specification of the same IDs, set spec->match for all subsequent
	 * matching device ID specs. */
	set_match(st->namespace, id, cb_data->specs, *match);

	return rc;
}

/* Select devices according to @select in subtype @st. Select only devices
 * which exist/are configured. */
static exit_code_t select_by_st_nocreate(struct select_opts *select,
					 struct util_list *selected,
					 config_t config,
					 read_scope_t scope,
					 struct subtype *st,
					 struct util_list *specs)
{
	struct select_cb_data data;

	data.select = select;
	data.selected = selected;
	data.config = config;
	data.scope = scope;
	if (util_list_is_empty(specs))
		data.specs = NULL;
	else
		data.specs = specs;

	return subtype_for_each_id(st, config, select_cb, &data);
}

/* Add a node for a devid specification that did not match any device. */
static struct selected_dev_node *add_failed_devid_spec(
					struct select_opts *select,
					struct util_list *selected,
					struct devid_spec *spec,
					struct selected_dev_node *before)
{
	struct selected_dev_node *sel;
	exit_code_t rc;

	if (select->subtype || spec->exists)
		rc = EXIT_DEVICE_NOT_FOUND;
	else
		rc = EXIT_INCOMPLETE_TYPE;

	sel = selected_dev_node_new(select->devtype, select->subtype,
				    spec->spec, spec->spec, rc);

	if (before)
		util_list_add_prev(selected, sel, before);
	else
		util_list_add_tail(selected, sel);

	return sel;
}

/* Add a devnode for any device that is a parent device of @devnode to
 * @result. */
static bool add_parent_devnodes(struct util_list *result,
				struct devnode *devnode)
{
	struct util_list *devnodes;
	struct ptrlist_node *p;
	struct devnode *d;
	bool rc = false;

	switch (devnode->type) {
	case BLOCKDEV:
		devnodes = blkinfo_get_ancestor_devnodes(devnode);
		if (devnodes) {
			rc = true;

			util_list_iterate(devnodes, p)
				ptrlist_add(result, p->ptr);

			ptrlist_free(devnodes, 0);
			break;
		}
		d = iscsi_get_net_devnode(devnode);
		if (d) {
			ptrlist_add(result, d);
			rc = true;
			break;
		}
		break;
	case NETDEV:
		if (net_add_linked_devnodes(result, devnode)) {
			rc = true;
			break;
		}
		if (net_add_vlan_base(result, devnode)) {
			rc = true;
			break;
		}
		if (net_add_bonding_base(result, devnode)) {
			rc = true;
			break;
		}
		break;
	default:
		break;
	}

	return rc;
}

/* Select device that provides device node found at specified path. */
exit_code_t select_by_devnode(struct select_opts *select,
			      struct util_list *selected,
			      config_t config, read_scope_t scope,
			      struct devtype *only_dt, struct subtype *only_st,
			      struct devnode *devnode, const char *path,
			      err_t err)
{
	struct select_opts *dummy_opts = NULL;
	struct subtype *st;
	char *id = NULL, *str;
	const char *name = path ? path : devnode->name;
	struct util_list *todos, *unresolved;
	exit_code_t rc = EXIT_OK;
	struct ptrlist_node *p;
	int num_resolved = 0;

	/* Allocate dummy selection options in case none were supplied. */
	if (!select) {
		dummy_opts = select_opts_new();
		select = dummy_opts;
	}

	todos = ptrlist_new();
	ptrlist_add(todos, devnode_copy(devnode));
	unresolved = strlist_new();

	util_list_iterate(todos, p) {
		devnode = p->ptr;

		if (subtypes_find_by_devnode(devnode, &st, &id)) {
			/* In case devtype or subtype was specified on command
			 * line, filter out devices that do not match type. */
			if ((only_st && st != only_st) ||
			    (only_dt && st->devtype != only_dt))
				goto next;

			match_state_and_add(select, selected, config, scope, st,
					    id, NULL, NULL);
			num_resolved++;
next:
			free(id);
		} else if (!add_parent_devnodes(todos, devnode))
			strlist_add(unresolved, devnode->name);
	}

	str = strlist_flatten(unresolved, " ");
	if (num_resolved == 0) {
		/* Not a single device could be resolved. */
		err_t_print(err, "Could not determine device that provides "
			    "%s (%s)\n", name, str);
		rc = EXIT_DEVICE_NOT_FOUND;
	} else if (!util_list_is_empty(unresolved)) {
		/* Some devices in a compound device could not be selected. */
		err_t_print(err, "Could not determine all devices that provide "
			    "%s (%s)\n", name, str);
	}
	free(str);

	ptrlist_free(todos, 1);
	strlist_free(unresolved);
	select_opts_free(dummy_opts);

	return rc;
}

/* Select device that provides device node found at specified path. */
exit_code_t select_by_node(struct select_opts *select,
			   struct util_list *selected, config_t config,
			   read_scope_t scope, struct devtype *only_dt,
			   struct subtype *only_st, const char *path,
			   err_t err)
{
	struct devnode *devnode;
	exit_code_t rc;

	devnode = devnode_from_node(path, err);
	if (!devnode)
		return EXIT_RUNTIME_ERROR;

	rc = select_by_devnode(select, selected, config, scope, only_dt,
			       only_st, devnode, path, err);

	free(devnode);

	return rc;
}

/* Select devices that provide the mountpoint in which path lies. */
exit_code_t select_by_path(struct select_opts *select,
			   struct util_list *selected, config_t config,
			   read_scope_t scope, struct devtype *only_dt,
			   struct subtype *only_st, const char *path,
			   err_t err)
{
	struct devnode *devnode;
	struct util_list *devnodes;
	struct ptrlist_node *p;
	exit_code_t rc;

	if (!util_path_exists(path)) {
		err_t_print(err, "Path not found: %s\n", path);
		return EXIT_DEVICE_NOT_FOUND;
	}

	/* Try to get devnode by using stat. */
	devnode = devnode_from_path(path);
	if (devnode)
		goto found;

	/* Try to get devnode via blkinfo. */
	devnode = blkinfo_get_devnode_by_path(path);
	if (devnode)
		goto found;

	/* Try to get devnodes via findmnt (e.g. for btrfs subvolume mounts) */
	devnodes = findmnt_get_devnodes_by_path(path);
	if (devnodes)
		goto found_multi;

	goto notfound;

found:
	/* Select "main" devnode. */
	rc = select_by_devnode(select, selected, config, scope, only_dt,
			       only_st, devnode, NULL, err);
	if (rc)
		goto out;

	/* Check if additional devnodes are involved (same file system UUID,
	 * e.g. for a btrfs file system with multiple devices). */
	devnodes = blkinfo_get_same_uuid_devnodes(devnode);
	if (!devnodes)
		goto out;

found_multi:
	util_list_iterate(devnodes, p) {
		rc = select_by_devnode(select, selected, config, scope, only_dt,
				       only_st, p->ptr, NULL, err);
		if (rc)
			break;
	}

	ptrlist_free(devnodes, 1);

out:
	free(devnode);

	return rc;

notfound:
	err_t_print(err, "Could not determine device that provides %s%s\n",
		    path, file_is_devnode(path) ? " (did you mean --by-node?)" :
						  "");

	return EXIT_DEVICE_NOT_FOUND;
}

static exit_code_t select_create_one(struct select_opts *select,
				     struct util_list *selected,
				     struct devtype *only_dt,
				     struct subtype *only_st,
				     config_t config, read_scope_t scope,
				     struct namespace *ns, const char *id,
				     const char *spec,
				     struct selected_dev_node **match_ptr)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	exit_code_t rc = EXIT_OK;

	for (i = 0; (dt = devtypes[i]); i++) {
		if (only_dt && dt != only_dt)
			continue;
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (only_st && st != only_st)
				continue;
			if (ns && st->namespace != ns)
				continue;

			rc = match_state_and_add(select, selected, config,
						 scope, st, id,
						 spec, match_ptr);
			if (rc)
				return rc;
		}
	}

	return rc;
}

static exit_code_t select_create_range(struct select_opts *select,
				       struct util_list *selected,
				       struct devtype *only_dt,
				       struct subtype *only_st,
				       config_t config, read_scope_t scope,
				       const char *range,
				       struct selected_dev_node **match_ptr)
{
	int i;
	struct namespace *ns;
	struct ns_range_iterator *it;
	exit_code_t rc = EXIT_OK;

	for (i = 0; (ns = namespaces[i]); i++) {
		if (!ns_is_id_range_valid(ns, range))
			continue;

		if (!check_range_size(ns, range))
			return EXIT_ABORTED;

		/* Select device for each ID in range. */
		it = ns_range_iterator_new();
		ns_range_for_each(ns, range, it) {
			rc = select_create_one(select, selected, only_dt,
					       only_st, config, scope,
					       ns, it->id, range, match_ptr);
			if (rc)
				break;
		}
		ns_range_iterator_free(it);
		if (rc)
			return rc;
	}

	return EXIT_OK;
}

static exit_code_t select_create_by_spec(struct select_opts *select,
					 struct util_list *selected,
					 config_t config, read_scope_t scope,
					 struct devid_spec *spec)
{
	struct util_list *cand;
	exit_code_t rc;
	struct selected_dev_node *match, *sel, *n;
	struct subtype *st;

	/* Special handling in case type is not fully specified: add
	 * candidates to special list that is checked afterwards. */
	if (select->subtype)
		cand = selected;
	else
		cand = selected_dev_list_new();

	match = NULL;
	if (is_range(spec->spec)) {
		/* Select range of devices. */
		rc = select_create_range(select, cand, select->devtype,
					 select->subtype, config, scope,
					 spec->spec, &match);
	} else {
		/* Select device by ID. */
		rc = select_create_one(select, cand, select->devtype,
				       select->subtype, config, scope, NULL,
				       spec->spec, spec->spec, &match);
	}
	if (rc)
		goto out;

	if (select->subtype) {
		/* Type was fully specified, we're done. */
		goto out;
	}

	/* Check for type ambiguities. */
	st = NULL;
	util_list_iterate(cand, sel) {
		if (!st) {
			st = sel->st;
			continue;
		}
		if (sel->st == st)
			continue;

		/* There are too many candidates. Create error entry. */
		match = selected_dev_list_add(selected, select->devtype,
					      select->subtype,
					      spec->spec, spec->spec,
					      EXIT_INCOMPLETE_TYPE);
		goto out;
	}

	/* No ambiguity found - copy candidates to selected list. */
	util_list_iterate_safe(cand, sel, n) {
		util_list_remove(cand, sel);
		util_list_add_tail(selected, sel);
		if (!match)
			match = sel;
	}

out:
	if (!spec->match)
		spec->match = match;
	if (cand != selected)
		selected_dev_list_free(cand);

	return rc;
}

static exit_code_t select_create(struct select_opts *select,
				 struct util_list *selected,
				 config_t config, read_scope_t scope,
				 struct util_list *specs)
{
	struct ptrlist_node *p;
	exit_code_t rc = EXIT_OK;

	/* Iterate over device IDs because there's a chance we don't know
	 * the subtype. */
	util_list_iterate(specs, p) {
		rc = select_create_by_spec(select, selected, config, scope,
					   p->ptr);
		if (rc)
			break;
	}

	return rc;
}

static exit_code_t select_nocreate(struct select_opts *select,
				   struct util_list *selected, int pairs,
				   config_t config, read_scope_t scope,
				   struct util_list *specs)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	exit_code_t rc = EXIT_OK;
	config_t id_config;
	unsigned long count;

	/* Determine from which configuration sets to check for devices. */
	id_config = get_config(select->existing || select->all ||
			       select->offline || select->online ||
			       SCOPE_ACTIVE(config),
			       select->configured || select->all ||
			       SCOPE_PERSISTENT(config));

	longrun_total = 0;
	if (quiet)
		goto skip;

	/* Count devices. */
	verb("Scanning for devices in %s configuration%s:\n",
	     config_to_str(id_config), id_config == config_all ? "s" : "");
	for (i = 0; (dt = devtypes[i]); i++) {
		if (select->devtype && dt != select->devtype)
			continue;
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (select->subtype && st != select->subtype)
				continue;
			count = subtype_count_ids(st, id_config);
			longrun_total += count;
			verb("  %-19s: %lu\n", st->devname, count);
		}
	}

	if (longrun_total == 0) {
		verb("  No device found\n");
		return EXIT_OK;
	}
	verb("  %-19s: %lu\n", "Total", longrun_total);

skip:
	/* Select devices. */
	longrun_start("Reading device information", pairs);
	for (i = 0; (dt = devtypes[i]); i++) {
		if (select->devtype && dt != select->devtype)
			continue;
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (select->subtype && st != select->subtype)
				continue;
			rc = select_by_st_nocreate(select, selected,
						   id_config, scope, st, specs);
			if (rc)
				goto out;
		}
	}

out:
	longrun_stop();

	return rc;
}

static struct subtype *derive_st(const char *spec)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st, *result = NULL;

	for (i = 0; (dt = devtypes[i]); i++) {
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (!ns_is_id_valid(st->namespace, spec) &&
			    !ns_is_id_range_valid(st->namespace, spec))
				continue;
			/* Abort on ambiguous match. */
			if (result)
				return NULL;
			result = st;
		}
	}

	return result;
}

static exit_code_t select_remaining(struct select_opts *select,
				    struct util_list *selected, int define,
				    config_t config, read_scope_t scope,
				    struct util_list *specs)
{
	struct subtype *st;
	struct ptrlist_node *p;
	struct devid_spec *spec;
	exit_code_t rc = EXIT_OK;

	util_list_iterate(specs, p) {
		spec = p->ptr;
		if (spec->match)
			continue;
		if (select->subtype)
			st = select->subtype;
		else
			st = derive_st(spec->spec);
		if (!st)
			continue;
		if (define && !st->support_definable)
			continue;
		if (is_range(spec->spec)) {
			/* Select range of devices. */
			rc = select_create_range(select, selected, st->devtype,
						 st, config,
						 scope, spec->spec,
						 &spec->match);
		} else {
			/* Select device by ID. */
			rc = select_create_one(select, selected, st->devtype,
					       st, config, scope,
					       NULL, spec->spec, spec->spec,
					       &spec->match);
		}
		if (rc)
			break;
	}

	return rc;
}

static exit_code_t select_by_devid(struct select_opts *select,
				   struct util_list *selected, int existing,
				   int pairs, config_t config,
				   read_scope_t scope, struct util_list *specs)
{
	static exit_code_t rc;

	if (existing) {
		rc = select_nocreate(select, selected, pairs, config, scope,
				     specs);
		if (rc)
			return rc;
		return select_remaining(select, selected, 1, config, scope,
					specs);
	}

	if (select->subtype) {
		/* Subtype specified - no guesswork involved. */
		if (!util_list_is_empty(specs)) {
			return select_create(select, selected, config, scope,
					     specs);
		}
		return select_nocreate(select, selected, pairs, config,
				       scope, specs);
	}

	/* Subtype not specified - check for existing devices first. Use
	 * config_all to enable using active devices as template for persistent
	 * configurations. */
	rc = select_nocreate(select, selected, pairs, config_all, scope, specs);
	if (rc)
		return rc;

	/* No information about the device type available. There are two
	 * possibilities:
	 * 1. Subtype can be inferred from namespace
	 * 2. A devid specification cannot be resolved */
	return select_remaining(select, selected, 0, config, scope, specs);
}

/* Add selected_dev_node entries for all device ID specifications that did not
 *  match anything. */
static void handle_unmatched_specs(struct select_opts *select,
				   struct util_list *selected,
				   struct util_list *specs)
{
	struct ptrlist_node *p;
	struct selected_dev_node *before;
	struct devid_spec *spec;

	/* Since unmatched entries should be added before the first match of
	 * the following devid specification, we need to traverse the
	 * devid_spec list in reverse. */
	before = NULL;
	for (p = util_list_end(specs); p; p = util_list_prev(specs, p)) {
		spec = p->ptr;
		if (spec->match) {
			/* This devid spec matched something. */
			before = spec->match;
			continue;
		}

		/* Add "not found" result for this devid spec. */
		before = add_failed_devid_spec(select, selected, spec, before);
	}
}

/* Remove duplicate entries in selected list. */
static void remove_duplicates(struct util_list *selected,
			      struct selected_dev_node *first)
{
	struct selected_dev_node *sel, *s, *n;

	sel = first ? first : util_list_start(selected);

	for (; sel; sel = util_list_next(selected, sel)) {
		for (s = util_list_next(selected, sel); s; s = n) {
			n = util_list_next(selected, s);
			if (sel->dt != s->dt || sel->st != s->st)
				continue;
			if (sel->id && s->id) {
				if (strcmp(sel->id, s->id) == 0)
					goto remove;
				continue;
			}
			if (sel->param && s->param &&
			    strcmp(sel->param, s->param) == 0)
				goto remove;
			continue;

remove:
			util_list_remove(selected, s);
			selected_dev_free(s);
		}
	}
}

/* Select devices that provide networking interface @name. */
exit_code_t select_by_interface(struct select_opts *select,
				struct util_list *selected, config_t config,
				read_scope_t scope, struct devtype *only_dt,
				struct subtype *only_st, const char *name,
				err_t err)
{
	struct devnode *d;
	exit_code_t rc;

	d = devnode_new(NETDEV, 0, 0, name);
	rc = select_by_devnode(select, selected, config, scope, only_dt,
			       only_st, d, NULL, err);
	free(d);

	return rc;
}

struct by_attr_cb_data {
	struct select_opts *select;
	struct util_list *selected;
	read_scope_t scope;
	const char *key;
	const char *value;
	bool invert;
};

static exit_code_t by_attr_cb(struct subtype *st, const char *id,
			      config_t config, void *data)
{
	struct by_attr_cb_data *cb_data = data;
	struct device *dev;
	static exit_code_t rc;
	struct setting *s;
	char *value;
	bool match = false;

	rc = subtype_read_device(st, id, config_all, cb_data->scope, &dev);
	if (rc)
		return rc;

	/* Check for attribute value in active configuration. */
	s = setting_list_find(dev->active.settings, cb_data->key);
	if (s)
		match = setting_match_value(s, cb_data->value);
	else {
		/* Try reading setting directly. */
		value = device_read_active_attrib(dev, cb_data->key);
		if (value && strcmp(value, cb_data->value) == 0)
			match = true;
		free(value);
	}
	if (match)
		goto out;

	/* Check for attribute value in persistent configuration. */
	s = setting_list_find(dev->persistent.settings, cb_data->key);
	if (s)
		match = setting_match_value(s, cb_data->value);

out:
	if ((match && !cb_data->invert) || (!match && cb_data->invert)) {
		/* Apply state selection and add. */
		rc = match_state_and_add(cb_data->select, cb_data->selected,
					 config, cb_data->scope, st, id, NULL,
					 NULL);
	}

	return rc;
}

/* Select devices with specified attribute settings. */
static exit_code_t select_by_attr(struct select_opts *select,
				  struct util_list *selected, config_t config,
				  read_scope_t scope, struct devtype *only_dt,
				  struct subtype *only_st, const char *attr,
				  err_t err)
{
	char *key, *value;
	exit_code_t rc = EXIT_OK;
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	struct by_attr_cb_data cb_data;
	bool invert = false;

	key = misc_strdup(attr);
	value = strchr(key, '=');
	if (!value) {
		rc = EXIT_USAGE_ERROR;
		goto out;
	}
	/* Check for KEY!=VALUE. */
	if (value > key && value[-1] == '!') {
		value[-1] = 0;
		invert = true;
	}
	*value = 0;
	value++;

	/* Iterate over all devices. */
	cb_data.select = select;
	cb_data.selected = selected;
	cb_data.scope = scope;
	cb_data.key = key;
	cb_data.value = value;
	cb_data.invert = invert;
	for (i = 0; (dt = devtypes[i]); i++) {
		if (only_dt && dt != only_dt)
			continue;
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (only_st && st != only_st)
				continue;
			rc = subtype_for_each_id(st, config_all, by_attr_cb,
						 &cb_data);
			if (rc)
				goto out;
		}
	}


out:
	free(key);

	return rc;
}

/* Determine list of IDs of selected devices based on selection options.
 * Results are stored as list of struct selected_dev_node in SELECTED.
 * If @existing is set, only return nodes for existing devices.
 * If @unblacklist is set, remove all devices specified by ID or ID range from
 * blacklists. If @pairs is set, output progress output in "pairs" format.
 * @config specifies the configuration from which to read devices. */
exit_code_t select_devices(struct select_opts *select,
			   struct util_list *selected, int existing,
			   int unblacklist, int pairs, config_t config,
			   read_scope_t scope, err_t err)
{
	struct util_list *specs = NULL;
	struct strlist_node *s;
	struct devid_spec *spec;
	exit_code_t rc = EXIT_OK;
	struct selected_dev_node *first;

	/* Note for later. */
	first = util_list_start(selected);

	if (unblacklist)
		unblacklist_devices(select);

	/* Skip non-function selection if only by- function was specified. */
	if (util_list_is_empty(&select->devids) &&
	    !(util_list_is_empty(&select->by_path) &&
	      util_list_is_empty(&select->by_node) &&
	      util_list_is_empty(&select->by_if) &&
	      util_list_is_empty(&select->by_attr)))
		goto by_function;

	/* Convert device ID specifications to enable tracking of specifications
	 * that did not match any device. */
	specs = ptrlist_new();
	util_list_iterate(&select->devids, s) {
		spec = misc_malloc(sizeof(struct devid_spec));
		spec->spec = s->str;
		ptrlist_add(specs, spec);
	}

	/* Select in all specified devtypes and subtypes. */
	rc = select_by_devid(select, selected, existing, pairs, config, scope,
			     specs);
	if (rc)
		goto out;

	handle_unmatched_specs(select, selected, specs);

by_function:
	/* Select devices specified via --by-node */
	util_list_iterate(&select->by_node, s) {
		rc = select_by_node(select, selected, config, scope,
				    select->devtype, select->subtype, s->str,
				    err);
		if (rc)
			goto out;
	}
	/* Select device specified via --by-path */
	util_list_iterate(&select->by_path, s) {
		rc = select_by_path(select, selected, config, scope,
				    select->devtype, select->subtype, s->str,
				    err);
		if (rc)
			goto out;
	}

	/* Select devices specified via --by-interface */
	util_list_iterate(&select->by_if, s) {
		rc = select_by_interface(select, selected, config, scope,
					 select->devtype, select->subtype,
					 s->str, err);
		if (rc)
			goto out;
	}

	/* Select devices specified via --by-attr */
	util_list_iterate(&select->by_attr, s) {
		rc = select_by_attr(select, selected, config, scope,
				    select->devtype, select->subtype,
				    s->str, err);
		if (rc)
			goto out;
	}

out:
	/* Release device ID specifications tracking list. */
	ptrlist_free(specs, 1);

	if (!rc)
		remove_duplicates(selected, first);

	return rc;
}
