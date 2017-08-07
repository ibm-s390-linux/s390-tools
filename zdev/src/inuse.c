/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <mntent.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "blkinfo.h"
#include "device.h"
#include "devnode.h"
#include "inuse.h"
#include "misc.h"
#include "path.h"
#include "select.h"
#include "subtype.h"

/* struct resource - A resource that is currently in use
 * @st: Subtype of device providing resource
 * @id: ID of device providing resource
 * @name: Name of the resource, e.g. the mount point. */
struct resource {
	struct subtype *st;
	char *id;
	char *name;
};

/* ptrlist of struct resources. */
static struct util_list *resources;

/* Return a newly allocated struct resource. */
static struct resource *resource_new(struct subtype *st, const char *id,
				     const char *name)
{
	struct resource *res;

	res = misc_malloc(sizeof(struct resource));
	res->st = st;
	res->id = misc_strdup(id);
	res->name = misc_strdup(name);

	return res;
}

/* Release all resources associated with @res. */
static void resource_free(struct resource *res)
{
	if (!res)
		return;
	free(res->id);
	free(res->name);
	free(res);
}

/* Release all allocated resources. */
void inuse_exit(void)
{
	struct ptrlist_node *p, *n;
	struct resource *res;

	if (!resources)
		return;
	util_list_iterate_safe(resources, p, n) {
		util_list_remove(resources, p);
		res = p->ptr;
		resource_free(res);
		free(p);
	}
	free(resources);
}

/* Return newly allocated strlist containing names of mountpoints for all
 * mounted file systems. */
static struct util_list *get_mountpoints(void)
{
	struct util_list *list;
	char *path;
	FILE *fd;
	struct mntent *m;

	list = strlist_new();

	/* Try lsblk output first because it doesn't contain non-blockdevice
	 * file systems. */
	blkinfo_add_mountpoints(list);

	/* Use /proc/mounts as well to get btrfs subvolume mounts. */
	path = path_get_proc("mounts");
	fd = setmntent(path, "r");
	if (!fd)
		goto out;

	while ((m = getmntent(fd))) {
		if (!m->mnt_dir || !m->mnt_fsname || !*m->mnt_dir ||
		    *m->mnt_fsname != '/')
			continue;
		strlist_add_unique(list, m->mnt_dir);
	}

	endmntent(fd);

out:
	free(path);

	return list;
}

static void add_mounts(struct util_list *list)
{
	struct util_list *mountpoints;
	struct strlist_node *mp;
	struct resource *res;
	struct util_list *selected;
	struct selected_dev_node *sel;
	char *r;

	mountpoints = get_mountpoints();

	util_list_iterate(mountpoints, mp) {
		selected = selected_dev_list_new();

		/* Determine list of devices providing mountpoint. */
		if (select_by_path(NULL, selected, config_active, scope_mandatory,
				   NULL, NULL, mp->str, err_ignore) != EXIT_OK)
			goto next;

		/* Process list. */
		util_list_iterate(selected, sel) {
			if (sel->rc != EXIT_OK || !sel->st || !sel->id)
				continue;

			r = misc_asprintf("Mount point %s", mp->str);
			res = resource_new(sel->st, sel->id, r);
			free(r);
			ptrlist_add(list, res);

			/* Expand list to also contain prereq-devices. */
			subtype_add_prereqs(sel->st, sel->id, selected);
		}

next:
		selected_dev_list_free(selected);
	}

	strlist_free(mountpoints);
}

/* Return newly allocated ptrlist containing devnodes of active swap devices. */
static struct util_list *get_swapdevs(void)
{
	struct util_list *list;
	char *path, *text, *curr, *next, **argv;
	struct devnode *devnode;
	int argc;

	list = ptrlist_new();

	/* Try lsblk output first because it doesn't contain non-blockdevice
	 * file systems. */
	blkinfo_add_swap_devnodes(list);
	if (!util_list_is_empty(list))
		return list;

	/* Fall back to /proc/swaps. */
	path = path_get_proc("swaps");
	text = misc_read_text_file(path, 0, err_ignore);
	free(path);
	if (!text)
		goto out;

	next = text;
	while ((curr = strsep(&next, "\n"))) {
		line_split(curr, &argc, &argv);
		if (argc > 0 && *(argv[0]) == '/') {
			devnode = devnode_from_node(argv[0], err_ignore);
			if (devnode)
				ptrlist_add(list, devnode);
		}
		line_free(argc, argv);
	}


out:
	free(text);

	return list;
}

static void add_swap(struct util_list *list)
{
	struct util_list *swapdevs;
	struct ptrlist_node *swap;
	struct devnode *devnode;
	struct resource *res;
	struct util_list *selected;
	struct selected_dev_node *sel;
	char *r;

	swapdevs = get_swapdevs();

	util_list_iterate(swapdevs, swap) {
		devnode = swap->ptr;
		selected = selected_dev_list_new();

		/* Determine list of devices providing mountpoint. */
		if (select_by_devnode(NULL, selected, config_active,
				      scope_mandatory, NULL, NULL, devnode,
				      NULL, err_ignore) != EXIT_OK)
			goto next;

		/* Process list. */
		util_list_iterate(selected, sel) {
			if (sel->rc != EXIT_OK || !sel->st || !sel->id)
				continue;

			r = misc_asprintf("Swap device %s", devnode->name);
			res = resource_new(sel->st, sel->id, r);
			free(r);
			ptrlist_add(list, res);

			/* Expand list to also contain prereq-devices. */
			subtype_add_prereqs(sel->st, sel->id, selected);
		}

next:
		selected_dev_list_free(selected);
	}

	ptrlist_free(swapdevs, 1);
}


/* Determine IPv4 and IPv6 addresses of networking interface @name. */
static void add_ip_addresses(struct util_list *addrs, const char *name)
{
	char *cmd, *text, *next, *curr, **argv;
	int argc;

	cmd = misc_asprintf("%s address show %s 2>/dev/null", PATH_IP, name);
	text = misc_read_cmd_output(cmd, 0, err_ignore);
	if (!text)
		goto out;

	next = text;
	while ((curr = strsep(&next, "\n"))) {
		line_split(curr, &argc, &argv);
		if (argc < 2)
			goto next;
		if (strcmp(argv[0], "inet") == 0)
			strlist_add(addrs, "IPv4 address %s", argv[1]);
		else if (strcmp(argv[0], "inet6") == 0)
			strlist_add(addrs, "IPv6 address %s", argv[1]);
next:
		line_free(argc, argv);

	}

out:
	free(text);
	free(cmd);
}

/* Add struct resources to @list for each device providing an interface with
 * IP address. */
static void add_network(struct util_list *list)
{
	char *path;
	struct util_list *interfaces, *addrs, *selected;
	struct strlist_node *net, *addr;
	struct selected_dev_node *sel;
	struct resource *res;

	path = path_get_sys_class("net", NULL);
	interfaces = strlist_new();

	if (!misc_read_dir(path, interfaces, NULL, NULL))
		goto out;

	/* Process all known networking interfaces. */
	util_list_iterate(interfaces, net) {
		/* Skip loopback. */
		if (strcmp(net->str, "lo") == 0)
			continue;

		selected = NULL;

		/* Determine IP addresses. */
		addrs = strlist_new();
		add_ip_addresses(addrs, net->str);
		if (util_list_is_empty(addrs))
			goto next;

		/* Get z Systems specific devices. */
		selected = selected_dev_list_new();
		if (select_by_interface(NULL, selected, config_active,
					scope_mandatory, NULL, NULL,
					net->str, err_ignore) != EXIT_OK)
			goto next;

		/* Process devices. */
		util_list_iterate(selected, sel) {
			if (sel->rc != EXIT_OK || !sel->st || !sel->id)
				continue;

			/* Add one resource per IP address provided. */
			util_list_iterate(addrs, addr) {
				res = resource_new(sel->st, sel->id, addr->str);
				ptrlist_add(list, res);
			}

			/* Expand list to also contain prereq-devices. */
			subtype_add_prereqs(sel->st, sel->id, selected);
		}

next:
		selected_dev_list_free(selected);
		strlist_free(addrs);
	}

out:
	strlist_free(interfaces);
	free(path);
}

/* Return a ptrlist of struct resources of Linux devices which are in use
 * by the system. The following devices are considered:
 *  - block devices providing a mounted file system
 *  - block devices providing swap space
 *  - networking interfaces providing an IP address. */
static struct util_list *get_resources(void)
{
	struct util_list *list;

	list = ptrlist_new();

	/* Add all devices providing mounted file systems. */
	add_mounts(list);

	/* Add all devices providing swap space. */
	add_swap(list);

	/* Add all devices providing networking interfaces in the up state. */
	add_network(list);

	return list;
}

/* Return a strlist of names of resources that are provided by device @dev
 * or %NULL if device is not in use. */
struct util_list *inuse_get_resources(struct device *dev)
{
	struct subtype *st = dev->subtype;
	struct resource *res;
	struct ptrlist_node *p;
	struct util_list *list;

	/* Filter out offline devices. */
	if (subtype_online_get(st, dev, config_active) != 1)
		return NULL;

	/* Match device against list of devices that are in use. */
	if (!resources)
		resources = get_resources();

	list = strlist_new();
	util_list_iterate(resources, p) {
		res = p->ptr;
		if (res->st == dev->subtype && strcmp(res->id, dev->id) == 0)
			strlist_add_unique(list, "%s", res->name);
	}

	/* Make handling of empty lists easier for caller. */
	if (util_list_is_empty(list)) {
		strlist_free(list);
		list = NULL;
	}

	return list;
}
