/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "lib/util_path.h"

#include "devnode.h"
#include "misc.h"
#include "path.h"

/* Create a newly allocated devnode object from the specified data. */
struct devnode *devnode_new(devnode_t type, unsigned int major,
			    unsigned int minor, const char *name)
{
	struct devnode *devnode;
	size_t len;

	len = strlen(name);
	devnode = misc_malloc(sizeof(struct devnode) + len + 1);
	devnode->type = type;
	devnode->major = major;
	devnode->minor = minor;
	memcpy(devnode->name, name, len);

	return devnode;
}

struct devnode *devnode_copy(struct devnode *d)
{
	return devnode_new(d->type, d->major, d->minor, d->name);
}

/* Used for debugging. */
void devnode_print(struct devnode *devnode, int level)
{
	printf("%*sdevnode at %p\n", level, "", (void *) devnode);
	level += 2;
	printf("%*stype=%d\n", level, "", devnode->type);
	printf("%*smajor=%d\n", level, "", devnode->major);
	printf("%*sminor=%d\n", level, "", devnode->minor);
	printf("%*sname=%s\n", level, "", devnode->name);
}

/* Create a newly allocated devnode object from a device special file. */
struct devnode *devnode_from_node(const char *path, err_t err)
{
	struct stat s;
	const char *name;

	if (stat(path, &s)) {
		err_t_print(err, "Could not get information for %s: %s\n",
			    path, strerror(errno));
		return NULL;
	}
	if (!S_ISBLK(s.st_mode) && !S_ISCHR(s.st_mode)) {
		err_t_print(err, "File is not a device special file: %s\n",
			    path);
		return NULL;
	}
	name = strrchr(path, '/');
	if (name)
		name++;
	else
		name = path;

	return devnode_new(S_ISBLK(s.st_mode) ? BLOCKDEV : CHARDEV,
			   major(s.st_rdev), minor(s.st_rdev), name);
}

/* Create a newly allocated devnode object from a sysfs dev file containing
 * major:minor data in text form. */
struct devnode *devnode_from_devfile(const char *path, const char *name,
				     devnode_t type)
{
	char *dev, *syspath = NULL;
	struct devnode *devnode = NULL;
	unsigned int major, minor;

	if (!path) {
		syspath = path_get_sys_block_dev(name);
		path = syspath;
	}

	dev = misc_read_text_file(path, 1, err_ignore);
	if (!dev)
		goto out;

	if (sscanf(dev, "%u:%u", &major, &minor) == 2)
		devnode = devnode_new(type, major, minor, name);

out:
	free(dev);
	free(syspath);

	return devnode;
}

/* Create a newly allocated devnode object from a major:minor combination. */
static struct devnode *devnode_from_majmin(devnode_t type, unsigned int major,
					   unsigned int minor)
{
	char *path, *link, *name;
	struct devnode *devnode = NULL;

	switch (type) {
	case BLOCKDEV:
		path = path_get_sys_dev_block(major, minor);
		break;
	case CHARDEV:
		path = path_get_sys_dev_char(major, minor);
		break;
	default:
		return NULL;
	}
	link = misc_readlink(path);
	if (!link)
		goto out;

	name = strrchr(link, '/');
	if (name)
		name++;
	else
		name = link;

	devnode = devnode_new(type, major, minor, name);

out:
	free(link);
	free(path);

	return devnode;
}

/* Return a devnode that represents the device on which path is located. */
struct devnode *devnode_from_path(const char *path)
{
	struct stat s;

	if (stat(path, &s))
		return NULL;

	return devnode_from_majmin(BLOCKDEV, major(s.st_dev), minor(s.st_dev));
}

/* Compare two devnodes by type, major and minor. Return:
 * -1: a < b
 *  1: a > b
 *  0: a == b
 **/
int devnode_cmp(struct devnode *a, struct devnode *b)
{
	if (a->type < b->type)
		return -1;
	if (a->type > b->type)
		return 1;
	if (a->type == BLOCKDEV || a->type == CHARDEV) {
		/* Block and character devices are compared by maj:min only. */
		if (a->major < b->major)
			return -1;
		if (a->major > b->major)
			return 1;
		if (a->minor < b->minor)
			return -1;
		if (a->minor > b->minor)
			return 1;
	} else {
		/* Network interfaces are compared by name only. */
		return strcmp(a->name, b->name);
	}

	return 0;
}

struct add_cb_data {
	struct util_list *list;
	int num;
	const char *prefix;
};

static exit_code_t add_part_cb(const char *path, const char *filename,
			       void *data)
{
	struct add_cb_data *cb_data = data;
	struct devnode *node;
	char *devpath;

	if (!starts_with(filename, cb_data->prefix))
		return EXIT_OK;

	devpath = misc_asprintf("%s/dev", path);
	node = devnode_from_devfile(devpath, filename, BLOCKDEV);
	free(devpath);
	if (node) {
		ptrlist_add(cb_data->list, node);
		cb_data->num++;
	}

	return EXIT_OK;
}

/* Add block device names to ptrlist found in @DATA. Note: the first entry
 * is always the main block device - when available, partitions will be
 * reported second. */
static exit_code_t add_block_cb(const char *path, const char *filename,
				void *data)
{
	struct add_cb_data *cb_data = data;
	struct devnode *node;
	char *devpath;

	/* Add main node. */
	devpath = misc_asprintf("%s/dev", path);
	node = devnode_from_devfile(devpath, filename, BLOCKDEV);
	free(devpath);
	if (!node)
		return EXIT_OK;
	ptrlist_add(cb_data->list, node);
	cb_data->num++;

	/* Add additional nodes. */
	cb_data->prefix = filename;
	if (util_path_is_dir(path))
		path_for_each(path, add_part_cb, cb_data);

	return EXIT_OK;
}

/* Add devnode objects to ptrlist LIST. Each devnode object represents one
 * block device node that is provided by the device found at sysfs path PATH.
 * Return the number of added objects. */
int devnode_add_block_from_sysfs(struct util_list *list, const char *path)
{
	struct add_cb_data cb_data;
	char *blkpath;

	cb_data.list = list;
	cb_data.num = 0;
	cb_data.prefix = NULL;

	blkpath = misc_asprintf("%s/block", path);
	if (util_path_is_dir(blkpath))
		path_for_each(blkpath, add_block_cb, &cb_data);
	free(blkpath);

	return cb_data.num;
}

static exit_code_t add_net_cb(const char *path, const char *filename,
			      void *data)
{
	struct add_cb_data *cb_data = data;
	struct devnode *node;

	/* Add main node. */
	node = devnode_new(NETDEV, 0, 0, filename);
	ptrlist_add(cb_data->list, node);
	cb_data->num++;

	return EXIT_OK;
}

/* Add devnode objects to ptrlist LIST. Each devnode object represents one
 * network interface that is provided by the device found at sysfs path PATH.
 * Return the number of added objects. */
int devnode_add_net_from_sysfs(struct util_list *list, const char *path)
{
	struct add_cb_data cb_data;
	char *netpath;

	cb_data.list = list;
	cb_data.num = 0;
	cb_data.prefix = NULL;

	netpath = misc_asprintf("%s/net", path);
	if (util_path_is_dir(netpath))
		path_for_each(netpath, add_net_cb, &cb_data);
	free(netpath);

	return cb_data.num;
}

/* Return the contents of the link in /sys/dev/ for @devnode or %NULL if the
 * link could not be read. */
char *devnode_readlink(struct devnode *devnode)
{
	char *path, *link;

	switch (devnode->type) {
	case BLOCKDEV:
		path = path_get_sys_dev_block(devnode->major, devnode->minor);
		break;
	case CHARDEV:
		path = path_get_sys_dev_char(devnode->major, devnode->minor);
		break;
	case NETDEV:
		path = path_get_sys_class("net", devnode->name);
		break;
	default:
		return NULL;
	}
	link = misc_readlink(path);
	free(path);

	return link;
}
