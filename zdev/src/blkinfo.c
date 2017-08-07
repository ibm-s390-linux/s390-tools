/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blkinfo.h"
#include "devnode.h"
#include "misc.h"

#define LSBLK_CMDLINE	"lsblk -P -o NAME,MAJ:MIN,FSTYPE,UUID,MOUNTPOINT,PKNAME 2>/dev/null"

struct blkinfo {
	struct devnode *devnode;
	char *fstype;
	char *uuid;
	char *mountpoint;
	char *parent;
};

static struct util_list *cached_blkinfos;

static struct blkinfo *blkinfo_new(const char *name, const char *majmin,
				   const char *fstype, const char *uuid,
				   const char *mountpoint, const char *parent)
{
	struct blkinfo *blkinfo;
	unsigned int major, minor;

	blkinfo = misc_malloc(sizeof(struct blkinfo));
	if (name && majmin) {
		if (sscanf(majmin, "%u:%u", &major, &minor) == 2) {
			blkinfo->devnode = devnode_new(BLOCKDEV, major, minor,
						       name);
		}
	}
	if (fstype && *fstype)
		blkinfo->fstype = misc_strdup(fstype);
	if (uuid && *uuid)
		blkinfo->uuid = misc_strdup(uuid);
	if (mountpoint && *mountpoint)
		blkinfo->mountpoint = misc_strdup(mountpoint);
	if (parent && *parent)
		blkinfo->parent = misc_strdup(parent);

	return blkinfo;
}

static void blkinfo_free(struct blkinfo *blkinfo)
{
	if (!blkinfo)
		return;
	free(blkinfo->devnode);
	free(blkinfo->fstype);
	free(blkinfo->uuid);
	free(blkinfo->mountpoint);
	free(blkinfo->parent);
	free(blkinfo);
}

/* Used for debugging. */
void blkinfo_print(struct blkinfo *blkinfo, int level)
{
	printf("%*sblkinfo at %p\n", level, "", (void *) blkinfo);
	level += 2;
	if (blkinfo->devnode)
		devnode_print(blkinfo->devnode, level);
	if (blkinfo->fstype)
		printf("%*sfstype=%s\n", level, "", blkinfo->fstype);
	if (blkinfo->uuid)
		printf("%*suuid=%s\n", level, "", blkinfo->uuid);
	if (blkinfo->mountpoint)
		printf("%*smountpoint=%s\n", level, "", blkinfo->mountpoint);
	if (blkinfo->parent)
		printf("%*sparent=%s\n", level, "", blkinfo->parent);
}

static char *isolate_keyword(char **line_ptr, const char *keyword)
{
	char *start, *end;

	start = strstr(*line_ptr, keyword);
	if (!start)
		return NULL;
	start += strlen(keyword);
	end = start;
	while (*end && *end != '"')
		end++;
	if (*end) {
		*end = 0;
		*line_ptr = end + 1;
	} else
		*line_ptr = end;

	return start;
}

static struct blkinfo *blkinfo_from_line(char *line)
{
	char *name, *majmin, *fstype, *uuid, *mountpoint, *parent;

	name		= isolate_keyword(&line, "NAME=\"");
	majmin		= isolate_keyword(&line, "MAJ:MIN=\"");
	fstype		= isolate_keyword(&line, "FSTYPE=\"");
	uuid		= isolate_keyword(&line, "UUID=\"");
	mountpoint	= isolate_keyword(&line, "MOUNTPOINT=\"");
	parent		= isolate_keyword(&line, "PKNAME=\"");

	return blkinfo_new(name, majmin, fstype, uuid, mountpoint, parent);
}

static struct util_list *blkinfos_read(void)
{
	char *output, *curr, *next;
	struct util_list *blkinfos;
	struct blkinfo *blkinfo;

	if (cached_blkinfos)
		return cached_blkinfos;

	output = misc_read_cmd_output(LSBLK_CMDLINE, 0, 1);
	if (!output)
		return NULL;

	blkinfos = ptrlist_new();

	/* Iterate over each line. */
	next = output;
	while ((curr = strsep(&next, "\n"))) {
		blkinfo = blkinfo_from_line(curr);
		if (blkinfo)
			ptrlist_add(blkinfos, blkinfo);
	}

	free(output);

	cached_blkinfos = blkinfos;

	return blkinfos;
}

static void blkinfos_free(struct util_list *blkinfos)
{
	struct ptrlist_node *p, *n;

	if (!blkinfos)
		return;

	util_list_iterate_safe(blkinfos, p, n) {
		util_list_remove(blkinfos, p);
		blkinfo_free(p->ptr);
		free(p);
	}
	free(blkinfos);
}

/* Used for debugging. */
void blkinfos_print(struct util_list *blkinfos, int level)
{
	struct ptrlist_node *p;

	printf("%*sblkinfos at %p\n", level, "", (void *) blkinfos);
	if (!blkinfos)
		return;
	level += 2;
	util_list_iterate(blkinfos, p)
		blkinfo_print(p->ptr, level);
}

/* Find a blkinfo for the specified devnode or NULL of none was found. */
static struct blkinfo *blkinfo_get_by_devnode(struct devnode *devnode)
{
	struct util_list *blkinfos;
	struct ptrlist_node *p;
	struct blkinfo *b;

	blkinfos = blkinfos_read();
	if (!blkinfos)
		return NULL;

	/* Get UUID for the specified devnode. */
	util_list_iterate(blkinfos, p) {
		b = p->ptr;
		if (b->devnode && devnode_cmp(b->devnode, devnode) == 0)
			return b;
	}

	return NULL;
}

/* Find a blkinfo for the specified device name or NULL if none was found. */
static struct blkinfo *blkinfo_get_by_name(const char *name)
{
	struct util_list *blkinfos;
	struct ptrlist_node *p;
	struct blkinfo *b;

	blkinfos = blkinfos_read();
	if (!blkinfos)
		return NULL;

	/* Get UUID for the specified devnode. */
	util_list_iterate(blkinfos, p) {
		b = p->ptr;
		if (b->devnode && strcmp(b->devnode->name, name) == 0)
			return b;
	}

	return NULL;
}

/* Find a blkinfo for the specified major+minor or NULL if none was found. */
static struct blkinfo *blkinfo_get_by_majmin(unsigned int major,
					     unsigned int minor)
{
	struct util_list *blkinfos;
	struct ptrlist_node *p;
	struct blkinfo *b;

	blkinfos = blkinfos_read();
	if (!blkinfos)
		return NULL;

	/* Get UUID for the specified devnode. */
	util_list_iterate(blkinfos, p) {
		b = p->ptr;
		if (b->devnode && b->devnode->major == major &&
		    b->devnode->minor == minor)
			return b;
	}

	return NULL;
}

/* Return a newly allocated ptrlist of devnodes of block devices which are
 * ancestors of the specified block device or NULL if no ancestors are found.
 * An ancestor is a block device which is the parent of another block device
 * according to lsblk data. */
struct util_list *blkinfo_get_ancestor_devnodes(struct devnode *devnode)
{
	struct util_list *blkinfos;
	struct util_list *todos, *result;
	struct util_list *done;
	struct devnode *curr, *p_devnode;
	struct blkinfo *blkinfo, *parent;
	struct ptrlist_node *p_curr, *p;
	int num_parents;

	blkinfos = blkinfos_read();
	if (!blkinfos)
		return NULL;

	todos = ptrlist_new();
	result = ptrlist_new();
	done = strlist_new();

	/* Repeat the resolution process until only devices with no parent
	 * remain. */
	ptrlist_add(todos, devnode_copy(devnode));
	while ((p_curr = util_list_start(todos))) {
		util_list_remove(todos, p_curr);
		curr = p_curr->ptr;
		free(p_curr);

		/* Check for parents. */
		num_parents = 0;
		util_list_iterate(blkinfos, p) {
			blkinfo = p->ptr;
			if (!blkinfo->devnode || !blkinfo->parent)
				continue;
			if (devnode_cmp(blkinfo->devnode, curr) != 0)
				continue;
			parent = blkinfo_get_by_name(blkinfo->parent);
			if (parent && parent->devnode)
				goto add;

			/* Try to resolve name to major:minor. */
			p_devnode = devnode_from_devfile(NULL, blkinfo->parent,
							 BLOCKDEV);
			if (!p_devnode)
				continue;
			parent = blkinfo_get_by_majmin(p_devnode->major,
						       p_devnode->minor);
			free(p_devnode);
			if (!parent || !parent->devnode)
				continue;

add:
			ptrlist_add(todos, devnode_copy(parent->devnode));
			num_parents++;
		}

		if (num_parents == 0 && devnode_cmp(curr, devnode) != 0 &&
		    !strlist_find(done, curr->name)) {
			/* Add device with no parent to results (except for
			 * the initially specified device). */
			ptrlist_add(result, curr);
			strlist_add(done, curr->name);
		} else
			free(curr);
	}
	ptrlist_free(todos, 0);
	strlist_free(done);

	/* Check if any ancestors were found. */
	if (util_list_is_empty(result)) {
		ptrlist_free(result, 0);
		return NULL;
	}

	return result;
}

/* Return a newly allocated ptrlist of devnodes of block devices which have
 * the same file system UUID and type or NULL if no such devices are found. */
struct util_list *blkinfo_get_same_uuid_devnodes(struct devnode *devnode)
{
	struct util_list *blkinfos;
	struct util_list *devnodes;
	struct ptrlist_node *p;
	struct blkinfo *b;
	char *uuid;

	blkinfos = blkinfos_read();
	if (!blkinfos)
		return NULL;

	b = blkinfo_get_by_devnode(devnode);
	if (!b)
		return NULL;

	uuid = b->uuid;
	if (!uuid)
		return NULL;

	/* Get all devnodes of devices with the same UUID. */
	devnodes = ptrlist_new();
	util_list_iterate(blkinfos, p) {
		b = p->ptr;
		if (!b->devnode || !b->uuid)
			continue;
		if (strcmp(b->uuid, uuid) != 0)
			continue;
		if (devnode_cmp(b->devnode, devnode) == 0)
			continue;
		ptrlist_add(devnodes, devnode_copy(b->devnode));
	}

	if (util_list_is_empty(devnodes)) {
		strlist_free(devnodes);
		devnodes = NULL;
	}

	return devnodes;
}

/* Check mountpoints in blkinfo for an entry that provides path. */
struct devnode *blkinfo_get_devnode_by_path(const char *path)
{
	struct util_list *blkinfos;
	struct ptrlist_node *p;
	struct blkinfo *b, *match = NULL;
	size_t blen, mlen = 0;

	blkinfos = blkinfos_read();
	if (!blkinfos)
		return NULL;

	util_list_iterate(blkinfos, p) {
		b = p->ptr;
		if (!b->devnode || !b->mountpoint)
			continue;
		blen = strlen(b->mountpoint);

		/* path:       /path/to/file
		 * mountpoint: /path */
		if (strncmp(path, b->mountpoint, blen) != 0)
			continue;
		if (path[blen] && path[blen] != '/')
			continue;

		/* Ensure longest match. */
		if (!match || blen > mlen) {
			match = b;
			mlen = blen;
		}
	}

	return match ? devnode_copy(match->devnode) : NULL;
}

/* Add list of mountpoints for mounted file systems to strlist @list. */
void blkinfo_add_mountpoints(struct util_list *list)
{
	struct util_list *blkinfos;
	struct ptrlist_node *p;
	struct blkinfo *b;

	blkinfos = blkinfos_read();
	if (!blkinfos)
		return;

	util_list_iterate(blkinfos, p) {
		b = p->ptr;
		if (!b->devnode || !b->mountpoint || *b->mountpoint != '/')
			continue;
		strlist_add_unique(list, b->mountpoint);
	}
}

/* Add list of newly allocated devnodes for active swap devices to ptrlist
 * @list. */
void blkinfo_add_swap_devnodes(struct util_list *list)
{
	struct util_list *blkinfos;
	struct ptrlist_node *p;
	struct blkinfo *b;

	blkinfos = blkinfos_read();
	if (!blkinfos)
		return;

	util_list_iterate(blkinfos, p) {
		b = p->ptr;
		if (!b->devnode || !b->mountpoint ||
		    strcmp(b->mountpoint, "[SWAP]") != 0)
			continue;
		ptrlist_add(list, devnode_copy(b->devnode));
	}
}

void blkinfo_exit(void)
{
	blkinfos_free(cached_blkinfos);
}
