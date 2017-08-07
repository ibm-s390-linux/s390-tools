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

#include "devnode.h"
#include "findmnt.h"
#include "misc.h"

#define FINDMNT_CMDLINE	"findmnt -n -T %s -o SOURCE 2>/dev/null"

static struct devnode *devnode_from_line(const char *line)
{
	char *copy, *end;
	struct devnode *devnode;

	copy = misc_strdup(line);

	/* Could be /dev/sda[/subvolname] */
	end = strchr(copy, '[');
	if (end)
		*end = 0;

	devnode = devnode_from_node(copy, err_ignore);

	free(copy);

	return devnode;
}

/* Return a newly allocated ptrlist containing all devnodes that provide
 * the file system on which @path is located. Return %NULL if no devnodes
 * were found. We need this in addition to lsblk output because lsblk doesn't
 * work with btrfs subvolumes. */
struct util_list *findmnt_get_devnodes_by_path(const char *path)
{
	struct util_list *devnodes;
	char *quoted_path, *cmd, *output, *next, *curr;
	struct devnode *devnode;

	devnodes = ptrlist_new();
	quoted_path = quote_str(path, 1);
	cmd = misc_asprintf(FINDMNT_CMDLINE, quoted_path);

	output = misc_read_cmd_output(cmd, 0, err_ignore);
	if (!output)
		goto out;

	/* Iterate over each line. */
	next = output;
	while ((curr = strsep(&next, "\n"))) {
		devnode = devnode_from_line(curr);
		if (devnode)
			ptrlist_add(devnodes, devnode);
	}

out:
	free(output);
	free(cmd);
	free(quoted_path);

	/* Make empty list detection easier for calling function. */
	if (util_list_is_empty(devnodes)) {
		ptrlist_free(devnodes, 1);
		devnodes = NULL;
	}

	return devnodes;
}
