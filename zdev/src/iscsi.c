/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <string.h>

#include "devnode.h"
#include "iscsi.h"
#include "misc.h"
#include "path.h"

/* Retrieve the IP address of the iSCSI initiator networking portal associated
 * with block device @blkdev. */
static char *ip_from_blockdev(struct devnode *blkdev)
{
	char *link, *curr, *end, *path = NULL, *ip = NULL;

	link = devnode_readlink(blkdev);
	if (!link)
		return NULL;

	/* ../../devices/platform/host0/session1/target0:0:0/0:0:0:1/... */
	curr = strstr(link, "/devices/");
	if (!curr)
		goto out;
	curr++;

	/* curr=devices/platform/host0/session1/target0:0:0/0:0:0:1/... */
	end = strstr(curr, "/session");
	if (!end)
		goto out;
	*end = 0;

	/* curr=devices/platform/host0 */
	end = strstr(curr, "/host");
	if (!end)
		goto out;
	end++;

	/* curr=devices/platform/host0
	 * end=host0 */
	path = path_get("/sys/%s/iscsi_host/%s/ipaddress", curr, end);
	ip = misc_read_text_file(path, 0, err_ignore);

out:
	free(path);
	free(link);

	return ip;
}

static struct devnode *netdev_from_ip(char *ip)
{
	char *cmd, *text, *dev, *end;
	struct devnode *devnode = NULL;

	cmd = misc_asprintf("%s -o address show to %s 2>/dev/null", PATH_IP,
			    ip);
	text = misc_read_cmd_output(cmd, 0, err_ignore);
	if (!text)
		goto out;

	/* text=2: enccw0.0.f5f0    inet ... */
	for (dev = text; *dev && !isspace(*dev); dev++);

	/* dev= enccw0.0.f5f0    inet ... */
	for (; isspace(*dev); dev++);

	/* dev=enccw0.0.f5f0    inet ... */
	for (end = dev; *end && !isspace(*end); end++);
	if (end == dev)
		goto out;
	*end = 0;

	/* dev=enccw0.0.f5f0 */
	devnode = devnode_new(NETDEV, 0, 0, dev);

out:
	free(cmd);
	free(text);

	return devnode;
}

/* Retrieve the networking device devnode that provides the specified
 * iSCSI block device @blkdev. */
struct devnode *iscsi_get_net_devnode(struct devnode *blkdev)
{
	struct devnode *devnode = NULL;
	char *ip;

	if (blkdev->type != BLOCKDEV)
		return NULL;

	ip = ip_from_blockdev(blkdev);
	if (!ip)
		return NULL;

	devnode = netdev_from_ip(ip);

	free(ip);

	return devnode;
}
