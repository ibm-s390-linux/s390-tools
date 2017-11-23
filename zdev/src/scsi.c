/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_path.h"

#include "misc.h"
#include "path.h"
#include "scsi.h"
#include "zfcp_lun.h"

struct scsi_hctl_devid {
	unsigned int host;
	unsigned int channel;
	unsigned int target;
	uint64_t lun;
};

struct scsi_zfcp {
	struct scsi_hctl_devid scsi;
	struct zfcp_lun_devid zfcp;
};

static struct util_list *scsi_zfcp_list;

static char *scsi_hctl_devid_to_str(struct scsi_hctl_devid *devid)
{
	return misc_asprintf("%u:%u:%u:%" PRIu64, devid->host, devid->channel,
			     devid->target, devid->lun);
}

/* Used for debugging. */
void scsi_zfcp_print(struct scsi_zfcp *s, int i)
{
	char *scsi, *zfcp;

	indent(i, "scsi_zfcp at %p:\n", (void *) s);
	i += 2;
	scsi = scsi_hctl_devid_to_str(&s->scsi);
	zfcp = zfcp_lun_devid_to_str(&s->zfcp);
	indent(i, "scsi=%s\n", scsi);
	indent(i, "zfcp=%s\n", zfcp);
	free(zfcp);
	free(scsi);
}

void scsi_reread(void)
{
	ptrlist_free(scsi_zfcp_list, 1);
	scsi_zfcp_list = NULL;
}

void scsi_exit(void)
{
	ptrlist_free(scsi_zfcp_list, 1);
}

static bool scsi_hctl_parse_devid(struct scsi_hctl_devid *id, const char *str)
{
	unsigned int host, channel, target;
	uint64_t lun;
	char dummy;

	if (sscanf(str, "%u:%u:%u:%" SCNu64 " %c", &host, &channel, &target,
		   &lun, &dummy) != 4)
		return false;

	if (id) {
		id->host = host;
		id->channel = channel;
		id->target = target;
		id->lun = lun;
	}

	return true;
}

/* Retrieve CCW device ID of HBA for specified SCSI device path. */
static char *devpath_to_hba_id(const char *path)
{
	char *copy, *start, *end, *hba_id = NULL;

	copy = misc_strdup(path);

	/* copy=/devices/css0/0.0.001c/0.0.1940/host0/... */
	end = strstr(copy, "/host");
	if (!end)
		goto out;
	*end = 0;
	/* copy=/devices/css0/0.0.001c/0.0.1940 */
	start = strrchr(copy, '/');
	if (!start)
		goto out;
	start++;
	hba_id = misc_strdup(start);

out:
	free(copy);

	return hba_id;
}

/* Retrieve WWPN from specified SCSI device path. */
static char *devpath_to_wwpn(const char *devpath)
{
	char *copy, *rport, *end, *path = NULL, *wwpn = NULL;

	/* devpath=/devices/css0/0.0.001c/0.0.1940/host0/rport-0:0-16/
	 *          target0:0:16/0:0:16:1085030433/ */
	copy = misc_strdup(devpath);
	rport = strstr(copy, "/rport-");
	end = skip_comp(rport);
	if (!end)
		goto out;
	*end = 0;

	/* devpath=/devices/css0/0.0.001c/0.0.1940/host0/rport-0:0-16
	 * rport=rport-0:0-16 */
	path = path_get("/sys%s/fc_remote_ports%s/port_name", copy, rport);
	wwpn = misc_read_text_file(path, 1, err_ignore);

out:
	free(path);
	free(copy);

	return wwpn;
}

static unsigned int lun_swap[] = { 6, 7, 4, 5 };

uint64_t scsi_lun_to_fcp_lun(uint64_t lun)
{
	byte_swap((uint8_t *) &lun, lun_swap, ARRAY_SIZE(lun_swap));

	return lun;
}

uint64_t scsi_lun_from_fcp_lun(uint64_t lun)
{
	byte_swap((uint8_t *) &lun, lun_swap, ARRAY_SIZE(lun_swap));

	return lun;
}

/* Retrieve FCP LUN from specified HCTL. */
static char *hctl_to_fcp_lun(const char *hctl)
{
	struct scsi_hctl_devid devid;

	if (!scsi_hctl_parse_devid(&devid, hctl))
		return NULL;

	return misc_asprintf("0x%016" PRIx64, scsi_lun_to_fcp_lun(devid.lun));
}

/* Retrieve FCP LUN from specified SCSI device path. Works with paths to
 * SCSI device and sub-directories (required for paths from /sys/dev/block and
 * /sys/dev/char). */
static char *devpath_to_fcp_lun(const char *devpath)
{
	char *hctl, *fcp_lun = NULL;

	hctl = scsi_hctl_from_devpath(devpath);
	if (hctl) {
		fcp_lun = hctl_to_fcp_lun(hctl);
		free(hctl);
	}

	return fcp_lun;
}

/* Try to determine the zfcp LUN ID from the specified zfcp SCSI device path. */
static char *devpath_to_zfcp_lun_id(const char *path)
{
	const char *devpath;
	char *hba_id, *wwpn, *fcp_lun, *zfcp_lun_id = NULL;

	devpath = strstr(path, "/devices/");
	if (!devpath)
		return NULL;

	hba_id = devpath_to_hba_id(devpath);
	wwpn = devpath_to_wwpn(devpath);
	fcp_lun = devpath_to_fcp_lun(devpath);

	if (hba_id && wwpn && fcp_lun)
		zfcp_lun_id = misc_asprintf("%s:%s:%s", hba_id, wwpn, fcp_lun);

	free(fcp_lun);
	free(wwpn);
	free(hba_id);

	return zfcp_lun_id;
}

/* Return the zfcp LUN ID from the specified SCSI HCTL ID. */
char *scsi_hctl_to_zfcp_lun_id(const char *hctl)
{
	char *buspath, *link = NULL, *zfcp_lun_id = NULL;

	buspath = path_get_sys_bus_dev("scsi", hctl);
	link = misc_readlink(buspath);
	if (!link)
		goto out;

	zfcp_lun_id = devpath_to_zfcp_lun_id(link);

out:
	free(link);
	free(buspath);

	return zfcp_lun_id;
}

static exit_code_t add_ids_cb(const char *path, const char *name, void *data)
{
	struct util_list *list = data;
	struct scsi_hctl_devid scsi_devid;
	struct zfcp_lun_devid zfcp_devid;
	char *zfcp_id;
	struct scsi_zfcp *s;

	if (starts_with(name, "host") || starts_with(name, "target"))
		return EXIT_OK;
	if (!scsi_hctl_parse_devid(&scsi_devid, name))
		return EXIT_OK;
	zfcp_id = scsi_hctl_to_zfcp_lun_id(name);
	if (!zfcp_id)
		return EXIT_OK;
	if (zfcp_lun_parse_devid(&zfcp_devid, zfcp_id, err_ignore) == EXIT_OK) {
		s = misc_malloc(sizeof(struct scsi_zfcp));
		s->scsi = scsi_devid;
		s->zfcp = zfcp_devid;
		ptrlist_add(list, s);
	}
	free(zfcp_id);

	return EXIT_OK;
}

static struct util_list *read_scsi_zfcp_list(void)
{
	struct util_list *list;
	char *path;

	list = ptrlist_new();
	path = path_get_sys_bus_dev("scsi", NULL);
	if (util_path_is_dir(path))
		path_for_each(path, add_ids_cb, list);
	free(path);

	return list;
}

static struct scsi_zfcp *get_scsi_zfcp(struct zfcp_lun_devid *devid)
{
	struct ptrlist_node *p;
	struct scsi_zfcp *s;

	if (!scsi_zfcp_list)
		scsi_zfcp_list = read_scsi_zfcp_list();

	/* Search for zfcp LUN device ID in cached list. */
	util_list_iterate(scsi_zfcp_list, p) {
		s = p->ptr;
		if (zfcp_lun_cmp_devids(&s->zfcp, devid) == 0)
			return s;
	}

	return NULL;
}

/* Check for SCSI device associated with zfcp lun device @devid. Return newly
 * allocated HCTL ID of SCSI device on success, %NULL on failure. */
char *scsi_hctl_from_zfcp_lun_devid(struct zfcp_lun_devid *devid)
{
	struct scsi_zfcp *s;

	s = get_scsi_zfcp(devid);
	if (s)
		return scsi_hctl_devid_to_str(&s->scsi);

	return NULL;
}

/* Check for SCSI device associated with zfcp LUN device @id. Return newly
 * allocated HCTL ID of SCSI device on success, %NULL on failure. */
char *scsi_hctl_from_zfcp_lun_id(const char *id)
{
	struct zfcp_lun_devid devid;

	if (zfcp_lun_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return NULL;

	return scsi_hctl_from_zfcp_lun_devid(&devid);
}

/* Check if SCSI device exists for zfcp LUN @id. */
bool scsi_hctl_exists(const char *id)
{
	struct zfcp_lun_devid devid;

	if (zfcp_lun_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		return false;

	if (!get_scsi_zfcp(&devid))
		return false;

	return true;
}

/* Add zfcp LUN ids for all SCSI devices to strlist @list. */
void scsi_hctl_add_zfcp_lun_ids(struct util_list *list)
{
	struct ptrlist_node *p;
	struct scsi_zfcp *s;
	char *id;

	if (!scsi_zfcp_list)
		scsi_zfcp_list = read_scsi_zfcp_list();

	util_list_iterate(scsi_zfcp_list, p) {
		s = p->ptr;
		id = zfcp_lun_devid_to_str(&s->zfcp);
		strlist_add(list, id);
		free(id);
	}
}

/* Return SCSI HCTL ID from SCSI device path. Works with paths to SCSI device
 * and sub-directories (required for paths from /sys/dev/block and
 * /sys/dev/char). */
char *scsi_hctl_from_devpath(const char *path)
{
	char *copy, *start, *end, *hctl = NULL;

	/* ../../devices/css0/0.0.001c/0.0.1940/host0/rport-0:0-16/
	 * target0:0:16/0:0:16:1085030433/ */
	copy = misc_strdup(path);
	start = strstr(copy, "/target");
	start = skip_comp(start);
	if (!start)
		goto out;
	start++;
	end = strchr(start, '/');
	if (end)
		*end = 0;
	hctl = misc_strdup(start);

out:
	free(copy);

	return hctl;
}
