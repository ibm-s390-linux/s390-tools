/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "devtype.h"
#include "lib/util_libc.h"
#include "misc.h"
#include "path.h"
#include "zfcp.h"
#include "zfcp_lun.h"

#define	PATH_MODE		(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

struct base_prefix {
	char *from;
	char *to;
};

/* prlist of struct base_prefix sorted descending by prefix length. */
static struct util_list *base_prefixes;

/* Add an entry to the prefix list. */
static void prefix_add(const char *key, const char *value)
{
	struct base_prefix *prefix, *curr;
	size_t len;
	struct ptrlist_node *p;

	prefix = misc_malloc(sizeof(struct base_prefix));
	prefix->from = misc_strdup(key);
	prefix->to = misc_strdup(value);

	/* Add to list according to length. */
	if (!base_prefixes)
		base_prefixes = ptrlist_new();
	len = strlen(key);
	p = NULL;
	util_list_iterate(base_prefixes, p) {
		curr = p->ptr;
		if (strlen(curr->from) < len)
			break;
	}
	if (p)
		ptrlist_add_before(base_prefixes, p, prefix);
	else
		ptrlist_add(base_prefixes, prefix);
}

/* Initialize the prefix list from a strlist. */
void path_set_base(struct util_list *base)
{
	struct strlist_node *s;
	char *copy, *value;

	if (!base)
		return;
	util_list_iterate(base, s) {
		copy = misc_strdup(s->str);
		value = strchr(copy, '=');
		if (value) {
			*value = 0;
			value++;
			prefix_add(copy, value);
		} else {
			prefix_add("", copy);
		}
		free(copy);
	}
}

/* Release the prefix list. */
void path_exit(void)
{
	struct ptrlist_node *p, *n;
	struct base_prefix *prefix;

	if (!base_prefixes)
		return;
	util_list_iterate_safe(base_prefixes, p, n) {
		util_list_remove(base_prefixes, p);
		prefix = p->ptr;
		free(prefix->from);
		free(prefix->to);
		free(prefix);
		free(p);
	}
	free(base_prefixes);
	base_prefixes = NULL;
}

/* Modify @path according to specified prefix conversion. */
static void apply_base(char **path)
{
	struct ptrlist_node *p;
	struct base_prefix *prefix;
	char *new_path;

	if (!base_prefixes)
		return;
	util_list_iterate(base_prefixes, p) {
		prefix = p->ptr;
		if (!starts_with(*path, prefix->from))
			continue;

		new_path = misc_asprintf("%s%s", prefix->to,
					 *path + strlen(prefix->from));
		free(*path);
		*path = new_path;
		break;
	}
}

/* Return a path that is created by resolving the specified format string
 * @fmt and applying any base prefixes. */
char *path_get(const char *fmt, ...)
{
	va_list args;
	char *path;

	/* Get original path. */
	va_start(args, fmt);
	if (vasprintf(&path, fmt, args) == -1)
		oom();
	va_end(args);

	/* Apply base prefix if necessary. */
	apply_base(&path);

	return path;
}

/* Create all directories leading up to path. */
exit_code_t path_create(const char *path)
{
	char *copy, *curr, *next;
	struct stat s;
	int rc;

	copy = misc_strdup(path);
	curr = (*copy == '/') ? copy + 1 : copy;
	curr = strchr(curr, '/');
	if (!curr) {
		free(copy);
		return EXIT_OK;
	}

	do {
		next = strchr(curr + 1, '/');

		*curr = 0;
		/* Ensure sub-path exists and is a directory. */
		rc = stat(copy, &s);
		if (rc == -1 && errno == EACCES)
			goto err_access;
		if (rc == 0 && !S_ISDIR(s.st_mode))
			goto err_file;
		if (rc == -1) {
			/* Create directory. */
			rc = mkdir(copy, PATH_MODE);
			if (rc)
				goto err_mkdir;
		}

		*curr = '/';
		curr = next;
	} while (curr);

	free(copy);

	return EXIT_OK;

err_access:
	error("Could not access '%s'\n", copy);
	free(copy);
	return EXIT_RUNTIME_ERROR;

err_file:
	error("Non-directory found in path '%s': %s\n", path, copy);
	free(copy);
	return EXIT_RUNTIME_ERROR;

err_mkdir:
	error("Could not create directory '%s': %s\n", copy, strerror(errno));
	free(copy);
	return EXIT_RUNTIME_ERROR;
}

/* Return path to modprobe.conf file for the specified device type. */
char *path_get_modprobe_conf(struct devtype *dt)
{
	return path_get("%s/%s-%s.conf", PATH_MODPROBE_CONF, MODPROBE_PREFIX,
			dt->name);
}

/* Return sysfs path to module directory. */
char *path_get_sys_module(const char *mod)
{
	return path_get("/sys/module/%s", mod);
}

/* Return sysfs path to module parameter file. */
char *path_get_sys_module_param(const char *mod, const char *name)
{
	if (name)
		return path_get("/sys/module/%s/parameters/%s", mod, name);

	return path_get("/sys/module/%s/parameters", mod);
}

/* Return sysfs path to block device dev file. */
char *path_get_sys_block_dev(const char *name)
{
	return path_get("/sys/block/%s/dev", name);
}

/* Return sysfs path to /sys/dev/block/major:minor directory. */
char *path_get_sys_dev_block(unsigned int major, unsigned int minor)
{
	return path_get("/sys/dev/block/%d:%d", major, minor);
}

/* Return sysfs path to /sys/dev/char/major:minor directory. */
char *path_get_sys_dev_char(unsigned int major, unsigned int minor)
{
	return path_get("/sys/dev/char/%d:%d", major, minor);
}

/* Return sysfs path to /sys/dev/char directory. */
char *path_get_sys_dev_char_devices(void)
{
	return path_get("/sys/dev/char");
}

/* Return sysfs path to class directory. */
char *path_get_sys_class(const char *class, const char *name)
{
	if (name)
		return path_get("/sys/class/%s/%s", class, name);

	return path_get("/sys/class/%s", class);
}

/* Return path to modprobe executable. */
char *path_get_modprobe(void)
{
	return path_get("%s", PATH_MODPROBE);
}

/* Return sysfs path to CCW device. */
char *path_get_ccw_device(const char *drv, const char *id)
{
	if (drv)
		return path_get("%s/drivers/%s/%s", PATH_CCW_BUS, drv, id);

	return path_get("%s/devices/%s", PATH_CCW_BUS, id);
}

/* Return sysfs path to directory containing all CCW devices. */
char *path_get_ccw_devices(const char *drv)
{
	if (drv)
		return path_get("%s/drivers/%s/", PATH_CCW_BUS, drv);

	return path_get("%s/devices/", PATH_CCW_BUS);
}

/* Return sysfs path to CCWGROUP device. */
char *path_get_ccwgroup_device(const char *drv, const char *id)
{
	if (drv)
		return path_get("%s/drivers/%s/%s", PATH_CCWGROUP_BUS, drv, id);

	return path_get("%s/devices/%s", PATH_CCWGROUP_BUS, id);
}

/* Return sysfs path to directory containing all CCWGROUP devices. */
char *path_get_ccwgroup_devices(const char *drv)
{
	if (drv)
		return path_get("%s/drivers/%s/", PATH_CCWGROUP_BUS, drv);

	return path_get("%s/devices/", PATH_CCWGROUP_BUS);
}

/* Return path to udev rule. */
char *path_get_udev_rule(const char *type, const char *id, bool vol)
{
	const char *path = vol ? PATH_UDEV_RULES_VOLATILE : PATH_UDEV_RULES;

	if (id) {
		return path_get("%s/%s-%s-%s%s", path,
				UDEV_PREFIX, type, id, UDEV_SUFFIX);
	}

	return path_get("%s/%s-%s%s", path,
			UDEV_PREFIX, type, UDEV_SUFFIX);
}

/* Return path to directory containing all udev rules. */
char *path_get_udev_rules(bool vol)
{
	const char *path = vol ? PATH_UDEV_RULES_VOLATILE : PATH_UDEV_RULES;

	return path_get("%s", path);
}

/* Return path to the specified file in the proc file system. */
char *path_get_proc(const char *filename)
{
	return path_get("%s/%s", PATH_PROC, filename);
}

/* Call a function for each entry in a directory:
 * exit_code_t callback(const char *abs_path, const char *rel_path, void *data)
 * Aborts when callback returns any value other than EXIT_OK.
 */
exit_code_t path_for_each(const char *path,
			  exit_code_t (*callback)(const char *, const char *,
						  void *), void *data)
{
	DIR *dir;
	struct dirent *de;
	char *p;
	exit_code_t rc = EXIT_OK;

	dir = opendir(path);
	if (!dir) {
		warn("Could not open directory %s: %s\n", path,
		     strerror(errno));
		return EXIT_RUNTIME_ERROR;
	}
	while (rc == EXIT_OK && (de = readdir(dir))) {
		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;
		p = path_get("%s/%s", path, de->d_name);
		rc = callback(p, de->d_name, data);
		free(p);
	}

	closedir(dir);

	return rc;
}

/* Return sysfs path to device or devices directory. */
char *path_get_sys_bus_dev(const char *bus, const char *id)
{
	if (!id)
		return path_get("/sys/bus/%s/devices", bus);

	return path_get("/sys/bus/%s/devices/%s", bus, id);
}

/* Return sysfs path to scsi drivers directory. */
char *path_get_sys_bus_drv(const char *bus, const char *drv)
{
	if (!drv)
		return path_get("/sys/bus/%s/drivers", bus);

	return path_get("/sys/bus/%s/drivers/%s", bus, drv);
}

/* Return sysfs path to zFCP LUN directory. */
char *path_get_zfcp_lun_dev(struct zfcp_lun_devid *id)
{
	return path_get("%s/drivers/%s/%x.%x.%04x/0x%016" PRIx64
			"/0x%016" PRIx64, PATH_CCW_BUS,
			ZFCP_CCWDRV_NAME, id->fcp_dev.cssid,
			id->fcp_dev.ssid, id->fcp_dev.devno, id->wwpn, id->lun);
}

/* Return sysfs path to zFCP target port directory. */
char *path_get_zfcp_port_dev(struct zfcp_lun_devid *id)
{
	return path_get("%s/drivers/%s/%x.%x.%04x/0x%016" PRIx64,
			PATH_CCW_BUS, ZFCP_CCWDRV_NAME,
			id->fcp_dev.cssid, id->fcp_dev.ssid,
			id->fcp_dev.devno, id->wwpn);
}

/* Return sysfs path to SCSI device directory. */
char *path_get_scsi_hctl_dev(const char *hctl)
{
	return path_get("/sys/bus/scsi/devices/%s", hctl);
}

/* Return sysfs path to a bus attribute */
char *path_get_bus_attr(const char *bus, const char *attr)
{
	return path_get("/sys/bus/%s/%s", bus, attr);
}

/* Read text file from adjusted path. */
char *path_read_text_file(int chomp, err_t err, char *fmt, ...)
{
	char *path, *path2, *text;
	va_list args;

	va_start(args, fmt);
	util_vasprintf(&path, fmt, args);
	va_end(args);
	path2 = path_get(path);
	text = misc_read_text_file(path2, chomp, err);
	free(path2);
	free(path);

	return text;
}
