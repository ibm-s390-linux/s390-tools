/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PATH_H
#define PATH_H PATH_H

#include "lib/zt_common.h"

#include "exit_code.h"
#include "misc.h"

#define	MODPROBE_PREFIX		"s390x"
#define UDEV_PREFIX		"41"
#define	UDEV_SUFFIX		".rules"

#define	PATH_MODPROBE_CONF	"/etc/modprobe.d"
#define PATH_MODPROBE		"/usr/sbin/modprobe"
#define PATH_CCW_BUS		"/sys/bus/ccw"
#define PATH_CCWGROUP_BUS	"/sys/bus/ccwgroup"
#define PATH_UDEV_RULES		"/etc/udev/rules.d"
#define	PATH_PROC		"/proc"

#define PATH_UDEVADM		"udevadm"
#define PATH_VMCP		TOOLS_BINDIR "/vmcp"
#define PATH_IP			"ip"

#define PATH_ROOT		"/"
#define PATH_ROOT_SCRIPT	TOOLS_LIBDIR "/zdev-root-update"

struct devtype;
struct zfcp_lun_devid;
struct util_list;

void path_exit(void);
void path_set_base(struct util_list *);

exit_code_t path_create(const char *);
char *path_get(const char *, ...);
char *path_get_modprobe_conf(struct devtype *);
char *path_get_sys_module(const char *);
char *path_get_sys_module_param(const char *, const char *);
char *path_get_sys_block_dev(const char *);
char *path_get_sys_dev_block(unsigned int, unsigned int);
char *path_get_sys_dev_char(unsigned int, unsigned int);
char *path_get_sys_dev_char_devices(void);
char *path_get_sys_class(const char *, const char *);
char *path_get_modprobe(void);
char *path_get_ccw_device(const char *, const char *);
char *path_get_ccw_devices(const char *);
char *path_get_ccwgroup_device(const char *, const char *);
char *path_get_ccwgroup_devices(const char *);
char *path_get_udev_rule(const char *, const char *);
char *path_get_udev_rules(void);
char *path_get_proc(const char *);
char *path_get_sys_bus_dev(const char *, const char *);
char *path_get_sys_bus_drv(const char *, const char *);
char *path_get_zfcp_lun_dev(struct zfcp_lun_devid *);
char *path_get_zfcp_port_dev(struct zfcp_lun_devid *);
char *path_get_scsi_hctl_dev(const char *);

exit_code_t path_for_each(const char *,
			  exit_code_t (*callback)(const char *, const char *,
						  void *), void *);

#endif /* PATH_H */
