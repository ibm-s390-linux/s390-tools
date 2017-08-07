/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef CCW_H
#define CCW_H

#include <inttypes.h>

#include "lib/ccw.h"

#include "devtype.h"
#include "exit_code.h"
#include "misc.h"
#include "setting.h"
#include "subtype.h"

#define CCW_BUS_NAME		"ccw"
#define CCW_CHPID_NUM		8
#define CCW_CHPID_MASK(i)	(1 << (CCW_CHPID_NUM - (i) - 1))
#define CCW_CHPID_MAX		255

struct attrib;
struct namespace;
struct subtype;

/**
 * ccw_chpid - Channel-Path ID
 * @cssid: Channel Subsystem ID
 * @id: CHPID number
 */
struct ccw_chpid {
	uint8_t cssid;
	uint8_t id;
} __attribute__ ((packed));

/**
 * ccw_devinfo - CCW device information
 * @devid: CCW device ID
 * @chpids: CHPID list
 * @pim: Path-Installed-Mask
 * @exists: Non-zero if CCW device exists
 */
struct ccw_devinfo {
	struct ccw_devid devid;
	struct ccw_chpid chpids[CCW_CHPID_NUM];
	unsigned int cutype:16;
	unsigned int devtype:16;
	unsigned int cumodel:8;
	unsigned int devmodel:8;
	unsigned int pim:8;
	unsigned int exists:1;
	unsigned int grouped:1;
};

/**
 * ccw_subtype_data - CCW subtype specific information
 * @ccwdrv: The name of the CCW device driver for this subtype
 * @mod: The name of the main kernel module for this subtype
 */
struct ccw_subtype_data {
	const char *ccwdrv;
	const char *mod;
};

extern struct attrib ccw_attr_online;
extern struct attrib ccw_attr_online_force;
extern struct attrib ccw_attr_cmb_enable;

/* CCW device ID namespace. */
extern struct namespace ccw_namespace;

/* CCW device subtype. */
extern struct subtype ccw_subtype;

/* Attribute related. */
int ccw_online_only_order_cmp(struct setting *, struct setting *);
bool ccw_online_only_check(struct setting *, struct setting *, config_t);
int ccw_offline_only_order_cmp(struct setting *, struct setting *);
bool ccw_offline_only_check(struct setting *, struct setting *, config_t);

/* Misc. */
void ccw_exit(void);
void cio_settle(int);
bool ccw_exists(const char *, const char *, const char *);
void ccw_get_ids(const char *, const char *, struct util_list *);
char *ccw_get_driver(struct ccw_devid *);
exit_code_t ccw_unbind_device(struct ccw_devid *);
exit_code_t ccw_bind_device(struct ccw_devid *, const char *);

/* ID handling. */
exit_code_t ccw_parse_devid(struct ccw_devid *, const char *, err_t);
bool ccw_parse_devid_simple(struct ccw_devid *, const char *);
bool ccw_is_id_similar(const char *);
char *ccw_normalize_id(const char *);
char *ccw_devid_to_str(struct ccw_devid *);
int ccw_cmp_devids(struct ccw_devid *, struct ccw_devid *);
int ccw_devid_distance(struct ccw_devid *, struct ccw_devid *);
bool ccw_devid_in_range(struct ccw_devid *, struct ccw_devid *,
			    struct ccw_devid *);
struct ccw_devid *ccw_copy_devid(struct ccw_devid *);

/* Blacklist handling. */
bool ccw_is_blacklist_active(void);
bool ccw_is_id_blacklisted(const char *);
bool ccw_is_id_range_blacklisted(const char *);
void ccw_unblacklist_id(const char *);
void ccw_unblacklist_id_range(const char *);
exit_code_t ccw_blacklist_persist(void);

/* CCW device information handling. */
void ccw_devinfo_print(struct ccw_devinfo *, int);
struct ccw_devinfo *ccw_devinfo_get(struct ccw_devid *, int);
int ccw_devinfo_chpids_cmp(struct ccw_devinfo *, struct ccw_devinfo *);
int ccw_devinfo_cutype_cmp(struct ccw_devinfo *, struct ccw_devinfo *);
int ccw_devinfo_devtype_cmp(struct ccw_devinfo *, struct ccw_devinfo *);

#endif /* CCW_H */
