/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <dirent.h>

#include "attrib.h"
#include "ccw.h"
#include "ccwgroup.h"
#include "devnode.h"
#include "devtype.h"
#include "internal.h"
#include "namespace.h"
#include "path.h"
#include "subtype.h"
#include "virtio.h"

/* must be negative and distinct from other virtio-ccw types */
#define VIRTIO_CCW_GENERIC_ID (-1)

struct ccw_subtype_data_virtio {
	struct ccw_subtype_data orig_data; /* must be first */
	int virtio_idx;
};

static struct subtype *virtio_ccw_find_st_by_idx(int virtio_device_type)
{
	struct subtype *other_st;

	for (int i = 0; (other_st = virtio_devtype.subtypes[i]); i++) {
		struct ccw_subtype_data_virtio *other_subtype_data =
			other_st->data;

		if (virtio_device_type == other_subtype_data->virtio_idx)
			return other_st;
	}
	return NULL;
}

static bool virtio_ccw_exists(struct subtype *st, const char *id, int fast)
{
	struct ccw_subtype_data_virtio *st_data = st->data;
	struct ccw_devinfo *devinfo = NULL;
	struct ccw_devid devid;
	int virtio_device_type;
	char *drv = NULL;
	bool rc = false;

	if (ccw_parse_devid(&devid, id, err_ignore) != EXIT_OK)
		goto out;

	if (!fast && !ccw_exists(NULL, NULL, id))
		goto out;

	drv = ccw_get_driver(&devid);

	if (!drv)
		goto out;

	if (strcmp(drv, "virtio_ccw")) {
		/* not virtio_ccw */
		goto out_free_drv;
	}

	devinfo = ccw_devinfo_get(&devid, false);

	if (!devinfo->exists)
		goto out_free_devinfo;

	virtio_device_type = devinfo->cumodel;

	if (st_data->virtio_idx == VIRTIO_CCW_GENERIC_ID) {
		/* generic virtio-ccw
		 * rc = true iff device type not found in subtype list
		 */
		rc = !virtio_ccw_find_st_by_idx(virtio_device_type);
	} else {
		/* not generic virtio-ccw
		 * device type must match that of current subtype
		 */
		rc = (virtio_device_type == st_data->virtio_idx);
	}

out_free_devinfo:
	free(devinfo);

out_free_drv:
	free(drv);

out:
	return rc;
}

static bool virtio_ccw_st_exists_active(struct subtype *st, const char *id)
{
	return virtio_ccw_exists(st, id, 0);
}

static bool get_ids_cb(const char *file, void *data)
{
	/* We use fast=1 here to prevent another stat() syscall per device
	 * when we already know that the directory exists. */
	return virtio_ccw_exists(data, file, 1);
}

static void virtio_ccw_st_add_active_ids(struct subtype *st,
					 struct util_list *ids)
{
	char *path;

	cio_settle(0);
	path = path_get_ccw_devices(NULL);
	misc_read_dir(path, ids, get_ids_cb, st);
	free(path);
}

#define DEF_VIRTIO_TYPE(type__, idx__, desc__, modname__)                      \
	static struct ccw_subtype_data_virtio virtio_##type__##_data = {       \
		.orig_data = { .mod = modname__,                               \
			       .ccwdrv = "virtio_ccw",                         \
			       .any_driver = false },                          \
		.virtio_idx = idx__                                            \
	};                                                                     \
	static struct subtype virtio_##type__##_subtype = {                    \
		.super = &ccw_subtype,                                         \
		.devtype = &virtio_devtype,                                    \
		.name = "virtio-" #type__,                                     \
		.title = desc__,                                               \
		.devname = "Virtual I/O device",                               \
		.modules = STRING_ARRAY(modname__),                            \
		.namespace = &ccw_namespace,                                   \
		.data = &virtio_##type__##_data,                               \
		.dev_attribs = ATTRIB_ARRAY(&ccw_attr_online,                  \
					    &ccw_attr_cmb_enable,              \
					    &internal_attr_early, ),           \
		.exists_active = virtio_ccw_st_exists_active,                  \
		.add_active_ids = virtio_ccw_st_add_active_ids,                \
		.unknown_dev_attribs = 1,                                      \
	}

DEF_VIRTIO_TYPE(ccw, VIRTIO_CCW_GENERIC_ID,
		"Virtual I/O devices (unknown subtype)", "virtio_ccw");
DEF_VIRTIO_TYPE(net, 1, "Virtual I/O network devices", "virtio_net");
DEF_VIRTIO_TYPE(blk, 2, "Virtual I/O block devices", "virtio_blk");
DEF_VIRTIO_TYPE(console, 3, "Virtual I/O console devices", "virtio_console");
DEF_VIRTIO_TYPE(rng, 4, "Virtual I/O rng devices", "virtio_rng");
DEF_VIRTIO_TYPE(balloon, 5, "Virtual I/O balloon devices", "virtio_balloon");
DEF_VIRTIO_TYPE(scsi, 8, "Virtual I/O scsi devices", "virtio_scsi");
DEF_VIRTIO_TYPE(9p, 9, "Virtual I/O 9p devices", "9pnet_virtio");
DEF_VIRTIO_TYPE(rproc_serial, 11, "Virtual I/O rproc-serial devices",
		"virtio_console");
DEF_VIRTIO_TYPE(gpu, 16, "Virtual I/O gpu devices", "virtio_gpu");
DEF_VIRTIO_TYPE(input, 18, "Virtual I/O input devices", "virtio_input");
DEF_VIRTIO_TYPE(vsock, 19, "Virtual I/O vsock devices",
		"vmw_vsock_virtio_transport");
DEF_VIRTIO_TYPE(crypto, 20, "Virtual I/O crypto devices", "virtio_crypto");
DEF_VIRTIO_TYPE(mem, 24, "Virtual I/O memory devices", "virtio_mem");
DEF_VIRTIO_TYPE(fs, 26, "Virtual I/O fs devices", "virtio_fs");

/*
 * Virtio devtype methods.
 */

/* Clean up all resources used by devtype object. */
static void virtio_devtype_exit(struct devtype *dt)
{
	setting_list_free(dt->active_settings);
	setting_list_free(dt->persistent_settings);
}

static exit_code_t virtio_devtype_read_settings(struct devtype *dt,
						config_t config)
{
	/* No kernel or module parameters exist for the virtio device driver,
	 * but at least determine module loaded state. */
	dt->active_settings = setting_list_new();
	dt->persistent_settings = setting_list_new();

	if (SCOPE_ACTIVE(config))
		dt->active_exists = devtype_is_module_loaded(dt);

	return EXIT_OK;
}

static exit_code_t virtio_devtype_write_settings(struct devtype *dt,
						 config_t config)
{
	/* No kernel or module parameters exist for the virtio device driver. */

	return EXIT_OK;
}

/*
 * Virtio devtype.
 */

struct devtype virtio_devtype = {
	.name = "virtio",
	.title = "Virtual I/O (virtio) Channel-Command-Word devices",
	.devname = "Virtual I/O",

	/* Subtypes here are generated with the DEF_VIRTIO_TYPE macro. */
	.subtypes = SUBTYPE_ARRAY(
			&virtio_9p_subtype,
			&virtio_balloon_subtype,
			&virtio_blk_subtype,
			&virtio_console_subtype,
			&virtio_crypto_subtype,
			&virtio_fs_subtype,
			&virtio_gpu_subtype,
			&virtio_input_subtype,
			&virtio_mem_subtype,
			&virtio_net_subtype,
			&virtio_rng_subtype,
			&virtio_rproc_serial_subtype,
			&virtio_scsi_subtype,
			&virtio_vsock_subtype,
			&virtio_ccw_subtype,
	),

	.type_attribs = ATTRIB_ARRAY(),

	.exit = &virtio_devtype_exit,

	.read_settings = &virtio_devtype_read_settings,
	.write_settings = &virtio_devtype_write_settings,
};
