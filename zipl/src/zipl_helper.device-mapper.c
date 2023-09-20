/*
 *
 * zipl_helper.device-mapper: print zipl parameters for a device-mapper device
 *
 * Copyright IBM Corp. 2009, 2017
 * Copyright Red Hat Inc. 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * Depending on the name by which the script is called, it serves one of two
 * purposes:
 *
 * 1. Usage: zipl_helper.device-mapper <target directory> or
 *                                     <major:minor of target device>
 *
 * This tool attempts to obtain zipl parameters for a target directory or
 * partition located on a device-mapper device. It assumes that the
 * device-mapper table for this device conforms to the following rules:
 * - directory is located on a device consisting of a single device-mapper
 *   target
 * - only linear, mirror and multipath targets are supported
 * - supported physical device types are DASD and SCSI devices
 * - all of the device which contains the directory must be located on a single
 *   physical device (which may be mirrored or accessed through a multipath
 *   target)
 * - any mirror in the device-mapper setup must include block 0 of the
 *   physical device
 *
 * 2. Usage: chreipl_helper.device-mapper <major:minor of target device>
 *
 * This tool identifies the physical device which contains the specified
 * device-mapper target devices. If the physical device was found, its
 * major:minor parameters are printed. Otherwise, the script exits with an
 * error message and a non-zero return code.
 *
 */

#include <errno.h>
#include <limits.h>
#include <linux/limits.h>
#include <locale.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>

#include "lib/dasd_base.h"
#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_path.h"
#include "lib/util_proc.h"

#define WARN(...) \
	fprintf(stderr, "Warning: " __VA_ARGS__)

#define ERR(...) \
	fprintf(stderr, "Error: " __VA_ARGS__)

struct target_status {
	char *path;
	char status;
	struct util_list_node list;
};

struct target_data {
	dev_t device;
	unsigned long start;
	struct util_list_node list;
};

struct target {
	unsigned long start;
	unsigned long length;
	unsigned short type;
	struct util_list *data;
	struct util_list_node list;
};

/* "extended" device */
struct ext_dev {
	dev_t dev;
	unsigned long fs_off; /* file system start */
};

struct dmpath_entry {
	struct ext_dev dev;
	struct target *target;
	struct util_list_node list;
};

struct device_characteristics {
	unsigned short type;
	unsigned int blocksize;
	unsigned long bootsectors;
	unsigned long partstart;
	struct hd_geometry geo;
};

struct physical_device {
	unsigned long offset;
	struct util_list *dmpath;
	struct device_characteristics dc;
};

enum driver_id {
	DM_DRIVER_ID,
	LAST_DRIVER_ID
};

enum util_id {
	ZIPL_UTIL_ID,
	CHREIPL_UTIL_ID,
	LAST_UTIL_ID
};

struct helper {
	int util_id;
	int driver_id;
	const char *name;
	int (*check_usage)(int argc, char *argv[]);
	int (*print_params)(char *argv[], struct helper *h);
};

/* From include/linux/fs.h */
#define BDEVNAME_SIZE 32

/* Constants */
#define SECTOR_SIZE 512
#define DASD_PARTN_MASK 0x03
#define SCSI_PARTN_MASK 0x0f

/* Internal constants */
enum dev_type {
	DEV_TYPE_CDL = 0,
	DEV_TYPE_LDL,
	DEV_TYPE_FBA,
	DEV_TYPE_SCSI
};

enum target_type {
	TARGET_TYPE_LINEAR = 0,
	TARGET_TYPE_MIRROR,
	TARGET_TYPE_MULTIPATH
};

enum lookup_result {
	DM_LOOKUP_ERROR,
	DM_EMPTY_TABLE,
	DM_NO_TARGET,
	DM_SINGLE_TARGET,
	DM_MULTIPLE_TARGETS
};

static void get_type_name(char *name, unsigned short type)
{
	switch (type) {
	case DEV_TYPE_SCSI:
		strcpy(name, "SCSI");
		break;
	case DEV_TYPE_CDL:
		strcpy(name, "CDL");
		break;
	case DEV_TYPE_FBA:
		strcpy(name, "FBA");
		break;
	case DEV_TYPE_LDL:
		strcpy(name, "LDL");
		break;
	default:
		name[0] = '\0';
		WARN("Unrecognized dev type %d\n", type);
	}
}

static FILE *exec_cmd_and_get_out_stream(const char *fmt, ...)
{
	FILE *stream;
	va_list ap;
	char *cmd;

	va_start(ap, fmt);
	util_vasprintf(&cmd, fmt, ap);
	va_end(ap);

	stream = popen(cmd, "r");
	if (stream == NULL)
		WARN("'%s' failed\n", cmd);
	free(cmd);

	return stream;
}

static struct target_data *target_data_new(unsigned int maj, unsigned int min,
					   unsigned int start)
{
	struct target_data *td = util_malloc(sizeof(struct target_data));

	td->device = makedev(maj, min);
	td->start = start;

	return td;
}

static void target_data_free(struct target_data *td)
{
	free(td);
}

static void target_data_list_free(struct util_list *data)
{
	struct target_data *td, *n;

	util_list_iterate_safe(data, td, n) {
		util_list_remove(data, td);
		target_data_free(td);
	}
	util_list_free(data);
}

static struct target *target_new(unsigned long start, unsigned long length,
				 unsigned short type, struct util_list *data)
{
	struct target *entry = util_malloc(sizeof(struct target));

	entry->start = start;
	entry->length = length;
	entry->type = type;
	entry->data = data;

	return entry;
}

static void target_free(struct target *target)
{
	target_data_list_free(target->data);
	free(target);
}

static unsigned long target_get_start(struct target *target)
{
	struct target_data *td = util_list_start(target->data);

	return target->start + td->start;
}

/*
 * Return the first device from those that constitute the logical TARGET
 */
static dev_t first_device_by_target_data(struct target *target)
{
	struct target_data *td = util_list_start(target->data);

	return td->device;
}

static struct dmpath_entry *dmpath_entry_new(struct ext_dev *dev,
					     struct target *target)
{
	struct dmpath_entry *de = util_malloc(sizeof(struct dmpath_entry));

	de->dev = *dev;
	de->target = target;
	return de;
}

static void dmpath_entry_free(struct dmpath_entry *entry)
{
	target_free(entry->target);
	free(entry);
}

static void dmpath_free(struct util_list *dmpath)
{
	struct dmpath_entry *de, *n;

	util_list_iterate_safe(dmpath, de, n) {
		util_list_remove(dmpath, de);
		dmpath_entry_free(de);
	}
	util_list_free(dmpath);
}

static struct dmpath_entry *dmpath_get_first_by_type(struct util_list *dmpath,
						     unsigned short type)
{
	struct dmpath_entry *te;

	util_list_iterate(dmpath, te) {
		if (te->target->type == type)
			return te;
	}

	return NULL;
}

static void get_device_name(char *devname, dev_t dev)
{
	struct util_proc_part_entry entry;

	if (util_proc_part_get_entry(dev, &entry) == 0) {
		strcpy(devname, entry.name);
		util_proc_part_free_entry(&entry);
	} else {
		sprintf(devname, "%u:%u", major(dev), minor(dev));
	}
}

static int create_temp_device_node(char *name, unsigned int major,
				   unsigned int minor)
{
	const char path_base[] = "/dev";
	char buf[PATH_MAX];
	int n;

	for (n = 0; n < 100; n++) {
		snprintf(buf, sizeof(buf), "%s/zipl-dm-temp-%02d", path_base, n);
		if (util_path_exists(buf))
			continue;
		if (mknod(buf, S_IFBLK, makedev(major, minor)) != 0)
			continue;
		strcpy(name, buf);

		return 0;
	}

	ERR("Could not create temporary device node in '%s'\n", path_base);

	return -1;
}

static long get_partition_start(unsigned int major, unsigned int minor)
{
	unsigned long val;

	if (!util_path_is_dir("/sys/dev/block/%u:%u", major, minor))
		return -1;

	if (util_file_read_ul(&val, 10, "/sys/dev/block/%u:%u/start",
			      major, minor) != 0) {
		return 0;
	}

	return val;
}

static int get_dev_characteristics(struct device_characteristics *dc, dev_t dev)
{
	char devname[PATH_MAX];
	dasd_information2_t info;
	long pstart;

	if (create_temp_device_node(devname, major(dev), minor(dev)) != 0)
		return -1;

	if (dasd_get_blocksize(devname, &dc->blocksize) != 0) {
		ERR("Could not get block size for '%s'\n", devname);
		goto err;
	}

	if (dasd_get_info(devname, &info) != 0) {
		/* Assume SCSI if dasdinfo failed */
		dc->type = DEV_TYPE_SCSI;
		/* First block contains IPL records */
		dc->bootsectors = dc->blocksize / SECTOR_SIZE;
	} else {
		if (dasd_get_geo(devname, &dc->geo) != 0) {
			ERR("Could not get geo info for '%s'\n", devname);
			goto err;
		}

		if (strncmp(info.type, "FBA", 3) == 0) {
			dc->type = DEV_TYPE_FBA;
			dc->bootsectors = dc->blocksize / SECTOR_SIZE;
		} else if (strncmp(info.type, "ECKD", 4) == 0) {
			if (info.format == 1) {
				dc->type = DEV_TYPE_LDL;
				dc->bootsectors = dc->blocksize * 2 /
					SECTOR_SIZE;
			} else if (info.format == 2) {
				dc->type = DEV_TYPE_CDL;
				dc->bootsectors = dc->blocksize *
					dc->geo.sectors / SECTOR_SIZE;
			}
		}
	}
	pstart = get_partition_start(major(dev), minor(dev));
	if (pstart < 0) {
		ERR("Could not determine partition start for '%s'\n",
		    devname);
		goto err;
	}
	dc->partstart = pstart / (dc->blocksize / SECTOR_SIZE);

	unlink(devname);

	return 0;

err:
	unlink(devname);

	return -1;
}

static struct util_list *get_linear_data(const char *devname, char *args)
{
	unsigned int major, minor, start;
	struct util_list *data;

	if (sscanf(args, "%u:%u %u", &major, &minor, &start) < 3) {
		ERR("Unrecognized device-mapper table format for device '%s'\n",
		    devname);
		return NULL;
	}

	data = util_list_new(struct target_data, list);
	util_list_add_tail(data, target_data_new(major, minor, start));

	return data;
}

#define STR_TOKEN_OR_GOTO(string, tok, label)				\
	do {								\
		tok = strtok(string, " ");				\
		if (tok == NULL) {					\
			goto label;					\
		}							\
	} while (0)

#define NEXT_STR_TOKEN_OR_GOTO(tok, label)				\
	STR_TOKEN_OR_GOTO(NULL, tok, label)

#define INT_TOKEN_OR_GOTO(string, tok, label)				\
	do {								\
		char *tp = strtok(string, " ");				\
		if (tp == NULL) {					\
			goto label;					\
		}							\
		errno = 0;						\
		tok = strtol(tp, NULL, 10);				\
		if (errno != 0) {					\
			goto label;					\
		}							\
	} while (0)

#define NEXT_INT_TOKEN_OR_GOTO(tok, label)				\
	INT_TOKEN_OR_GOTO(NULL, tok, label)

#define SKIP_TOKEN_OR_GOTO(string, label)				\
	do {								\
		if (strtok(string, " ") == NULL) {			\
			goto label;					\
		}							\
	} while (0)

#define SKIP_NEXT_TOKEN_OR_GOTO(label)					\
	SKIP_TOKEN_OR_GOTO(NULL, label)

#define SKIP_NEXT_TOKENS_OR_GOTO(count, label)				\
	do {								\
		int i;							\
		for (i = 0; i < count; i++) {				\
			SKIP_NEXT_TOKEN_OR_GOTO(label);			\
		}							\
	} while (0)

/*
 * There is no kernel documentation for the mirror target. Parameters obtained
 * from Linux sources: drivers/md/dm-log.c and drivers/md/dm-raid1.c
 *
 * <starting_sector> <length> mirror \
 * <log_type> <#log_args> <log_arg1>...<log_argN> \
 * <#devs> <device_name_1> <offset_1>...<device name N> <offset N> \
 * <#features> <feature_1>...<feature_N>
 */
static struct util_list *get_mirror_data(const char *devname, char *args)
{
	struct util_list *data = util_list_new(struct target_data, list);
	long nlogs, ndevs, nfeats, base_offset = -1;

	SKIP_TOKEN_OR_GOTO(args, out); /* log_type */
	NEXT_INT_TOKEN_OR_GOTO(nlogs, out); /* #log_args */
	SKIP_NEXT_TOKENS_OR_GOTO(nlogs, out); /* log_args* */
	NEXT_INT_TOKEN_OR_GOTO(ndevs, out);

	for (; ndevs > 0; ndevs--) {
		unsigned int major, minor;
		long offset;
		char *name;

		NEXT_STR_TOKEN_OR_GOTO(name, out);
		if (sscanf(name, "%u:%u", &major, &minor) < 2)
			goto out;
		NEXT_INT_TOKEN_OR_GOTO(offset, out);
		if ((base_offset >= 0) && (offset != base_offset)) {
			ERR("Unsupported setup: Mirror target on device '%s' "
			    "contains entries with varying sector offsets\n",
			    devname);
			goto out2;
		} else {
			base_offset = offset;
		}
		util_list_add_tail(data, target_data_new(major, minor, offset));
	}
	NEXT_INT_TOKEN_OR_GOTO(nfeats, out);
	SKIP_NEXT_TOKENS_OR_GOTO(nfeats, out);

	return data;

out:
	ERR("Unrecognized device-mapper table format for device '%s'\n", devname);
out2:
	target_data_list_free(data);

	return NULL;
}

static struct target_status *target_status_new(const char *path, char status)
{
	struct target_status *ts = util_malloc(sizeof(struct target_status));

	ts->path = util_strdup(path);
	ts->status = status;

	return ts;
}

static void target_status_free(struct target_status *ts)
{
	free(ts->path);
	free(ts);
}

static void status_list_free(struct util_list *status)
{
	struct target_status *ts, *n;

	util_list_iterate_safe(status, ts, n) {
		util_list_remove(status, ts);
		target_status_free(ts);
	}
	util_list_free(status);
}

static char status_list_get_status(struct util_list *status, const char *node)
{
	struct target_status *ts;

	util_list_iterate(status, ts) {
		if (strcmp(ts->path, node) == 0)
			return ts->status;
	}

	return 'F';
}

static struct util_list *get_multipath_status(const char *devname)
{
	struct util_list *status;
	int len, failed = 0;
	char *line = NULL;
	size_t n = 0;
	FILE *fp;

	fp = exec_cmd_and_get_out_stream("dmsetup status /dev/%s 2>/dev/null",
					 devname);
	if (fp == NULL) {
		ERR("No paths found for '%s'\n", devname);
		return NULL;
	}

	status = util_list_new(struct target_status, list);
	while (getline(&line, &n, fp) != -1) {
		char *token = NULL;
		long cnt, ngr;

		/* Sample output (single line):
		 * 0 67108864 multipath \
		 * 2 0 0 \
		 * 0 \
		 * 2 2 \
		 *     E 0 \
		 *     2 2 \
		 *         8:16 F 1 \
		 *				0 1 \
		 *		   8:0 F 1 \
		 *		       0 1 \
		 *	   A 0 \
		 *	   2 2 \
		 *		   8:32 A 0 \
		 *		        0 1 \
		 *		   8:48 A 0 \
		 *		        0 1
		 */
		STR_TOKEN_OR_GOTO(line, token, out);
		SKIP_NEXT_TOKEN_OR_GOTO(out); /* length */

		NEXT_STR_TOKEN_OR_GOTO(token, out); /* dtype */
		if (strcmp(token, "multipath") != 0)
			continue;

		NEXT_INT_TOKEN_OR_GOTO(cnt, out); /* #mp_feature_args */
		SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); /* mp_feature_args* */
		NEXT_INT_TOKEN_OR_GOTO(cnt, out); /* #handler_status_args */
		SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); /* handler_status_args* */

		NEXT_INT_TOKEN_OR_GOTO(ngr, out);
		SKIP_NEXT_TOKEN_OR_GOTO(out); /* ign */
		for (; ngr > 0; ngr--) {
			long npaths, nsa;

			NEXT_STR_TOKEN_OR_GOTO(token, out); /* group_state */
			NEXT_INT_TOKEN_OR_GOTO(cnt, out); /* #ps_status_args */
			SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); /* ps_status_args* */
			NEXT_INT_TOKEN_OR_GOTO(npaths, out);
			NEXT_INT_TOKEN_OR_GOTO(nsa, out);

			for (; npaths > 0; npaths--) {
				struct target_status *ts;
				char *path, *active;

				/* Fetch single path description */
				NEXT_STR_TOKEN_OR_GOTO(path, out);
				NEXT_STR_TOKEN_OR_GOTO(active, out);
				ts = target_status_new(path, active[0]);

				util_list_add_tail(status, ts);

				NEXT_INT_TOKEN_OR_GOTO(cnt, out); /* fail_cnt */

				failed += (active[0] != 'A');

				SKIP_NEXT_TOKENS_OR_GOTO(nsa, out); /* selector_args* */
			}
		}
	}

	len = util_list_len(status);
	if (len == 0) {
		ERR("No paths found for '%s'\n", devname);
		goto out;
	} else if (failed == len) {
		ERR("All paths for '%s' failed\n", devname);
		goto out;
	} else if (failed > 0) {
		WARN("There are one or more failed paths for device '%s'\n",
		     devname);
	}
	goto success;
 out:
	status_list_free(status);
	status = NULL;
 success:
	free(line);
	pclose(fp);
	return status;
}

static struct util_list *get_multipath_data(const char *devname, char *args)
{
	struct util_list *data = util_list_new(struct target_data, list);
	struct util_list *status = get_multipath_status(devname);
	long cnt, pgroups;

	if (status == NULL)
		goto out_status;

	INT_TOKEN_OR_GOTO(args, cnt, out); /* #feat */
	SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); /* feats* */
	NEXT_INT_TOKEN_OR_GOTO(cnt, out); /* #handlers */
	SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); /* handlers* */
	NEXT_INT_TOKEN_OR_GOTO(pgroups, out);
	SKIP_NEXT_TOKEN_OR_GOTO(out); /* pathgroup */
	for (; pgroups > 0; pgroups--) {
		long npaths;

		SKIP_NEXT_TOKEN_OR_GOTO(out); /* path_selector */
		NEXT_INT_TOKEN_OR_GOTO(cnt, out); /* #selector_args */
		SKIP_NEXT_TOKENS_OR_GOTO(cnt, out); /* selector_args* */
		NEXT_INT_TOKEN_OR_GOTO(npaths, out);
		NEXT_INT_TOKEN_OR_GOTO(cnt, out); /* #np_args */
		for (; npaths > 0; npaths--) {
			unsigned int major, minor;
			char *path;

			NEXT_STR_TOKEN_OR_GOTO(path, out);
			if (sscanf(path, "%u:%u", &major, &minor) < 2)
				goto out;

			if (status_list_get_status(status, path) == 'A') {
				struct target_data *td;

				td = target_data_new(major, minor, 0);
				util_list_add_tail(data, td);
			}
			SKIP_NEXT_TOKENS_OR_GOTO(cnt, out);
		}
	}

	status_list_free(status);

	return data;

out:
	status_list_free(status);
out_status:
	target_data_list_free(data);
	ERR("Unrecognized device-mapper table format for device '%s'\n", devname);

	return NULL;
}

static void table_free(struct util_list *table)
{
	struct target *target, *n;

	if (!table)
		return;
	util_list_iterate_safe(table, target, n) {
		util_list_remove(table, target);
		target_free(target);
	}
	util_list_free(table);
}

/**
 * Remove all targets which don't maintain bytes in the interval
 * [start,start+length-1] from the TABLE
 */
static void filter_table(struct util_list *table, unsigned int start,
			 unsigned int length)
{
	struct target *target, *n;

	util_list_iterate_safe(table, target, n) {
		if (!(((target->start + target->length - 1) >= start) &&
		      (target->start <= (start + length - 1)))) {
			util_list_remove(table, target);
			target_free(target);
		}
	}
}

/**
 * Return list of target devices
 */
static int get_table(dev_t dev, struct util_list **table)
{
	char devname[BDEVNAME_SIZE];
	char *line = NULL;
	size_t n = 0;
	FILE *fp;

	*table = util_list_new(struct target, list);

	fp = exec_cmd_and_get_out_stream("dmsetup table -j %u -m %u 2>/dev/null",
					 major(dev), minor(dev));
	if (fp == NULL)
		return 0;

	get_device_name(devname, dev);
	while (getline(&line, &n, fp) != -1) {
		char *type = NULL, *args = NULL;
		struct util_list *data = NULL;
		unsigned long start, length;
		unsigned short ttype;

		if (sscanf(line, "%lu %lu %ms %m[a-zA-Z0-9_: -]",
			   &start, &length, &type, &args) < 4) {
			ERR("Unrecognized device-mapper table format for device '%s'\n",
			    devname);
			goto out;
		}
		if (strcmp(type, "linear") == 0) {
			data = get_linear_data(devname, args);
			ttype = TARGET_TYPE_LINEAR;
		} else if (strcmp(type, "mirror") == 0) {
			data = get_mirror_data(devname, args);
			ttype = TARGET_TYPE_MIRROR;
		} else if (strcmp(type, "multipath") == 0) {
			data = get_multipath_data(devname, args);
			ttype = TARGET_TYPE_MULTIPATH;
		} else {
			ERR("Unsupported setup: Unsupported device-mapper "
			    "target type '%s' for device '%s'\n",
			    type, devname);
		}
		free(type);
		free(args);
		if (data == NULL)
			goto out;
		util_list_add_tail(*table, target_new(start, length, ttype, data));
	}
	free(line);
	pclose(fp);
	return 0;
out:
	free(line);
	pclose(fp);
	table_free(*table);
	*table = NULL;
	return -1;
}

static bool is_dasd(unsigned short type)
{
	return (type == DEV_TYPE_CDL) || (type == DEV_TYPE_LDL) ||
		(type == DEV_TYPE_FBA);
}

/**
 * Remove TARGET from TABLE and add it to DMPATH
 */
static void target_move(struct target *target, struct ext_dev *dev,
			struct util_list **table,
			struct util_list *dmpath)
{
	util_list_remove(*table, target);
	table_free(*table);
	*table = NULL;
	util_list_add_head(dmpath, dmpath_entry_new(dev, target));
}

/**
 * Look for a TARGET in a device-mapper's TABLE on the parent level by DEVICE
 */
static int lookup_parent(dev_t device, struct util_list **table,
			 struct target **target,
			 void (*filter_table_fn)(struct util_list *table,
						 unsigned int start,
						 unsigned int len),
			 unsigned int start, unsigned int len)
{
	if (get_table(device, table))
		return DM_LOOKUP_ERROR;
	if (*table == NULL || util_list_is_empty(*table))
		return DM_EMPTY_TABLE;
	/* optionally apply filter to the table */
	if (filter_table_fn)
		filter_table_fn(*table, start, len);
	*target = util_list_start(*table);
	if (*target == NULL)
		return DM_NO_TARGET;
	if (util_list_next(*table, *target) != NULL)
		return DM_MULTIPLE_TARGETS;
	return DM_SINGLE_TARGET;
}

/**
 * Starting from DEVICE go upward the device tree and find the topmost
 * device, which is not a logical device managed by device-mapper driver.
 *
 * On success: return the whole path traveled. Data of the topmost target
 * in that path consists of non-dm devices.
 * FS_START contains file system offset on the topmost dm-device.
 *
 * BOTTOM: the logical device at the lowest level from which the ascent
 * begins.
 */
static struct util_list *dmpath_walk(struct ext_dev *bottom, const char *dir,
				     unsigned long *fs_start)
{
	struct util_list *dmpath = util_list_new(struct dmpath_entry, list);
	struct util_list *table = NULL;
	struct ext_dev top = *bottom;
	char devname[BDEVNAME_SIZE];
	struct target *target;
	unsigned int length;
	int ret;

	ret = lookup_parent(top.dev, &table, &target, NULL, 0, 0);
	switch (ret) {
	case DM_LOOKUP_ERROR:
		goto error;
	case DM_EMPTY_TABLE:
		get_device_name(devname, top.dev);
		ERR("Could not retrieve device-mapper information for device "
		    "'%s'\n", devname);
		goto error;
	case DM_NO_TARGET:
		/* impossible: table is not empty and no filter was applied */
		assert(0);
		goto error;
	case DM_MULTIPLE_TARGETS:
		ERR("Unsupported setup: Directory '%s' is located on a "
		    "multi-target device-mapper device\n", dir);
		goto error;
	case DM_SINGLE_TARGET:
		break;
	}
	length = target->length;

	while (true) {
		target_move(target, &top, &table, dmpath);
		/*
		 * Go to the upper level.
		 * First, select the first device from those that constitute
		 * the logical target (which is the "point of branching" in
		 * the device tree).
		 */
		top.dev = first_device_by_target_data(target);
		top.fs_off += target_get_start(target);
		/*
		 * look for a target maintaining bytes in the interval
		 * [fs_off, fs_off+length - 1] on the parent level
		 */
		ret = lookup_parent(top.dev, &table, &target,
				    filter_table, top.fs_off, length);
		switch (ret) {
		case DM_LOOKUP_ERROR:
			goto error;
		case DM_EMPTY_TABLE:
			/* Found non-dm device */
			table_free(table);
			*fs_start = top.fs_off;
			return dmpath;
		case DM_NO_TARGET:
			/* break through */
		case DM_MULTIPLE_TARGETS:
			ERR("Unsupported setup: Could not map directory '%s' "
			    "to a single physical device\n", dir);
			goto error;
		case DM_SINGLE_TARGET:
			break;
		}
	}
 error:
	table_free(table);
	dmpath_free(dmpath);
	return NULL;
}

static int get_physical_device(struct physical_device *pd, struct ext_dev *dev,
			       const char *dir)
{
	pd->dmpath = dmpath_walk(dev, dir, &pd->offset);

	return pd->dmpath == NULL ? -1 : 0;
}

static int device_by_filename(dev_t *dev, const char *filename)
{
	struct stat buf;

	if (stat(filename, &buf) != 0) {
		ERR("Could not stat '%s'", filename);
		return -1;
	}
	*dev = buf.st_dev;
	return 0;
}

static struct dmpath_entry *get_top_entry(struct physical_device *pd)
{
	return util_list_start(pd->dmpath);
}

/**
 * Find the topmost entry in the DMPATH, which provides access to
 * the boot sectors
 */
static struct dmpath_entry *find_base_entry(struct util_list *dmpath,
					    unsigned int nr_boot_sectors)
{
	struct dmpath_entry *te, *tm, *top;

	top = util_list_start(dmpath);

	util_list_iterate(dmpath, te) {
		if (target_get_start(te->target) != 0 ||
		    te->target->length < nr_boot_sectors)
			break;
		top = te;
	}
	/* Check for mirroring between base device and fs device */
	for (tm = te; tm != NULL; tm = util_list_next(dmpath, tm)) {
		if (tm->target->type == TARGET_TYPE_MIRROR) {
			char name[BDEVNAME_SIZE];

			get_device_name(name, tm->dev.dev);
			ERR("Unsupported setup: Block 0 is not mirrored in "
			    "device '%s'\n", name);
			return NULL;
		}
	}
	return top;
}

static inline dev_t get_partition_base(unsigned short type, dev_t dev)
{
	return makedev(major(dev), minor(dev) &
		       (is_dasd(type) ? ~DASD_PARTN_MASK : ~SCSI_PARTN_MASK));
}

static int extract_major_minor_from_cmdline(char *argv[], unsigned int *major,
					    unsigned int *minor)
{
	if (sscanf(argv[1], "%u:%u", major, minor) != 2)
		return -1;
	return 0;
}

static bool toolname_is(const char *toolname, const char *what)
{
	int wlen = strlen(what);
	int tlen = strlen(toolname);

	if (tlen < wlen)
		return false;

	return strcmp(toolname + tlen - wlen, what) == 0;
}

static void print_usage_zipl_helper(const char *toolname)
{
	fprintf(stderr, "%s <major:minor of target device>", toolname);
	fprintf(stderr, " or <target directory>\n");
}

static void print_usage_chreipl_helper(const char *toolname)
{
	fprintf(stderr, "%s <major:minor of target device>\n", toolname);
}

/**
 * Complete the PD structure and assign the base device
 */
static int complete_physical_device(struct physical_device *pd, dev_t *base_dev)
{
	struct device_characteristics *dc = &pd->dc;
	struct dmpath_entry *top_entry, *base_entry;
	dev_t top_dev;

	top_entry = get_top_entry(pd);
	top_dev = first_device_by_target_data(top_entry->target);

	/* Retrieve parameters of the topmost device */
	if (get_dev_characteristics(dc, top_dev) != 0)
		return -1;

	if (dc->partstart > 0) {
		/*
		 * The topmost found device is a partition.
		 * Since just a part of the physical device is mapped, only
		 * the physical device can provide access to the boot record
		 */
		struct device_characteristics ndc = {0};
		struct dmpath_entry *mirror;

		/* Check for mirror */
		mirror = dmpath_get_first_by_type(pd->dmpath,
						  TARGET_TYPE_MIRROR);
		if (mirror != NULL) {
			char name[BDEVNAME_SIZE];

			get_device_name(name, mirror->dev.dev);
			/* IPL records are not mirrored */
			ERR("Unsupported setup: Block 0 is not mirrored in "
			    "device '%s'\n", name);
			return -1;
		}
		base_entry = top_entry;
		*base_dev = get_partition_base(dc->type, top_dev);
		/* Complete the filesystem offset */
		pd->offset += (dc->partstart * (dc->blocksize / SECTOR_SIZE));
		dc->partstart = 0;
		/* Update device geometry */
		get_dev_characteristics(&ndc, *base_dev);
		dc->geo = ndc.geo;
	} else {
		/*
		 * All of the device is mapped, so the base device is the
		 * top most dm device which provides access to boot sectors
		 */
		base_entry = find_base_entry(pd->dmpath, dc->bootsectors);
		if (!base_entry)
			return -1;
		*base_dev = base_entry->dev.dev;
	}
	/* Check for valid offset of filesystem */
	if ((pd->offset % (dc->blocksize / SECTOR_SIZE)) != 0) {
		ERR("File system not aligned on physical block size\n");
		return -1;
	}
	return 0;
}

/**
 * Print a set of zipl parameters for a base device.
 *
 * BASE: physical or logical device, which provides access to boot sectors
 * FS_START: offset (in sectors) of the first block managed by the file system
 */
static void base_dev_to_params(dev_t base, struct device_characteristics *dc,
			       unsigned long fs_start)
{
	char type_name[8];

	printf("targetbase=%u:%u\n", major(base), minor(base));
	get_type_name(type_name, dc->type);
	printf("targettype=%s\n", type_name);
	if (dc->geo.cylinders != 0 &&
	    dc->geo.heads != 0 &&
	    dc->geo.sectors != 0) {
		printf("targetgeometry=%d,%d,%d\n",
		       dc->geo.cylinders,
		       dc->geo.heads,
		       dc->geo.sectors);
	}
	printf("targetblocksize=%d\n", dc->blocksize);
	printf("targetoffset=%lu\n",
	       fs_start / (dc->blocksize / SECTOR_SIZE));
}

/**
 * Print parameters for logical device DEV required by zipl
 * tool to install IPL records on its's physical components.
 *
 * DEV: a logical device managed by device-mapper driver
 */
static int dm_dev_to_zipl_params(struct ext_dev *dev, char *dir)
{
	struct physical_device pd = {0};
	dev_t base_dev;

	if (get_physical_device(&pd, dev, dir))
		return -1;
	if (complete_physical_device(&pd, &base_dev))
		goto error;
	base_dev_to_params(base_dev, &pd.dc, pd.offset);
	dmpath_free(pd.dmpath);
	return 0;
error:
	dmpath_free(pd.dmpath);
	return -1;
}

static int dm_dev_to_chreipl_params(dev_t dev, char *dir)
{
	struct physical_device pd = {0};
	struct ext_dev xdev = {dev, 0};
	dev_t top_dev;

	if (get_physical_device(&pd, &xdev, dir))
		return -1;
	top_dev = get_top_entry(&pd)->dev.dev;
	printf("%u:%u\n", major(top_dev), minor(top_dev));
	dmpath_free(pd.dmpath);
	return 0;
}

static int handle_device_mapper(dev_t dev, int util_id, char *name)
{
	struct ext_dev xdev = {dev, 0};

	switch (util_id) {
	case CHREIPL_UTIL_ID:
		return dm_dev_to_chreipl_params(dev, name);
	case ZIPL_UTIL_ID:
		return dm_dev_to_zipl_params(&xdev, name);
	default:
		ERR("Unsupported utility %d\n", util_id);
		return -1;
	}
}

static int print_params_device_mapper(char *argv[], struct helper *h)
{
	unsigned int major, minor;
	char *name = argv[1];
	dev_t dev;

	if (extract_major_minor_from_cmdline(argv, &major, &minor) == 0)
		dev = makedev(major, minor);
	else if (device_by_filename(&dev, name))
		return -1;
	return handle_device_mapper(dev, h->util_id, name);
}

static int check_usage_zipl_helper(int argc, char *argv[])
{
	if (argc <= 1) {
		print_usage_zipl_helper(argv[0]);
		return -1;
	}
	return 0;
}

static int check_usage_chreipl_helper(int argc, char *argv[])
{
	unsigned int major, minor;

	if (argc <= 1 ||
	    extract_major_minor_from_cmdline(argv, &major, &minor)) {
		print_usage_chreipl_helper(argv[0]);
		return -1;
	}
	return 0;
}

static struct helper helpers[LAST_DRIVER_ID][LAST_UTIL_ID] = {
	[DM_DRIVER_ID][ZIPL_UTIL_ID] = {
		. util_id = ZIPL_UTIL_ID,
		. driver_id = DM_DRIVER_ID,
		. name = "zipl_helper.device-mapper",
		. check_usage = check_usage_zipl_helper,
		. print_params = print_params_device_mapper
	},
	[DM_DRIVER_ID][CHREIPL_UTIL_ID] = {
		. util_id = CHREIPL_UTIL_ID,
		. driver_id = DM_DRIVER_ID,
		. name = "chreipl_helper.device-mapper",
		. check_usage = check_usage_chreipl_helper,
		. print_params = print_params_device_mapper
	},
};

static struct helper *helper_by_toolname(const char *toolname)
{
	int i, j;

	for (i = 0; i < LAST_DRIVER_ID; i++)
		for (j = 0; j < LAST_UTIL_ID; j++)
			if (toolname_is(toolname, helpers[i][j].name))
				return &helpers[i][j];
	return NULL;
}

int main(int argc, char *argv[])
{
	struct helper *h;

	h = helper_by_toolname(argv[0]);
	assert(h != NULL);

	if (h->check_usage(argc, argv))
		exit(EXIT_FAILURE);

	if (setlocale(LC_ALL, "C") == NULL) {
		ERR("Could not use standard locale\n");
		exit(EXIT_FAILURE);
	}
	if (h->print_params(argv, h))
		exit(EXIT_FAILURE);
	exit(EXIT_SUCCESS);
}
