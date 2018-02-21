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

struct target_entry {
	dev_t device;
	struct target *target;
	struct util_list_node list;
};

struct physical_device {
	dev_t device;
	unsigned long offset;
	struct util_list *target_list;
};

struct device_characteristics {
	unsigned short type;
	unsigned int blocksize;
	unsigned long bootsectors;
	unsigned long partstart;
	struct hd_geometry geo;
};

/* From include/linux/fs.h */
#define BDEVNAME_SIZE 32

/* Constants */
const unsigned int SECTOR_SIZE = 512;
const unsigned int DASD_PARTN_MASK = 0x03;
const unsigned int SCSI_PARTN_MASK = 0x0f;

const char CHREIPL_HELPER[] = "chreipl_helper.device-mapper";

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

	return td->start;
}

static void target_get_major_minor(struct target *target, unsigned int *major,
				   unsigned int *minor)
{
	struct target_data *td = util_list_start(target->data);

	*major = major(td->device);
	*minor = minor(td->device);
}

static struct target_entry *target_entry_new(dev_t dev, struct target *target)
{
	struct target_entry *te = util_malloc(sizeof(struct target_entry));

	te->device = dev;
	te->target = target;

	return te;
}

static void target_entry_free(struct target_entry *entry)
{
	target_free(entry->target);
	free(entry);
}

static struct target_entry *target_list_get_first_by_type(struct util_list *target_list,
							  unsigned short type)
{
	struct target_entry *te;

	util_list_iterate(target_list, te) {
		if (te->target->type == type)
			return te;
	}

	return NULL;
}

static void target_list_free(struct util_list *target_list)
{
	struct target_entry *te, *n;

	util_list_iterate_safe(target_list, te, n) {
		util_list_remove(target_list, te);
		target_entry_free(te);
	}
	util_list_free(target_list);
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

	free(line);
	pclose(fp);

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

	return status;

out:
	free(line);
	pclose(fp);
	status_list_free(status);

	return NULL;
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

	util_list_iterate_safe(table, target, n) {
		util_list_remove(table, target);
		target_free(target);
	}
	util_list_free(table);
}

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

/*
 * Return list of target devices
 */
static struct util_list *get_table(dev_t dev)
{
	char devname[BDEVNAME_SIZE];
	struct util_list *table;
	char *line = NULL;
	size_t n = 0;
	FILE *fp;

	table = util_list_new(struct target, list);

	fp = exec_cmd_and_get_out_stream("dmsetup table -j %u -m %u 2>/dev/null",
					 major(dev), minor(dev));
	if (fp == NULL)
		return table;

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
		util_list_add_tail(table, target_new(start, length, ttype, data));
	}

	free(line);
	pclose(fp);

	return table;

out:
	free(line);
	pclose(fp);
	table_free(table);

	return NULL;
}

static bool is_dasd(unsigned short type)
{
	return (type == DEV_TYPE_CDL) || (type == DEV_TYPE_LDL) ||
		(type == DEV_TYPE_FBA);
}

static int get_physical_device(struct physical_device *pd, dev_t dev,
			       const char *directory)
{
	struct util_list *target_list = NULL;
	struct util_list *table = NULL;
	unsigned int start, length;
	struct target *target;

	table = get_table(dev);
	if (table == NULL || util_list_is_empty(table)) {
		char devname[BDEVNAME_SIZE];

		get_device_name(devname, dev);
		ERR("Could not retrieve device-mapper information for device "
		    "'%s'\n", devname);

		if (table != NULL)
			table_free(table);

		return -1;
	}

	target = util_list_start(table);

	/* Filesystem must be on a single dm target */
	if (util_list_next(table, target) != NULL) {
		ERR("Unsupported setup: Directory '%s' is located on a "
		    "multi-target device-mapper device\n", directory);
		table_free(table);

		return -1;
	}
	util_list_remove(table, target);
	table_free(table);

	target_list = util_list_new(struct target_entry, list);

	util_list_add_head(target_list, target_entry_new(dev, target));
	start = target->start;
	length = target->length;
	while (true) {
		unsigned int major, minor;

		/* Convert fs_start to offset on parent dm device */
		start += target_get_start(target);
		target_get_major_minor(target, &major, &minor);
		table = get_table(makedev(major, minor));
		/* Found non-dm device */
		if (table == NULL || util_list_is_empty(table)) {
			pd->device = makedev(major, minor);
			pd->offset = start;
			pd->target_list = target_list;

			if (table != NULL)
				table_free(table);

			return 0;
		}
		/* Get target in parent table which contains filesystem.
		 * We are interested only in targets between
		 * [start,start+length-1].
		 */
		filter_table(table, start, length);
		target = util_list_start(table);
		if (target == NULL || util_list_next(table, target) != NULL) {
			ERR("Unsupported setup: Could not map directory '%s' "
			    "to a single physical device\n", directory);
			table_free(table);
			target_list_free(target_list);

			return -1;
		}
		util_list_remove(table, target);
		util_list_add_head(target_list,
				   target_entry_new(makedev(major, minor), target));
		table_free(table);
		/* Convert fs_start to offset on parent target */
		start -= target->start;
	}
}

static int get_major_minor(dev_t *dev, const char *filename)
{
	struct stat buf;

	if (stat(filename, &buf) != 0) {
		ERR("Could not stat '%s'", filename);
		return -1;
	}
	*dev = buf.st_dev;

	return 0;
}

static int get_physical_device_dir(struct physical_device *pd,
				   const char *directory)
{
	dev_t dev;

	if (get_major_minor(&dev, directory) != 0)
		return -1;

	return get_physical_device(pd, dev, directory);
}

static int get_target_base(dev_t *base, dev_t bottom, unsigned int length,
			   struct util_list *target_list)
{
	struct target_entry *te, *tm;
	dev_t top = bottom;

	util_list_iterate(target_list, te) {
		if ((te->target->start != 0) ||
		    (target_get_start(te->target) != 0) ||
		    (te->target->length < length)) {
			break;
		}
		top = te->device;
	}

	/* Check for mirroring between base device and fs device */
	for (tm = te; tm != NULL; tm = util_list_next(target_list, tm)) {
		if (tm->target->type == TARGET_TYPE_MIRROR) {
			char name[BDEVNAME_SIZE];

			get_device_name(name, tm->device);
			ERR("Unsupported setup: Block 0 is not mirrored in "
			    "device '%s'\n", name);
			return -1;
		}
	}

	*base = top;

	return 0;
}

static inline dev_t get_partition_base(unsigned short type, dev_t dev)
{
	return makedev(major(dev), minor(dev) &
		       (is_dasd(type) ? ~DASD_PARTN_MASK : ~SCSI_PARTN_MASK));
}

static int extract_major_minor_from_cmdline(char *argv[], unsigned int *major,
					    unsigned int *minor)
{
	if (sscanf(argv[1], "%u:%u", major, minor) != 2) {
		return -1;
	}

	return 0;
}

static bool toolname_is_chreipl_helper(const char *toolname)
{
	int clen = strlen(CHREIPL_HELPER);
	int tlen = strlen(toolname);

	if (tlen < clen)
		return false;

	return strcmp(toolname + tlen - clen, CHREIPL_HELPER) == 0;
}

void print_usage(const char *toolname)
{
	fprintf(stderr, "%s <major:minor of target device>", toolname);
	if (!toolname_is_chreipl_helper(toolname))
		fprintf(stderr, " or <target directory>");
	fprintf(stderr, "\n");
}

int main(int argc, char *argv[])
{
	struct device_characteristics dc = {0};
	const char *toolname = argv[0];
	struct physical_device pd;
	unsigned int major, minor;
	char *directory = NULL;
	char type_name[8];
	dev_t base;
	int res;

	if (argc <= 1)
		goto usage;

	if (setlocale(LC_ALL, "C") == NULL) {
		ERR("Could not use standard locale\n");
		exit(EXIT_FAILURE);
	}

	if (toolname_is_chreipl_helper(toolname)) {
		if (extract_major_minor_from_cmdline(argv, &major, &minor) != 0)
			goto usage;

		if (get_physical_device(&pd, makedev(major, minor), argv[1]) != 0)
			exit(EXIT_FAILURE);

		printf("%u:%u\n", major(pd.device), minor(pd.device));
		target_list_free(pd.target_list);
		exit(EXIT_SUCCESS);
	}

	directory = argv[1];
	if (extract_major_minor_from_cmdline(argv, &major, &minor) == 0)
		res = get_physical_device(&pd, makedev(major, minor), directory);
	else
		res = get_physical_device_dir(&pd, directory);

	if (res != 0)
		exit(EXIT_FAILURE);

	if (get_dev_characteristics(&dc, pd.device) != 0)
		goto error;

	/* Handle partitions */
	if (dc.partstart > 0) {
		struct device_characteristics ndc = {0};
		struct target_entry *mirror;

		/* Only the partition of the physical device is mapped so only
		 * the physical device can provide access to the boot record
		 */
		base = get_partition_base(dc.type, pd.device);
		/* Check for mirror */
		mirror = target_list_get_first_by_type(pd.target_list,
						       TARGET_TYPE_MIRROR);
		if (mirror != NULL) {
			char name[BDEVNAME_SIZE];

			get_device_name(name, mirror->device);
			/* IPL records are not mirrored */
			ERR("Unsupported setup: Block 0 is not mirrored in "
			    "device '%s'\n", name);
			goto error;
		}
		/* Adjust filesystem offset */
		pd.offset += (dc.partstart * (dc.blocksize / SECTOR_SIZE));
		dc.partstart = 0;
		/* Update device geometry */
		get_dev_characteristics(&ndc, base);
		dc.geo = ndc.geo;
	} else {
		/* All of the device is mapped, so the base device is the
		 * top most dm device which provides access to boot sectors
		 */
		if (get_target_base(&base, pd.device, dc.bootsectors,
				    pd.target_list) != 0)
			goto error;
	}

	/* Check for valid offset of filesystem */
	if ((pd.offset % (dc.blocksize / SECTOR_SIZE)) != 0) {
		ERR("File system not aligned on physical block size\n");
		goto error;
	}

	target_list_free(pd.target_list);

	/* Print resulting information */
	printf("targetbase=%u:%u\n", major(base), minor(base));
	get_type_name(type_name, dc.type);
	printf("targettype=%s\n", type_name);
	if (dc.geo.cylinders != 0 && dc.geo.heads != 0 && dc.geo.sectors != 0) {
		printf("targetgeometry=%d,%d,%d\n",
		       dc.geo.cylinders, dc.geo.heads, dc.geo.sectors);
	}
	printf("targetblocksize=%d\n", dc.blocksize);
	printf("targetoffset=%lu\n", (pd.offset / (dc.blocksize / SECTOR_SIZE)));

	exit(EXIT_SUCCESS);

error:
	if (pd.target_list != NULL)
		target_list_free(pd.target_list);
	exit(EXIT_FAILURE);

usage:
	print_usage(toolname);
	exit(EXIT_FAILURE);
}
