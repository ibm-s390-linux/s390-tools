/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_file.h"

#include "attrib.h"
#include "ccw.h"
#include "ccwgroup.h"
#include "dasd.h"
#include "device.h"
#include "export.h"
#include "firmware.h"
#include "misc.h"
#include "path.h"
#include "qeth.h"
#include "subtype.h"
#include "zfcp_host.h"
#include "zfcp_lun.h"

/* In-memory firmware file representation. */
struct fw_file {
	const char *name;
	char *buffer;
	size_t size;
	char *last_access;
	size_t last_size;
};

/* Record access to fields of the buffered file for use in warning messages. */
#define fwacc(f, x)	((f)->last_access = (char *) &(x), \
			 (f)->last_size = sizeof(x), x)

/*
 * Firmware file format definitions.
 */

/* Firmware file header. */
struct fw_filehdr {
	uint32_t magic;
	uint16_t ver;
	uint16_t hdr_len;
	uint32_t file_len;
	uint32_t seq;
	uint32_t zeroes;
	uint16_t de_count;
	char unused[10];
} __packed;

#define FW_HDR_MAGIC		0x7a646576	/* ASCII "zdev" */
#define FW_HDR_VER_Z14		0x0000

/* I/O device ID. */
struct fw_iodevid {
	uint8_t cssid;
	uint8_t ssid;
	uint16_t devno;
} __packed;

#define FW_IODEVID_FLAG_MCSS	0x01

/* Device setting. */
struct fw_setting {
	uint16_t len;
	uint8_t key_type;
	uint8_t key_len;
	uint8_t val_type;
	uint8_t val_len;
	char data[];
} __packed;

#define FW_SETTING_KEYTYPE_ASCII	0x00
#define FW_SETTING_VALTYPE_ASCII	0x00
#define FW_SETTING_VALTYPE_UINT		0x01

/* Device settings list. */
struct fw_setlist {
	uint16_t len;
	char data[];
} __packed;

/* Device entry header. */
struct fw_dehdr {
	uint16_t type;
	uint16_t len;
	uint32_t seq;
} __packed;

#define FW_DE_HDR_TYPE_DASD		0x0001
#define FW_DE_HDR_TYPE_ZFCP_HOST	0x0002
#define FW_DE_HDR_TYPE_ZFCP_LUN		0x0003
#define FW_DE_HDR_TYPE_QETH		0x0004

/* DASD device entry. */
struct fw_dasd {
	struct fw_dehdr hdr;
	uint8_t id_flags;
	struct fw_iodevid id;
	char settings[];
} __packed;

/* zFCP host device entry. */
struct fw_zfcp_host {
	struct fw_dehdr hdr;
	uint8_t id_flags;
	struct fw_iodevid id;
	char settings[];
} __packed;

/* zFCP LUN device entry. */
struct fw_zfcp_lun {
	struct fw_dehdr hdr;
	uint8_t id_flags;
	struct fw_iodevid id;
	uint64_t wwpn;
	uint64_t fcp_lun;
	char settings[];
} __packed;

/* QETH device entry. */
struct fw_qeth {
	struct fw_dehdr hdr;
	uint8_t id_flags;
	struct fw_iodevid read_id;
	struct fw_iodevid write_id;
	struct fw_iodevid data_id;
	char settings[];
} __packed;

/* Dasd types definitions for rd.dasd parser */
enum dasd_type {
	DASD_NO_DEVICE,
	DASD_ECKD,
	DASD_NO_ECKD,
};

/* Emit a warning that refers to a position in a firmware file. */
static void fwwarn(struct fw_file *f, const char *fmt, ...)
{
	va_list args;
	off_t start = (off_t) (f->last_access - f->buffer),
	      end = start + f->last_size - 1;

	fprintf(stderr, "%s: ", f->name);
	if (start == end)
		fprintf(stderr, "Byte 0x%zx: ", start);
	else
		fprintf(stderr, "Bytes 0x%zx-0x%zx: ", start, end);

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	fprintf(stderr, "\n");
}

/* Basic file format header sanity check. */
static bool check_header(struct fw_file *f, struct fw_filehdr *hdr)
{
	if (fwacc(f, hdr->magic) != FW_HDR_MAGIC)
		fwwarn(f, "Invalid file magic (0x%08x)", hdr->magic);
	else if (fwacc(f, hdr->ver) != FW_HDR_VER_Z14)
		fwwarn(f, "Unsupported file version (0x%04x)", hdr->ver);
	else
		return true;

	return false;
}

#define READ_RETRY	3

/* Read a firmware configuration file. */
static exit_code_t read_fw(struct fw_file *file, FILE *fd, const char *filename)
{
	struct fw_file f = { NULL };
	struct fw_filehdr *hdr;
	char *buffer, *buffer2;
	size_t size, size2;
	int retry;
	exit_code_t rc = EXIT_OK;

	for (retry = 0; retry < READ_RETRY; retry++) {
		/* Read complete file once */
		rc = (exit_code_t) util_file_read_fd_buf(fd, (void **) &buffer,
							 &size);
		if (rc) {
			warn("%s: Could not read file", filename);
			return rc;
		}
		if (!buffer) {
			/* Empty file - skip silently as this is the default
			 * on machines without firmware support. */
			return rc;
		}

		/* Re-read complete file to detect in-flight modifications. */
		if (fseek(fd, 0, SEEK_SET) == -1) {
			/* Could be a pipe, socket, or FIFO - accept v1. */
			break;
		}
		rc = (exit_code_t) util_file_read_fd_buf(fd, (void **) &buffer2,
							 &size2);
		if (rc || !buffer2) {
			/* Could not get second version - accept v1. */
			break;
		}

		if (size == size2 && memcmp(buffer, buffer2, size) == 0) {
			/* No change */
			free(buffer2);
			break;
		}

		free(buffer);
		free(buffer2);
	}

	if (retry >= READ_RETRY) {
		warnx("%s: File changed %d times while reading - aborting",
		      filename, retry);
		return EXIT_RUNTIME_ERROR;
	}

	/* Perform basic checks */
	f.name = filename;
	f.buffer = buffer;
	f.size = size;
	hdr = (void *) buffer;
	if (!check_header(&f, hdr)) {
		free(buffer);
		return EXIT_FORMAT_ERROR;
	}
	if (fwacc(&f, hdr->file_len) > size) {
		fwwarn(&f, "File length mismatch (expect %zu) - adjusting",
		       size);
		hdr->file_len = size;
	}

	*file = f;

	return EXIT_OK;
}

/* Return textual representation of a device entry type. */
static const char *type_to_str(uint16_t type)
{
	switch (type) {
	case FW_DE_HDR_TYPE_DASD:
		return "dasd";
	case FW_DE_HDR_TYPE_ZFCP_HOST:
		return "zfcp-host";
	case FW_DE_HDR_TYPE_ZFCP_LUN:
		return "zfcp-lun";
	case FW_DE_HDR_TYPE_QETH:
		return "qeth";
	default:
		return "<unknown>";
	}
}

/* Convert a binary format device setting of the specified length to integer. */
static unsigned long parse_value(char *data, uint8_t len)
{
	switch (len) {
	case 1:
		return (unsigned long) *((uint8_t *) data);
	case 2:
		return (unsigned long) *((uint16_t *) data);
	case 4:
		return (unsigned long) *((uint32_t *) data);
	case 8:
		return (unsigned long) *((uint64_t *) data);
	default:
		return 0;
	}
}

/* Perform sanity checks on device setting. */
static bool check_setting(struct fw_file *f, struct fw_setting *set)
{
	/* Key sanity checks */
	if (fwacc(f, set->key_type) != FW_SETTING_KEYTYPE_ASCII) {
		fwwarn(f, "Unsupported key type: %d", set->key_type);
		return false;
	}
	if (fwacc(f, set->key_len) < 1) {
		fwwarn(f, "Unsupported key length: %d", set->key_len);
		return false;
	}
	if (sizeof(struct fw_setting) + fwacc(f, set->key_len) > set->len) {
		fwwarn(f, "Key length exceeds setting");
		return false;
	}
	if (fwacc(f, set->data[set->key_len - 1])) {
		fwwarn(f, "Key not null-terminated");
		return false;
	}

	/* Value sanity checks */
	if (fwacc(f, set->val_type) != FW_SETTING_VALTYPE_UINT &&
	    fwacc(f, set->val_type) != FW_SETTING_VALTYPE_ASCII) {
		fwwarn(f, "Unsupported value type: %d", set->val_type);
		return false;
	}
	if (fwacc(f, set->val_len) < 1) {
		fwwarn(f, "Unsupported value length: %d", set->val_len);
		return false;
	}
	if (sizeof(struct fw_setting) + set->key_len +
	    fwacc(f, set->val_len) > set->len) {
		fwwarn(f, "Value length exceeds setting");
		return false;
	}
	if ((set->val_type == FW_SETTING_VALTYPE_ASCII) &&
	    fwacc(f, set->data[set->key_len + set->val_len - 1])) {
		fwwarn(f, "Value not null-terminated");
		return false;
	}
	if (set->val_type == FW_SETTING_VALTYPE_UINT) {
		switch (fwacc(f, set->val_len)) {
		case 1:
		case 2:
		case 4:
		case 8:
			break;
		default:
			fwwarn(f, "Unsupported integer value length: %d",
			       set->val_len);
			return false;
		}
	}

	return true;
}

/* Add a setting to the device. Emit a warning if the setting is not known. */
static void _add_setting(const char *filename, struct device *dev,
			 config_t config, const char *key, const char *value)
{
	struct attrib *a;
	struct setting_list *list;

	list = device_get_setting_list(dev, config, SITE_FALLBACK);
	a = attrib_find(dev->subtype->dev_attribs, key);
	if (!a) {
		warnx("%s: Applying unknown device setting %s=%s", filename,
		      key, value);
	}
	setting_list_apply(list, a, key, value);
}

static void add_setting(const char *filename, struct device *dev,
			config_t config, const char *key, const char *value)
{
	if (SCOPE_ACTIVE(config))
		_add_setting(filename, dev, config_active, key, value);
	if (SCOPE_PERSISTENT(config))
		_add_setting(filename, dev, config_persistent, key, value);
	if (SCOPE_AUTOCONF(config))
		_add_setting(filename, dev, config_autoconf, key, value);
}

/* Parse a single device setting in firmware format and apply it to the
 * specified device. */
static void parse_setting(struct fw_file *f, struct fw_setting *set,
			  struct device *dev, config_t config)
{
	char *ascii_key, *ascii_val;
	unsigned long ulong_val;

	if (!check_setting(f, set))
		return;

	ascii_key = &set->data[0];
	if (set->val_type == FW_SETTING_VALTYPE_UINT) {
		ulong_val = parse_value(&set->data[set->key_len], set->val_len);
		ascii_val = misc_asprintf("%lu", ulong_val);
		add_setting(f->name, dev, config, ascii_key, ascii_val);
		free(ascii_val);
	} else {
		ascii_val = &set->data[set->key_len];
		add_setting(f->name, dev, config, ascii_key, ascii_val);
	}
}

/* Parse a device settings list in firmware format and apply the resulting
 * settings to the specified device. */
static void parse_settings(struct fw_file *f, char *data, struct device *dev,
			   config_t config)
{
	struct fw_setlist *list = (struct fw_setlist *) data;
	struct fw_setting *set;
	uint16_t off;

	for (off = sizeof(struct fw_setlist); off < list->len;
	     off += set->len) {
		set = (struct fw_setting *) &data[off];
		if (fwacc(f, set->len) < sizeof(struct fw_setting)) {
			fwwarn(f, "Setting too short");
			break;
		}
		if (off + fwacc(f, set->len) > list->len) {
			fwwarn(f, "Setting too long");
			break;
		}
		parse_setting(f, set, dev, config);
	}
}

/* Perform sanity checks on an I/O device ID. */
static bool check_iodevid(struct fw_file *f, uint8_t *flags,
			  struct fw_iodevid *id)
{

	if (fwacc(f, *flags) & FW_IODEVID_FLAG_MCSS) {
		fwwarn(f, "Unsupported entry in non-default CSS");
		return false;
	}
	if (fwacc(f, id->cssid) != 0) {
		fwwarn(f, "Non-zero CSS-ID");
		return false;
	}
	return true;
}

/* Perform sanity checks on a device entry. */
static bool check_de_size(struct fw_file *f, struct fw_dehdr *de, size_t size)
{
	if (fwacc(f, de->len) < size) {
		fwwarn(f, "Device entry too short (expect %zu)", size);
		return false;
	}
	return true;
}

/* Convert an I/O device ID to CCW device ID format. */
static void io_to_ccw(struct ccw_devid *c, struct fw_iodevid *i)
{
	c->cssid = i->cssid;
	c->ssid = i->ssid;
	c->devno = i->devno;
}

/* Register a new device configuration. */
static struct device *add_device(struct fw_file *f, struct subtype *st,
				 const char *id, config_t config,
				 struct util_list *objects)
{
	struct device *dev;

	if (!st->devices)
		st->devices = device_list_new(st);

	dev = device_list_find(st->devices, id, NULL);
	if (!dev) {
		dev = device_new(st, id);
		if (!dev) {
			warnx("%s: Skipping invalid %s device ID %s", f->name,
			      st->name, id);
			return NULL;
		}
		device_list_add(st->devices, dev);
	}
	ptrlist_add(objects, object_new(export_device, dev));

	/* Prepare device for new settings. */
	if (SCOPE_ACTIVE(config)) {
		setting_list_clear(dev->active.settings);
		if (dev->subtype->support_definable)
			dev->active.definable = 1;
		else
			dev->active.exists = 1;
	}
	if (SCOPE_PERSISTENT(config)) {
		setting_list_clear(dev->persistent.settings);
		dev->persistent.exists = 1;
	}
	if (SCOPE_AUTOCONF(config)) {
		setting_list_clear(dev->autoconf.settings);
		dev->autoconf.exists = 1;
	}

	return dev;
}

/* Return the device-type of the provided device-id by analysing modalias */
static enum dasd_type is_eckd(const char *id)
{
	const char * const eckd_type[] = { "3390", "3380", "9345" };
	size_t i;
	char *device_path, *buffer;
	int rc = DASD_NO_ECKD;

	/* Remove the device-id from the blacklist */
	ccw_unblacklist_id(id);

	/* Do a cio_settle before trying to read the modalias */
	cio_settle(1);

	device_path = path_get_ccw_device(NULL, id);
	/* Read the modalias value */
	buffer = path_read_text_file(1, err_ignore, "%s/modalias",
				     device_path);
	if (!buffer) {
		rc = DASD_NO_DEVICE;
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(eckd_type); i++) {
		if (strstr(buffer, eckd_type[i])) {
			rc = DASD_ECKD;
			goto out;
		}
	}

out:
	free(buffer);
	free(device_path);
	return rc;
}

/* Parse a DASD device entry. */
static void parse_dasd(struct fw_file *f, struct fw_dehdr *de, config_t config,
		       struct util_list *objects)
{
	struct fw_dasd *dasd = (struct fw_dasd *) de;
	struct ccw_devid devid;
	struct device *dev_eckd = NULL, *dev_fba = NULL;
	char *id;

	if (!check_de_size(f, de, sizeof(struct fw_dasd)))
		return;
	if (!check_iodevid(f, &dasd->id_flags, &dasd->id))
		return;

	/* Could be either dasd_eckd or dasd_fba - add both entries */
	io_to_ccw(&devid, &dasd->id);
	id = ccw_devid_to_str(&devid);

	switch (is_eckd(id)) {
	case DASD_ECKD:
		dev_eckd = add_device(f, &dasd_subtype_eckd, id, config,
				      objects);
		break;
	case DASD_NO_ECKD:
		dev_fba = add_device(f, &dasd_subtype_fba, id, config, objects);
		break;
	case DASD_NO_DEVICE:
		fwwarn(f, "DASD device %s does not exist", id);
		break;
	default:
		break;
	}

	free(id);

	if (dasd->hdr.len > sizeof(struct fw_dasd)) {
		if (dev_eckd)
			parse_settings(f, dasd->settings, dev_eckd, config);
		if (dev_fba)
			parse_settings(f, dasd->settings, dev_fba, config);
	}
}

/* Parse a zFCP host device entry. */
static void parse_zfcp_host(struct fw_file *f, struct fw_dehdr *de,
			    config_t config, struct util_list *objects)
{
	struct fw_zfcp_host *zfcp_host = (struct fw_zfcp_host *) de;
	struct ccw_devid devid;
	struct device *dev;
	char *id;

	if (!check_de_size(f, de, sizeof(struct fw_zfcp_host)))
		return;
	if (!check_iodevid(f, &zfcp_host->id_flags, &zfcp_host->id))
		return;

	/* Add zfcp_host entry */
	io_to_ccw(&devid, &zfcp_host->id);
	id = ccw_devid_to_str(&devid);
	dev = add_device(f, &zfcp_host_subtype, id, config, objects);
	free(id);

	if (dev && zfcp_host->hdr.len > sizeof(struct fw_zfcp_host))
		parse_settings(f, zfcp_host->settings, dev, config);
}

/* Parse a zFCP LUN device entry. */
static void parse_zfcp_lun(struct fw_file *f, struct fw_dehdr *de,
			   config_t config, struct util_list *objects)
{
	struct fw_zfcp_lun *zfcp_lun = (struct fw_zfcp_lun *) de;
	struct zfcp_lun_devid devid;
	struct device *dev;
	char *id;

	if (!check_de_size(f, de, sizeof(struct fw_zfcp_lun)))
		return;
	if (!check_iodevid(f, &zfcp_lun->id_flags, &zfcp_lun->id))
		return;

	/* Add zfcp_lun entry */
	io_to_ccw(&devid.fcp_dev, &zfcp_lun->id);
	devid.wwpn = zfcp_lun->wwpn;
	devid.lun = zfcp_lun->fcp_lun;
	id = zfcp_lun_devid_to_str(&devid);
	dev = add_device(f, &zfcp_lun_subtype, id, config, objects);
	free(id);

	if (dev && zfcp_lun->hdr.len > sizeof(struct fw_zfcp_lun))
		parse_settings(f, zfcp_lun->settings, dev, config);

}

/* Parse a QETH device entry. */
static void parse_qeth(struct fw_file *f, struct fw_dehdr *de, config_t config,
		       struct util_list *objects)
{
	struct fw_qeth *qeth = (struct fw_qeth *) de;
	struct ccwgroup_devid devid;
	struct device *dev;
	char *id;

	if (!check_de_size(f, de, sizeof(struct fw_qeth)))
		return;
	if (!check_iodevid(f, &qeth->id_flags, &qeth->read_id) ||
	    !check_iodevid(f, &qeth->id_flags, &qeth->write_id) ||
	    !check_iodevid(f, &qeth->id_flags, &qeth->data_id))
		return;

	/* Add qeth entry */
	devid.num = 3;
	io_to_ccw(&devid.devid[0], &qeth->read_id);
	io_to_ccw(&devid.devid[1], &qeth->write_id);
	io_to_ccw(&devid.devid[2], &qeth->data_id);
	id = ccwgroup_devid_to_str(&devid);
	dev = add_device(f, &qeth_subtype_qeth, id, config, objects);
	free(id);

	if (dev && qeth->hdr.len > sizeof(struct fw_qeth))
		parse_settings(f, qeth->settings, dev, config);
}

/* Parse a firmware file. */
static void parse_fw(struct fw_file *f, long skip, config_t config,
		     struct util_list *objects)
{
	char *data = f->buffer;
	struct fw_filehdr *hdr = (struct fw_filehdr *) data;
	struct fw_dehdr *de;
	uint16_t count = 0;
	uint32_t off;

	for (off = hdr->hdr_len; off < hdr->file_len; off += de->len) {
		count++;
		de = (struct fw_dehdr *) &data[off];
		if (fwacc(f, de->len) == 0) {
			fwwarn(f, "Empty device entry");
			break;
		}
		if (off + fwacc(f, de->len) > hdr->file_len) {
			fwwarn(f, "Device entry too long");
			break;
		}
		if (skip >= 0 && de->seq <= skip) {
			debug("Skipping %s entry due to sequence (%08x)\n",
			      type_to_str(de->type), de->seq);
			continue;
		}
		switch (fwacc(f, de->type)) {
		case FW_DE_HDR_TYPE_DASD:
			parse_dasd(f, de, config, objects);
			break;
		case FW_DE_HDR_TYPE_ZFCP_HOST:
			parse_zfcp_host(f, de, config, objects);
			break;
		case FW_DE_HDR_TYPE_ZFCP_LUN:
			parse_zfcp_lun(f, de, config, objects);
			break;
		case FW_DE_HDR_TYPE_QETH:
			parse_qeth(f, de, config, objects);
			break;
		default:
			fwwarn(f, "Unknown entry (type=%04x)", de->type);
			break;
		}
	}

	if (count != fwacc(f, hdr->de_count))
		fwwarn(f, "Device entry count mismatch");
}

/* Read configuration objects from @fd in firmware file format. Add pointers to
 * newly allocated struct export_objects to ptrlist @objects. If @skip is a
 * positive number, skip over entries with a sequence number equal to or
 * greater than @skip. */
exit_code_t firmware_read(FILE *fd, const char *filename, long skip,
			  config_t config, struct util_list *objects)
{
	struct fw_file file;
	exit_code_t rc;

	rc = read_fw(&file, fd, filename);
	if (rc)
		return rc;

	parse_fw(&file, skip, config, objects);
	free(file.buffer);

	return rc;
}

/* Check if @fd refers to a file in binary firmware format. */
bool firmware_detect(FILE *fd)
{
	int c;

	c = fgetc(fd);
	ungetc(c, fd);

	/* Note: A full check would require looking at least at the first 4
	 * bytes, but fd might be non-seekable (e.g. pipe). Since there is no
	 * way that a textual import file can start with a 'z', looking at
	 * the first char should be enough. */

	return c == 'z';
}
