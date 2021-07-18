/*
 * lscss - Tool to list information about subchannels
 *
 * Copyright IBM Corp. 2003, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>

#include "lib/ccw.h"
#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_rec.h"
#include "lib/util_scandir.h"
#include "lib/util_panic.h"
#include "lib/zt_common.h"

#include "misc.h"

/*
 * Numbers for lscss command options that do not have a short form
 */
#define OPT_AVAIL	256	/* --avail */
#define OPT_VPM		257	/* --vpm */
#define OPT_IO		258	/* --io */
#define OPT_CHSC	259	/* --chsc */
#define OPT_EADM	260	/* --eadm */
#define OPT_VFIO	261	/* --vfio */

/* Bus_id format for subchannel or device id */
#define ID_FORMAT	"^[[:xdigit:]]{1,2}[.][[:xdigit:]][.][[:xdigit:]]{4}$"
/* UUID format */
#define UUID_FORMAT	"^[[:xdigit:]]{8}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{4}-[[:xdigit:]]{12}$"

/* Misc constants */
#define MAX_BUF_SIZE		256
#define PREFIX_ID_LENGTH	4
#define SHORT_ID_LENGTH		4
#define CHPIDS_SEGMENT_LENGTH	8

/* Range of subchannel or device identifiers */
struct range {
	struct util_list_node node; /* Pointers to previous and next range */
	struct ccw_devid lower; /* Lower sch_id or bus_id */
	struct ccw_devid upper; /* Upper sch_id or bus_id */
};

/* Device type and model */
struct devtype {
	struct util_list_node node; /* Pointers to previous and next devtype */
	bool no_model; /* <type> format input */
	unsigned int type; /* Device type */
	unsigned int model; /* Specific model of the specified device type */
};

/* Subchannel types */
enum sch_type {
	SUBCHANNEL_TYPE_IO   = 0,	/* I/O subchannels */
	SUBCHANNEL_TYPE_CHSC = 1,	/* CHSC subchannels */
	SUBCHANNEL_TYPE_EADM = 3,	/* EADM subchannels */
};

/*
 * Private data
 */
static struct lscss_cmd_opts {
	/* Boolean flags to indicate wich command options are in effect */
	bool opt_short;		/* -s or --short */
	bool opt_devtype;	/* -t or --devtype */
	bool opt_devrange;	/* -d or --devrange */
	bool opt_avail;		/* --avail */
	bool opt_vpm;		/* --vpm */
	bool opt_uppercase;	/* -u or --uppercase */
	bool opt_io;		/* --io */
	bool opt_chsc;		/* --chsc */
	bool opt_eadm;		/* --eadm */
	bool opt_vfio;		/* --vfio */
	/* List of device types for the output limitation */
	int dev_count;
	struct util_list *devtypes;
	/* List of  sch_id or bus_id ranges for the output limitation */
	int rng_count;
	struct util_list *ranges;
} cmd;

/*
 * Program configuration
 */
static const struct util_prg prg = {
	.desc	= "List information about available subchannels.\n"
		  "\nRANGE\n"
		  "   ID              Select single subchannel by ID, e.g. 0.0.004f or 4f\n"
		  "   FROM-TO         Select range of subchannels between FROM and TO\n"
		  "   ID1,ID2-ID3,... Select list of subchannels or subchannel ranges",
	.args	= "[RANGE]",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2017,
			.pub_last = 2017,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Command line options
 */
static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("OPTIONS"),
	{
		.option = { "short", no_argument, NULL, 's'},
		.desc = "Shorten IDs by removing leading \"0.0.\" "
			"Note: only IDs beginning with \"0.0.\" "
			"will be displayed in this case.",
	},
	{
		.option = { "devtype", required_argument, NULL, 't'},
		.argument = "TYPE,..",
		.desc = "For IO subchannels, limit output to devices of "
			"the given TYPE (DEVTYPE[/MODEL])",
	},
	{
		.option = { "devrange", no_argument, NULL, 'd'},
		.desc = "Indicate that RANGE refers to device identifiers",
	},
	{
		.option = { "avail", no_argument, NULL, OPT_AVAIL},
		.desc = "Show availability attribute of IO devices",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "vpm", no_argument, NULL, OPT_VPM},
		.desc = "Show verified path mask",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "uppercase", no_argument, NULL, 'u'},
		.desc = "Print values using uppercase",
	},
	{
		.option = { "io", no_argument, NULL, OPT_IO},
		.desc = "Show IO subchannels (default)",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "chsc", no_argument, NULL, OPT_CHSC},
		.desc = "Show CHSC subchannels",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "eadm", no_argument, NULL, OPT_EADM},
		.desc = "Show EADM subchannels",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "vfio", no_argument, NULL, OPT_VFIO},
		.desc = "Show VFIO subchannel information",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "all", no_argument, NULL, 'a'},
		.desc = "Show subchannels of all types",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

/*
 * Add new subchannel or device range to the ranges list for further output
 * limitation
 */
static void add_new_range(const char *lower_id, const char *upper_id)
{
	struct range *rng;

	rng = util_malloc(sizeof(*rng));
	if (!ccw_parse_str(&rng->lower, lower_id))
		errx(EXIT_FAILURE, "Invalid ID specified: %s", lower_id);
	if (!ccw_parse_str(&rng->upper, upper_id))
		errx(EXIT_FAILURE, "Invalid ID specified: %s", upper_id);
	util_list_add_tail(cmd.ranges, rng);
}

/*
 * Check if subchannel or device bus_id is within the provided range
 */
static bool id_in_range(struct range *rng, struct ccw_devid *id)
{
	/* First compare cssid, then ssid and finally devno */
	if (id->cssid == rng->lower.cssid) {
		if (id->ssid == rng->lower.ssid) {
			if (id->devno < rng->lower.devno)
				return false;
		} else if (id->ssid < rng->lower.ssid) {
			return false;
		}
	} else if (id->cssid < rng->lower.cssid) {
		return false;
	}

	if (id->cssid == rng->upper.cssid) {
		if (id->ssid == rng->upper.ssid) {
			if (id->devno > rng->upper.devno)
				return false;
		} else if (id->ssid > rng->upper.ssid) {
			return false;
		}
	} else if (id->cssid > rng->upper.cssid) {
		return false;
	}

	return true;
}

/*
 * Check if subchannel or device id matches any range in the ranges list
 */
static bool id_in_ranges_list(const char *id)
{
	struct ccw_devid ccw_id;
	struct range *rng;

	if (!ccw_parse_str(&ccw_id, id))
		errx(EXIT_FAILURE, "Invalid subchannel directory '%s'", id);
	util_list_iterate(cmd.ranges, rng) {
		if (id_in_range(rng, &ccw_id))
			return true;
	}
	return false;
}

/*
 * Parse a string into a devtype structure
 *
 * @param[in,out] dt   Pointer to devtype structure to be initialized
 * @parm[in]      id   String to parse
 *
 * @returns       true if the input string has been parsed successfuly;
 *                otherwise false
 */
static bool parse_devtype_str(struct devtype *dt, const char *id)
{
	char d;

	if (strncasecmp(id, "0x", 2) == 0)
		return false;
	dt->no_model = false;
	if (sscanf(id, "%4x %c", &dt->type, &d) == 1) {
		/* Process <type> input format (maximum length of 4 characters) */
		dt->no_model = true;
	} else if (sscanf(id, "%4x/%2x %c", &dt->type, &dt->model,
			  &d) != 2) {
		/*
		 * Process <type>/<model> input format (maximum lengths of 4 and 2
		 * characters respectively)
		 */
		return false;
	}
	return true;
}

/*
 * Add new device type to the devtypes list for further output limitation
 */
static void add_new_devtype(const char *dtype)
{
	struct devtype *dt;

	dt = util_malloc(sizeof(struct devtype));
	if (!parse_devtype_str(dt, dtype))
		errx(EXIT_FAILURE, "Invalid device type specified: %s", dtype);
	util_list_add_tail(cmd.devtypes, dt);
}

/*
 * Check if provided device type matches any from the device types list
 */
static bool in_devtypes_list(char *dtype)
{
	struct devtype arg_dt;
	struct devtype *dt;

	if (!parse_devtype_str(&arg_dt, dtype))
		errx(EXIT_FAILURE, "Invalid device type detected: %s", dtype);
	util_list_iterate(cmd.devtypes, dt) {
		if (arg_dt.type == dt->type) {
			if (dt->no_model || arg_dt.model == dt->model)
				return true;
		}
	}
	return false;
}

/*
 * Fill in the device related entry fields (devtyp, cutype, use, avail)
 *
 * @returns 0 - devtype matches devtypes list, device information filled in
 *          1 - devtype does not match devtypes list, skip entry
 */
static int fill_device_info(struct util_rec *rec, char *path, char *device)
{
	unsigned long int val_ul;
	char buf[MAX_BUF_SIZE];

	if (!path || !device) {
		if (cmd.opt_devtype && cmd.dev_count > 0)
			return 1;
		util_rec_set(rec, "devtyp", "");
		util_rec_set(rec, "cutype", "");
		util_rec_set(rec, "use", "");
		if (cmd.opt_avail)
			util_rec_set(rec, "avail", "");
		return 0;
	}

	if (util_file_read_line(buf, sizeof(buf), "%s/%s/devtype",
				path, device) == 0) {
		if (strcmp(buf, "n/a") == 0)
			/* Special case for 'n/a' devtype */
			strncpy(buf, "0000/00", sizeof(buf));
		if (cmd.opt_devtype && cmd.dev_count > 0 &&
		   !in_devtypes_list(buf))
			return 1;
		if (cmd.opt_uppercase)
			util_str_toupper(buf);
		util_rec_set(rec, "devtyp", "%s", buf);
	} else {
		if (cmd.opt_devtype && cmd.dev_count > 0)
			return 1;
		util_rec_set(rec, "devtyp", "");
	}

	if (util_file_read_line(buf, sizeof(buf), "%s/%s/cutype",
				path, device) == 0) {
		if (cmd.opt_uppercase)
			util_str_toupper(buf);
		util_rec_set(rec, "cutype", "%s", buf);
	} else {
		util_rec_set(rec, "cutype", "");
	}

	if (util_file_read_ul(&val_ul, 10, "%s/%s/online", path, device) == 0) {
		if (val_ul == 1) {
			snprintf(buf, sizeof(buf), "yes");
			if (cmd.opt_uppercase)
				util_str_toupper(buf);
			util_rec_set(rec, "use", "%s", buf);
		} else {
			util_rec_set(rec, "use", "");
		}
	} else {
		util_rec_set(rec, "use", "");
	}

	if (cmd.opt_avail) {
		if (util_file_read_line(buf, sizeof(buf), "%s/%s/availability",
					path, device) == 0) {
			if (cmd.opt_uppercase)
				util_str_toupper(buf);
			util_rec_set(rec, "avail", "%s", buf);
		} else {
			util_rec_set(rec, "avail", "");
		}
	}
	return 0;
}

static bool is_sch_vfio(char *path)
{
	char lnk[PATH_MAX], driver_path[PATH_MAX];
	ssize_t rc;

	snprintf(lnk, PATH_MAX, "%s/driver", path);
	rc = readlink(lnk, driver_path, PATH_MAX);
	if (rc < 0)
		return false;

	util_assert(rc < (PATH_MAX - 1),
		    "Internal error: Symlink name too long");
	driver_path[rc] = '\0';

	if (strcmp(basename(driver_path), "vfio_ccw") == 0)
		return true;
	return false;
}

/*
 * Fill in the MDEV id entry field
 *
 * @returns 0 - MDEV id information filled in
 *          1 - skip entry
 */
static int fill_vfio_devid(struct util_rec *rec, char *path)
{
	char *device, buf[MAX_BUF_SIZE];
	struct dirent **de_vec;
	int count;

	if (!is_sch_vfio(path))
		return 1;

	/* Find and process mdev device directory */
	count = util_scandir(&de_vec, alphasort, path, "%s", UUID_FORMAT);
	if (count > 0) {
		device = de_vec[0]->d_name;
		snprintf(buf, sizeof(buf), "%s", device);
	} else {
		strncpy(buf, "none", sizeof(buf));
	}
	if (cmd.opt_uppercase)
		util_str_toupper(buf);
	util_rec_set(rec, "mdev", "%s", buf);
	util_scandir_free(de_vec, count);
	return 0;
}

/*
 * Fill in the CCW device id entry field
 *
 * @returns 0 - CCW device id information filled in
 *          1 - skip entry
 */
static int fill_io_devid(struct util_rec *rec, char *path)
{
	char *device, buf[MAX_BUF_SIZE];
	struct dirent **de_vec;
	int count;

	/* Find and process device directory */
	count = util_scandir(&de_vec, alphasort, path, "%s", ID_FORMAT);
	if (count > 0) {
		device = de_vec[0]->d_name;
		if (cmd.opt_short) {
			/* Display only 0.0.xxxx devices for --short */
			if (strncmp(device, "0.0.", PREFIX_ID_LENGTH) != 0)
				return 1;
			snprintf(buf, sizeof(buf), "%s", device +
				 strlen(device) - SHORT_ID_LENGTH);
		} else {
			snprintf(buf, sizeof(buf), "%s", device);
		}
		if (cmd.opt_devrange && cmd.rng_count > 0 &&
		   !id_in_ranges_list(device)) {
			util_scandir_free(de_vec, count);
			return 1;
		}
		if (fill_device_info(rec, path, device) != 0) {
			util_scandir_free(de_vec, count);
			return 1;
		}
	} else {
		if (cmd.opt_devrange && cmd.rng_count > 0) {
			util_scandir_free(de_vec, count);
			return 1;
		}
		if (util_file_read_line(buf, sizeof(buf), "%s/dev_busid",
					path) == 0) {
			if (cmd.opt_short) {
				if (strncmp(buf, "0.0.", PREFIX_ID_LENGTH) != 0)
					return 1;
				memmove(buf, buf + PREFIX_ID_LENGTH,
					(sizeof(buf) - PREFIX_ID_LENGTH));
			}
		}
		fill_device_info(rec, NULL, NULL);
	}
	if (cmd.opt_uppercase)
		util_str_toupper(buf);
	util_rec_set(rec, "device", "%s", buf);
	util_scandir_free(de_vec, count);
	return 0;
}

/*
 * Print IO subchannel entry
 */
static void print_sch_io(struct util_rec *rec, char *path, char *sch_dir)
{
	unsigned int pim, pam, pom;
	char buf[MAX_BUF_SIZE];

	/* Fill in subchannel ID */
	if (cmd.opt_short) {
		/* Display only 0.0.xxxx subchannels for --short */
		if (strncmp(sch_dir, "0.0.", PREFIX_ID_LENGTH) != 0)
			return;
		snprintf(buf, sizeof(buf), "%s", sch_dir +
			 strlen(sch_dir) - SHORT_ID_LENGTH);
	} else {
		snprintf(buf, sizeof(buf), "%s", sch_dir);
	}
	if (!cmd.opt_devrange && cmd.rng_count > 0 &&
	    !id_in_ranges_list(sch_dir))
		return;
	if (cmd.opt_uppercase)
		util_str_toupper(buf);
	util_rec_set(rec, "subch", "%s", buf);
	if (cmd.opt_vfio) {
		if (fill_vfio_devid(rec, path) != 0)
			return;
	} else if (fill_io_devid(rec, path) != 0)
		return;
	/* Fill in PIM-PAM-POM data */
	if (util_file_read_line(buf, sizeof(buf), "%s/pimpampom", path) == 0) {
		if (sscanf(buf, "%x %x %x", &pim, &pam, &pom) == 3) {
			if (cmd.opt_uppercase) {
				util_rec_set(rec, "pim", "%02X", pim);
				util_rec_set(rec, "pam", "%02X", pam);
				util_rec_set(rec, "pom", "%02X", pom);
			} else {
				util_rec_set(rec, "pim", "%02x", pim);
				util_rec_set(rec, "pam", "%02x", pam);
				util_rec_set(rec, "pom", "%02x", pom);
			}
		} else {
			util_rec_set(rec, "pim", "");
			util_rec_set(rec, "pam", "");
			util_rec_set(rec, "pom", "");
		}
	} else {
		util_rec_set(rec, "pim", "");
		util_rec_set(rec, "pam", "");
		util_rec_set(rec, "pom", "");
	}
	/* Fill in VPM data */
	if (cmd.opt_vpm) {
		if (util_file_read_line(buf, sizeof(buf),
					"%s/vpm", path) == 0) {
			if (cmd.opt_uppercase)
				util_str_toupper(buf);
			util_rec_set(rec, "vpm", "%s", buf);
		} else {
			util_rec_set(rec, "vpm", "");
		}
	}
	/*
	 * Fill in CHPIDs data.
	 * Since chpids are stored as a list of two digit hexadecimal numbers,
	 * we first read it as a single string, then eliminate blanks from it
	 * and then break in two 8-char segments.
	 */
	if (util_file_read_line(buf, sizeof(buf), "%s/chpids", path) == 0) {
		misc_str_remove_symbol(buf, ' ');
		if (cmd.opt_uppercase)
			util_str_toupper(buf);
		util_rec_set(rec, "chpids", "%.8s %.8s", buf,
			     buf + CHPIDS_SEGMENT_LENGTH);
	} else {
		util_rec_set(rec, "chpids", "");
	}

	util_rec_print(rec);
}

/*
 * Print CHSC subchannel entry
 */
static void print_sch_chsc(struct util_rec *rec, char *sch_dir)
{
	char buf[MAX_BUF_SIZE];

	/* Skip entry if devrange or devtype option is active */
	if (cmd.opt_devrange && cmd.rng_count > 0)
		return;
	if (cmd.opt_devtype && cmd.dev_count > 0)
		return;
	/* Fill in subchannel ID */
	if (cmd.opt_short) {
		/* Display only 0.0.xxxx subchannels for --short */
		if (strncmp(sch_dir, "0.0.", PREFIX_ID_LENGTH) != 0)
			return;
		snprintf(buf, sizeof(buf), "%s", sch_dir +
			 strlen(sch_dir) - SHORT_ID_LENGTH);
	} else {
		snprintf(buf, sizeof(buf), "%s", sch_dir);
	}
	if (cmd.rng_count > 0 && !id_in_ranges_list(sch_dir))
		return;
	if (cmd.opt_uppercase)
		util_str_toupper(buf);
	util_rec_set(rec, "subch", "%s", buf);
	/* Device field is always 'n/a' for CHSC */
	strncpy(buf, "n/a", sizeof(buf));
	if (cmd.opt_uppercase)
		util_str_toupper(buf);
	util_rec_set(rec, "device", "%s", buf);

	util_rec_print(rec);
}

/*
 * Print EADM subchannel entry
 */
static void print_sch_eadm(struct util_rec *rec, char *sch_dir)
{
	char buf[MAX_BUF_SIZE];

	/* Skip entry if devrange or devtype option is active */
	if (cmd.opt_devrange && cmd.rng_count > 0)
		return;
	if (cmd.opt_devtype && cmd.dev_count > 0)
		return;
	/* Fill in subchannel ID */
	if (cmd.opt_short) {
		/* Display only 0.0.xxxx subchannels for --short */
		if (strncmp(sch_dir, "0.0.", PREFIX_ID_LENGTH) != 0)
			return;
		snprintf(buf, sizeof(buf), "%s", sch_dir +
			 strlen(sch_dir) - SHORT_ID_LENGTH);
	} else {
		snprintf(buf, sizeof(buf), "%s", sch_dir);
	}
	if (cmd.rng_count > 0 && !id_in_ranges_list(sch_dir))
		return;
	if (cmd.opt_uppercase)
		util_str_toupper(buf);
	util_rec_set(rec, "subch", "%s", buf);
	/* Device field is always 'n/a' for EADM */
	strncpy(buf, "n/a", sizeof(buf));
	if (cmd.opt_uppercase)
		util_str_toupper(buf);
	util_rec_set(rec, "device", "%s", buf);

	util_rec_print(rec);
}

/*
 * Print information for all defunct devices in one css
 */
static void print_defunct_devices(struct util_rec *rec, char *path)
{
	char *device, buf[MAX_BUF_SIZE];
	struct dirent **de_vec;
	int i, count;

	/* Process all the devices within defunct directory */
	count = util_scandir(&de_vec, alphasort, path, "%s", ID_FORMAT);
	for (i = 0; i < count; i++) {
		device = de_vec[i]->d_name;
		if (cmd.opt_short) {
			/* Display only 0.0.xxxx devices for --short */
			if (strncmp(device, "0.0.", PREFIX_ID_LENGTH) != 0)
				return;
			snprintf(buf, sizeof(buf), "%s", device +
				 strlen(device) - SHORT_ID_LENGTH);
		} else {
			snprintf(buf, sizeof(buf), "%s", device);
		}
		if (cmd.opt_devrange && cmd.rng_count > 0 &&
		   !id_in_ranges_list(device))
			continue;

		if (fill_device_info(rec, path, device) != 0)
			continue;

		if (cmd.opt_uppercase)
			util_str_toupper(buf);
		util_rec_set(rec, "device", "%s", buf);
		/* Subchannel field is always 'n/a' for defunct devices */
		strncpy(buf, "n/a", sizeof(buf));
		if (cmd.opt_uppercase)
			util_str_toupper(buf);
		util_rec_set(rec, "subch", "%s", buf);
		/* Other fields are blank */
		util_rec_set(rec, "pim", "");
		util_rec_set(rec, "pam", "");
		util_rec_set(rec, "pom", "");
		if (cmd.opt_vpm)
			util_rec_set(rec, "vpm", "");
		util_rec_set(rec, "chpids", "");

		util_rec_print(rec);
	}
	util_scandir_free(de_vec, count);
}

/*
 * Loop through subchannel directories and print entries of specified type
 */
static void print_subchannels_of_type(enum sch_type type_requested,
				      struct util_rec *rec)
{
	unsigned long int type_ul;
	struct dirent **de_vec;
	char *path, *sch_dir;
	int i, count;

	path = util_path_sysfs("bus/css/devices");
	count = util_scandir(&de_vec, alphasort, path, "%s", ID_FORMAT);
	free(path);
	for (i = 0; i < count; i++) {
		sch_dir = de_vec[i]->d_name;
		path = util_path_sysfs("bus/css/devices/%s", sch_dir);
		if (util_file_read_ul(&type_ul, 10, "%s/type", path) == 0) {
			if (type_ul != type_requested)
				continue;
			if (type_ul == SUBCHANNEL_TYPE_IO)
				print_sch_io(rec, path, sch_dir);
			else if (type_ul == SUBCHANNEL_TYPE_CHSC)
				print_sch_chsc(rec, sch_dir);
			else if (type_ul == SUBCHANNEL_TYPE_EADM)
				print_sch_eadm(rec, sch_dir);
		} else {
		/*
		 * Subchannels with no type identifier treated as
		 * IO subchannels
		 */
			if (type_requested == SUBCHANNEL_TYPE_IO)
				print_sch_io(rec, path, sch_dir);
		}
		free(path);
	}
	util_scandir_free(de_vec, count);
	/* Process defunct devices (if no subchannel range is specified) */
	if (!cmd.opt_devrange && cmd.rng_count > 0)
		return;
	path = util_path_sysfs("devices");
	count = util_scandir(&de_vec, alphasort, path, "css.*");
	free(path);
	for (i = 0; i < count; i++) {
		path = util_path_sysfs("devices/%s/defunct", de_vec[i]->d_name);
		print_defunct_devices(rec, path);
		free(path);
	}
	util_scandir_free(de_vec, count);
}

/*
 * Print subchannels table
 */
static void cmd_lscss(void)
{
	struct util_rec *rec;

	if (cmd.opt_io) {
		rec = util_rec_new_wide("-");
		util_rec_def(rec, "device", UTIL_REC_ALIGN_LEFT, 8, "Device");
		util_rec_def(rec, "subch",  UTIL_REC_ALIGN_LEFT, 9, "Subchan.");
		util_rec_def(rec, "devtyp", UTIL_REC_ALIGN_LEFT, 7, "DevType");
		util_rec_def(rec, "cutype", UTIL_REC_ALIGN_LEFT, 7, "CU Type");
		util_rec_def(rec, "use",    UTIL_REC_ALIGN_LEFT, 4, "Use");
		util_rec_def(rec, "pim",    UTIL_REC_ALIGN_LEFT, 3, "PIM");
		util_rec_def(rec, "pam",    UTIL_REC_ALIGN_LEFT, 3, "PAM");
		if (cmd.opt_vpm) {
			util_rec_def(rec, "pom", UTIL_REC_ALIGN_LEFT, 3, "POM");
			util_rec_def(rec, "vpm", UTIL_REC_ALIGN_LEFT, 3, "VPM");
		} else
			util_rec_def(rec, "pom", UTIL_REC_ALIGN_LEFT, 4, "POM");
		util_rec_def(rec, "chpids", UTIL_REC_ALIGN_LEFT, 17, "CHPIDs");
		if (cmd.opt_avail)
			util_rec_def(rec, "avail", UTIL_REC_ALIGN_LEFT, 6,
				     "Avail.");
		/* Print header only if other subchannel types are requested */
		if (cmd.opt_chsc || cmd.opt_eadm || cmd.opt_vfio)
			printf("IO Subchannels and Devices:\n");
		util_rec_print_hdr(rec);
		print_subchannels_of_type(SUBCHANNEL_TYPE_IO, rec);
		util_rec_free(rec);
	}

	if (cmd.opt_chsc) {
		rec = util_rec_new_wide("-");
		util_rec_def(rec, "device", UTIL_REC_ALIGN_LEFT, 8, "Device");
		util_rec_def(rec, "subch",  UTIL_REC_ALIGN_LEFT, 9, "Subchan.");
		/* Print header only if other subchannel types also requested */
		if (cmd.opt_io || cmd.opt_eadm || cmd.opt_vfio)
			printf("\nCHSC Subchannels:\n");
		util_rec_print_hdr(rec);
		print_subchannels_of_type(SUBCHANNEL_TYPE_CHSC, rec);
		util_rec_free(rec);
	}

	if (cmd.opt_eadm) {
		rec = util_rec_new_wide("-");
		util_rec_def(rec, "device", UTIL_REC_ALIGN_LEFT, 8, "Device");
		util_rec_def(rec, "subch",  UTIL_REC_ALIGN_LEFT, 9, "Subchan.");
		/* Print header only if other subchannel types also requested */
		if (cmd.opt_chsc || cmd.opt_io || cmd.opt_vfio)
			printf("\nEADM Subchannels:\n");
		util_rec_print_hdr(rec);
		print_subchannels_of_type(SUBCHANNEL_TYPE_EADM, rec);
		util_rec_free(rec);
	}

	if (cmd.opt_vfio) {
		rec = util_rec_new_wide("-");
		util_rec_def(rec, "mdev",   UTIL_REC_ALIGN_LEFT, 37, "MDEV");
		util_rec_def(rec, "subch",  UTIL_REC_ALIGN_LEFT, 9, "Subchan.");
		util_rec_def(rec, "pim",    UTIL_REC_ALIGN_LEFT, 3, "PIM");
		util_rec_def(rec, "pam",    UTIL_REC_ALIGN_LEFT, 3, "PAM");
		if (cmd.opt_vpm) {
			util_rec_def(rec, "pom", UTIL_REC_ALIGN_LEFT, 3, "POM");
			util_rec_def(rec, "vpm", UTIL_REC_ALIGN_LEFT, 3, "VPM");
		} else
			util_rec_def(rec, "pom", UTIL_REC_ALIGN_LEFT, 4, "POM");
		util_rec_def(rec, "chpids", UTIL_REC_ALIGN_LEFT, 17, "CHPIDs");
		/* Print header only if other subchannel types are requested */
		if (cmd.opt_io || cmd.opt_chsc || cmd.opt_eadm)
			printf("\nI/O Subchannels used for VFIO:\n");
		util_rec_print_hdr(rec);
		print_subchannels_of_type(SUBCHANNEL_TYPE_IO, rec);
		util_rec_free(rec);
	}
}

/*
 * Parse options and execute the command
 */
int main(int argc, char *argv[])
{
	char *id_from, *id_to, *id_list = NULL;
	char *dtype, *dtype_list = NULL;
	int c, i;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while (1) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		case 's':
			cmd.opt_short = true;
			break;
		case 't':
			cmd.opt_devtype = true;
			dtype_list = optarg;
			break;
		case 'd':
			cmd.opt_devrange = true;
			break;
		case OPT_AVAIL:
			cmd.opt_avail = true;
			break;
		case OPT_VPM:
			cmd.opt_vpm = true;
			break;
		case 'u':
			cmd.opt_uppercase = true;
			break;
		case OPT_IO:
			cmd.opt_io = true;
			break;
		case OPT_CHSC:
			cmd.opt_chsc = true;
			break;
		case OPT_EADM:
			cmd.opt_eadm = true;
			break;
		case OPT_VFIO:
			cmd.opt_vfio = true;
			break;
		case 'a':
			cmd.opt_io = true;
			cmd.opt_chsc = true;
			cmd.opt_eadm = true;
			break;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}
	/*
	 * VFIO subchannel view and IO subchannel view are mutual exclusion.
	 * And it does not make sense to use the -d, -t, and --avail options
	 * together with --vfio.
	 */
	if (cmd.opt_vfio &&
	    (cmd.opt_io || cmd.opt_devrange ||
	     cmd.opt_devtype || cmd.opt_avail)) {
		errx(EXIT_FAILURE, "Invalid option combination: "
		     "--vfio can not be used with --io, -d, -t or --avail");
	}
	/* Display IO subchannels by default */
	if (!cmd.opt_chsc && !cmd.opt_eadm && !cmd.opt_vfio)
		cmd.opt_io = true;

	/* Process the list of specified device types */
	if (dtype_list != NULL) {
		cmd.devtypes = util_list_new(struct devtype, node);
		cmd.dev_count = 0;
		/* Loop over comma-separated list */
		dtype = strtok(dtype_list, ",");
		while (dtype != NULL) {
			add_new_devtype(dtype);
			cmd.dev_count++;
			dtype = strtok(NULL, ",");
		}
	}

	/* Scan RANGE parameters appending each argument with comma */
	for (i = optind; i < argc; i++) {
		if (i > optind)
			id_list = util_strcat_realloc(id_list, ",");
		id_list = util_strcat_realloc(id_list, argv[i]);
	}

	/* Process the list of specified ranges */
	if (id_list != NULL) {
		cmd.ranges = util_list_new(struct range, node);
		cmd.rng_count = 0;
		/* Loop over comma-separated list */
		id_from = strtok(id_list, ",");
		while (id_from != NULL) {
			id_to = strchr(id_from, '-');
			if (id_to == NULL)
				id_to = id_from;
			else
				*id_to++ = '\0';
			if (*id_to == '\0')
				errx(EXIT_FAILURE, "Invalid ID specified: %s", id_from);
			add_new_range(id_from, id_to);
			cmd.rng_count++;
			id_from = strtok(NULL, ",");
		}
		free(id_list);
	}

	/* Process lscss command with provided options and attributes */
	cmd_lscss();
	util_list_free(cmd.devtypes);
	util_list_free(cmd.ranges);
	return EXIT_SUCCESS;
}
