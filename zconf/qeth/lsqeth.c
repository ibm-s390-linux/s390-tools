/**
 * lsqeth - command of s390-tools
 *
 * List qeth-based network devices with their attributes
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <argz.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_opt.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_rec.h"
#include "lib/util_scandir.h"
#include "lib/zt_common.h"

#include "misc.h"

#define ID_FORMAT		"^[[:xdigit:]]{1,2}[.][[:xdigit:]][.][[:xdigit:]]{4}$"
#define MAX_ID_LENGTH		10
#define PAGE_SIZE		4096

/*
 * Constants for CP call (taken from vmcp.h)
 */
#define VMCP_DEVICE_NODE "/dev/vmcp"
#define VMCP_GETCODE _IOR(0x10, 1, int)
#define VMCP_SETBUF _IOW(0x10, 2, int)
#define VMCP_GETSIZE _IOR(0x10, 3, int)
#define CP_BUF_SIZE	8192

/*
 * Private data
 */
static struct lsqeth_cmd_flags {
	bool proc_format;
} cmd;

/*
 * Program configuration
 */
const struct util_prg prg = {
	.desc	= "List all qeth-based network devices with their corresponding settings.\n"
		  "\nINTERFACE"
		  "\n List only attributes of specified interface",
	.args	= "[INTERFACE]",
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
		.option = { "proc", no_argument, NULL, 'p'},
		.desc = "List all devices in the former /proc/qeth format"
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

/*
 * Exchange content of field value via simple translation map
 *
 * If the attribute is required for translation (attibute name is present in
 * tr_attr_list[]) then the value of the attribute (if matches the dictionary
 * translation key) is exchanged by the target value of the translation
 * dictionary (sys_to_proc_dict[][2]).
 *
 */
static void tr_to_proc_format(char *val, const char *attr_name)
{
	static const char *tr_attr_list[] = {
		"checksumming",
		"priority_queueing",
		"route4",
		"route6"
	};
	static const char *sys_to_proc_dict[][2] = {
		{"sw checksumming", "sw"},
		{"hw checksumming", "hw"},
		{"no checksumming", "no"},
		{"always queue 0", "always_q_0"},
		{"always queue 1", "always_q_1"},
		{"always queue 2", "always_q_2"},
		{"always queue 3", "always_q_3"},
		{"by precedence", "by_prec."},
		{"by type of service", "by_ToS"},
		{"by skb-priority", "by_skb"},
		{"by VLAN headers", "by_vlan"},
		{"primary router", "pri"},
		{"secondary router", "sec"},
		{"primary connector+", "p+c"},
		{"primary connector", "p.c"},
		{"secondary connector+", "s+c"},
		{"secondary connector", "s.c"},
		{"multicast router+", "mc+"},
		{"multicast router", "mc"},
		{NULL, NULL}
	};
	unsigned int i = 0;

	if (misc_str_in_list(attr_name, tr_attr_list,
			     ARRAY_SIZE(tr_attr_list))) {
		while (sys_to_proc_dict[i][0]) {
			if (strcmp(val, sys_to_proc_dict[i][0]) == 0) {
				strcpy(val, sys_to_proc_dict[i][1]);
				return;
			}
			i++;
		}
	}
}

/*
 * Read IPv4 and IPv6 addresses from related sysfs entries for ipa/parp/vipa and
 * store each value at the end of *argz array. Return the number of entries stored.
 */
static int get_qethconf(const char *name, const char *if_name, char **argz,
			size_t *argz_len)
{
	char *path;
	int count;

	path = util_path_sysfs("class/net/%s/device/%s/add4", if_name, name);
	count = misc_argz_add_from_file(argz, argz_len, path);
	free(path);
	path = util_path_sysfs("class/net/%s/device/%s/add6", if_name, name);
	count += misc_argz_add_from_file(argz, argz_len, path);
	free(path);
	return count;
}

/*
 * Get checksumming information for specified interface
 */
static void ethtool_checksumming(char *buf, const char *if_name)
{
	struct ethtool_value val;
	struct ifreq ifr;
	int fd, rc;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		errx(EXIT_FAILURE, "Internal error: cannot get SOCK_DGRAM socket");
	strncpy(ifr.ifr_name, if_name, IFNAMSIZ);
	val.cmd = ETHTOOL_GRXCSUM;
	ifr.ifr_data = (void *)&val;
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);
	if (!rc && val.data)
		strcpy(buf, "hw");
	else
		strcpy(buf, "sw");
}

/*
 * Call cp command and return the resulting lines as argz vector
 *
 * @param[in,out]	argz	argz vector allocated by argz_create
 *			so the caller should free the allocated memory
 * @param[in,out]	argz_len	argz length
 * @param[in]	fmt	Format string specifying the cp command
 */
static void exec_cp(char **argz, size_t *argz_len, const char *fmt, ...)
{
	int fd, response_code, response_size, rc;
	static const int buf_size = CP_BUF_SIZE;
	char *buf, *command;
	va_list ap;

	fd = open(VMCP_DEVICE_NODE, O_RDWR);
	if (fd == -1)
		errx(EXIT_FAILURE, "Could not open device %s", VMCP_DEVICE_NODE);
	if (ioctl(fd, VMCP_SETBUF, &buf_size) == -1)
		errx(EXIT_FAILURE, "Could not set buffer size");
	UTIL_VASPRINTF(&command, fmt, ap);
	if (write(fd, command, strlen(command)) == -1)
		errx(EXIT_FAILURE, "Could not issue CP command");
	free(command);
	if (ioctl(fd, VMCP_GETCODE, &response_code) == -1)
		errx(EXIT_FAILURE, "Could not query return code");
	if (ioctl(fd, VMCP_GETSIZE, &response_size) == -1)
		errx(EXIT_FAILURE, "Could not query response size");
	buf = util_malloc(buf_size);
	rc = misc_read_buf(fd, buf, buf_size);
	if (rc == -1)
		errx(EXIT_FAILURE, "Could not read CP response");
	rc = argz_create_sep(buf, '\n', argz, argz_len);
	if (rc)
		errx(EXIT_FAILURE, "Memory allocation error for CP response processing");
	free(buf);
}

/*
 * Return card_type attribute value based on 'vmcp q v nic' output
 */
static char *print_LAN(const char *cdev0)
{
	char *tok_vec[5], *tk, *result, *retstr, *devno, *entry;
	char *tail = "not coupled";
	size_t argz_len = 0;
	char *argz = NULL;
	unsigned int i;

	devno = strrchr(cdev0, '.') + 1;
	exec_cp(&argz, &argz_len, "QUERY VIRTUAL NIC %s", devno);
	/* Process CP command output in argz format */
	if (argz_count(argz, argz_len) < 2)
		errx(EXIT_FAILURE, "Internal error: Unexpected result of 'vmcp q v nic' command");
	/* Tokenize second line */
	entry = argz_next(argz, argz_len, argz);
	memset(tok_vec, 0, sizeof(tok_vec));
	tk = strtok(entry, " \t");
	for (i = 0; i < ARRAY_SIZE(tok_vec) && tk; i++) {
		tok_vec[i] = tk;
		tk = strtok(NULL, " \t");
	}
	util_asprintf(&result, "%s %s %s", tok_vec[2], tok_vec[3], tok_vec[4]);
	/* Tokenize first line */
	entry = argz;
	memset(tok_vec, 0, sizeof(tok_vec));
	tk = strtok(entry, " \t");
	for (i = 0; i < ARRAY_SIZE(tok_vec) && tk; i++) {
		tok_vec[i] = tk;
		tk = strtok(NULL, " \t");
	}
	if (strncmp(result, "LAN", 3) == 0) {
		if (strncmp(result + 5, "* Internal", 11) != 0)
			tail = result + 5;
		util_asprintf(&retstr, "GuestLAN: %s (%s %s)",
			      tail, tok_vec[2], tok_vec[3]);
	} else {
		util_asprintf(&retstr, "%s (%s %s)", result, tok_vec[2],
			      tok_vec[3]);
	}
	free(result);
	free(argz);
	return retstr;
}

/*
 * Update card_type field for Virtual NIC devices
 */
static void update_card_type(struct util_rec *rec)
{
	const char *card_type, *cdev0;
	char *upd_card_type;

	if (!util_path_is_readable("/dev/vmcp"))
		return;
	card_type = util_rec_get(rec, "card_type");
	if (!card_type)
		return;
	if (strncmp(card_type, "GuestLAN", 8) == 0 ||
	    strncmp(card_type, "Virt.NIC", 8) == 0) {
		cdev0 = util_rec_get(rec, "cdev0");
		if (!cdev0)
			return;
		upd_card_type = print_LAN(cdev0);
		util_rec_set(rec, "card_type", upd_card_type);
		free(upd_card_type);
	}
}

/*
 * Process regular sysfs attribute and save it to the record.
 */
static void process_sysfs_attribute(struct util_rec *rec, const char *path,
				    const char *attr_name, const char *if_name)
{
	char buf[PAGE_SIZE];
	char *link = NULL;

	/* Process cdev attributes (for normal output format only) */
	if (strncmp(attr_name, "cdev", 4) == 0 && !cmd.proc_format) {
		link = misc_link_target("%s/%s", path, attr_name);
		/* If no simlink found, cdev* record field will not be set */
		if (link) {
			util_rec_set(rec, attr_name, basename(link));
			free(link);
		}
	}
	/* Process other sysfs attributes */
	if (util_file_read_line(buf, sizeof(buf), "%s/%s",
				path, attr_name) == 0 &&
	    strlen(buf) != 0 &&
	    strcmp(buf, "n/a") != 0) {
		/* Translate attribute values to proc-format if required */
		if (cmd.proc_format)
			tr_to_proc_format(buf, attr_name);
		/* Hex notation for 'chpid' attribute in proc format */
		if (strcmp(attr_name, "chpid") == 0 &&
		    cmd.proc_format)
			util_rec_set(rec, attr_name, "x%s", buf);
		else
			util_rec_set(rec, attr_name, buf);
	} else {
		/* Special case for 'checksumming' and 'route6' */
		if (strcmp(attr_name, "checksumming") == 0) {
			if (cmd.proc_format) {
				ethtool_checksumming(buf, if_name);
				util_rec_set(rec, attr_name, buf);
			}
		} else if (strcmp(attr_name, "route6") == 0 &&
			   strcmp(buf, "n/a") == 0) {
			util_rec_set(rec, attr_name, "no");
		} else {
			/* Set 'n/a' default value for proc format*/
			if (cmd.proc_format)
				util_rec_set(rec, attr_name, "n/a");
		}
	}
}

/*
 * Set ipa/parp/vipa attributes for normal format output.
 */
static void set_ipa_vipa_parp(struct util_rec *rec, const char *attr_name,
			      const char *path, const char *if_name)
{
	size_t argz_len = 0;
	char *argz = NULL;

	if (strcmp(attr_name, "ipa") == 0) {
		if (!util_path_is_dir("%s/ipa_takeover", path))
			return;
		if (get_qethconf("ipa_takeover", if_name, &argz, &argz_len))
			util_rec_set_argz(rec, attr_name, argz, argz_len);
	} else if (strcmp(attr_name, "parp") == 0) {
		if (!util_path_is_dir("%s/rxip", path))
			return;
		if (get_qethconf("rxip", if_name, &argz, &argz_len))
			util_rec_set_argz(rec, attr_name, argz, argz_len);
	} else {
		if (!util_path_is_dir("%s/vipa", path))
			return;
		if (get_qethconf("vipa", if_name, &argz, &argz_len))
			util_rec_set_argz(rec, attr_name, argz, argz_len);
	}
	free(argz);
}

/*
 * Set devices attribute for proc format output: '<cdev0>/<cdev1>/<cdev2>'
 */
static void set_devices_fld(struct util_rec *rec, const char *path)
{
	char buf[3*MAX_ID_LENGTH + 3] = "";
	char *link;
	int i;

	for (i = 0; i < 3; i++) {
		link = misc_link_target("%s/cdev%d", path, i);
		/* File name is a link */
		if (i == 2 && link) {
			strcat(buf, basename(link));
		} else {
			if (link)
				strcat(strcat(buf, basename(link)), "/");
			else
				strcat(buf, "/");
		}
		free(link);
	}
	util_rec_set(rec, "devices", buf);
}

/*
 * Check if the attribute should be skipped for layer2 device
 */
static bool not_layer2_attr(const char *attr_name)
{
	/* Layer3 specific attributes */
	static const char *layer3_vec[] = {
		"route4",
		"route6",
		"large_send",
		"fake_ll",
		"fake_broadcast",
		"checksumming",
		"hsuid",
		"sniffer"
	};

	return misc_str_in_list(attr_name, layer3_vec, ARRAY_SIZE(layer3_vec));
}

/*
 * Collect and print attributes for qeth-based device in sepcified format
 */
static void print_device(struct util_rec *rec, const char *device_id)
{
	char *path, *path_net, *if_name;
	unsigned long int layer2 = 0;
	struct util_rec_fld *fld;
	const char *attr_name;
	char buf[PAGE_SIZE];

	path = util_path_sysfs("bus/ccwgroup/drivers/qeth/%s", device_id);
	/* Process if_name attribute */
	if (util_file_read_line(buf, sizeof(buf), "%s/if_name", path) == 0)
		if_name = util_strdup(buf);
	else
		if_name = util_strdup("");
	util_rec_set(rec, "if_name", if_name);

	/* Read layer2 attribute */
	path_net = util_path_sysfs("class/net");
	util_file_read_ul(&layer2, 10, "%s/%s/device/layer2",
			  path_net, if_name);
	free(path_net);
	/* Iterate over each rec field */
	util_rec_iterate(rec, fld) {
		attr_name = util_rec_fld_get_key(fld);
		/* Skip layer3 attributes for layer2 device in normal format output */
		if (layer2 == 1 &&
		    !cmd.proc_format &&
		    not_layer2_attr(attr_name))
			continue;
		/* Skip if_name attribute(already processed) */
		if (strcmp(attr_name, "if_name") == 0)
			continue;
		/* Process 'devices' field for proc format output */
		if (strcmp(attr_name, "devices") == 0 && cmd.proc_format) {
			set_devices_fld(rec, path);
			continue;
		}
		/* Process ipa/parp/vipa attributes */
		if (strcmp(attr_name, "ipa") == 0 ||
		    strcmp(attr_name, "vipa") == 0 ||
		    strcmp(attr_name, "parp") == 0) {
			set_ipa_vipa_parp(rec, attr_name, path, if_name);
			continue;
		}
		/* Process other sysfs attributes */
		process_sysfs_attribute(rec, path, attr_name, if_name);
	}
	free(if_name);
	free(path);
	/* Print the record */
	if (!cmd.proc_format) {
		/* Check if card_type attribute needs to be modified */
		update_card_type(rec);
		/* Print record header for each device in normal format output */
		util_rec_print_hdr(rec);
	}
	util_rec_print(rec);
}

/*
 * Setup record with the fields needed for output in wide form
 */
static void setup_rec_wide(struct util_rec *rec)
{
	util_rec_def(rec, "devices", UTIL_REC_ALIGN_LEFT, 26, "devices");
	util_rec_def(rec, "chpid", UTIL_REC_ALIGN_LEFT, 5, "CHPID");
	util_rec_def(rec, "if_name", UTIL_REC_ALIGN_LEFT, 16, "interface");
	util_rec_def(rec, "card_type", UTIL_REC_ALIGN_LEFT, 14, "cardtype");
	util_rec_def(rec, "portno", UTIL_REC_ALIGN_LEFT, 4, "port");
	util_rec_def(rec, "checksumming", UTIL_REC_ALIGN_LEFT, 6, "chksum");
	util_rec_def(rec, "priority_queueing", UTIL_REC_ALIGN_LEFT, 10,
		     "prio-q'ing");
	util_rec_def(rec, "route4", UTIL_REC_ALIGN_LEFT, 4, "rtr4");
	util_rec_def(rec, "route6", UTIL_REC_ALIGN_LEFT, 4, "rtr6");
	util_rec_def(rec, "layer2", UTIL_REC_ALIGN_LEFT, 5, "lay'2");
	util_rec_def(rec, "buffer_count", UTIL_REC_ALIGN_LEFT, 5, "cnt");
}

/*
 * Setup record for output in long form
 */
static void setup_rec_long(struct util_rec *rec)
{
	util_rec_def(rec, "if_name", UTIL_REC_ALIGN_LEFT, 0, "Device name");
	util_rec_def(rec, "card_type", UTIL_REC_ALIGN_LEFT, 0, "card_type");
	util_rec_def(rec, "cdev0", UTIL_REC_ALIGN_LEFT, 0, "cdev0");
	util_rec_def(rec, "cdev1", UTIL_REC_ALIGN_LEFT, 0, "cdev1");
	util_rec_def(rec, "cdev2", UTIL_REC_ALIGN_LEFT, 0, "cdev2");
	util_rec_def(rec, "chpid", UTIL_REC_ALIGN_LEFT, 0, "chpid");
	util_rec_def(rec, "online", UTIL_REC_ALIGN_LEFT, 0, "online");
	util_rec_def(rec, "portname", UTIL_REC_ALIGN_LEFT, 0, "portname");
	util_rec_def(rec, "portno", UTIL_REC_ALIGN_LEFT, 0, "portno");
	util_rec_def(rec, "route4", UTIL_REC_ALIGN_LEFT, 0, "route4");
	util_rec_def(rec, "route6", UTIL_REC_ALIGN_LEFT, 0, "route6");
	util_rec_def(rec, "checksumming", UTIL_REC_ALIGN_LEFT, 0,
		     "checksumming");
	util_rec_def(rec, "state", UTIL_REC_ALIGN_LEFT, 0, "state");
	util_rec_def(rec, "priority_queueing", UTIL_REC_ALIGN_LEFT, 0,
		     "priority_queueing");
	util_rec_def(rec, "detach_state", UTIL_REC_ALIGN_LEFT, 0,
		     "detach_state");
	util_rec_def(rec, "fake_ll", UTIL_REC_ALIGN_LEFT, 0, "fake_ll");
	util_rec_def(rec, "fake_broadcast", UTIL_REC_ALIGN_LEFT, 0,
		     "fake_broadcast");
	util_rec_def(rec, "buffer_count", UTIL_REC_ALIGN_LEFT, 0,
		     "buffer_count");
	util_rec_def(rec, "add_hhlen", UTIL_REC_ALIGN_LEFT, 0, "add_hhlen");
	util_rec_def(rec, "layer2", UTIL_REC_ALIGN_LEFT, 0, "layer2");
	util_rec_def(rec, "large_send", UTIL_REC_ALIGN_LEFT, 0, "large_send");
	util_rec_def(rec, "isolation", UTIL_REC_ALIGN_LEFT, 0, "isolation");
	util_rec_def(rec, "hsuid", UTIL_REC_ALIGN_LEFT, 0, "hsuid");
	util_rec_def(rec, "sniffer", UTIL_REC_ALIGN_LEFT, 0, "sniffer");
	util_rec_def(rec, "bridge_role", UTIL_REC_ALIGN_LEFT, 0,
		     "bridge_role");
	util_rec_def(rec, "bridge_state", UTIL_REC_ALIGN_LEFT, 0,
		     "bridge_state");
	util_rec_def(rec, "bridge_hostnotify", UTIL_REC_ALIGN_LEFT, 0,
		     "bridge_hostnotify");
	util_rec_def(rec, "bridge_reflect_promisc", UTIL_REC_ALIGN_LEFT, 0,
		     "bridge_reflect_promisc");
	util_rec_def(rec, "switch_attrs", UTIL_REC_ALIGN_LEFT, 0,
		     "switch_attrs");
	util_rec_def(rec, "ipa", UTIL_REC_ALIGN_LEFT, 0, "ipa");
	util_rec_def(rec, "vipa", UTIL_REC_ALIGN_LEFT, 0, "vipa");
	util_rec_def(rec, "parp", UTIL_REC_ALIGN_LEFT, 0, "parp");
	util_rec_def(rec, "vnicc/bridge_invisible", UTIL_REC_ALIGN_LEFT, 0,
		     "vnicc/bridge_invisible");
	util_rec_def(rec, "vnicc/flooding", UTIL_REC_ALIGN_LEFT, 0,
		     "vnicc/flooding");
	util_rec_def(rec, "vnicc/learning", UTIL_REC_ALIGN_LEFT, 0,
		     "vnicc/learning");
	util_rec_def(rec, "vnicc/learning_timeout", UTIL_REC_ALIGN_LEFT, 0,
		     "vnicc/learning_timeout");
	util_rec_def(rec, "vnicc/mcast_flooding", UTIL_REC_ALIGN_LEFT, 0,
		     "vnicc/mcast_flooding");
	util_rec_def(rec, "vnicc/rx_bcast", UTIL_REC_ALIGN_LEFT, 0,
		     "vnicc/rx_bcast");
	util_rec_def(rec, "vnicc/takeover_learning", UTIL_REC_ALIGN_LEFT, 0,
		     "vnicc/takeover_learning");
	util_rec_def(rec, "vnicc/takeover_setvmac", UTIL_REC_ALIGN_LEFT, 0,
		     "vnicc/takeover_setvmac");
}

/*
 * Setup the record according to the desired output format
 */
static struct util_rec *setup_rec()
{
	struct util_rec *rec;

	if (cmd.proc_format) {
		rec = util_rec_new_wide("-");
		setup_rec_wide(rec);
	} else {
		rec = util_rec_new_long("-", ":", "if_name", 32, 40);
		setup_rec_long(rec);
	}
	return rec;
}

/*
 * Entry point
 */
int main(int argc, char *argv[])
{
	char device[MAX_ID_LENGTH];
	struct dirent **de_vec;
	struct util_rec *rec;
	int i, c = 0, count;
	char *path, *link;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	while (c != -1) {
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
		case 'p':
			cmd.proc_format = true;
			continue;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}
	/* Error if more than 1 argument specified */
	if (argc > optind + 1) {
		warnx("Too many arguments");
		util_prg_print_parse_error();
		return EXIT_FAILURE;
	}
	/* Create a proper record structure */
	rec = setup_rec();
	/* For proc output format print record header only once */
	if (cmd.proc_format)
		util_rec_print_hdr(rec);
	if (argc > optind) {
		/* Single argument specified (interface name), get related device_id */
		path = util_path_sysfs("class/net/");
		link = misc_link_target("%s/%s/device/cdev0",
					path, argv[optind]);
		free(path);
		if (link) {
			/* Interface present */
			snprintf(device, sizeof(device), "%s", basename(link));
			free(link);
			print_device(rec, device);
			free(rec);
		} else {
			errx(EXIT_FAILURE, "No such device: %s", argv[optind]);
		}
	} else {
		/* No optional arguments specified, process all available devices */
		path = util_path_sysfs("bus/ccwgroup/drivers/qeth/");
		count = util_scandir(&de_vec, alphasort, path, "%s",
				     ID_FORMAT);
		free(path);
		for (i = 0; i < count; i++) {
			/* Check if a symbolic link */
			if (de_vec[i]->d_type != DT_LNK)
				continue;
			if (i > 0)
				rec = setup_rec();
			print_device(rec, de_vec[i]->d_name);
			free(rec);
		}
		util_scandir_free(de_vec, count);
	}
	return EXIT_SUCCESS;
}
