/**
 * lszcrypt - Display zcrypt devices and configuration settings
 *
 * Copyright IBM Corp. 2008, 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <stdint.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_proc.h"
#include "lib/util_rec.h"
#include "lib/util_scandir.h"
#include "lib/zt_common.h"

/*
 * Private data
 */
struct lszcrypt_l {
	int verbose;
} l;

struct lszcrypt_l *lszcrypt_l = &l;

/*
 * Capabilities
 */
#define CAP_RSA2K	"RSA 2K Clear Key"
#define CAP_RSA4K	"RSA 4K Clear Key"
#define CAP_CCA		"CCA Secure Key"
#define CAP_RNG		"Long RNG"
#define CAP_EP11	"EP11 Secure Key"

/*
 * Card types
 */
#define MASK_APSC	    0x80000000
#define MASK_RSA4K	    0x60000000
#define MASK_COPRO	    0x10000000
#define MASK_ACCEL	    0x08000000
#define MASK_EP11	    0x04000000

/*
 * Classification
 */
#define MASK_CLASS_FULL	      0x00800000
#define CLASS_FULL            "full function set"
#define MASK_CLASS_STATELESS  0x00400000
#define CLASS_STATELESS       "restricted function set"

/*
 * facility bits
 */
#define MAX_FAC_BITS 9
static struct fac_bits_s {
	int mask;
	char c;
} fac_bits[MAX_FAC_BITS] = {
	{ 0x80000000, 'S' },
	{ 0x40000000, 'M' },
	{ 0x20000000, 'C' },
	{ 0x10000000, 'D' },
	{ 0x08000000, 'A' },
	{ 0x04000000, 'X' },
	{ 0x02000000, 'N' },
	{ 0x00800000, 'F' },
	{ 0x00400000, 'R' },
};

/*
 * Program configuration
 */
const struct util_prg prg = {
	.desc = "Display zcrypt device and configuration information.",
	.args = "[DEVICE_IDS]",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2008,
			.pub_last = 2020,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Configuration of command line options
 */
static struct util_opt opt_vec[] = {
	{
		.option = {"bus", 0, NULL, 'b'},
		.desc = "Show AP bus attributes then exit",
	},
	{
		.option = { "capability", required_argument, NULL, 'c'},
		.argument = "DEVICE_ID",
		.desc = "Show the capabilities of a cryptographic device",
	},
	{
		.option = {"domains", 0, NULL, 'd'},
		.desc = "Show the configured AP usage and control domains",
	},
	{
		.option = {"verbose", 0, NULL, 'V'},
		.desc = "Print verbose messages",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

/*
 * Show bus
 */
static void show_bus(void)
{
	long domain, max_domain, config_time, value;
	unsigned long long poll_timeout;
	const char *poll_thread, *ap_interrupts;
	char *ap;

	/* check if ap driver is available */
	ap = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(ap))
		errx(EXIT_FAILURE, "Crypto device driver not available.");

	util_file_read_l(&domain, 10, "%s/ap_domain", ap);
	util_file_read_l(&max_domain, 10, "%s/ap_max_domain_id", ap);
	util_file_read_l(&config_time, 10, "%s/config_time", ap);
	util_file_read_ull(&poll_timeout, 10, "%s/poll_timeout", ap);
	util_file_read_l(&value, 10, "%s/poll_thread", ap);
	if (value == 1)
		poll_thread = "enabled";
	else
		poll_thread = "disabled";
	util_file_read_l(&value, 10, "%s/ap_interrupts", ap);
	if (value == 1)
		ap_interrupts = "enabled";
	else
		ap_interrupts = "disabled";
	printf("ap_domain=0x%lx\n", domain);
	printf("ap_max_domain_id=0x%lx\n", max_domain);
	if (util_path_is_reg_file("%s/ap_interrupts", ap))
		printf("ap_interrupts are %s\n", ap_interrupts);
	printf("config_time=%ld (seconds)\n", config_time);
	printf("poll_thread is %s\n", poll_thread);
	if (util_path_is_reg_file("%s/poll_timeout", ap))
		printf("poll_timeout=%llu (nanoseconds)\n", poll_timeout);
	free(ap);
}

/*
 * Print domain array using util_rec
 */
static void show_domains_util_rec(char *domain_array[])
{
	struct util_rec *rec = util_rec_new_wide("-");
	char buf[256];
	int i, x, n;

	util_rec_def(rec, "domain", UTIL_REC_ALIGN_RIGHT, 6, "DOMAIN");
	for (i = 0; i < 16; i++) {
		sprintf(buf, "%02x", i);
		util_rec_def(rec, buf, UTIL_REC_ALIGN_RIGHT, 2, buf);
	}

	util_rec_print_hdr(rec);
	n = 0;
	for (i = 0; i < 16; i++) {
		sprintf(buf, "%02x", i * 16);
		util_rec_set(rec, "domain", buf);
		for (x = 0; x < 16; x++) {
			sprintf(buf, "%02x", x);
			util_rec_set(rec, buf, domain_array[n++]);
		}
		util_rec_print(rec);
	}
	util_rec_free(rec);
	printf("------------------------------------------------------\n");
	printf("C: Control domain\n");
	printf("U: Usage domain\n");
	printf("B: Both (Control + Usage domain)\n");
}

/*
 * Show domains
 */
static void show_domains(void)
{
	char ctrl_domain_mask[80], usag_domain_mask[80], byte_str[3] = {};
	int ctrl_chunk, usag_chunk;
	char *ap, *domain_array[32 * 8 + 4];
	int i, x, n;
	uint8_t dom_mask_bit;

	/* check if ap driver is available */
	ap = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(ap))
		errx(EXIT_FAILURE, "Crypto device driver not available.");

	util_file_read_line(ctrl_domain_mask, sizeof(ctrl_domain_mask),
			    "%s/ap_control_domain_mask", ap);
	if (strstr(ctrl_domain_mask, "not"))
		errx(EXIT_FAILURE, "Control domain mask not available.");
	util_file_read_line(usag_domain_mask, sizeof(usag_domain_mask),
			    "%s/ap_usage_domain_mask", ap);
	if (strstr(usag_domain_mask, "not"))
		errx(EXIT_FAILURE, "Usage domain mask not available.");
	/* remove leading '0x' from domain mask string */
	memmove(&ctrl_domain_mask[0], &ctrl_domain_mask[2],
		sizeof(ctrl_domain_mask) - 2);
	memmove(&usag_domain_mask[0], &usag_domain_mask[2],
		sizeof(usag_domain_mask) - 2);
	n = 0;
	for (i = 0; i < 32; i++) {
		dom_mask_bit = 0x80;
		memcpy(byte_str, &ctrl_domain_mask[i * 2], 2);
		sscanf(byte_str, "%02x", &ctrl_chunk);
		memcpy(byte_str, &usag_domain_mask[i * 2], 2);
		sscanf(byte_str, "%02x", &usag_chunk);
		for (x = 1; x <= 8; x++) {
			if (ctrl_chunk & dom_mask_bit &&
			    usag_chunk & dom_mask_bit)
				domain_array[n] = "B"; /* c/u */
			else if (ctrl_chunk & dom_mask_bit)
				domain_array[n] = "C";
			else if (usag_chunk & dom_mask_bit)
				domain_array[n] = "U";
			else
				domain_array[n] = ".";
			dom_mask_bit = dom_mask_bit >> 1;
			n += 1;
		}
	}
	for (i = n; i < 260; i++)
		domain_array[n++] = "";

	show_domains_util_rec(domain_array);
}

/*
 * Show capability
 */
static void show_capability(const char *id_str)
{
	unsigned long func_val;
	long hwtype, id;
	char *p, *ap, *dev, card[16], cbuf[256];

	/* check if ap driver is available */
	ap = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(ap))
		errx(EXIT_FAILURE, "Crypto device driver not available.");

	id = strtol(id_str, &p, 0);
	if (id < 0 || id > 255 || p == id_str || *p != '\0')
		errx(EXIT_FAILURE, "Error - '%s' is an invalid cryptographic device id.", id_str);
	snprintf(card, sizeof(card), "card%02lx", id);
	dev = util_path_sysfs("devices/ap/%s", card);
	if (!util_path_is_dir(dev))
		errx(EXIT_FAILURE, "Error - cryptographic device %s does not exist.", card);
	util_file_read_l(&hwtype, 10, "%s/hwtype", dev);
	/* If sysfs attribute is missing, set functions to 0 */
	if (util_file_read_ul(&func_val, 16, "%s/ap_functions", dev))
		func_val = 0x00000000;
	/* Skip devices, which are not supported by zcrypt layer */
	if (!util_path_is_readable("%s/type", dev) ||
	    !util_path_is_readable("%s/online", dev)) {
		printf("Detailed capability information for %s (hardware type %ld) is not available.\n",
		       card, hwtype);
		return;
	}
	cbuf[0] = '\0';
	if (func_val & MASK_CLASS_FULL)
		snprintf(cbuf, sizeof(cbuf), "%s", CLASS_FULL);
	else if (func_val & MASK_CLASS_STATELESS)
		snprintf(cbuf, sizeof(cbuf), "%s", CLASS_STATELESS);
	printf("%s provides capability for:\n", card);
	switch (hwtype) {
	case 6:
	case 8:
		if (func_val & MASK_RSA4K)
			printf("%s", CAP_RSA4K);
		else
			printf("%s", CAP_RSA2K);
		break;
	case 7:
	case 9:
		printf("%s\n", CAP_RSA4K);
		if (cbuf[0])
			printf("%s (%s)\n", CAP_CCA, cbuf);
		else
			printf("%s\n", CAP_CCA);
		printf("%s", CAP_RNG);
		break;
	case 10: /* CEX4S */
	case 11: /* CEX5S */
	case 12: /* CEX6S */
	case 13: /* CEX7S */
		if (func_val & MASK_ACCEL) {
			if (func_val & MASK_RSA4K)
				printf("%s", CAP_RSA4K);
			else
				printf("%s", CAP_RSA2K);
		} else if (func_val & MASK_COPRO) {
			printf("%s\n", CAP_RSA4K);
			if (cbuf[0])
				printf("%s (%s)\n", CAP_CCA, cbuf);
			else
				printf("%s\n", CAP_CCA);
			printf("%s", CAP_RNG);
		} else if (func_val & MASK_EP11) {
			printf("%s", CAP_EP11);
		} else {
			printf("Detailed capability information for %s (hardware type %ld) is not available.",
			       card, hwtype);
		}
		break;
	default:
			printf("Detailed capability information for %s (hardware type %ld) is not available.",
			       card, hwtype);
		break;
	}
	printf("\n");
}

/*
 * Read subdevice default attributes
 */
static void read_subdev_rec_default(struct util_rec *rec, const char *grp_dev,
				    const char *sub_dev)
{
	long value;
	char buf[256];
	unsigned long facility;

	if (util_file_read_line(buf, sizeof(buf), "%s/type", grp_dev))
		util_rec_set(rec, "type", "-");
	else
		util_rec_set(rec, "type", buf);

	if (util_path_is_readable("%s/%s/online", grp_dev, sub_dev)) {
		util_file_read_l(&value, 10, "%s/%s/online", grp_dev, sub_dev);
		if (value > 0)
			util_rec_set(rec, "online", "online");
		else {
			/* device is offline, check config (if available) */
			if (util_path_is_readable("%s/%s/config", grp_dev, sub_dev)) {
				util_file_read_l(&value, 10, "%s/%s/config", grp_dev, sub_dev);
				if (value > 0)
					util_rec_set(rec, "online", "offline");
				else
					util_rec_set(rec, "online", "deconfig");
			} else
				util_rec_set(rec, "online", "offline");
		}
	} else {
		/* no online attribute */
		util_rec_set(rec, "online", "-");
	}

	util_file_read_ul(&facility, 16, "%s/ap_functions", grp_dev);
	if (facility & MASK_COPRO)
		util_rec_set(rec, "mode", "CCA-Coproc");
	else if (facility & MASK_ACCEL)
		util_rec_set(rec, "mode", "Accelerator");
	else if (facility & MASK_EP11)
		util_rec_set(rec, "mode", "EP11-Coproc");
	else
		util_rec_set(rec, "mode", "Unknown");

	util_file_read_line(buf, sizeof(buf), "%s/%s/request_count",
			    grp_dev, sub_dev);
	util_rec_set(rec, "requests", buf);
}

/*
 * Read subdevice verbose attributes
 */
static void read_subdev_rec_verbose(struct util_rec *rec, const char *grp_dev,
				    const char *sub_dev)
{
	int i;
	unsigned long facility;
	char buf[256], afile[PATH_MAX];
	long depth, pending1, pending2;

	if (l.verbose == 0)
		return;

	util_file_read_l(&pending1, 10, "%s/%s/pendingq_count",
			 grp_dev, sub_dev);
	util_file_read_l(&pending2, 10, "%s/%s/requestq_count",
			 grp_dev, sub_dev);
	util_rec_set(rec, "pending", "%ld", pending1 + pending2);

	util_file_read_line(buf, sizeof(buf), "%s/hwtype", grp_dev);
	util_rec_set(rec, "hwtype", buf);

	util_file_read_l(&depth, 10, "%s/depth", grp_dev);
	util_rec_set(rec, "depth", "%02d", depth + 1);

	util_file_read_ul(&facility, 16, "%s/ap_functions", grp_dev);
	for (i = 0; i < MAX_FAC_BITS; i++)
		buf[i] = facility & fac_bits[i].mask ? fac_bits[i].c : '-';
	buf[i] = '\0';
	util_rec_set(rec, "facility", buf);

	snprintf(afile, sizeof(afile), "%s/%s/driver", grp_dev, sub_dev);
	afile[sizeof(afile) - 1] = '\0';
	memset(buf, 0, sizeof(buf));
	if (readlink(afile, buf, sizeof(buf)) > 0)
		util_rec_set(rec, "driver", strrchr(buf, '/') + 1);
	else
		util_rec_set(rec, "driver", "-no-driver-");
}

/*
 * Show one subdevice
 */
static void show_subdevice(struct util_rec *rec, const char *grp_dev,
			   const char *sub_dev)
{
	if (!util_path_is_dir("%s/%s", grp_dev, sub_dev))
		errx(EXIT_FAILURE, "Error - cryptographic device %s/%s does not exist.", grp_dev, sub_dev);

	/*
	 * If not verbose mode, skip devices which are not supported
	 * by the zcrypt layer.
	 */
	if (l.verbose == 0 &&
	    (!util_path_is_readable("%s/type", grp_dev) ||
	     !util_path_is_readable("%s/%s/online", grp_dev, sub_dev)))
		return;

	util_rec_set(rec, "card", sub_dev);
	read_subdev_rec_default(rec, grp_dev, sub_dev);
	read_subdev_rec_verbose(rec, grp_dev, sub_dev);

	util_rec_print(rec);
}

/*
 * Show subdevices
 */
static void show_subdevices(struct util_rec *rec, const char *grp_dev)
{
	struct dirent **dev_vec;
	int i, count;

	count = util_scandir(&dev_vec, alphasort, grp_dev, "..\\....");
	if (count < 1)
		errx(EXIT_FAILURE, "Error - no subdevices found for %s.\n", grp_dev);
	for (i = 0; i < count; i++)
		show_subdevice(rec, grp_dev, dev_vec[i]->d_name);
}

/*
 * Read default attributes
 */
static void read_rec_default(struct util_rec *rec, const char *grp_dev)
{
	long value;
	char buf[256];
	unsigned long facility;

	if (util_file_read_line(buf, sizeof(buf), "%s/type", grp_dev))
		util_rec_set(rec, "type", "-");
	else
		util_rec_set(rec, "type", buf);

	util_file_read_ul(&facility, 16, "%s/ap_functions", grp_dev);
	if (facility & MASK_COPRO)
		util_rec_set(rec, "mode", "CCA-Coproc");
	else if (facility & MASK_ACCEL)
		util_rec_set(rec, "mode", "Accelerator");
	else if (facility & MASK_EP11)
		util_rec_set(rec, "mode", "EP11-Coproc");
	else
		util_rec_set(rec, "mode", "Unknown");

	if (util_path_is_readable("%s/online", grp_dev)) {
		util_file_read_l(&value, 10, "%s/online", grp_dev);
		if (value > 0)
			util_rec_set(rec, "online", "online");
		else {
			if (util_path_is_readable("%s/config", grp_dev)) {
				util_file_read_l(&value, 10, "%s/config", grp_dev);
				if (value > 0)
					util_rec_set(rec, "online", "offline");
				else
					util_rec_set(rec, "online", "deconfig");
			} else
				util_rec_set(rec, "online", "offline");
		}
	}

	util_file_read_line(buf, sizeof(buf), "%s/request_count", grp_dev);
	util_rec_set(rec, "requests", buf);
}

/*
 * Read verbose attributes
 */
static void read_rec_verbose(struct util_rec *rec, const char *grp_dev)
{
	int i;
	unsigned long facility;
	char buf[256], afile[PATH_MAX];
	long depth, pending1, pending2;

	if (l.verbose == 0)
		return;

	util_file_read_l(&pending1, 10, "%s/pendingq_count", grp_dev);
	util_file_read_l(&pending2, 10, "%s/requestq_count", grp_dev);
	util_rec_set(rec, "pending", "%ld", pending1 + pending2);

	util_file_read_line(buf, sizeof(buf), "%s/hwtype", grp_dev);
	util_rec_set(rec, "hwtype", buf);

	util_file_read_l(&depth, 10, "%s/depth", grp_dev);
	util_rec_set(rec, "depth", "%02d", depth + 1);

	util_file_read_ul(&facility, 16, "%s/ap_functions", grp_dev);
	for (i = 0; i < MAX_FAC_BITS; i++)
		buf[i] = facility & fac_bits[i].mask ? fac_bits[i].c : '-';
	buf[i] = '\0';
	util_rec_set(rec, "facility", buf);

	snprintf(afile, sizeof(afile), "%s/driver", grp_dev);
	afile[sizeof(afile) - 1] = '\0';
	memset(buf, 0, sizeof(buf));
	if (readlink(afile, buf, sizeof(buf)) > 0)
		util_rec_set(rec, "driver", strrchr(buf, '/') + 1);
	else
		util_rec_set(rec, "driver", "-no-driver-");
}

/*
 * Show device: device is in the form "card00", "card01", ...
 */
static void show_device(struct util_rec *rec, const char *device)
{
	char *grp_dev, card[16];

	util_rec_set(rec, "card", card);

	strcpy(card, &device[4]);
	grp_dev = util_path_sysfs("devices/ap/%s", device);
	if (!util_path_is_dir(grp_dev))
		errx(EXIT_FAILURE, "Error - cryptographic device %s does not exist.", device);

	/*
	 * If not verbose mode, skip devices which are not supported
	 * by the zcrypt layer.
	 */
	if (l.verbose == 0 &&
	    (!util_path_is_readable("%s/type", grp_dev) ||
	     !util_path_is_readable("%s/online", grp_dev))) {
		goto out_free;
	}
	util_rec_set(rec, "card", card);

	read_rec_default(rec, grp_dev);
	read_rec_verbose(rec, grp_dev);

	util_rec_print(rec);
	show_subdevices(rec, grp_dev);
out_free:
	free(grp_dev);
}

/*
 * Define the *default* attributes
 */
static void define_rec_default(struct util_rec *rec)
{
	util_rec_def(rec, "card", UTIL_REC_ALIGN_LEFT, 11, "CARD.DOMAIN");
	util_rec_def(rec, "type", UTIL_REC_ALIGN_LEFT, 5, "TYPE");
	util_rec_def(rec, "mode", UTIL_REC_ALIGN_LEFT, 11, "MODE");
	util_rec_def(rec, "online", UTIL_REC_ALIGN_LEFT, 8, "STATUS");
	util_rec_def(rec, "requests", UTIL_REC_ALIGN_RIGHT, 8, "REQUESTS");
}

/*
 * Define the *verbose* attributes
 */
static void define_rec_verbose(struct util_rec *rec)
{
	if (l.verbose == 0)
		return;
	util_rec_def(rec, "pending", UTIL_REC_ALIGN_RIGHT, 8, "PENDING");
	util_rec_def(rec, "hwtype", UTIL_REC_ALIGN_RIGHT, 6, "HWTYPE");
	util_rec_def(rec, "depth", UTIL_REC_ALIGN_RIGHT, 6, "QDEPTH");
	util_rec_def(rec, "facility", UTIL_REC_ALIGN_LEFT, 10, "FUNCTIONS");
	util_rec_def(rec, "driver", UTIL_REC_ALIGN_LEFT, 11, "DRIVER");
}

/*
 * Show all devices
 */
static void show_devices_all(void)
{
	struct util_rec *rec = util_rec_new_wide("-");
	struct dirent **dev_vec;
	int i, count;
	char *ap, *path;

	/* check if ap driver is available */
	ap = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(ap))
		errx(EXIT_FAILURE, "Crypto device driver not available.");

	/* Define the record */
	define_rec_default(rec);
	define_rec_verbose(rec);

	/* Scan the devices */
	path = util_path_sysfs("devices/ap/");
	count = util_scandir(&dev_vec, alphasort, path, "card[0-9a-fA-F]+");
	if (count < 1)
		errx(EXIT_FAILURE, "No crypto card devices found.");
	util_rec_print_hdr(rec);
	for (i = 0; i < count; i++)
		show_device(rec, dev_vec[i]->d_name);
	free(path);
}

/*
 * Show devices specified on commandline
 */
static void show_devices_argv(char *argv[])
{
	struct util_rec *rec = util_rec_new_wide("-");
	struct dirent **dev_vec, **subdev_vec;
	char *ap, *grp_dev, *path, *card, *sub_dev;
	int id, dom, i, n, dev_cnt, sub_cnt;

	/* check if ap driver is available */
	ap = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(ap))
		errx(EXIT_FAILURE, "Crypto device driver not available.");

	/* Define the record */
	define_rec_default(rec);
	define_rec_verbose(rec);

	util_rec_print_hdr(rec);
	for (i = 0; argv[i] != NULL; i++) {
		id = -1;
		dom = -1;
		if (sscanf(argv[i], "%x.%x", &id, &dom) >= 1) {
			/* at least the id field was valid */
			if (id >= 0 && dom >= 0) {	/* single subdevice */
				util_asprintf(&sub_dev, "%02x.%04x", id, dom);
				grp_dev = util_path_sysfs("devices/ap/card%02x",
							  id);
				show_subdevice(rec, grp_dev, sub_dev);
				free(grp_dev);
				free(sub_dev);
			} else {			/* group device */
				util_asprintf(&card, "card%02x", id);
				show_device(rec, card);
				free(card);
			}
			return;
		}
		if (sscanf(argv[i]+1, "%x", &dom) == 1) {
			/* list specific domains of all adapters */
			path = util_path_sysfs("devices/ap/");
			dev_cnt = util_scandir(&dev_vec, alphasort, path,
					       "card[0-9a-fA-F]+");
			if (dev_cnt < 1)
				errx(EXIT_FAILURE, "No crypto card devices found.");
			free(path);
			for (i = 0; i < dev_cnt; i++) {
				path = util_path_sysfs("devices/ap/%s",
						       dev_vec[i]->d_name);
				sub_cnt = util_scandir(&subdev_vec, alphasort,
						       path,
						       "[0-9a-fA-F]+.%04x",
						       dom);
				if (sub_cnt < 1)
					errx(EXIT_FAILURE, "No queue devices with given domain value found.");
				for (n = 0; n < sub_cnt; n++) {
					show_subdevice(rec, path,
						       subdev_vec[n]->d_name);
				}
				free(path);
			}
			return;
		}
		printf("Invalid adpater id!\n");
	}
}

/*
 * Describe adapter ids
 */
void print_adapter_id_help(void)
{
	printf("\n");
	printf("DEVICE_IDS\n");
	printf("  List of cryptographic device ids separated by blanks which will be displayed.\n");
	printf("  DEVICE_ID could either be card device id ('<card-id>') or queue device id\n");
	printf("  '<card-id>.<domain-id>'). To filter all devices according to a dedicated\n");
	printf("  domain just provide '.<domain-id>'.\n");
	printf("  If no ids are given, all available devices are displayed.\n");
	printf("\n");
	printf("EXAMPLE:\n");
	printf("  List all cryptographic devices with card id '02'.\n");
	printf("  #>lszcrypt 02\n");
	printf("\n");
	printf("  List cryptographic devices with card id '02' and domain id '0005'.\n");
	printf("  #>lszcrypt 02.0005\n");
	printf("\n");
}

/*
 * Entry point
 */
int main(int argc, char **argv)
{
	int c;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);
	while (1) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;
		switch (c) {
		case 'b':
			show_bus();
			return EXIT_SUCCESS;
		case 'c':
			show_capability(optarg);
			return EXIT_SUCCESS;
		case 'd':
			show_domains();
			return EXIT_SUCCESS;
		case 'V':
			l.verbose++;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			print_adapter_id_help();
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}
	if (optind == argc)
		show_devices_all();
	else
		show_devices_argv(&argv[optind]);
	return EXIT_SUCCESS;
}
