/**
 * lszcrypt - Display zcrypt devices and configuration settings
 *
 * Copyright IBM Corp. 2008, 2023
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

#include "misc.h"

/*
 * Private data
 */
static struct lszcrypt_l {
	int verbose;
	int showaccel;
	int showcca;
	int showep11;
	int showcard;
	int showqueue;
} l;

/*
 * Capabilities
 */
#define CAP_RSA2K	"RSA 2K Clear Key"
#define CAP_RSA4K	"RSA 4K Clear Key"
#define CAP_CCA		"CCA Secure Key"
#define CAP_RNG		"Long RNG"
#define CAP_EP11	"EP11 Secure Key"
#define CAP_APMMS       "AP bus max message size limit %ld Kb"
#define CAP_HSL         "Hardware support for stateless filtering"

/*
 * Card types and other feature masks
 */
#define MASK_APSC	    0x80000000
#define MASK_RSA4K	    0x60000000
#define MASK_COPRO	    0x10000000
#define MASK_ACCEL	    0x08000000
#define MASK_EP11	    0x04000000
#define MASK_HSL	    0x01000000

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
#define MAX_FAC_BITS 10
static struct fac_bits_s {
	int mask;
	char c;
} fac_bits[MAX_FAC_BITS] = {
	{ 0x80000000, 'S' }, /* bit 0 */
	{ 0x40000000, 'M' }, /* bit 1 */
	{ 0x20000000, 'C' }, /* bit 2 */
	{ 0x10000000, 'D' }, /* bit 3, cca mode */
	{ 0x08000000, 'A' }, /* bit 4, accel mode */
	{ 0x04000000, 'X' }, /* bit 5, ep11 mode */
	{ 0x02000000, 'N' }, /* bit 6, apxa */
	{ 0x01000000, 'H' }, /* bit 7, stateless filtering by hardware */
	{ 0x00800000, 'F' }, /* bit 8, full function set */
	{ 0x00400000, 'R' }, /* bit 9, restricted function set */
};

#define EXTRACT_BS_BITS(f) (((f) & 0x0000c000UL) >> 14)

/*
 * Program configuration
 */
static const struct util_prg prg = {
	.desc = "Display zcrypt device and configuration information.",
	.args = "[DEVICE_IDS]",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2008,
			.pub_last = 2023,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Configuration of command line options
 */

#define OPT_ACCELONLY  0x81
#define OPT_CCAONLY    0x82
#define OPT_EP11ONLY   0x83
#define OPT_CARDONLY   0x84
#define OPT_QUEUEONLY  0x85

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
	{
		.option = {"accelonly", 0, NULL, OPT_ACCELONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from cards/queues in Accelerator mode",
	},
	{
		.option = {"ccaonly", 0, NULL, OPT_CCAONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from cards/queues in CCA-Coprocessor mode",
	},
	{
		.option = {"ep11only", 0, NULL, OPT_EP11ONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from cards/queues in EP11-Coprocessor mode",
	},
	{
		.option = {"cardonly", 0, NULL, OPT_CARDONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from cards but no queue info",
	},
	{
		.option = {"queueonly", 0, NULL, OPT_QUEUEONLY},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show only information from queues but no card info",
	},
	{
		.option = {"serial", 0, NULL, 's'},
		.desc = "Show the serial numbers for CCA and EP11 crypto cards",
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
	const char *poll_thread, *ap_interrupts;
	unsigned long long poll_timeout;
	char features[256];
	char *ap;

	/* check if ap driver is available */
	ap = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(ap))
		errx(EXIT_FAILURE, "Crypto device driver not available.");

	if (util_path_is_readable("%s/features", ap))
		util_file_read_line(features, sizeof(features), "%s/features", ap);
	else
		features[0] = '\0';
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
	if (features[0])
		printf("features: %s\n", features);
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
 * Show serialnumbers
 */
static void show_serialnumbers(void)
{
	struct util_rec *rec = util_rec_new_wide("-");
	struct dirent **dev_vec;
	int i, count;
	char *ap, *path, *device, *grp_dev, card[16], buf[256];
	long config = -1, online = -1, chkstop = -1;
	unsigned long facility;

	/* check if ap driver is available */
	ap = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(ap))
		errx(EXIT_FAILURE, "Crypto device driver not available.");

	/* define the record */
	util_rec_def(rec, "card", UTIL_REC_ALIGN_LEFT, 8, "CARD.DOM");
	util_rec_def(rec, "type", UTIL_REC_ALIGN_LEFT, 5, "TYPE");
	util_rec_def(rec, "mode", UTIL_REC_ALIGN_LEFT, 11, "MODE");
	util_rec_def(rec, "status", UTIL_REC_ALIGN_LEFT, 10, "STATUS");
	util_rec_def(rec, "serialnr", UTIL_REC_ALIGN_LEFT, 8, "SERIALNR");

	/* scan the devices */
	path = util_path_sysfs("devices/ap/");
	count = util_scandir(&dev_vec, alphasort, path, "card[0-9a-fA-F]+");
	if (count < 1)
		errx(EXIT_FAILURE, "No crypto card devices found.");
	util_rec_print_hdr(rec);
	for (i = 0; i < count; i++) {
		device = dev_vec[i]->d_name;
		grp_dev = util_path_sysfs("devices/ap/%s", device);
		if (!util_path_is_dir(grp_dev))
			errx(EXIT_FAILURE, "Error - cryptographic device %s does not exist.", device);
		if (!util_path_is_readable("%s/type", grp_dev) ||
		    !util_path_is_readable("%s/online", grp_dev))
			goto next;
		strcpy(card, device + 4);
		util_rec_set(rec, "card", card);
		util_file_read_line(buf, sizeof(buf), "%s/type", grp_dev);
		util_rec_set(rec, "type", buf);
		util_file_read_ul(&facility, 16, "%s/ap_functions", grp_dev);
		if (facility & MASK_COPRO)
			util_rec_set(rec, "mode", "CCA-Coproc");
		else if (facility & MASK_EP11)
			util_rec_set(rec, "mode", "EP11-Coproc");
		else
			goto next;
		if (util_path_is_readable("%s/config", grp_dev))
			util_file_read_l(&config, 10, "%s/config", grp_dev);
		if (util_path_is_readable("%s/chkstop", grp_dev))
			util_file_read_l(&chkstop, 10, "%s/chkstop", grp_dev);
		if (util_path_is_readable("%s/online", grp_dev))
			util_file_read_l(&online, 10, "%s/online", grp_dev);
		if (config == 0) {
			util_rec_set(rec, "status", "deconfig");
		} else {
			if (chkstop > 0)
				util_rec_set(rec, "status", "chkstop");
			else if (online > 0)
				util_rec_set(rec, "status", "online");
			else if (online == 0)
				util_rec_set(rec, "status", "offline");
			else
				util_rec_set(rec, "status", "-");
		}
		if (util_file_read_line(buf, sizeof(buf), "%s/serialnr", grp_dev))
			util_rec_set(rec, "serialnr", "-");
		else {
			buf[8] = '\0';
			util_rec_set(rec, "serialnr", buf);
		}
		util_rec_print(rec);
next:
		free(grp_dev);
	}

	free(path);
}

/*
 * Show card capability
 */
static void show_card_capability(int id)
{
	unsigned long func_val;
	long hwtype, max_msg_size;
	char *dev, card[16], cbuf[256];

	snprintf(card, sizeof(card), "card%02x", id);
	dev = util_path_sysfs("devices/ap/%s", card);
	if (!util_path_is_dir(dev))
		errx(EXIT_FAILURE, "Error - cryptographic device %s does not exist.", card);
	util_file_read_l(&hwtype, 10, "%s/hwtype", dev);
	/* If sysfs attribute is missing, set functions to 0 */
	if (util_file_read_ul(&func_val, 16, "%s/ap_functions", dev))
		func_val = 0x00000000;
	/* try to read the ap bus max message size for this card */
	if (util_file_read_l(&max_msg_size, 10, "%s/max_msg_size", dev))
		max_msg_size = 0;
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
			printf("%s\n", CAP_RSA4K);
		else
			printf("%s\n", CAP_RSA2K);
		break;
	case 7:
	case 9:
		printf("%s\n", CAP_RSA4K);
		if (cbuf[0])
			printf("%s (%s)\n", CAP_CCA, cbuf);
		else
			printf("%s\n", CAP_CCA);
		printf("%s\n", CAP_RNG);
		break;
	case 10: /* CEX4S */
	case 11: /* CEX5S */
	case 12: /* CEX6S */
	case 13: /* CEX7S */
	case 14: /* CEX8S */
		if (func_val & MASK_ACCEL) {
			if (func_val & MASK_RSA4K)
				printf("%s\n", CAP_RSA4K);
			else
				printf("%s\n", CAP_RSA2K);
		} else if (func_val & MASK_COPRO) {
			printf("%s\n", CAP_RSA4K);
			if (cbuf[0])
				printf("%s (%s)\n", CAP_CCA, cbuf);
			else
				printf("%s\n", CAP_CCA);
			if (func_val & MASK_HSL)
				printf("%s\n", CAP_HSL);
			printf("%s\n", CAP_RNG);
		} else if (func_val & MASK_EP11) {
			printf("%s\n", CAP_EP11);
		} else {
			printf("Detailed capability information for %s (hardware type %ld) is not available.\n",
			       card, hwtype);
		}
		if (max_msg_size > 0)
			printf(CAP_APMMS "\n", max_msg_size / 1024);
		break;
	default:
		printf("Detailed capability information for %s (hardware type %ld) is not available.\n",
		       card, hwtype);
		break;
	}

	free(dev);
}

/*
 * Show queue capability
 */
static void show_queue_capability(int id, int dom)
{
	char *dev, card[16], queue[16], buf[256];

	snprintf(card, sizeof(card), "card%02x", id);
	snprintf(queue, sizeof(queue), "%02x.%04x", id, dom);
	dev = util_path_sysfs("devices/ap/%s/%s", card, queue);
	if (!util_path_is_dir(dev))
		errx(EXIT_FAILURE, "Error - cryptographic queue device %02x.%04x does not exist.",
		     id, dom);

	printf("queue %02x.%04x capabilities:\n", id, dom);

	if (util_path_is_reg_file("%s/se_bind", dev)) {
		if (util_file_read_line(buf, sizeof(buf), "%s/se_bind", dev))
			printf("SE bind state: error\n");
		else
			printf("SE bind state: %s\n", buf);
	}
	if (util_path_is_reg_file("%s/se_associate", dev)) {
		if (util_file_read_line(buf, sizeof(buf), "%s/se_associate", dev))
			printf("SE association state: error\n");
		else
			printf("SE association state: %s\n", buf);
	}
	if (util_path_is_reg_file("%s/mkvps", dev)) {
		char *mkvps = util_path_sysfs("devices/ap/%s/%s/mkvps", card, queue);
		FILE *f = fopen(mkvps, "r");

		if (!f)
			errx(EXIT_FAILURE, "Error - failed to open sysfs file %s.",
			     mkvps);
		while (fgets(buf, sizeof(buf), f)) {
			if (strstr(buf, "WK CUR") ||
			    strstr(buf, "AES CUR") ||
			    strstr(buf, "APKA CUR") ||
			    strstr(buf, "ASYM CUR"))
				printf("MK %s", buf); /* no newline here */
		}
		fclose(f);
		free(mkvps);
	}

	free(dev);
}

/*
 * Show capability
 */
static void show_capability(const char *id_str)
{
	char *p, *ap;
	int id, dom;

	/* check if ap driver is available */
	ap = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(ap))
		errx(EXIT_FAILURE, "Crypto device driver not available.");

	if (sscanf(id_str, "%x.%x", &id, &dom) == 2) {
		show_queue_capability(id, dom);
	} else {
		id = strtol(id_str, &p, 0);
		if (id < 0 || id > 255 || p == id_str || *p != '\0')
			errx(EXIT_FAILURE,
			     "Error - '%s' is an invalid cryptographic device id.",
			     id_str);
		show_card_capability(id);
	}
}

/*
 * Read driver entry in dir or in dir/subdir and store driver into buf.
 * Returns:
 *    0 if there is no driver link (no driver bound to this device or error)
 *    1 if one of the cexXcard or cexXqueue driver is bound to this device
 *    2 if the vfio is bound to this device
 */
static int read_driver(const char *dir, const char *subdir, char *buf, size_t buflen)
{
	char drvlink[PATH_MAX], linktarget[PATH_MAX];
	char *p, driver[256];

	if (subdir)
		snprintf(drvlink, sizeof(drvlink), "%s/%s/driver", dir, subdir);
	else
		snprintf(drvlink, sizeof(drvlink), "%s/driver", dir);
	drvlink[sizeof(drvlink) - 1] = '\0';

	memset(linktarget, 0, sizeof(linktarget));

	if (readlink(drvlink, linktarget, sizeof(linktarget)) > 0) {
		p = strrchr(linktarget, '/');
		if (p) {
			strncpy(driver, p + 1, sizeof(driver));
			driver[sizeof(driver) - 1] = '\0';
			strncpy(buf, driver, buflen);
			if (misc_regex_match(driver, "cex[0-9](card|queue)"))
				return 1;
			else if (misc_regex_match(driver, "vfio.ap"))
				return 2;
		}
	}

	return 0;
}

/*
 * Read subdevice default attributes
 */
static void read_subdev_rec_default(struct util_rec *rec, const char *grp_dev,
				    const char *sub_dev)
{
	long config = -1, online = -1, chkstop = -1;
	char buf[256];
	unsigned long facility;

	if (util_file_read_line(buf, sizeof(buf), "%s/type", grp_dev))
		util_rec_set(rec, "type", "-");
	else
		util_rec_set(rec, "type", buf);

	if (util_path_is_readable("%s/%s/config", grp_dev, sub_dev))
		util_file_read_l(&config, 10, "%s/%s/config", grp_dev, sub_dev);
	if (util_path_is_readable("%s/%s/chkstop", grp_dev, sub_dev))
		util_file_read_l(&chkstop, 10, "%s/%s/chkstop", grp_dev, sub_dev);
	if (util_path_is_readable("%s/%s/online", grp_dev, sub_dev))
		util_file_read_l(&online, 10, "%s/%s/online", grp_dev, sub_dev);

	util_rec_set(rec, "status", "-");
	if (config == 0) {
		util_rec_set(rec, "status", "deconfig");
	} else {
		if (chkstop > 0)
			util_rec_set(rec, "status", "chkstop");
		else if (online > 0)
			util_rec_set(rec, "status", "online");
		else if (online == 0)
			util_rec_set(rec, "status", "offline");
		else {
			/* no online attribute, maybe use status attribute */
			if (util_path_is_readable("%s/%s/status",
						  grp_dev, sub_dev)) {
				util_file_read_line(buf, sizeof(buf),
						    "%s/%s/status",
						    grp_dev, sub_dev);
				util_rec_set(rec, "status", buf);
			}
		}
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

	if (config == 0) {
		util_rec_set(rec, "requests", "-");
	} else {
		util_file_read_line(buf, sizeof(buf), "%s/%s/request_count",
				    grp_dev, sub_dev);
		util_rec_set(rec, "requests", buf);
	}
}

/*
 * Read subdevice verbose attributes
 */
static void read_subdev_rec_verbose(struct util_rec *rec, const char *grp_dev,
				    const char *sub_dev)
{
	int i, drvinfo;
	unsigned long facility;
	char buf[256];
	long depth, pending1, pending2, config = -1;

	if (l.verbose == 0)
		return;

	drvinfo = read_driver(grp_dev, sub_dev, buf, sizeof(buf));
	util_rec_set(rec, "driver", drvinfo > 0 ? buf : "-no-driver-");

	if (util_path_is_readable("%s/config", grp_dev))
		util_file_read_l(&config, 10, "%s/config", grp_dev);

	if (config == 0 || drvinfo != 1) {
		util_rec_set(rec, "pending", "-");
	} else {
		util_file_read_l(&pending1, 10, "%s/%s/pendingq_count",
				 grp_dev, sub_dev);
		util_file_read_l(&pending2, 10, "%s/%s/requestq_count",
				 grp_dev, sub_dev);
		util_rec_set(rec, "pending", "%ld", pending1 + pending2);
	}

	util_file_read_line(buf, sizeof(buf), "%s/hwtype", grp_dev);
	util_rec_set(rec, "hwtype", buf);

	util_file_read_l(&depth, 10, "%s/depth", grp_dev);
	util_rec_set(rec, "depth", "%02d", depth + 1);

	if (util_file_read_ul(&facility, 16, "%s/ap_functions", grp_dev))
		errx(EXIT_FAILURE,
		     "Error - Read of sysfs attribute %s/ap_functions failed.",
		     grp_dev);
	for (i = 0; i < MAX_FAC_BITS; i++)
		buf[i] = facility & fac_bits[i].mask ? fac_bits[i].c : '-';
	buf[i] = '\0';
	util_rec_set(rec, "facility", buf);

	if (ap_bus_has_SB_support()) {
		if (util_file_read_ul(&facility, 16, "%s/%s/ap_functions",
				      grp_dev, sub_dev)) {
			util_rec_set(rec, "sestat", "error");
			return;
		}
		switch (EXTRACT_BS_BITS(facility)) {
		case 0:
			util_rec_set(rec, "sestat", "usable");
			break;
		case 1:
			util_rec_set(rec, "sestat", "bound");
			break;
		case 2:
			util_rec_set(rec, "sestat", "unbound");
			break;
		case 3:
			util_rec_set(rec, "sestat", "illicit");
			break;
		default:
			util_rec_set(rec, "sestat", "-");
		}
	}
}

/*
 * Show one subdevice
 */
static void show_subdevice(struct util_rec *rec, const char *grp_dev,
			   const char *sub_dev)
{
	char type[16], t = '\0';

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

	if (!l.showqueue)
		return;

	util_rec_set(rec, "card", sub_dev);
	if (util_file_read_line(type, sizeof(type), "%s/type", grp_dev) == 0)
		t = type[strlen(type) - 1];

	if ((t == 'A' && !l.showaccel) ||
	    (t == 'C' && !l.showcca) ||
	    (t == 'P' && !l.showep11))
		return;

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
	long config = -1, online = -1, chkstop = -1;
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

	if (util_path_is_readable("%s/config", grp_dev))
		util_file_read_l(&config, 10, "%s/config", grp_dev);
	if (util_path_is_readable("%s/chkstop", grp_dev))
		util_file_read_l(&chkstop, 10, "%s/chkstop", grp_dev);
	if (util_path_is_readable("%s/online", grp_dev))
		util_file_read_l(&online, 10, "%s/online", grp_dev);
	if (config == 0) {
		util_rec_set(rec, "status", "deconfig");
	} else {
		if (chkstop > 0)
			util_rec_set(rec, "status", "chkstop");
		else if (online > 0)
			util_rec_set(rec, "status", "online");
		else if (online == 0)
			util_rec_set(rec, "status", "offline");
		else
			util_rec_set(rec, "status", "-");
	}

	if (config == 0) {
		util_rec_set(rec, "requests", "-");
	} else {
		util_file_read_line(buf, sizeof(buf), "%s/request_count", grp_dev);
		util_rec_set(rec, "requests", buf);
	}
}

/*
 * Read verbose attributes
 */
static void read_rec_verbose(struct util_rec *rec, const char *grp_dev)
{
	int i;
	unsigned long facility;
	char buf[256];
	long depth, pending1, pending2, config = -1;

	if (l.verbose == 0)
		return;

	if (util_path_is_readable("%s/config", grp_dev))
		util_file_read_l(&config, 10, "%s/config", grp_dev);

	if (config == 0) {
		util_rec_set(rec, "pending", "-");
	} else {
		util_file_read_l(&pending1, 10, "%s/pendingq_count", grp_dev);
		util_file_read_l(&pending2, 10, "%s/requestq_count", grp_dev);
		util_rec_set(rec, "pending", "%ld", pending1 + pending2);
	}

	util_file_read_line(buf, sizeof(buf), "%s/hwtype", grp_dev);
	util_rec_set(rec, "hwtype", buf);

	util_file_read_l(&depth, 10, "%s/depth", grp_dev);
	util_rec_set(rec, "depth", "%02d", depth + 1);

	util_file_read_ul(&facility, 16, "%s/ap_functions", grp_dev);
	for (i = 0; i < MAX_FAC_BITS; i++)
		buf[i] = facility & fac_bits[i].mask ? fac_bits[i].c : '-';
	buf[i] = '\0';
	util_rec_set(rec, "facility", buf);

	i = read_driver(grp_dev, NULL, buf, sizeof(buf));
	util_rec_set(rec, "driver", i > 0 ? buf : "-no-driver-");

	if (ap_bus_has_SB_support())
		util_rec_set(rec, "sestat", "-");
}

/*
 * Show device: device is in the form "card00", "card01", ...
 */
static void show_device(struct util_rec *rec, const char *device)
{
	char *grp_dev, card[16], type[16], t = '\0';

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

	if (util_file_read_line(type, sizeof(type), "%s/type", grp_dev) == 0)
		t = type[strlen(type) - 1];

	if ((t == 'A' && !l.showaccel) ||
	    (t == 'C' && !l.showcca) ||
	    (t == 'P' && !l.showep11))
		goto out_free;

	read_rec_default(rec, grp_dev);
	read_rec_verbose(rec, grp_dev);

	if (l.showcard)
		util_rec_print(rec);
	if (l.showqueue)
		show_subdevices(rec, grp_dev);
out_free:
	free(grp_dev);
}

/*
 * Define the *default* attributes
 */
static void define_rec_default(struct util_rec *rec)
{
	util_rec_def(rec, "card", UTIL_REC_ALIGN_LEFT, 8, "CARD.DOM");
	util_rec_def(rec, "type", UTIL_REC_ALIGN_LEFT, 5, "TYPE");
	util_rec_def(rec, "mode", UTIL_REC_ALIGN_LEFT, 11, "MODE");
	util_rec_def(rec, "status", UTIL_REC_ALIGN_LEFT, 10, "STATUS");
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
	if (ap_bus_has_SB_support())
		util_rec_def(rec, "sestat", UTIL_REC_ALIGN_LEFT, 11, "SESTAT");
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
static void show_devices_argv(int argc, char **argv)
{
	int id, dom, argidx, devidx, n, dev_cnt, sub_cnt;
	struct util_rec *rec = util_rec_new_wide("-");
	char *ap, *grp_dev, *path, *card, *sub_dev;
	struct dirent **dev_vec, **subdev_vec;

	/* check if ap driver is available */
	ap = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(ap))
		errx(EXIT_FAILURE, "Crypto device driver not available.");

	/* Define the record */
	define_rec_default(rec);
	define_rec_verbose(rec);

	util_rec_print_hdr(rec);
	for (argidx = 0; argidx < argc; argidx++) {
		id = -1;
		dom = -1;
		if (sscanf(argv[argidx], "%x.%x", &id, &dom) >= 1) {
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
			continue;
		}
		if (sscanf(argv[argidx] + 1, "%x", &dom) == 1) {
			/* list specific domains of all adapters */
			path = util_path_sysfs("devices/ap/");
			dev_cnt = util_scandir(&dev_vec, alphasort, path,
					       "card[0-9a-fA-F]+");
			if (dev_cnt < 1)
				errx(EXIT_FAILURE, "No crypto card devices found.");
			free(path);
			for (devidx = 0; devidx < dev_cnt; devidx++) {
				path = util_path_sysfs("devices/ap/%s",
						       dev_vec[devidx]->d_name);
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
			continue;
		}
		printf("Invalid adpater id!\n");
	}
}

/*
 * Describe adapter ids
 */
static void print_adapter_id_help(void)
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
		case 's':
			show_serialnumbers();
			return EXIT_SUCCESS;
		case 'V':
			l.verbose++;
			break;
		case OPT_ACCELONLY:
			l.showaccel = 1;
			break;
		case OPT_CCAONLY:
			l.showcca = 1;
			break;
		case OPT_EP11ONLY:
			l.showep11 = 1;
			break;
		case OPT_CARDONLY:
			l.showcard = 1;
			break;
		case OPT_QUEUEONLY:
			l.showqueue = 1;
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

	switch (l.showaccel + l.showcca + l.showep11) {
	case 0:
		l.showaccel = l.showcca = l.showep11 = 1;
		break;
	case 1:
		break;
	default:
		warnx("Only one of --accelonly or --ccaonly or --ep11only can be specified");
		return EXIT_FAILURE;
	}

	switch (l.showcard + l.showqueue) {
	case 0:
		l.showcard = l.showqueue = 1;
		break;
	case 1:
		break;
	default:
		warnx("Only one of --cardonly or --queueonly can be specified");
		return EXIT_FAILURE;
	}

	if (optind == argc)
		show_devices_all();
	else
		show_devices_argv((argc - optind), &argv[optind]);
	return EXIT_SUCCESS;
}
