/*
 * zpcictl - Manage PCI devices on z Systems
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_proc.h"
#include "lib/util_rec.h"
#include "lib/util_scandir.h"
#include "lib/util_sys.h"

#include "zpcictl.h"

#define SMARTCTL_CMDLINE "smartctl -x %s 2>/dev/null"

static const struct util_prg prg = {
	.desc = "Use zpcictl to manage PCI devices on IBM Z\n"
		"DEVICE is the slot ID or node of the device "
		"(e.g. 0000:00:00.0 or /dev/nvme0)",
	.args = "DEVICE",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2018,
			.pub_last = 2018,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/* Defines for options with no short command */
#define OPT_RESET	128
#define OPT_DECONF	129
#define OPT_REPORT_ERR	130

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("ERROR HANDLING OPTIONS"),
	{
		.option = { "reset", no_argument, NULL, OPT_RESET },
		.desc = "Reset the device",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "deconfigure", no_argument, NULL, OPT_DECONF },
		.desc = "Deconfigure the device to prepare for any repair action",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "report-error", no_argument, NULL, OPT_REPORT_ERR },
		.desc = "Report a device error to the Support Element (SE)",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	UTIL_OPT_SECTION("GENERAL OPTIONS"),
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static int is_char_dev(const char *dev)
{
	struct stat s;

	if (stat(dev, &s))
		return 0;

	return S_ISCHR(s.st_mode);
}

static int is_blk_dev(const char *dev)
{
	struct stat s;

	if (stat(dev, &s))
		return 0;

	return S_ISBLK(s.st_mode);
}

static void fopen_err(char *path)
{
	warnx("Could not open file %s: %s", path, strerror(errno));
	free(path);
	exit(EXIT_FAILURE);
}

static void fclose_err(char *path)
{
	if (errno == EIO || errno == EOPNOTSUPP)
		warnx("Unsupported operation: %s: %s", path, strerror(errno));
	else
		warnx("Could not close file: %s: %s", path, strerror(errno));
	free(path);
	exit(EXIT_FAILURE);

}

static void fread_err(FILE *fp, char *path)
{
	warnx("Could not read file: %s: %s", path, strerror(errno));
	if (fclose(fp))
		fclose_err(path);
	free(path);
	exit(EXIT_FAILURE);
}

static void fwrite_err(FILE *fp, char *path)
{
	warnx("Could not write to file: %s: %s", path, strerror(errno));
	if (fclose(fp))
		fclose_err(path);
	free(path);
	exit(EXIT_FAILURE);
}

#define READ_CHUNK_SIZE		512

static char *collect_smart_data(struct zpci_device *pdev)
{
	char *buffer = NULL;
	size_t count = 0;
	char *cmd;
	FILE *fd;

	if (!pdev->device)
		return NULL;

	util_asprintf(&cmd, SMARTCTL_CMDLINE, pdev->device);
	fd = popen(cmd, "r");
	if (!fd)
		goto out;

	while (!feof(fd)) {
		buffer = realloc(buffer, count + READ_CHUNK_SIZE);
		if (!buffer) {
			warnx("Could not collect S.M.A.R.T. data");
			goto out;
		}
		count += fread(&buffer[count], 1, READ_CHUNK_SIZE, fd);
		if (ferror(fd)) {
			free(buffer);
			buffer = NULL;
			goto out;
		}
	}

	buffer = realloc(buffer, count);
	if (!buffer && count > 0)
		warnx("Could not collect S.M.A.R.T. data");
	if (buffer)
		buffer[count] = '\0';

out:
	pclose(fd);
	free(cmd);

	return buffer;
}

static unsigned int sysfs_read_value(struct zpci_device *pdev, const char *attr)
{
	unsigned int val;
	char *path;
	FILE *fp;

	path = util_path_sysfs("bus/pci/devices/%s/%s", pdev->slot, attr);
	fp = fopen(path, "r");
	if (!fp)
		fopen_err(path);
	if (fscanf(fp, "%x", &val) != 1) {
		fread_err(fp, path);
	}
	if (fclose(fp))
		fclose_err(path);
	free(path);

	return val;
}

static void sysfs_write_value(struct zpci_device *pdev, const char *attr,
				unsigned int val)
{
	char *path;
	FILE *fp;

	path = util_path_sysfs("bus/pci/devices/%s/%s", pdev->slot, attr);
	fp = fopen(path, "w");
	if (!fp)
		fopen_err(path);
	if (fprintf(fp, "%x", val) < 0) {
		fwrite_err(fp, path);
	}
	if (fclose(fp))
		fclose_err(path);
	free(path);
}

static void sysfs_report_error(struct zpci_report_error *report, char *slot)
{
	size_t r_size;
	char *path;
	FILE *fp;

	r_size = sizeof(*report);

	path = util_path_sysfs("bus/pci/devices/%s/report_error", slot);
	fp = fopen(path, "w");
	if (!fp)
		fopen_err(path);
	if (fwrite(report, 1, r_size, fp) != r_size)
		fwrite_err(fp, path);
	if (fclose(fp))
		fclose_err(path);
	free(path);
}

static void get_device_node(struct zpci_device *pdev)
{
	struct dirent **de_vec;
	char *path, *dev;
	char slot[13];
	int count, i;

	path = util_path_sysfs("bus/pci/devices/%s/nvme", pdev->slot);
	count = util_scandir(&de_vec, alphasort, path, "nvme*");
	if (count == -1) {
		warnx("Could not read directory %s: %s", path, strerror(errno));
		free(path);
		return;
	}

	for (i = 0; i < count; i++) {
		util_asprintf(&dev, "/dev/%s", de_vec[i]->d_name);
		if (util_sys_get_dev_addr(dev, slot) != 0)
			continue;
		if (strcmp(slot, pdev->slot) == 0) {
			pdev->device = dev;
			break;
		}
	}

	util_scandir_free(de_vec, count);
	free(path);
}

static int device_exists(char *dev)
{
	char *path;
	int rc = 0;

	/* In case a device node is specified, this will be sufficiant */
	if (util_path_exists(dev) && !util_path_is_dir(dev))
		return 1;

	path = util_path_sysfs("bus/pci/devices/%s", dev);
	if (util_path_exists(path))
		rc = 1;
	free(path);

	return rc;
}

static void get_device_info(struct zpci_device *pdev, char *dev)
{
	if (!device_exists(dev))
		errx(EXIT_FAILURE, "Could not find device %s", dev);
	if (is_blk_dev(dev))
		errx(EXIT_FAILURE, "Unsupported device type %s", dev);
	if (is_char_dev(dev)) {
		if (util_sys_get_dev_addr(dev, pdev->slot) != 0)
			errx(EXIT_FAILURE,
			     "Could not determine slot address for %s", dev);
		pdev->device = dev;
	} else {
		strcpy(pdev->slot, dev);
	}

	pdev->class = sysfs_read_value(pdev, "class");
	pdev->fid = sysfs_read_value(pdev, "function_id");
	pdev->pchid = sysfs_read_value(pdev, "pchid");

	/*
	 * In case a slot address was specified, the device node for NVMe
	 * devices is still needed. Otherwise it won't be possible to collect
	 * S.M.A.R.T. data at a later point.
	 */
	if (!pdev->device && pdev->class == PCI_CLASS_NVME)
		get_device_node(pdev);
}

/*
 * Issue an SCLP Adapter Error Notification event with a specific action
 * qualifier.
 *
 * Collect additional information when possible (e.g. S.M.A.R.T. data for NVMe
 * devices).
 */
static void sclp_issue_action(struct zpci_device *pdev, int action)
{
	struct zpci_report_error report = {
		.header = { 0 },
		.data = { 0 }
	};
	char *sdata = NULL;

	report.header.version = 1;
	report.header.action = action;
	report.header.length = sizeof(report.data);
	report.data.timestamp = (__u64)time(NULL);
	report.data.err_log_id = 0x4713;

	if (pdev->class == PCI_CLASS_NVME)
		sdata = collect_smart_data(pdev);
	if (sdata) {
		util_strlcpy(report.data.log_data, sdata,
			     sizeof(report.data.log_data));
		free(sdata);
	}
	sysfs_report_error(&report, pdev->slot);
}

/*
 * Reset the PCI device and initiate a re-initialization.
 */
static void sclp_reset_device(struct zpci_device *pdev)
{
	sclp_issue_action(pdev, SCLP_ERRNOTIFY_AQ_RESET);
	sysfs_write_value(pdev, "recover", 1);
}

/*
 * De-Configure/repair PCI device. Moves the device from configured
 * to reserved state.
 */
static void sclp_deconfigure(struct zpci_device *pdev)
{
	sclp_issue_action(pdev, SCLP_ERRNOTIFY_AQ_DECONF);
}

/*
 * Report an error to the SE.
 */
static void sclp_report_error(struct zpci_device *pdev)
{
	sclp_issue_action(pdev, SCLP_ERRNOTIFY_AQ_REPORT_ERR);
}

static void parse_cmdline(int argc, char *argv[], struct options *opts)
{
	int cmd;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	do {
		cmd = util_opt_getopt_long(argc, argv);

		switch (cmd) {
		case OPT_RESET:
			opts->reset = 1;
			break;
		case OPT_DECONF:
			opts->deconfigure = 1;
			break;
		case OPT_REPORT_ERR:
			opts->report = 1;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'v':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case -1:
			/* End of options string */
			if (argc == 1) {
				errx(EXIT_FAILURE,
				     "Use '%s --help' for more information",
				     argv[0]);
			}
			break;
		}
	} while (cmd != -1);
}

int main(int argc, char *argv[])
{
	struct zpci_device pdev = { 0 };
	struct options opts = { 0 };

	parse_cmdline(argc, argv, &opts);

	if (optind >= argc)
		errx(EXIT_FAILURE, "No device specified");

	get_device_info(&pdev, argv[optind]);

	if (opts.reset)
		sclp_reset_device(&pdev);
	else if (opts.deconfigure)
		sclp_deconfigure(&pdev);
	else if (opts.report)
		sclp_report_error(&pdev);

	return 0;
}
