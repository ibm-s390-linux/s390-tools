/*
 * dasdfmt - Format DASD ECKD devices for use by Linux
 *
 * Copyright IBM Corp. 1999, 2017
 * Copyright Red Hat Inc. 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <linux/version.h>
#include <stdarg.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/utsname.h>

#include "lib/dasd_base.h"
#include "lib/dasd_sys.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_prg.h"
#include "lib/util_proc.h"
#include "lib/vtoc.h"
#include "lib/zt_common.h"

#include "dasdfmt.h"

#define BUSIDSIZE  8
#define SEC_PER_DAY (60 * 60 * 24)
#define SEC_PER_HOUR (60 * 60)

static int filedes;
static int disk_disabled;
static format_data_t format_params;
static format_mode_t mode;
static char *prog_name;
static volatile sig_atomic_t program_interrupt_in_progress;
static int reqsize;

static const struct util_prg prg = {
	.desc = "Use dasdfmt to format a DASD ECKD device for use by Linux.\n"
		"DEVICE is the node of the device (e.g. '/dev/dasda').",
	.args = "DEVICE",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 1999,
			.pub_last = 2017,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Global variables for program options and other relevant information
 */
static struct dasdfmt_globals {
	dasd_information2_t dasd_info;
	char *dev_path; /* device path entered by user */
	char *dev_node; /* reliable device node determined by dasdfmt */
	int   verbosity;
	int   testmode;
	int   withoutprompt;
	int   print_progressbar;
	int   print_hashmarks, hashstep;
	int   print_percentage;
	int   force;
	int   writenolabel;
	int   labelspec;
	int   cdl_format;
	int   blksize_specified;
	int   reqsize_specified;
	int   keep_volser;
	int   force_host;
	int   layout_specified;
	int   check;
	int   mode_specified;
	int   ese;
	int   no_discard;
} g = {
	.dasd_info = { 0 },
};

/* Defines for options with no short command */
#define OPT_CHECK	128
#define OPT_NOZERO	129
#define OPT_NODISCARD	130

static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("FORMAT ACTIONS"),
	{
		.option = { "mode", required_argument, NULL, 'M' },
		.argument = "MODE",
		.desc = "Specify scope of operation using MODE:\n"
			"  full: Full device (default)\n"
			"  quick: Only the first two tracks\n"
			"  expand: Unformatted tracks at device end",
	},
	{
		.option = { "check", no_argument, NULL, OPT_CHECK },
		.desc = "Perform complete format check on device",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	UTIL_OPT_SECTION("FORMAT OPTIONS"),
	{
		.option = { "blocksize", required_argument, NULL, 'b' },
		.argument = "SIZE",
		.desc = "Format blocks to SIZE bytes (default 4096)",
	},
	{
		.option = { "disk_layout", required_argument, NULL, 'd' },
		.argument = "LAYOUT",
		.desc = "Specify the disk layout:\n"
			"  cdl: Compatible Disk Layout (default)\n"
			"  ldl: Linux Disk Layout",
	},
	{
		.option = { "keep_volser", no_argument, NULL, 'k' },
		.desc = "Do not change the current volume serial",
	},
	{
		.option = { "label", required_argument, NULL, 'l' },
		.argument = "VOLSER",
		.desc = "Specify volume serial number",
	},
	{
		.option = { "no_label", no_argument, NULL, 'L' },
		.desc = "Don't write a disk label",
	},
	{
		.option = { "requestsize", required_argument, NULL, 'r' },
		.argument = "NUM",
		.desc = "Process NUM cylinders in one formatting step",
	},
	{
		.option = { "norecordzero", no_argument, NULL, OPT_NOZERO },
		.desc = "Prevent storage server from modifying record 0",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { "no-discard", no_argument, NULL, OPT_NODISCARD },
		.desc = "Do not discard space before formatting",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	{
		.option = { NULL, no_argument, NULL, 'y' },
		.desc = "Start formatting without further user-confirmation",
		.flags = UTIL_OPT_FLAG_NOLONG,
	},
	UTIL_OPT_SECTION("DISPLAY PROGRESS"),
	{
		.option = { "hashmarks", required_argument, NULL, 'm' },
		.argument = "NUM",
		.desc = "Show a hashmark every NUM cylinders",
	},
	{
		.option = { "progressbar", no_argument, NULL, 'p' },
		.desc = "Show a progressbar",
	},
	{
		.option = { "percentage", no_argument, NULL, 'P' },
		.desc = "Show progress in percent",
	},
	UTIL_OPT_SECTION("MISC"),
	{
		.option = { "check_host_count", no_argument, NULL, 'C' },
		.desc = "Check if device is in use by other hosts",
	},
	{
		.option = { "force", no_argument, NULL, 'F' },
		.desc = "Format without performing sanity checking",
	},
	{
		.option = { "test", no_argument, NULL, 't' },
		.desc = "Run in dry-run mode without modifying the DASD",
	},
	{
		.option = { NULL, no_argument, NULL, 'v' },
		.desc = "Print verbose messages when executing",
		.flags = UTIL_OPT_FLAG_NOLONG,
	},
	UTIL_OPT_HELP,
	{
		.option = { "version", no_argument, NULL, 'V' },
		.desc = "Print version information, then exit",
	},
	UTIL_OPT_END
};

/* Report error, free memory, and exit */
static void error(const char *format, ...)
{
	va_list args;

	fprintf(stderr, "%s: ", prog_name);
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fprintf(stderr, "\n");

	free(g.dev_node);
	free(g.dev_path);

	exit(EXIT_FAILURE);
}

/*
 * Helper function to calculate the days, hours, minutes, and seconds
 * for a given timestamp in seconds
 */
static void calc_time(time_t time, int *d, int *h, int *m, int *s)
{
	*d = time / SEC_PER_DAY;
	time %= SEC_PER_DAY;
	*h = time / SEC_PER_HOUR;
	time %= SEC_PER_HOUR;
	*m = time / 60;
	*s = time % 60;
}

/*
 * This function calculates and prints the estimated time of accomplishment.
 */
static void print_eta(int p_new, int started)
{
	static struct timeval start;
	struct timeval now;
	time_t time_elapsed;
	time_t time_end;
	int d, h, m, s;
	static int p_init;
	int p;

	if (!started) {
		gettimeofday(&start, NULL);
		p_init = p_new;
	}
	gettimeofday(&now, NULL);
	time_elapsed = now.tv_sec - start.tv_sec;

	/*
	 * We might start somewhere in the middle with an initial percentage
	 * value of i.e. 60%. Therefore we need to calculate the relative
	 * percentage of p_new within that remaining range (100 - 60) in order
	 * to correctly estimate the remaining time.
	 */
	if (p_init == 100)
		p = p_init;
	else
		p = 100 * (p_new - p_init) / (100 - p_init);

	if (p == 0)
		time_end = time_elapsed;
	else
		time_end = time_elapsed * (100 - p) / p;

	/* Calculate days, hours, minutes, and seconds */
	calc_time(time_end, &d, &h, &m, &s);
	if (p_new == 100)
		calc_time(time_elapsed, &d, &h, &m, &s);

	/* Avoid printing leading zeros */
	if (d > 0)
		printf(" [%dd %dh %dm %ds%-4s", d, h, m, s, "]");
	else if (h > 0)
		printf(" [%dh %dm %ds%-7s", h, m, s, "]");
	else if (m > 0)
		printf(" [%dm %ds%-6s", m, s, "]");
	else if (s > 0 || p > 50)
		printf(" [%ds%-5s", s, "]");
	else
		printf(" [--%-1s", "]");
}

/*
 * Draw the progress indicator depending on what command line argument is set.
 * This can either be a progressbar, hashmarks, or percentage.
 */
static void draw_progress(int cyl, unsigned int cylinders, int aborted)
{
	static int hashcount;
	static int started;
	static int p_old;
	int p_new = 0;
	int barlength;
	int i;

	if (g.print_progressbar) {
		printf("cyl %7d of %7d |", cyl, cylinders);
		p_new = cyl * 100 / cylinders;
		if (p_new != p_old || !started || aborted) {
			/* percent value has changed */
			p_old = p_new;
			barlength = cyl * 33 / cylinders;
			for (i = 1; i <= barlength; i++)
				printf("#");
			for (i = barlength + 1; i <= 33; i++)
				printf("-");
			printf("|%3d%%", p_new);
			if (aborted)
				p_new = 100;
			print_eta(p_new, started);
			started = 1;
		}
		printf("\r");
		fflush(stdout);
	}

	if (g.print_hashmarks && (cyl / g.hashstep - hashcount) != 0) {
		printf("#");
		fflush(stdout);
		hashcount++;
	}

	if (g.print_percentage) {
		printf("cyl %7d of %7d |%3d%%\n", cyl, cylinders,
		       cyl * 100 / cylinders);
		fflush(stdout);
	}
}

/*
 * Helper function for recs_per_track.
 */
static inline unsigned int ceil_quot(unsigned int d1, unsigned int d2)
{
	return (d1 + (d2 - 1)) / d2;
}

/*
 * Calculate records per track depending on the device characteristics.
 */
static unsigned int recs_per_track(struct dasd_eckd_characteristics *rdc,
				   unsigned int kl, unsigned int dl)
{
	int dn, kn;

	switch (rdc->dev_type) {
	case 0x3380:
		if (kl)
			return 1499 / (15 + 7 + ceil_quot(kl + 12, 32) +
				       ceil_quot(dl + 12, 32));
		else
			return 1499 / (15 + ceil_quot(dl + 12, 32));
	case 0x3390:
		dn = ceil_quot(dl + 6, 232) + 1;
		if (kl) {
			kn = ceil_quot(kl + 6, 232) + 1;
			return 1729 / (10 + 9 + ceil_quot(kl + 6 * kn, 34) +
				       9 + ceil_quot(dl + 6 * dn, 34));
		} else {
			return 1729 / (10 + 9 + ceil_quot(dl + 6 * dn, 34));
		}
	case 0x9345:
		dn = ceil_quot(dl + 6, 232) + 1;
		if (kl) {
			kn = ceil_quot(kl + 6, 232) + 1;
			return 1420 / (18 + 7 + ceil_quot(kl + 6 * kn, 34) +
				       ceil_quot(dl + 6 * dn, 34));
		} else {
			return 1420 / (18 + 7 + ceil_quot(dl + 6 * dn, 34));
		}
	}
	return 0;
}

/*
 * Evaluate errors recognized by format checks and print appropriate error
 * messages depending on the content of cdata.
 */
static void evaluate_format_error(format_check_t *cdata, unsigned int heads)
{
	struct dasd_eckd_characteristics *rdc;
	/* Special blocksize values of the first 3 records of trk 0 of cyl 0 */
	const int blksizes_trk0[] = { 24, 144, 80 };
	/* Special blocksize value of trk 1 cyl 0 */
	const int blksize_trk1 = 96;
	unsigned int cyl;
	unsigned int head;
	unsigned int rpt;
	unsigned int kl = 0;
	int blksize = cdata->expect.blksize;

	if (g.print_progressbar || g.print_hashmarks)
		printf("\n");

	/*
	 * If mode is not QUICK and a device format couldn't be determined, the
	 * device is considered not formatted.
	 * Also, reading record zero will never happen. If the record in error
	 * is 0 nonetheless, the device is not formatted at all as well!
	 */
	if ((g.dasd_info.format == DASD_FORMAT_NONE && mode != QUICK) ||
	    cdata->rec == 0) {
		ERRMSG("WARNING: The specified device is not "
		       "formatted at all.\n");
		return;
	}

	cyl = cdata->unit / heads;
	head = cyl >> 16;
	head <<= 4;
	head |= cdata->unit % heads;

	/*
	 * Set special expected values for the first 3 records of trk 0 of cyl 0
	 * and trk 1 of cyl 0 when checking a CDL formatted device.
	 */
	if ((cdata->expect.intensity & DASD_FMT_INT_COMPAT) &&
	    cyl == 0 && head == 0 && cdata->rec < 4) {
		kl = 4;
		blksize = blksizes_trk0[cdata->rec - 1];
	}
	if ((cdata->expect.intensity & DASD_FMT_INT_COMPAT) &&
	    cyl == 0 && head == 1) {
		kl = 44;
		blksize = blksize_trk1;
	}

	rdc = (struct dasd_eckd_characteristics *)
				&g.dasd_info.characteristics;

	rpt = recs_per_track(rdc, kl, cdata->expect.blksize);

	ERRMSG("WARNING: The specified device is not formatted as expected.\n");
	switch (cdata->result) {
	case DASD_FMT_ERR_TOO_FEW_RECORDS:
		ERRMSG("Too few records (found %d, expected %d) "
		       "at cyl: %d trk: %d rec: %d.\n",
		       cdata->num_records, rpt, cyl, head, cdata->rec);
		break;
	case DASD_FMT_ERR_TOO_MANY_RECORDS:
		ERRMSG("Too many records (found %d, expected %d) "
		       "at cyl: %d trk: %d rec: %d.\n",
		       cdata->num_records, rpt, cyl, head, cdata->rec);
		break;
	case DASD_FMT_ERR_BLKSIZE:
		ERRMSG("Invalid blocksize (found %d, expected %d) "
		       "at cyl: %d trk: %d rec: %d.\n",
		       cdata->blksize, blksize, cyl, head, cdata->rec);
		break;
	case DASD_FMT_ERR_RECORD_ID:
		ERRMSG("Invalid record ID at cyl: %d trk: %d rec: %d.\n",
		       cyl, head, cdata->rec);
		break;
	case DASD_FMT_ERR_KEY_LENGTH:
		ERRMSG("Invalid key length (found %d, expected %d) "
		       "at cyl: %d trk: %d rec: %d.\n",
		       cdata->key_length, kl, cyl, head, cdata->rec);
		break;
	}
}

static void disk_enable(void)
{
	int err;

	err = dasd_disk_enable(filedes);
	if (err != 0)
		error("(prepare device) IOCTL BIODASDENABLE failed: %s", strerror(err));
	disk_disabled = 0;
}

static void disk_disable(const char *device)
{
	int err;

	err = dasd_disk_disable(device, &filedes);
	if (err != 0)
		error("(prepare device) IOCTL BIODASDDISABLE failed: %s", strerror(err));
	disk_disabled = 1;
}

/*
 * signal handler:
 * enables the disk again in case of SIGTERM, SIGINT and SIGQUIT
 */
static void program_interrupt_signal(int sig)
{
	int rc;

	if (program_interrupt_in_progress)
		raise(sig);
	program_interrupt_in_progress = 1;

	if (disk_disabled) {
		printf("Re-accessing the device...\n");
		disk_enable();
	}

	printf("Rereading the partition table...\n");
	rc = dasd_reread_partition_table(g.dev_node, 5);
	if (rc) {
		ERRMSG("%s: (signal handler) Re-reading partition table "
		       "failed. (%s)\n", prog_name, strerror(rc));
	} else {
		printf("Exiting...\n");
	}

	signal(sig, SIG_DFL);
	raise(sig);
}

/*
 * Check given device name for blanks and some special characters.
 * Retrieve reliable device node and store device information in global
 * dev_node and dev_path accordingly.
 */
static void get_device_name(int optind, int argc, char *argv[])
{
	struct util_proc_dev_entry dev_entry;
	unsigned int maj, min;
	struct stat dev_stat;

	if (optind + 1 < argc)
		error("More than one device specified!");

	if (optind >= argc)
		error("No device specified!");

	if (strlen(argv[optind]) >= PATH_MAX)
		error("device name too long!");
	util_asprintf(&g.dev_path, argv[optind]);

	if (stat(g.dev_path, &dev_stat) != 0)
		error("Could not get information for device node %s: %s",
		      g.dev_path, strerror(errno));

	maj = major(dev_stat.st_rdev);
	min = minor(dev_stat.st_rdev);
	if (min & PARTN_MASK)
		error("Unable to format partition %s. Please specify a device.", g.dev_path);

	if (util_proc_dev_get_entry(dev_stat.st_rdev, 1, &dev_entry) == 0) {
		if (strncmp(dev_entry.name, "dasd", 4) != 0)
			error("Unsupported device type '%s'.", dev_entry.name);
	} else {
		printf("%s WARNING: Unable to get driver name for device node %s",
		       prog_name, g.dev_path);
	}
	/* Get reliable device node */
	util_asprintf(&g.dev_node, "/dev/block/%d:%d", maj, min);
}

static void get_blocksize(unsigned int *blksize)
{
	int err;

	err = dasd_get_blocksize(g.dev_node, blksize);
	if (err != 0)
		error("the ioctl to get the blocksize of the device failed: %s", strerror(err));
}

/*
 * Check whether a specified blocksize matches the blocksize of the device
 */
static void check_blocksize(unsigned int blksize)
{
	unsigned int dev_blksize;

	if (!g.blksize_specified ||
	    g.dasd_info.format == DASD_FORMAT_NONE)
		return;

	get_blocksize(&dev_blksize);
	if (dev_blksize != blksize) {
		warnx("WARNING: Device is formatted with a different blocksize (%d).", dev_blksize);
		error("Use --mode=full to perform a clean format.");
	}
}

/*
 * Check whether a specified layout matches the layout
 * a device is formatted with.
 */
static void check_layout(unsigned int intensity)
{
	char layout[4];

	if (!g.layout_specified ||
	    g.dasd_info.format == DASD_FORMAT_NONE)
		return;

	if ((intensity & DASD_FMT_INT_COMPAT) &&
	    g.dasd_info.format == DASD_FORMAT_CDL)
		return;

	if (!(intensity & DASD_FMT_INT_COMPAT) &&
	    g.dasd_info.format == DASD_FORMAT_LDL)
		return;

	if (g.dasd_info.format == DASD_FORMAT_CDL)
		sprintf(layout, "CDL");
	if (g.dasd_info.format == DASD_FORMAT_LDL)
		sprintf(layout, "LDL");

	error("WARNING: Device is formatted with a different layout (%s).", layout);
}

/*
 * check for disk type and set some variables (e.g. usage count)
 */
static void check_disk(void)
{
	int err;
	bool ro;

	err = dasd_is_ro(g.dev_node, &ro);
	if (err != 0)
		error("the ioctl call to retrieve read/write status information failed: %s",
		      strerror(err));
	if (ro)
		error("Disk is read only!");
	if (!g.force) {
		if (g.dasd_info.open_count > 1)
			error("Disk in use!");
	}
	if (strncmp(g.dasd_info.type, "ECKD", 4) != 0) {
		warnx("Unsupported disk type");
		error("%s is not an ECKD disk!", g.dev_path);
	}
	if (dasd_sys_raw_track_access(g.dev_node))
		error("Device '%s' is in raw-track access mode", g.dev_path);
}

/*
 * check the volume serial for special
 * characters  and move blanks to the end
 */
static int check_volser(char *s, int devno)
{
	int i, j;

	for (i = 0; i < 6; i++) {
		if ((s[i] < 0x20) || (s[i] > 0x7a) ||
		    ((s[i] >= 0x21) && (s[i] <= 0x22)) ||  /*  !"        */
		    ((s[i] >= 0x26) && (s[i] <= 0x2f)) ||  /* &'()*+,-./ */
		    ((s[i] >= 0x3a) && (s[i] <= 0x3f)) ||  /*  :;<=>?    */
		    ((s[i] >= 0x5b) && (s[i] <= 0x60)))    /*  \]^_`     */
			s[i] = ' ';
		s[i] = toupper(s[i]);
	}
	s[6] = 0x00;

	for (i = 0; i < 6; i++) {
		if (s[i] == ' ')
			for (j = i; j < 6; j++)
				if (s[j] != ' ') {
					s[i] = s[j];
					s[j] = ' ';
					break;
				}
	}

	if (s[0] == ' ') {
		printf("Usage error, switching to default.\n");
		sprintf(s, "0X%04x", devno);
		for (i = 0; i < 6; i++)
			s[i] = toupper(s[i]);
		return -1;
	}

	return 0;
}

/*
 * do some blocksize checks
 */
static int check_param(char *s, size_t buffsize, format_data_t *data)
{
	int tmp = data->blksize;

	if ((tmp < 512) || (tmp > 4096)) {
		strncpy(s, "Blocksize must be one of the following positive "
			"integers:\n512, 1024, 2048, 4096.", buffsize);
		if (buffsize > 0)
			s[buffsize - 1] = '\0';
		return -1;
	}

	while (tmp > 0) {
		if ((tmp % 2) && (tmp != 1)) {
			strncpy(s, "Blocksize must be a power of 2.", buffsize);
			if (buffsize > 0)
				s[buffsize - 1] = '\0';
			return -1;
		}
		tmp /= 2;
	}

	return 0;
}

/*
 * Retrieve disk information and set cylinders and heads accordingly.
 */
static void set_geo(unsigned int *cylinders,
		    unsigned int *heads)
{
	struct dasd_eckd_characteristics *characteristics;

	if (g.verbosity > 0)
		printf("Retrieving disk geometry...\n");

	characteristics = (struct dasd_eckd_characteristics *)
				&g.dasd_info.characteristics;
	if (characteristics->no_cyl == LV_COMPAT_CYL &&
	    characteristics->long_no_cyl)
		*cylinders = characteristics->long_no_cyl;
	else
		*cylinders = characteristics->no_cyl;
	*heads = characteristics->trk_per_cyl;
}

/*
 * Set VTOC label information
 */
static void set_label(volume_label_t *vlabel,
		      format_data_t *p, unsigned int cylinders)
{
	char inp_buffer[5];

	if (g.writenolabel) {
		if (cylinders > LV_COMPAT_CYL && !g.withoutprompt) {
			printf("\n--->> ATTENTION! <<---\n");
			printf("You specified to write no labels to a"
			       " volume with more then %u cylinders.\n"
			       "Cylinders above this limit will not be"
			       " accessible as a linux partition!\n"
			       "Type \"yes\" to continue, no will leave"
			       " the disk untouched: ", LV_COMPAT_CYL);
			if (fgets(inp_buffer, sizeof(inp_buffer), stdin) == NULL)
				return;
			if (strcasecmp(inp_buffer, "yes") &&
			    strcasecmp(inp_buffer, "yes\n")) {
				printf("Omitting ioctl call (disk will "
					"NOT be formatted).\n");
				return;
			}
		}
	} else {
		if (!g.labelspec && !g.keep_volser) {
			char buf[7];

			sprintf(buf, "0X%04x", g.dasd_info.devno);
			check_volser(buf, g.dasd_info.devno);
			vtoc_volume_label_set_volser(vlabel, buf);
		}

		if (p->intensity & DASD_FMT_INT_COMPAT) {
			g.cdl_format = 1;
			vtoc_volume_label_set_label(vlabel, "VOL1");
			vtoc_volume_label_set_key(vlabel, "VOL1");
			vtoc_set_cchhb(&vlabel->vtoc, 0x0000, 0x0001, 0x01);
		} else {
			vtoc_volume_label_set_label(vlabel, "LNX1");
		}
	}
}

/*
 * Check whether hashsteps are within the correct interval.
 */
static void check_hashmarks(void)
{
	if (g.print_hashmarks) {
		if (g.hashstep < reqsize)
			g.hashstep = reqsize;
		if (g.hashstep < 1 || g.hashstep > 1000) {
			printf("Hashmark increment is not in range <1,1000>, "
			       "using the default.\n");
			g.hashstep = 10;
		}

		printf("Printing hashmark every %d cylinders.\n",
		       g.hashstep);
	}
}

/*
 * This function checks whether a range of tracks is in regular format
 * with the specified block size.
 */
static format_check_t check_track_format(format_data_t *p)
{
	format_check_t cdata = {
		.expect = {
			.blksize = p->blksize,
			.intensity = p->intensity,
			.start_unit = p->start_unit,
			.stop_unit = p->stop_unit
		}, 0
	};
	char msg[128] = "";
	int err;

	err = dasd_check_format(g.dev_node, &cdata);
	if (err != 0) {
		if (err == ENOTTY) {
			sprintf(msg, "Missing kernel support for format checking");
			if (mode == EXPAND)
				strcat(msg, ". Mode 'expand' cannot be used");
			else if (!g.check)
				strcat(msg, " (--force to override)");
			error("%s.", msg);
		}
		error("Could not check format: %s", strerror(err));
	}

	return cdata;
}

/*
 * Either do the actual format or check depending on the check-value.
 */
static int process_tracks(unsigned int cylinders, unsigned int heads,
			  format_data_t *format_params)
{
	format_check_t cdata = { .expect = {0}, 0};
	format_data_t step = *format_params;
	unsigned long step_value;
	unsigned long cur_trk;
	int cyl = 0, err;

	check_hashmarks();

	cur_trk = format_params->start_unit;

	while (cur_trk < format_params->stop_unit) {
		step_value = reqsize * heads - (cur_trk % heads);
		step.start_unit = cur_trk;
		if (cur_trk + heads * reqsize >= format_params->stop_unit)
			step.stop_unit = format_params->stop_unit;
		else
			step.stop_unit = cur_trk + step_value - 1;

		if (g.check) {
			cdata = check_track_format(&step);
			if (cdata.result) {
				cyl = cur_trk / heads + 1;
				draw_progress(cyl, cylinders, 1);
				evaluate_format_error(&cdata, heads);
				break;
			}
		} else {
			err = dasd_format_disk(filedes, &step);
			if (err != 0)
				error("the ioctl call to format tracks failed: %s", strerror(err));
		}

		cyl = cur_trk / heads + 1;
		draw_progress(cyl, cylinders, 0);

		cur_trk += step_value;
	}
	/* We're done, draw the 100% mark */
	if (!cdata.result) {
		cyl = step.stop_unit / heads + 1;
		draw_progress(cyl, cylinders, 0);
		printf("\n");
	}

	return cdata.result;
}

/*
 * This function checks the format of the entire disk.
 */
static void check_disk_format(unsigned int cylinders, unsigned int heads,
			      format_data_t *check_params)
{
	check_params->start_unit = 0;
	check_params->stop_unit = (cylinders * heads) - 1;

	printf("Checking format of the entire disk...\n");

	if (g.testmode) {
		printf("Test mode active, omitting ioctl.\n");
		return;
	}

	check_blocksize(check_params->blksize);
	check_layout(check_params->intensity);

	/*
	 * If no layout was specified, set the intensity
	 * according to what the layout seems to be.
	 */
	if (!g.layout_specified) {
		if (g.dasd_info.format == DASD_FORMAT_CDL)
			check_params->intensity |= DASD_FMT_INT_COMPAT;
		else if (g.dasd_info.format == DASD_FORMAT_LDL)
			check_params->intensity &= ~DASD_FMT_INT_COMPAT;
	}

	if (process_tracks(cylinders, heads, check_params))
		error("Use --mode=full to perform a clean format.");

	printf("Done. Disk is fine.\n");
}

/*
 * ask the user to specify a blocksize
 */
static format_data_t ask_user_for_blksize(format_data_t params)
{
	char c, str[ERR_LENGTH], buffer[20];
	int i, rc;

	i = params.blksize;

	do {
		params.blksize = i;

		printf("Please enter the blocksize of the formatting [%d]: ", i);
		if (fgets(buffer, sizeof(buffer), stdin) == NULL)
			break;

		rc = sscanf(buffer, "%d%c", &params.blksize, &c);
		if ((rc == 2) && (c == '\n'))
			rc = 1;
		if (rc == -1)
			rc = 1; /* this happens, if enter is pressed */
		if (rc != 1)
			printf(" -- wrong input, try again.\n");

		if (check_param(str, ERR_LENGTH, &params) < 0) {
			printf(" -- %s\n", str);
			rc = 0;
		}
	} while (rc != 1);

	return params;
}

/*
 * print all information needed to format the device
 */
static void dasdfmt_print_info(volume_label_t *vlabel, unsigned int cylinders,
			       unsigned int heads, format_data_t *p)
{
	char volser[6], vollbl[4];

	printf("Drive Geometry: %d Cylinders * %d Heads =  %d Tracks\n",
	       cylinders, heads, (cylinders * heads));

	printf("Device Type: %s Provisioned\n",
	       g.ese ? "Thinly" : "Fully");
	printf("\nI am going to format the device ");
	printf("%s in the following way:\n", g.dev_path);
	printf("   Device number of device : 0x%x\n", g.dasd_info.devno);
	printf("   Labelling device        : %s\n",
	       (g.writenolabel) ? "no" : "yes");

	if (!g.writenolabel) {
		vtoc_volume_label_get_label(vlabel, vollbl);
		printf("   Disk label              : %.4s\n", vollbl);
		vtoc_volume_label_get_volser(vlabel, volser);
		printf("   Disk identifier         : %.6s\n", volser);
	}
	printf("   Extent start (trk no)   : %u\n", p->start_unit);
	printf("   Extent end (trk no)     : %u\n", p->stop_unit);
	printf("   Compatible Disk Layout  : %s\n",
	       (p->intensity & DASD_FMT_INT_COMPAT) ? "yes" : "no");
	printf("   Blocksize               : %d\n", p->blksize);
	printf("   Mode                    : %s\n", mode_str[mode]);
	if (g.ese) {
		printf("   Full Space Release      : %s\n",
		       (g.no_discard || mode == FULL) ? "no" : "yes");
	}
	if (g.testmode)
		printf("Test mode active, omitting ioctl.\n");
}

/*
 * get volser
 */
static int dasdfmt_get_volser(char *volser)
{
	unsigned int blksize;
	volume_label_t vlabel;

	get_blocksize(&blksize);

	if ((strncmp(g.dasd_info.type, "ECKD", 4) == 0) &&
	    !g.dasd_info.FBA_layout) {
		/* OS/390 and zOS compatible disk layout */
		vtoc_read_volume_label(g.dev_node,
				       g.dasd_info.label_block * blksize,
				       &vlabel);
		vtoc_volume_label_get_volser(&vlabel, volser);
		return 0;
	} else {
		return -1;
	}
}

/*
 * do all the labeling (volume label and initial VTOC)
 */
static void dasdfmt_write_labels(volume_label_t *vlabel,
				 unsigned int cylinders, unsigned int heads)
{
	int label_position;
	struct hd_geometry geo;
	format4_label_t f4;
	format5_label_t f5;
	format7_label_t f7;
	unsigned int blksize;
	int rc, fd;
	void *ipl1_record, *ipl2_record;
	int ipl1_record_len, ipl2_record_len;

	if (g.verbosity > 0)
		printf("Retrieving dasd information... ");

	get_blocksize(&blksize);

	/*
	 * Don't rely on the cylinders returned by HDIO_GETGEO, they might be
	 * to small. geo is only used to get the number of sectors, which may
	 * vary depending on the format.
	 */
	rc = dasd_get_geo(g.dev_node, &geo);
	if (rc != 0)
		error("(write labels) IOCTL HDIO_GETGEO failed: %s", strerror(rc));

	if (g.verbosity > 0)
		printf("ok\n");

	/* write empty bootstrap (initial IPL records) */
	if (g.verbosity > 0)
		printf("Writing empty bootstrap...\n");

	/*
	 * Note: ldl labels do not contain the key field
	 */
	if (g.cdl_format) {
		/* Prepare copy with key (CDL) */
		ipl1_record	= &ipl1;
		ipl2_record	= &ipl2;
		ipl1_record_len	= sizeof(ipl1);
		ipl2_record_len	= sizeof(ipl2);
	} else {
		/* Prepare copy without key (LDL) */
		ipl1_record	= ipl1.data;
		ipl2_record	= ipl2.data;
		ipl1_record_len	= sizeof(ipl1.data);
		ipl2_record_len	= sizeof(ipl2.data);
	}

	fd = open(g.dev_node, O_RDWR);
	if (fd < 0)
		error("Unable to open device '%s': %s", g.dev_path, strerror(errno));

	if (lseek(fd, 0, SEEK_SET) != 0) {
		close(fd);
		error("lseek command 0 failed: %s", strerror(errno));
	}

	rc = write(fd, ipl1_record, ipl1_record_len);
	if (rc != ipl1_record_len) {
		close(fd);
		error("Writing the bootstrap IPL1 failed, only wrote %d bytes.", rc);
	}

	label_position = blksize;
	rc = lseek(fd, label_position, SEEK_SET);
	if (rc != label_position) {
		close(fd);
		error("lseek command to %i failed: %s", label_position, strerror(errno));
	}

	rc = write(fd, ipl2_record, ipl2_record_len);
	if (rc != ipl2_record_len) {
		close(fd);
		error("Writing the bootstrap IPL2 failed, only wrote %d bytes.", rc);
	}

	/* write VTOC */
	vtoc_init_format4_label(&f4, geo.cylinders, cylinders, heads,
				geo.sectors, blksize, g.dasd_info.dev_type);

	vtoc_init_format5_label(&f5);
	vtoc_init_format7_label(&f7);
	vtoc_set_freespace(&f4, &f5, &f7, '+', 0, FIRST_USABLE_TRK,
			   (cylinders * heads - 1), cylinders, heads);

	label_position = g.dasd_info.label_block * blksize;

	if (g.verbosity > 0)
		printf("Writing label...\n");

	rc = lseek(fd, label_position, SEEK_SET);
	if (rc != label_position) {
		close(fd);
		error("lseek command to %i failed: %s", label_position, strerror(errno));
	}

	/*
	 * Note: cdl volume labels do not contain the 'formatted_blocks' part
	 * and ldl labels do not contain the key field
	 */
	if (g.cdl_format) {
		rc = write(fd, vlabel, (sizeof(*vlabel) -
					sizeof(vlabel->formatted_blocks)));
	} else {
		vlabel->ldl_version = 0xf2; /* EBCDIC '2' */
		vlabel->formatted_blocks = cylinders * heads * geo.sectors;
		rc = write(fd, &vlabel->vollbl, (sizeof(*vlabel)
						 - sizeof(vlabel->volkey)));
	}

	if (((rc != sizeof(*vlabel) - sizeof(vlabel->formatted_blocks)) &&
	     g.cdl_format) ||
	    ((rc != (sizeof(*vlabel) - sizeof(vlabel->volkey))) &&
	     !g.cdl_format)) {
		close(fd);
		error("Error writing volume label (%d).", rc);
	}

	if (g.verbosity > 0)
		printf("Writing VTOC... ");

	label_position = (VTOC_START_CC * heads + VTOC_START_HH) *
		geo.sectors * blksize;

	rc = lseek(fd, label_position, SEEK_SET);
	if (rc != label_position) {
		close(fd);
		error("lseek command to %i failed: %s", label_position, strerror(errno));
	}

	/* write VTOC FMT4 DSCB */
	rc = write(fd, &f4, sizeof(format4_label_t));
	if (rc != sizeof(format4_label_t)) {
		close(fd);
		error("Error writing FMT4 label (%d).", rc);
	}

	label_position += blksize;

	rc = lseek(fd, label_position, SEEK_SET);
	if (rc != label_position) {
		close(fd);
		error("lseek to %i failed: %s", label_position, strerror(errno));
	}

	/* write VTOC FMT5 DSCB */
	rc = write(fd, &f5, sizeof(format5_label_t));
	if (rc != sizeof(format5_label_t)) {
		close(fd);
		error("Error writing FMT5 label (%d).", rc);
	}

	if ((cylinders * heads) > BIG_DISK_SIZE) {
		label_position += blksize;

		rc = lseek(fd, label_position, SEEK_SET);
		if (rc != label_position) {
			close(fd);
			error("lseek to %i failed: %s", label_position, strerror(errno));
		}

		/* write VTOC FMT 7 DSCB (only on big disks) */
		rc = write(fd, &f7, sizeof(format7_label_t));
		if (rc != sizeof(format7_label_t)) {
			close(fd);
			error("Error writing FMT7 label (rc=%d).", rc);
		}
	}

	fsync(fd);

	close(fd);

	if (g.verbosity > 0)
		printf("ok\n");
}

/*
 * This function will search for the beginning of an unformatted area
 * on the device. It checks selected tracks beforehand and makes sure
 * that the device is formatted to a certain extent. Otherwise the
 * process is terminated.
 */
static void dasdfmt_find_start(unsigned int cylinders, unsigned int heads,
			       format_data_t *format_params)
{
	format_check_t cdata;
	unsigned int middle;
	unsigned int left = 2;
	unsigned int right = (cylinders * heads) - 1;
	unsigned int first = left;

	check_blocksize(format_params->blksize);

	format_params->start_unit = 0;
	format_params->stop_unit = 4;
	cdata = check_track_format(format_params);

	if (cdata.result) {
		evaluate_format_error(&cdata, heads);
		error("Use --mode=full to perform a clean format.");
	}

	printf("Expansion mode active. Searching for starting position...\n");

	while (left <= right) {
		/* new track number to look at */
		middle = left + ((right - left) / 2);

		format_params->start_unit = middle;
		format_params->stop_unit = middle;
		cdata = check_track_format(format_params);
		if (cdata.blksize != format_params->blksize) {
			first = middle;
			right = middle - 1;
		} else {
			left = middle + 1;
		}
	}

	if (first == 2 && cdata.blksize == format_params->blksize)
		error("No unformatted part found, aborting.");

	printf("Done. Unformatted part starts at track %d.\n", first);

	/* return format_params with start_unit set to the correct value */
	format_params->start_unit = first;
}

static void dasdfmt_release_space(void)
{
	format_data_t r = {
		.start_unit = 0,
		.stop_unit = 0,
		.intensity = DASD_FMT_INT_ESE_FULL,
	};
	int err = 0;

	if (!g.ese || g.no_discard)
		return;

	printf("Releasing space for the entire device...\n");
	err = dasd_release_space(g.dev_node, &r);
	if (err)
		error("Could not release space: %s", strerror(err));
}

static void dasdfmt_prepare_and_format(unsigned int cylinders, unsigned int heads,
				       format_data_t *p)
{
	format_data_t temp = {
		.start_unit = 0,
		.stop_unit = 0,
		.blksize = p->blksize,
		.intensity = ((p->intensity & ~DASD_FMT_INT_FMT_NOR0)
			      | DASD_FMT_INT_INVAL)
	};
	int err;

	if (!(g.withoutprompt && g.verbosity < 1))
		printf("Formatting the device. This may take a while "
		       "(get yourself a coffee).\n");

	if (g.verbosity > 0)
		printf("Detaching the device...\n");

	disk_disable(g.dev_node);

	if (g.verbosity > 0)
		printf("Invalidate first track...\n");

	err = dasd_format_disk(filedes, &temp);
	if (err != 0)
		error("(invalidate first track) IOCTL BIODASDFMT failed: %s", strerror(err));

	/* except track 0 from standard formatting procss */
	p->start_unit = 1;

	process_tracks(cylinders, heads, p);

	if (g.verbosity > 0)
		printf("formatting tracks complete...\n");

	temp.intensity = p->intensity;

	if (g.verbosity > 0)
		printf("Revalidate first track...\n");

	err = dasd_format_disk(filedes, &temp);
	if (err != 0)
		error("(re-validate first track) IOCTL BIODASDFMT failed: %s", strerror(err));

	if (g.verbosity > 0)
		printf("Re-accessing the device...\n");

	disk_enable();
}

/*
 * This function will start the expand format process.
 */
static void dasdfmt_expand_format(unsigned int cylinders, unsigned int heads,
				  format_data_t *p)
{
	if (!(g.withoutprompt && g.verbosity < 1))
		printf("Formatting the device. This may take a while "
		       "(get yourself a coffee).\n");

	if (g.verbosity > 0)
		printf("Detaching the device...\n");

	disk_disable(g.dev_node);

	process_tracks(cylinders, heads, p);

	if (g.verbosity > 0)
		printf("Formatting tracks complete...\n");

	if (g.verbosity > 0)
		printf("Re-accessing the device...\n");

	disk_enable();
}

/*
 * This function will only format the first two tracks of a DASD.
 * The rest of the DASD is untouched and left as is.
 */
static void dasdfmt_quick_format(unsigned int cylinders, unsigned int heads,
				 format_data_t *p)
{
	format_check_t cdata = { .expect = {0}, 0 };
	format_data_t tmp = *p;
	int err;

	if (g.force) {
		printf("Skipping format check due to --force.\n");
	} else if (g.ese) {
		printf("Skipping format check due to thin-provisioned device.\n");
	} else {
		check_blocksize(p->blksize);

		printf("Checking the format of selected tracks...\n");

		/* Check device format on the first and last 3 regular tracks */
		tmp.start_unit = 2;
		tmp.stop_unit = 4;
		cdata = check_track_format(&tmp);
		if (!cdata.result) {
			tmp.start_unit = (cylinders * heads) - 3;
			tmp.stop_unit = (cylinders * heads) - 1;
			cdata = check_track_format(&tmp);
		}
		if (cdata.result) {
			evaluate_format_error(&cdata, heads);
			error("Use --mode=full to perform a clean format.");
		} else {
			printf("Done. Disk seems fine.\n");
		}
	}

	if (!(g.withoutprompt && g.verbosity < 1))
		printf("Formatting the first two tracks of the device.\n");

	/* Disable the device before we do anything */
	disk_disable(g.dev_node);

	/* Now do the actual formatting of our first two tracks */
	err = dasd_format_disk(filedes, p);
	if (err != 0)
		error("the ioctl to format the device failed: %s", strerror(err));

	/* Re-Enable the device so that we can continue working with it */
	disk_enable();
}

static void do_format_dasd(volume_label_t *vlabel, format_data_t *p,
			   unsigned int cylinders, unsigned int heads)
{
	char inp_buffer[5];
	int count, err;

	p->start_unit = 0;

	switch (mode) {
	case FULL: /* all tracks */
		p->stop_unit  = (cylinders * heads) - 1;
		break;
	case QUICK: /* just the first two */
		p->stop_unit = 1;
		break;
	case EXPAND: /* only the end of the disk */
		dasdfmt_find_start(cylinders, heads, p);
		p->stop_unit  = (cylinders * heads) - 1;
		break;
	}

	if (g.verbosity > 0 || !g.withoutprompt || g.testmode)
		dasdfmt_print_info(vlabel, cylinders, heads, p);

	count = dasd_get_host_access_count(g.dev_node);
	if (g.force_host) {
		if (count > 1) {
			printf("\n");
			warnx("Disk %s is online on OS instances in %d different LPARs.",
			      g.dev_path, count);
			warnx("Note: Your installation might include z/VM systems that are configured to");
			error("automatically vary on disks, regardless of whether they are subsequently used.\n");
		} else if (count < 0) {
			ERRMSG("\nHosts access information not available for disk %s.\n\n",
			       g.dev_path);
			return;
		}
	} else if (count > 1)
		ERRMSG("\nWARNING:\n"
		       "Disk %s is online on operating system instances in %d different LPARs.\n"
		       "Ensure that the disk is not being used by a system outside your LPAR.\n"
		       "Note: Your installation might include z/VM systems that are configured to\n"
		       "automatically vary on disks, regardless of whether they are subsequently used.\n",
		       g.dev_path, count);

	if (!g.testmode) {
		if (!g.withoutprompt) {
			printf("\n");
			if (mode != EXPAND)
				printf("--->> ATTENTION! <<---\nAll data of "
				       "that device will be lost.\n");
			printf("Type \"yes\" to continue, no will leave the "
			       "disk untouched: ");
			if (fgets(inp_buffer, sizeof(inp_buffer), stdin) == NULL)
				return;
			if (strcasecmp(inp_buffer, "yes") &&
			    strcasecmp(inp_buffer, "yes\n")) {
				printf("Omitting ioctl call (disk will "
					"NOT be formatted).\n");
				return;
			}
		}

		switch (mode) {
		case FULL:
			dasdfmt_prepare_and_format(cylinders, heads, p);
			break;
		case QUICK:
			dasdfmt_release_space();
			dasdfmt_quick_format(cylinders, heads, p);
			break;
		case EXPAND:
			dasdfmt_expand_format(cylinders, heads, p);
			break;
		}

		printf("Finished formatting the device.\n");

		if (!(g.writenolabel || mode == EXPAND))
			dasdfmt_write_labels(vlabel, cylinders, heads);

		printf("Rereading the partition table... ");
		err = dasd_reread_partition_table(g.dev_node, 5);
		if (err != 0) {
			ERRMSG("%s: error during rereading the partition "
			       "table: %s.\n", prog_name, strerror(err));
		} else {
			printf("ok\n");
		}
	}
}

static void eval_format_mode(void)
{
	if (!g.force && g.mode_specified && g.ese && mode == EXPAND) {
		warnx("WARNING: The specified device is thin-provisioned");
		warnx("Format mode 'expand' is not feasible.");
		error("Use --mode=full or --mode=quick to perform a clean format");
	}

	if (!g.mode_specified)
		mode = g.ese ? QUICK : FULL;
}

/*
 * Set prog_name to the last component of the program name to be in line with
 * err() and warn() function (and its derivatives).
 */
static void set_prog_name(char *s)
{
	char *p = strrchr(s, '/');

	if (p == NULL)
		prog_name = s;
	else
		prog_name = p + 1;
}

int main(int argc, char *argv[])
{
	volume_label_t vlabel;
	char old_volser[7];

	char str[ERR_LENGTH];
	char buf[7];

	char *blksize_param_str = NULL;
	char *reqsize_param_str = NULL;
	char *hashstep_str      = NULL;

	int rc;
	unsigned int cylinders, heads;

	/* Establish a handler for interrupt signals. */
	signal(SIGTERM, program_interrupt_signal);
	signal(SIGINT,  program_interrupt_signal);
	signal(SIGQUIT, program_interrupt_signal);

	/******************* initialization ********************/
	set_prog_name(argv[0]);

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	/* set default values */
	vtoc_volume_label_init(&vlabel);

	format_params.blksize   = DEFAULT_BLOCKSIZE;
	format_params.intensity = DASD_FMT_INT_COMPAT;

	/*************** parse parameters **********************/

	while (1) {
		rc = util_opt_getopt_long(argc, argv);

		switch (rc) {
		case 'F':
			g.force = 1;
			break;
		case 'd':
			if (strcasecmp(optarg, "cdl") == 0) {
				format_params.intensity |= DASD_FMT_INT_COMPAT;
				if (g.writenolabel) {
					error("WARNING: using the cdl "
					      "format without writing a "
					      "label doesn't make much "
					      "sense!");
				}
			} else if (strcasecmp(optarg, "ldl") == 0) {
				format_params.intensity &= ~DASD_FMT_INT_COMPAT;
			} else {
				error("%s is not a valid option!", optarg);
			}
			g.layout_specified = 1;
			break;
		case 'y':
			g.withoutprompt = 1;
			break;
		case OPT_NOZERO:
			format_params.intensity |= DASD_FMT_INT_FMT_NOR0;
			break;
		case 't':
			g.testmode = 1;
			break;
		case 'p':
			if (!(g.print_hashmarks || g.print_percentage))
				g.print_progressbar = 1;
			break;
		case 'm':
			if (!(g.print_progressbar || g.print_percentage)) {
				hashstep_str = optarg;
				g.print_hashmarks = 1;
			}
			break;
		case 'P':
			if (!(g.print_hashmarks || g.print_progressbar))
				g.print_percentage = 1;
			break;
		case 'v':
			g.verbosity = 1;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			exit(EXIT_SUCCESS);
		case 'V':
			util_prg_print_version();
			exit(EXIT_SUCCESS);
		case 'l':
			strncpy(buf, optarg, 6);
			if (check_volser(buf, 0) < 0)
				break;
			vtoc_volume_label_set_volser(&vlabel, buf);
			g.labelspec = 1;
			break;
		case 'L':
			if (format_params.intensity & DASD_FMT_INT_COMPAT) {
				error("WARNING: using the cdl format "
				      "without writing a label doesn't "
				      "make much sense!");
			}
			g.writenolabel = 1;
			break;
		case 'b':
			blksize_param_str = optarg;
			g.blksize_specified = 1;
			break;
		case 'r':
			reqsize_param_str = optarg;
			g.reqsize_specified = 1;
			break;
		case 'k':
			g.keep_volser = 1;
			break;
		case 'C':
			g.force_host = 1;
			break;
		case 'M':
			if (strcasecmp(optarg, "full") == 0)
				mode = FULL;
			else if (strcasecmp(optarg, "quick") == 0)
				mode = QUICK;
			else if (strcasecmp(optarg, "expand") == 0)
				mode = EXPAND;
			else
				error("The specified mode '%s' is invalid. "
				      "Consult the man page for more information.",
				      optarg);
			g.mode_specified = 1;
			break;
		case OPT_NODISCARD:
			g.no_discard = 1;
			break;
		case OPT_CHECK:
			g.check = 1;
			break;
		case -1:
			/* End of options string - start of devices list */
			break;
		default:
			error("Try '%s --help' for more information.", prog_name);
		}

		if (rc == -1)
			break; /* exit loop if finished */
	}

	CHECK_SPEC_MAX_ONCE(g.blksize_specified, "blocksize");
	CHECK_SPEC_MAX_ONCE(g.labelspec, "label");
	CHECK_SPEC_MAX_ONCE(g.writenolabel, "omit-label-writing flag");

	if (g.blksize_specified)
		PARSE_PARAM_INTO(format_params.blksize, blksize_param_str, 10,
				 "blocksize");
	if (g.reqsize_specified) {
		PARSE_PARAM_INTO(reqsize, reqsize_param_str, 10, "requestsize");
		if (reqsize < 1 || reqsize > 255)
			error("invalid requestsize %d specified", reqsize);
	} else {
		reqsize = DEFAULT_REQUESTSIZE;
	}

	if (g.print_hashmarks)
		PARSE_PARAM_INTO(g.hashstep, hashstep_str, 10, "hashstep");

	get_device_name(optind, argc, argv);

	rc = dasd_get_info(g.dev_node, &g.dasd_info);
	if (rc != 0)
		error("the ioctl call to retrieve device information failed: %s", strerror(rc));

	g.ese = dasd_sys_ese(g.dev_node);
	eval_format_mode();

	/* Either let the user specify the blksize or get it from the kernel */
	if (!g.blksize_specified) {
		if (!(mode == FULL ||
		      g.dasd_info.format == DASD_FORMAT_NONE) || g.check)
			get_blocksize(&format_params.blksize);
		else
			format_params = ask_user_for_blksize(format_params);
	}

	if (g.keep_volser) {
		if (g.labelspec)
			error("The -k and -l options are mutually exclusive");
		if (!(format_params.intensity & DASD_FMT_INT_COMPAT))
			error("WARNING: VOLSER cannot be kept when using the ldl format!");

		if (dasdfmt_get_volser(old_volser) == 0)
			vtoc_volume_label_set_volser(&vlabel, old_volser);
		else
			error("VOLSER not found on device %s", g.dev_path);
	}

	check_disk();

	if (check_param(str, ERR_LENGTH, &format_params) < 0)
		error("%s", str);

	set_geo(&cylinders, &heads);
	set_label(&vlabel, &format_params, cylinders);

	if (g.check)
		check_disk_format(cylinders, heads, &format_params);
	else
		do_format_dasd(&vlabel, &format_params, cylinders, heads);

	free(g.dev_path);
	free(g.dev_node);

	return 0;
}
