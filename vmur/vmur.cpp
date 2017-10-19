/*
 * vmur - Work with z/VM spool file queues (reader, punch, printer)
 *
 * Copyright IBM Corp. 2007, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <signal.h>
#include <iconv.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <ctype.h>
#include <linux/types.h>

#include "lib/vmdump.h"
#include "lib/zt_common.h"

#include "vmur.h"

/* Program name */
static char *prog_name;

/* Short description */
static const char tool_name[] =
	"vmur: Control virtual reader, punch, and printer";

/* Copyright notice */
static const char copyright_notice[] = "Copyright IBM Corp. 2007, 2017";

/*
 * Structure vmur is used to store the command line parameters and
 * other information needed at different places
 */
struct vmur {
	char  spoolid[5];
	int   spoolid_specified;
	char  spoolfile_name[9];
	int   spoolfile_name_specified;
	char  spoolfile_type[9];
	int   spoolfile_type_specified;
	char  devnode[PATH_MAX];
	int   devnode_specified;
	char  node[9];
	int   node_specified;
	char  file_name[PATH_MAX];
	int   file_name_specified;
	char  queue[4];
	int   queue_specified;
	char  user[9];
	int   user_specified;
	int   blocked_separator;
	int   blocked_padding;
	int   blocked_specified;
	int   rdr_specified;
	int   text_specified;
	int   force_specified;
	int   stdout_specified;
	int   hold_specified;
	int   convert_specified;
	enum  ur_action action;
	int   devno;
	int   ur_reclen;
	int   file_reclen;
	enum spoolfile_fmt spoolfile_fmt;
	struct sigaction sigact;
	iconv_t iconv;
	int   lock_fd;
	int   lock_attributes;
	/* ur device spool state */
	char  spool_restore_cmd[MAXCMDLEN];
	int   spool_restore_needed;
	char  spool_class;
	int   spool_class_specified;
	char  spool_dest[9];
	int   spool_dest_specified;
	char  spool_form[9];
	int   spool_form_specified;
	char  spool_dist[9];
	int   spool_dist_specified;
	char  tag_data[137];
	int   tag_specified;
} vmur_info;

/*
 * Print version information.
 */
static void print_version (void)
{
	printf("%s version %s\n", tool_name, RELEASE_STRING);
	printf("%s\n", copyright_notice);
}

/*
 * Convert string to to_upper
 */
static char *to_upper(char *str)
{
	char *ptr = str;

	while (*ptr) {
		*ptr = toupper(*ptr);
		ptr++;
	}
	return str;
}

/*
 * Convert string to valid CP spool file name
 */
static char *to_valid_cpname(char *str)
{
	if (strlen(str) > 8)
		str[8] = 0;

	while (*str) {
		if (!isprint(*str) || isspace(*str))
			*str = '_';
		str++;
	}
	return str;
}

/*
 * Convert string to valid Linux file name
 */
static char *to_valid_linux_name(char *str)
{
	while (*str) {
		if (*str == '/')
			*str = '_';
		str++;
	}
	return str;
}

/*
 * Print out usage text
 */

static char HELP_TEXT[] =
"Usage: vmur receive [OPTIONS] [SPOOLID] [FILE]\n"
"       vmur punch   [OPTIONS] [FILE]\n"
"       vmur print   [OPTIONS] [FILE]\n"
"       vmur purge   [OPTIONS] [SPOOLID]\n"
"       vmur order   [OPTIONS] [SPOOLID]\n"
"       vmur list    [OPTIONS] [SPOOLID]\n"
"\n"
"Control virtual reader, punch, and printer. Available commands are:\n"
"  * REceive: Receive spool files from reader queue\n"
"  * PUNch:   Punch a file to punch queue\n"
"  * PRint:   Print a file to printer queue\n"
"  * PURge:   Purge spool files\n"
"  * ORder:   Order spool file\n"
"  * LIst:    List spool files\n"
"\n"
"General options:\n"
"\n"
"-h, --help               Print this help, then exit.\n"
"-v, --version            Print version information, then exit.\n"
"\n"
"Options of 'receive' command:\n"
"\n"
"-d, --device             Device node of the VM virtual reader.\n"
"                         If omitted, /dev/vmrdr-0.0.000c is assumed.\n"
"-t, --text               Indicates text data causing EBCDIC to ASCII\n"
"                         conversion.\n"
"-b, --blocked            Use blocked mode.\n"
"-c, --convert            Specifies to convert VMDUMP file into a format\n"
"                         appropriate for further analysis with (l)crash.\n"
"-O, --stdout             Write spool file to stdout.\n"
"-f, --force              Overwrite files without prompt.\n"
"-H, --hold               Hold spool file in reader after receive.\n"
"-C, --class              Specify the spool class to match a reader file.\n"
"\n"
"Options for 'punch' and 'print' command:\n"
"\n"
"-d, --device             Device node of the VM virtual punch or printer.\n"
"                         If omitted, /dev/vmpun-0.0.000d or\n"
"                         /dev/vmprt-0.0.000e is assumed, respectively.\n"
"-t, --text               Indicates text data causing ASCII to EBCDIC\n"
"                         conversion.\n"
"-b, --blocked            Use blocked mode.\n"
"-r, --rdr                Indicates to transfer file from punch/printer\n"
"                         to reader.\n"
"-u, --user               Transfer file to user's reader.\n"
"                         If omitted: Your guest machine's reader.\n"
"-n, --node               Remote node to send the file to.\n"
"                         If omitted: Your local VM node.\n"
"-N, --name               Name of new spool file.\n"
"-f, --force              Convert file name to valid spool file name\n"
"                         automatically without prompt.\n"
"-C, --class              Spool class to be assigned to the created spool file.\n"
"    --form               Form to be assigned to the created spool file.\n"
"    --dest               Destination to be assigned to the created spool file.\n"
"    --dist               Distribution code for the resulting spool file.\n"
"-w, --wait               Wait for the specified device to be free rather than getting\n"
"                         vmur in use error.\n"
"-T, --tag                Up to 136 characters of information to associate with the\n"
"                         spool file. The contents and format of this data are\n"
"                         flexible; they are the responsibility of the file originator\n"
"                         and the end user.\n"
"\n"
"Options for 'purge' command:\n"
"\n"
"-f, --force              Purge without prompt.\n"
"\n"
"Options for 'order', 'list', and 'purge' commands:\n"
"\n"
"-q, --queue              Target queue for command. Possible queues are:\n"
"                         'rdr' (default), 'pun' and 'prt'.\n";

static void usage(void)
{
	printf("%s", HELP_TEXT);
}

/*
 * Signal handler
 */
static void set_signal_handler(struct vmur *info,
			       void (*handler) (int, siginfo_t *, void *))
{
	info->sigact.sa_flags = (SA_NODEFER | SA_SIGINFO | SA_RESETHAND);
	info->sigact.sa_sigaction = handler;

	if (sigemptyset(&info->sigact.sa_mask) < 0)
		goto fail;
	if (sigaction(SIGINT, &info->sigact, NULL) < 0)
		goto fail;
	if (sigaction(SIGTERM, &info->sigact, NULL) < 0)
		goto fail;

	return;
fail:
	ERR_EXIT("Could not initialize signal handler (errno = %i)\n", errno);
}

/*
 * Read at most COUNT bytes from FD into memory at location BUF.
 * Return number of bytes read on success, -1 on error.
 */
static ssize_t read_buf(int fd, char *buf, ssize_t count)
{
	ssize_t rc, len;

	for (len = 0; len < count; len += rc) {
		rc = read(fd, &buf[len], count - len);
		if (rc == -1)
			return -1;
		if (rc == 0)
			break;
	}
	return len;
}

/*
 * Strip leading CP header from error message
 */
static void strip_cperr(char *buf)
{
	unsigned int i;

	for (i = 0; i < strlen(buf) - CP_PREFIX_LEN; i++) {
		if (strncmp(buf + i, "HCP", 3) == 0) {
			int offs = i + CP_PREFIX_LEN;
			memmove(buf, buf + offs, strlen(buf) - offs);
			/* terminate string and remove newline */
			buf[strlen(buf) - offs - 1] = 0;
			return;
		}
	}
}

/*
 * Handle CP error message and exit
 */
static void cperr_exit(char *cpcmd, int cprc, char *buf)
{
	if (strlen(buf) <= CP_PREFIX_LEN)
		ERR_EXIT("CP command '%s' failed with rc=%i\n", cpcmd, cprc);

	strip_cperr(buf);
	ERR_EXIT("%s\n", buf);
}

static void _cpcmd(char *cpcmd, char **resp, int *rc, int retry, int upper)
{
	int fd, len, cprc, bufsize = VMCP_BUFSIZE;
	char *buf;
	char cmd[MAXCMDLEN];

	strcpy(cmd, cpcmd);
	if (upper)
		to_upper(cmd);

	fd = open(VMCP_DEVICE_NODE, O_RDWR);
	if (fd == -1)
		ERR_EXIT("Could not issue CP command: \"%s\"\n"
			 "Ensure that vmcp kernel module is loaded!\n", cmd);

	do {
		if (ioctl(fd, VMCP_SETBUF, &bufsize) == -1)
			goto fail;

		if (write(fd, cmd, strlen(cmd)) == -1)
			goto fail;

		if (ioctl(fd, VMCP_GETCODE, &cprc) == -1)
			goto fail;

		if (ioctl(fd, VMCP_GETSIZE, &len) == -1)
			goto fail;

		if (len <= bufsize)
			break;
		else if (retry)
			bufsize = len;
		else
			ERR_EXIT("Not enough buffer space (%i/%i) for CP "
				 "command '%s'.\nSorry, please issue command "
				 "on your 3270 console!\n", len, bufsize, cmd);
	} while (1);

	buf = (char *) malloc(len + 1);
	if (!buf)
		ERR_EXIT("Out of memory for CP command '%s'\n", cmd);

	memset(buf, 0, len + 1);
	if (read_buf(fd, buf, len) == -1)
		goto fail;

	if (rc == NULL) {
		if (cprc != 0) {
			/* caller wants us to handle the error */
			cperr_exit(cmd, cprc, buf);
		}
	} else {
		*rc = cprc;
	}

	if (resp)
		*resp = buf;
	else
		free(buf);
	close(fd);
	return;

fail:
	ERR_EXIT("CP command '%s' failed.\n", cmd);
}

/*
 * Issue   CP command:
 * @cpcmd: CP command to be issued.
 * @resp:  CP command response on success, an error message on error.
 * @rc:    CP return code.
 * @retry: retry = 1 -> CP command can be retried.
 * This function converts the command string to uppercase.
 */
static void cpcmd(char *cpcmd, char **resp, int *rc, int retry)
{
	_cpcmd(cpcmd, resp, rc, retry, 1);
}

/*
 * Issue   CP command:
 * @cpcmd: CP command to be issued.
 * @resp:  CP command response on success, an error message on error.
 * @rc:    CP return code.
 * @retry: retry = 1 -> CP command can be retried.
 * This function does not convert the command string to uppercase.
 */
static void cpcmd_cs(char *cpcmd, char **resp, int *rc, int retry)
{
	_cpcmd(cpcmd, resp, rc, retry, 0);
}

/*
 * Extract minor from sysfs file
 */
static int get_minor(char *path)
{
	FILE *fd;
	char buf[20];
	int major, minor, rc;

	fd = fopen(path, "r");
	if (!fd)
		ERR_EXIT("Could not open %s (err = %i)\n", path, errno);
	rc = fread(buf, sizeof(buf), 1, fd);
	if (rc == -1)
		ERR_EXIT("Could not read %s (err = %i)\n", path, errno);
	fclose(fd);

	if (sscanf(buf, "%i:%i", &major, &minor) != 2)
		ERR_EXIT("Malformed content of %s: %s\n", path, buf);

	return minor;
}

/*
 * Find device number of ur device
 */
static int get_ur_devno(int minor)
{
	struct dirent *direntp;
	char dev_file[PATH_MAX];
	DIR *fd;
	char bus_id[9] = {};
	int devno;

	errno = 0;
	fd = opendir(SYSFS_CLASS_DIR);
	if (!fd)
		ERR_EXIT("Could not open %s (err = %i)\n", SYSFS_CLASS_DIR,
			 errno);
	while ((direntp = readdir(fd))) {
		if (strcmp(direntp->d_name, ".") == 0)
			continue;
		if (strcmp(direntp->d_name, "..") == 0)
			continue;
		sprintf(dev_file, "%s/%s/dev", SYSFS_CLASS_DIR,
			direntp->d_name);
		if (get_minor(dev_file) == minor) {
			/* extract device id from <vmxxx-0.0.yyyy> */
			memcpy(bus_id, &direntp->d_name[6], 8);
			goto found;
		}
	};
	if (errno != 0)
		ERR_EXIT("Could not read %s (err = %i)\n",
			    SYSFS_CLASS_DIR, errno);
	else
		ERR_EXIT("Device is not online\n");
found:
	if (sscanf(bus_id, "0.0.%x", &devno) != 1)
		ERR_EXIT("Could not extract device number from %s\n",
			 direntp->d_name);
	closedir(fd);
	return devno;
}

/*
 * Extract major/minor from device node
 */
static dev_t get_node_dev(char *devnode)
{
	struct stat stat_info;

	if (stat(devnode, &stat_info)) {
		ERR("Unable to get status for '%s': %s\n", devnode,
		    strerror(errno));
		ERR_EXIT("Please check if device is online!\n");
	}

	return stat_info.st_rdev;
}

/*
 * Extract major of vmur driver
 */
static int get_driver_major(unsigned long *major)
{
	FILE *fh;
	char string[PROC_DEVICES_FILE_WIDTH];
	char last_string[PROC_DEVICES_FILE_WIDTH];

	fh = fopen(PROC_DEVICES_FILE, "r");
	if (!fh) {
		ERR("WARNING: Cannot check for vmur in file %s.\n%s\n",
		    PROC_DEVICES_FILE, strerror(errno));
		return -1; /* check not possible, just continue */
	}
	while (fscanf(fh, "%s", string) != EOF) {
		if (strcmp(string, "vmur") == 0) {
			fclose(fh);
			*major = atoi(last_string);
			return 0;
		} else {
			strcpy(last_string, string);
		}
	}
	fclose(fh);
	ERR_EXIT("Unit record device driver not loaded.\n");
}

/*
 * Copy printable characters
 */
static void strncpy_graph(char *dest, const char *src, size_t len)
{
	size_t n;

	for (n = 0; n < len; n++) {
		if (!isgraph(src[n]))
			break;
		dest[n] = src[n];
	}
	dest[n] = '\0';
}

/*
 * Create CP command to restore spooling options
 */
static void save_spool_options(struct vmur *info)
{
	char cmd[MAXCMDLEN], *resp;
	char cl, value[9], *tmp;
	int n;

	/* Retrieve spooling options for ur device */
	sprintf(cmd, "QUERY VIRTUAL %X", info->devno);
	cpcmd(cmd, &resp, NULL, 0);

	/* Prepare CP spool restore command */
	n = sprintf(info->spool_restore_cmd, "SPOOL %X NOCONT", info->devno);

	/* Save the CLASS value if required */
	if (info->spool_class_specified) {
		cl = resp[13];
		n += sprintf(info->spool_restore_cmd + n, " CL %c", cl);
	}

	/* Save FORM value if required */
	if (info->spool_form_specified) {
		tmp = strstr(resp, "FORM ");
		if (tmp == NULL)
			ERR_EXIT("Could not retrieve value for the FORM "
				 "spooling option\n");
		strncpy_graph(value, tmp + 5, 8);
		n += sprintf(info->spool_restore_cmd + n, " FORM %s", value);
	}

	/* Save DEST value if required */
	if (info->spool_dest_specified) {
		tmp = strstr(resp, "DEST ");
		if (tmp == NULL)
			ERR_EXIT("Could not retrieve value for the DEST "
				 "spooling option\n");
		strncpy_graph(value, tmp + 5, 8);
		n += sprintf(info->spool_restore_cmd + n, " DEST %s", value);
	}

	/* Save DIST value if required */
	if (info->spool_dist_specified) {
		tmp = strstr(resp, "DIST ");
		if (tmp == NULL)
			ERR_EXIT("Could not retrieve value for the DIST "
				 "spooling option\n");
		strncpy_graph(value, tmp + 5, 8);
		n += sprintf(info->spool_restore_cmd + n, " DIST %s", value);
	}

	free(resp);
	++info->spool_restore_needed;
}

/*
 * Restore saved spooling options for a ur device
 */
static void restore_spool_options(struct vmur *info)
{
	if (!info->spool_restore_needed)
		return;

	cpcmd(info->spool_restore_cmd, NULL, NULL, 0);
	--info->spool_restore_needed;
}

/*
 * Returns non-zero if spool options have to be saved, changed, and restored,
 * otherwise zero is returned.
 */
static int require_spool_setup(struct vmur *info)
{
	return !!(info->spool_class_specified ||
		  info->spool_form_specified ||
		  info->spool_dest_specified ||
		  info->spool_dist_specified ||
		  info->spool_tag_specified);
}

/*
 * Setup spooling options for a ur device
 */
static void setup_spool_options(struct vmur *info)
{
	char cmd[MAXCMDLEN];
	int n, rc;

	/*
	 * Check if spool options must be changed.  If so, save the current
	 * spool option values and restore them at program exit.
	 */
	if (!require_spool_setup(info))
		return;

	/* Save spool options */
	save_spool_options(info);

	/* Change spool options */
	n = sprintf(cmd, "SPOOL %X NOCONT", info->devno);
	if (info->spool_class_specified)
		n += sprintf(cmd + n, " CLASS %c", info->spool_class);
	if (info->spool_form_specified)
		n += sprintf(cmd + n, " FORM %s", info->spool_form);
	if (info->spool_dest_specified)
		n += sprintf(cmd + n, " DEST %s", info->spool_dest);
	if (info->spool_dist_specified)
		n += sprintf(cmd + n, " DIST %s", info->spool_dist);

	cpcmd(cmd, NULL, &rc, 0);
	if (rc)
		ERR_EXIT("Could not set spooling options (rc=%i)\n", rc);
}

/*
 * Setup and check ur device
 */
static void setup_ur_device(struct vmur *info)
{
	unsigned long driver_major;
	dev_t node_dev;
	int rc;

	/*
	 * Few vmur commands do not require a particular device node and,
	 * therefore, no device setup is required.
	 */
	if (!strlen(info->devnode))
		return;

	node_dev = get_node_dev(info->devnode);
	rc = get_driver_major(&driver_major);
	if ((rc == 0) && (driver_major != major(node_dev)))
		ERR_EXIT("'%s' is not a unit record device.\n",
			 info->devnode);
	info->devno = get_ur_devno(minor(node_dev));
}

/*
 * initialize the vmur info structure
 */
static void init_info(struct vmur *info)
{
	memset(info, 0, sizeof(struct vmur));
	strcpy(info->queue, "rdr");
	info->lock_fd = -1;
	info->lock_attributes = LOCK_EX | LOCK_NB;
}

/*
 * set positional spoolid parameter
 */
static void set_spoolid(struct vmur *info, char **argv, int argc, int optind,
			int mandatory)
{
	char *str;

	if (argc <= optind) {
		if (mandatory)
			ERR_EXIT("No spool id specified.\n");
		else
			return;
	}

	if ((argc > optind + 1) && (info->action != RECEIVE))
		ERR_EXIT("More than one spool id specified.\n");

	str = argv[optind];

	if (strlen(str) > 4)
		goto invalid;

	while (*str) {
		if (!isdigit(*str))
			goto invalid;
		str++;
	}

	strcpy(info->spoolid, argv[optind]);
	++info->spoolid_specified;
	return;

invalid:
	ERR_EXIT("Spoolid must be a decimal number in range 0-9999\n");
}

/*
 * set positional file parameter
 */
static void set_file(struct vmur *info, char **argv, int argc, int optind)
{
	if (argc <= optind)
		return;

	if (argc > optind + 1)
		ERR_EXIT("More than one file specified.\n");

	strncpy(info->file_name, argv[optind], sizeof(info->file_name) - 1);
	++info->file_name_specified;
}

/*
 * Set queue: rdr, pun or prt
 */
static void set_queue(struct vmur *info, char *queue)
{
	if (strcmp(queue, "rdr") == 0)
		strcpy(info->queue, "rdr");
	else if (strcmp(queue, "pun") == 0)
		strcpy(info->queue, "pun");
	else if (strcmp(queue, "prt") == 0)
		strcpy(info->queue, "prt");
	else
		ERR_EXIT("Invalid queue: %s\n", queue);
	return;
}

/*
 * Set block mode and the separator and padding byte
 */
static void set_blocked(struct vmur *info, char *blocked)
{
	if (sscanf(blocked, "0x%x,0x%x", &info->blocked_separator,
		   &info->blocked_padding) != 2)
		goto fail;
	if (info->blocked_separator > 255)
		goto fail;
	if (info->blocked_padding > 255)
		goto fail;
	++info->blocked_specified;
	return;
fail:
	ERR_EXIT("Invalid blocked parameter. It must have the format "
		 "'0xSS,0xPP'.\n");
}

/*
 * Set spool class value
 */
static void set_spool_class(struct vmur *info, const char *val, int is_rdr)
{
	char cl = val[0];

	if (strlen(val) > 1 || (!isalnum(cl) && cl != '*'))
		ERR_EXIT("Class must be one of A through Z, 0 through 9, "
			 "or an asterisk (*)\n");
	if (cl == '*' && !is_rdr)
		ERR_EXIT("The asterisk (*) class is only valid for readers\n");
	info->spool_class = toupper(cl);
	++info->spool_class_specified;
}

/*
 * Parse the command line: General options
 */
static void check_std_opts(int opt)
{
	switch (opt) {
	case 'v':
		print_version();
		exit(0);
	case 'h':
		usage();
		exit(0);
	}
}

static void std_usage_exit(void)
{
	fprintf(stderr, "Try '%s --help' for more information.\n", prog_name);
	exit(1);
}

/*
 * Parse the command line: Receive command
 */
static void parse_opts_receive(struct vmur *info, int argc, char *argv[])
{
	int opt, index;
	static struct option long_options[] = {
		{ "version",     no_argument,       NULL, 'v'},
		{ "help",        no_argument,       NULL, 'h'},
		{ "text",        no_argument,       NULL, 't'},
		{ "stdout",      no_argument,       NULL, 'O'},
		{ "force",       no_argument,       NULL, 'f'},
		{ "hold",        no_argument,       NULL, 'H'},
		{ "convert",     no_argument,       NULL, 'c'},
		{ "device",      required_argument, NULL, 'd'},
		{ "blocked",     required_argument, NULL, 'b'},
		{ "class",       required_argument, NULL, 'C'},
		{ 0,             0,                 0,    0  }
	};
	static const char option_string[] = "vhtOfHcd:b:C:";

	strcpy(info->devnode, VMRDR_DEVICE_NODE);
	while (1) {
		opt = getopt_long(argc, argv, option_string,
				  long_options, &index);
		if (opt == -1)
			break;
		check_std_opts(opt);
		switch (opt) {
		case 't':
			++info->text_specified;
			break;
		case 'd':
			++info->devnode_specified;
			strncpy(info->devnode, optarg,
				sizeof(info->devnode) - 1);
			break;
		case 'O':
			++info->stdout_specified;
			break;
		case 'b':
			set_blocked(info, optarg);
			break;
		case 'f':
			++info->force_specified;
			break;
		case 'H':
			++info->hold_specified;
			break;
		case 'c':
			++info->convert_specified;
			break;
		case 'C':
			set_spool_class(info, optarg, 1);
			break;
		default:
			std_usage_exit();
		}
	}

	set_spoolid(info, argv, argc, optind + 1, 1);
	set_file(info, argv, argc, optind + 2);

	CHECK_SPEC_MAX(info->text_specified, 1, "text");
	CHECK_SPEC_MAX(info->devnode_specified, 1, "devnode");
	CHECK_SPEC_MAX(info->file_name_specified, 1, "file");
	CHECK_SPEC_MAX(info->blocked_specified, 1, "blocked");
	CHECK_SPEC_MAX(info->force_specified, 1, "force");
	CHECK_SPEC_MAX(info->hold_specified, 1, "hold");
	CHECK_SPEC_MAX(info->stdout_specified, 1, "stdout");
	CHECK_SPEC_MAX(info->convert_specified, 1, "convert");
	CHECK_SPEC_MAX(info->spool_class_specified, 1, "class");

	if (info->stdout_specified && info->file_name_specified)
		ERR_EXIT("File name not allowed, when --stdout specified!\n");
	if (info->blocked_specified + info->text_specified +
	    info->convert_specified > 1)
		ERR_EXIT("Conflicting options: -b, -t and -c are mutually "
			 "exclusive.\n");
	if (!info->spool_class_specified)
		set_spool_class(info, "*", 1);
}

/*
 * Validate VM userID
 */
static int invalid_userid(char *operand)
{
	if (strlen(operand) > 8)
		return 1;
	while (*operand) {
		if (!isalnum(*operand) &&
		    (strchr("@#$_-", *operand) == NULL))
			return 1;
		operand++;
	}
	return 0;
}

/*
 * Validate CP command operand such as nodeID or name/type
 */
static int invalid_operand(char *operand)
{
	if (strlen(operand) > 8)
		return 1;
	while (*operand) {
		if (!isprint(*operand) || isspace(*operand))
			return 1;
		operand++;
	}
	return 0;
}

/*
 * Check whether user is in the CP directory
 */
static int check_local_user(const char *user)
{
	char cmd[MAXCMDLEN];
	int cprc;

	strcpy(cmd, "LINK ");
	strcat(cmd, user);
	cpcmd(cmd, NULL, &cprc, 0);
	if ((cprc == 53)	/* user not in CP directory */
	    || (cprc == 20))	/* Userid missing or invalid */
		return 1;
	else
		return 0;
}

/*
 * Set spool file name/type in vmur structure and validate name/type
 */
static void set_spoolfile_name(struct vmur *info, char *name)
{
	char spoolfile_name[PATH_MAX], spoolfile_type[PATH_MAX] = {};
	int i, flag = 0;

	strcpy(spoolfile_name, name);

	if (strlen(spoolfile_name) == 0)
		ERR_EXIT("Empty spool file name is invalid\n");

	/* check for period delimiting name from type */
	if (spoolfile_name[strlen(spoolfile_name) - 1] == '.')
		flag = 1; /* name/type string ends with period */
	for (i = strlen(spoolfile_name) - 1; i > 0; i--) {
		if (spoolfile_name[i] == '.') {
			if (flag && (spoolfile_name[i-1] == '.'))
				continue;
			else
				break;
		}
	}
	if ((i > 0) && (i < (int) strlen(spoolfile_name) - 1)) {
		strcpy(spoolfile_type, spoolfile_name + i + 1);
		spoolfile_name[i] = 0;
		++info->spoolfile_type_specified;
	}

	if (info->force_specified) {
		/* adjust spool file name, in order to have a valid one */
		to_valid_cpname(spoolfile_name);
		if (info->spoolfile_type_specified)
			to_valid_cpname(spoolfile_type);
		goto out;
	}
	if (invalid_operand(spoolfile_name) || invalid_operand(spoolfile_type))
		goto invalid;
out:
	strcpy(info->spoolfile_name, spoolfile_name),
	++info->spoolfile_name_specified;
	if (info->spoolfile_type_specified)
		strcpy(info->spoolfile_type, spoolfile_type);
	return;

invalid:
	ERR_EXIT("Malformed spool file name: %s\n"
		 "Specify --force, if the name should be converted "
		 "automatically.\n", name);
}

/*
 * Parse the command line: punch command
 */
static void parse_opts_punch_print(struct vmur *info, int argc, char *argv[])
{
	int opt, index;
	char *spoolfile_name = NULL;
	static struct option long_options[] = {
		{ "version",     no_argument,       NULL, 'v'},
		{ "help",        no_argument,       NULL, 'h'},
		{ "text",        no_argument,       NULL, 't'},
		{ "rdr",         no_argument,       NULL, 'r'},
		{ "force",       no_argument,       NULL, 'f'},
		{ "wait",	 no_argument,	    NULL, 'w'},
		{ "user",        required_argument, NULL, 'u'},
		{ "node",        required_argument, NULL, 'n'},
		{ "device",      required_argument, NULL, 'd'},
		{ "blocked",     required_argument, NULL, 'b'},
		{ "name",        required_argument, NULL, 'N'},
		{ "class",       required_argument, NULL, 'C'},
		{ "dest",        required_argument, NULL, 'D'},
		{ "form",        required_argument, NULL, 'F'},
		{ "dist",	 required_argument, NULL, 'I'},
		{ "tag",         required_argument, NULL, 'T'},
		{ 0,             0,                 0,    0  }
	};
	static const char option_string[] = "vhtrfwu:n:d:b:N:C:T:";

	if (info->action == PUNCH) {
		strcpy(info->devnode, VMPUN_DEVICE_NODE);
		info->ur_reclen = VMPUN_RECLEN;
	} else {
		strcpy(info->devnode, VMPRT_DEVICE_NODE);
		info->ur_reclen = VMPRT_RECLEN;
	}

	while (1) {
		opt = getopt_long(argc, argv, option_string,
				  long_options, &index);
		if (opt == -1)
			break;
		check_std_opts(opt);
		switch (opt) {
		case 'd':
			++info->devnode_specified;
			strcpy(info->devnode, optarg);
			break;
		case 'N':
			++info->spoolfile_name_specified;
			spoolfile_name = optarg;
			break;
		case 'r':
			++info->rdr_specified;
			break;
		case 'f':
			++info->force_specified;
			break;
		case 't':
			++info->text_specified;
			break;
		case 'u':
			++info->user_specified;
			if (invalid_userid(optarg))
				ERR_EXIT("Invalid userid: %s\n", optarg);
			else
				strcpy(info->user, optarg);
			break;
		case 'b':
			set_blocked(info, optarg);
			break;
		case 'n':
			++info->node_specified;
			if (invalid_operand(optarg))
				ERR_EXIT("Invalid node specified.\n");
			else
				strcpy(info->node, optarg);
			break;
		case 'C':
			set_spool_class(info, optarg, 0);
			break;
		case 'D':
			++info->spool_dest_specified;
			if (invalid_operand(optarg))
				ERR_EXIT("Invalid destination: %s\n", optarg);
			else
				strcpy(info->spool_dest, optarg);
			break;
		case 'F':
			++info->spool_form_specified;
			if (invalid_operand(optarg))
				ERR_EXIT("Invalid form: %s\n", optarg);
			else
				strcpy(info->spool_form, optarg);
			break;
		case 'I':
			++info->spool_dist_specified;
			if (invalid_operand(optarg))
				ERR_EXIT("Invalid distribution code: %s\n", optarg);
			else
				strcpy(info->spool_dist, optarg);
			break;
		case 'w':
                        info->lock_attributes &= ~LOCK_NB;
			break;	
		case 'T':
			++info->spool_tag_specified;
			strncpy_graph(info->tag_data,optarg,sizeof(info->tag_data));			
                        break;
		default:
			std_usage_exit();
		}
	}

	CHECK_SPEC_MAX(info->rdr_specified, 1, "rdr");
	CHECK_SPEC_MAX(info->force_specified, 1, "force");
	CHECK_SPEC_MAX(info->user_specified, 1, "user");
	CHECK_SPEC_MAX(info->file_name_specified, 1, "file");
	CHECK_SPEC_MAX(info->spoolfile_name_specified, 1, "name");
	CHECK_SPEC_MAX(info->user_specified, 1, "user");
	CHECK_SPEC_MAX(info->node_specified, 1, "node");
	CHECK_SPEC_MAX(info->blocked_specified, 1, "blocked");
	CHECK_SPEC_MAX(info->spool_class_specified, 1, "class");
	CHECK_SPEC_MAX(info->spool_form_specified, 1, "form");
	CHECK_SPEC_MAX(info->spool_dest_specified, 1, "dest");
	CHECK_SPEC_MAX(info->spool_dist_specified, 1, "dist");
	CHECK_SPEC_MAX(info->tag_specified, 1, "tag");

	if (info->user_specified && !info->rdr_specified)
		ERR_EXIT("--user without --rdr specified\n");
	if (info->node_specified && !info->user_specified)
		ERR_EXIT("--node without --user specified\n");
	if ((info->user_specified && !info->node_specified)
	    && check_local_user(info->user))
		ERR_EXIT("Invalid userid: %s\n", info->user);
	if (info->node_specified && check_local_user(RSCS_USERID))
		ERR_EXIT("Invalid RSCS userid: %s\n", info->node);
	if (info->blocked_specified && info->text_specified)
		ERR_EXIT("Conflicting options: -b together with -t "
			 "specified\n");
	if (info->tag_specified && info->node_specified)
		ERR_EXIT("Conflicting options: --tag with --node specified\n");

	set_file(info, argv, argc, optind + 1);

	if (info->spoolfile_name_specified)
		set_spoolfile_name(info, spoolfile_name);
	else if (info->file_name_specified)
		set_spoolfile_name(info, basename(info->file_name));
	else
		ERR_EXIT("No name for spool file specified!\n");
}

/*
 * Parse the command line: Purge command
 */
static void parse_opts_purge(struct vmur *info, int argc, char *argv[])
{
	int opt, index;
	static struct option long_options[] = {
		{ "version",     no_argument,       NULL, 'v'},
		{ "help",        no_argument,       NULL, 'h'},
		{ "force",       no_argument,       NULL, 'f'},
		{ "queue",       no_argument,       NULL, 'q'},
		{ "class",       required_argument, NULL, 'C'},
		{ "dest",        required_argument, NULL, 'D'},
		{ "form",        required_argument, NULL, 'F'},
		{ 0,             0,                 0,    0  }
	};
	static const char option_string[] = "fvhq:C:";

	while (1) {
		opt = getopt_long(argc, argv, option_string,
				  long_options, &index);
		if (opt == -1)
			break;
		check_std_opts(opt);
		switch (opt) {
		case 'f':
			++info->force_specified;
			break;
		case 'q':
			++info->queue_specified;
			set_queue(info, optarg);
			break;
		case 'C':
			set_spool_class(info, optarg, 0);
			break;
		case 'D':
			++info->spool_dest_specified;
			if (invalid_operand(optarg))
				ERR_EXIT("Invalid destination: %s\n", optarg);
			else
				strcpy(info->spool_dest, optarg);
			break;
		case 'F':
			++info->spool_form_specified;
			if (invalid_operand(optarg))
				ERR_EXIT("Invalid form: %s\n", optarg);
			else
				strcpy(info->spool_form, optarg);
			break;
		default:
			std_usage_exit();
		}
	}
	CHECK_SPEC_MAX(info->force_specified, 1, "force");
	CHECK_SPEC_MAX(info->queue_specified, 1, "queue");
	CHECK_SPEC_MAX(info->spool_class_specified, 1, "class");
	CHECK_SPEC_MAX(info->spool_form_specified, 1, "form");
	CHECK_SPEC_MAX(info->spool_dest_specified, 1, "dest");
	set_spoolid(info, argv, argc, optind + 1, 0);
}

/*
 * Parse the command line: Order command
 */
static void parse_opts_order(struct vmur *info, int argc, char *argv[])
{
	int opt, index;
	static struct option long_options[] = {
		{ "version",     no_argument,       NULL, 'v'},
		{ "help",        no_argument,       NULL, 'h'},
		{ "queue",       required_argument, NULL, 'q'},
		{ 0,             0,                 0,    0  }
	};
	static const char option_string[] = "vhq:";

	while (1) {
		opt = getopt_long(argc, argv, option_string,
				  long_options, &index);
		if (opt == -1)
			break;
		check_std_opts(opt);
		switch (opt) {
		case 'q':
			++info->queue_specified;
			set_queue(info, optarg);
			break;
		default:
			std_usage_exit();
		}
	}
	CHECK_SPEC_MAX(info->queue_specified, 1, "queue");
	set_spoolid(info, argv, argc, optind + 1, 1);
}

/*
 * Parse the command line: List command
 */
static void parse_opts_list(struct vmur *info, int argc, char *argv[])
{
	int opt, index;
	static struct option long_options[] = {
		{ "version",     no_argument,       NULL, 'v'},
		{ "help",        no_argument,       NULL, 'h'},
		{ "queue",       required_argument, NULL, 'q'},
		{ 0,             0,                 0,    0  }
	};
	static const char option_string[] = "vhq:";

	while (1) {
		opt = getopt_long(argc, argv, option_string,
				  long_options, &index);
		if (opt == -1)
			break;
		check_std_opts(opt);
		switch (opt) {
		case 'q':
			++info->queue_specified;
			set_queue(info, optarg);
			break;
		default:
			std_usage_exit();
		}
	}
	CHECK_SPEC_MAX(info->queue_specified, 1, "queue");
	set_spoolid(info, argv, argc, optind + 1, 0);
}

/*
 * Parse the command line: Default options
 */
static void parse_opts_default(int argc, char *argv[])
{
	int opt, index;
	static struct option long_options[] = {
		{ "version",     no_argument,       NULL, 'v'},
		{ "help",        no_argument,       NULL, 'h'},
		{ 0,             0,                 0,    0  }
	};
	static const char option_string[] = "vh";

	while (1) {
		opt = getopt_long(argc, argv, option_string,
				  long_options, &index);
		if (opt == -1)
			break;
		check_std_opts(opt);
		std_usage_exit();
	}
}

/*
 * Parse action strings
 */
static int is_action(enum ur_action action, char *str)
{
	char action_str[80] = {};

	if (strlen(str) < ur_action_prefix_len[action])
		return 0;
	if (strlen(str) > strlen(ur_action_str[action]))
		return 0;

	strncpy(action_str, ur_action_str[action], strlen(str));

	if (strcasecmp(str, action_str) != 0)
		return 0;

	return 1;
}

/*
 * Get action string and set action field in info structure
 */
static int set_action(struct vmur *info, char *str)
{
	int action;

	for (action = 0; action < LAST; action++) {
		if (is_action((enum ur_action) action, str)) {
			info->action = (enum ur_action) action;
			return 0;
		}
	}
	return -EINVAL;
}

/*
 * The toplevel parameter parsing function
 */
static void parse_opts(struct vmur *info, int argc, char *argv[])
{
	if (argc == 1)
		ERR_EXIT("Missing command\n");

	if (set_action(info, argv[1])) {
		parse_opts_default(argc, argv);
		ERR("Unknown command '%s'\n", argv[1]);
		std_usage_exit();
	}

	switch (info->action) {
	case RECEIVE:
		return parse_opts_receive(info, argc, argv);
	case PUNCH:
		return parse_opts_punch_print(info, argc, argv);
	case PRINT:
		return parse_opts_punch_print(info, argc, argv);
	case PURGE:
		return parse_opts_purge(info, argc, argv);
	case ORDER:
		return parse_opts_order(info, argc, argv);
	case LIST:
		return parse_opts_list(info, argc, argv);
	default:
		ERR_EXIT("Internal error. Unknown action: %i\n", info->action);
	}
}

/*
 * Check if spool file has hold state "NONE"
 */
static void check_hold_state(char *spoolid)
{
	char cmd[MAXCMDLEN];
	char *response;

	sprintf(cmd, "QUERY READER * %s ALL SHORTDATE", spoolid);
	cpcmd(cmd, &response, 0, 0);
	response[114] = 0;
	if (strcmp(&response[110], "NONE") != 0)
		ERR_EXIT("Could not receive spool file %s: hold state = %s\n",
			 spoolid, &response[110]);
	free(response);
}

/*
 * Issue CP command ORDER RDR <spoolid>.
 * If ORDER fails, the CP command response is as follows:
 *      NO FILES ORDERED
 * HCPxxxnnnt <message text>
 * If ORDER returns successfully, CP command CHANGE RDR <spoolid> NOHOLD
 * is issued.
 */
static void order_change_reader_file(struct vmur *info)
{
	char cmd[MAXCMDLEN];

	sprintf(cmd, "ORDER * READER %s", info->spoolid);
	cpcmd(cmd, NULL, NULL, 0);
	sprintf(cmd, "CHANGE * READER %s NOHOLD", info->spoolid);
	cpcmd(cmd, NULL, NULL, 0);

	check_hold_state(info->spoolid);
}

/*
 * Issue CP command CLOSE RDR
 */
static void close_reader(struct vmur *info, const char *hold)
{
	char cmd[MAXCMDLEN];

	sprintf(cmd, "CLOSE %X %s", info->devno, hold);
	cpcmd(cmd, NULL, NULL, 0);
}

/*
 * strip leading and trailing blanks
 */
static char *strstrip(char *s)
{
	size_t size;
	char *end;

	size = strlen(s);

	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

	while (*s && isspace(*s))
		s++;

	return s;
}

/*
 *  Check whether reader can handle class of reader spool file
 */
static int check_class(struct vmur *info)
{
	char cmd[MAXCMDLEN];
	char device_class, file_class;
	char *buf;

	sprintf(cmd, "QUERY VIRTUAL %X", info->devno);
	cpcmd(cmd, &buf, NULL, 0);
	device_class = buf[13];
	free(buf);
	if (device_class == '*') /* reader device can handle any class */
		return 0;

	sprintf(cmd, "QUERY RDR * %s ALL SHORTDATE", info->spoolid);
	cpcmd(cmd, &buf, NULL, 0);
	file_class = buf[91];
	free(buf);
	if (file_class != device_class)
		return 1;
	return 0;
}

/*
 * Get file name for spoolid from reader
 */
static int get_filename_from_reader(struct vmur *info)
{
	char cmd[MAXCMDLEN];
	char name[9] = {0};
	char type[9] = {0};
	char *buf;

	sprintf(cmd, "QUERY RDR * %s ALL SHORTDATE", info->spoolid);
	cpcmd(cmd, &buf, NULL, 0);
	memcpy(name, &buf[130], 8);
	strstrip(name);
	memcpy(type, &buf[140], 8);
	strstrip(type);
	free(buf);
	if (strlen(name) == 0) {
		ERR("Please specify name to receive "
		    "unnamed spool file: %s\n", info->spoolid);
		return 1;
	}

	to_valid_linux_name(name);
	to_valid_linux_name(type);

	if (strlen(type) == 0)
		strcpy(info->file_name, name);
	else
		sprintf(info->file_name, "%s.%s", name, type);
	info->file_name_specified = 1;
	return 0;
}

/*
 * Serialize access to unit record devices and their related spool file queues:
 * open lock file and apply lock
 */
static void acquire_lock(struct vmur *info)
{
	char failed_action[10] = {};
	char lock_file[PATH_MAX];
	
        snprintf(lock_file,sizeof(lock_file), "%s-%04x",LOCK_FILE,info->devno);
	info->lock_fd = open(lock_file, O_RDONLY | O_CREAT, S_IRUSR);
	if (info->lock_fd == -1) {
		ERR("WARNING: Unable to open lock file %s, continuing "
		    "without any serialization.\n", LOCK_FILE);
		return;
	}
	if (flock(info->lock_fd, info->lock_attributes) == -1) {
		switch (info->action) {
		case RECEIVE:
			strcpy(failed_action, "received");
			break;
		case PUNCH:
			strcpy(failed_action, "punched");
			break;
		case PRINT:
			strcpy(failed_action, "printed");
			break;
		case PURGE:
			strcpy(failed_action, "purged");
			break;
		case ORDER:
			strcpy(failed_action, "ordered");
			break;
		default:
			strcpy(failed_action, "processed");
		}
		ERR("A concurrent instance of vmur is already active."
		    " No file %s.\n", failed_action);
		exit(EBUSY);
	}
}

/*
 * Release lock and close lock file
 */
static void release_lock(struct vmur *info)
{
	flock(info->lock_fd, LOCK_UN);
	close(info->lock_fd);
	info->lock_fd = -1;
}

/*
 * Check if file already exists. If yes, ask if it should be overwritten.
 */
static void check_overwrite(struct vmur *info)
{
	char buf[5] = {};
	char *str;
	struct stat stat_info;

	if (info->force_specified)
		return;

	if (stat(info->file_name, &stat_info))
		return;

	if (S_ISDIR(stat_info.st_mode)) {
		ERR("Cannot overwrite directory '%s'\n", info->file_name);
		exit(1);
	}

	fprintf(stderr, "%s: Overwrite '%s'? ", prog_name, info->file_name);
	str = fgets(buf, sizeof(buf), stdin);
	if (!str)
		exit(1);
	if (strcasecmp(buf, "y\n") == 0)
		return;
	if (strcasecmp(buf, "yes\n") == 0)
		return;
	close_reader(info, "HOLD");
	exit(0);
}

/*
 * Get format of spool file: Check VMDUMP and NETDATA flags,
 *                           set record length of file
 */
enum spoolfile_fmt get_spoolfile_fmt(struct vmur *info,
				     struct splink_page *buf)
{
	struct splink_record *rec;
	char netdata_id[5] = {0xc9, 0xd5, 0xd4, 0xd9, 0xf0}; /* EBCDIC: INMR0 */
	unsigned int i;

	rec = (struct splink_record *) &buf->data;

	if (buf->magic != 0)
		return TYPE_VMDUMP;

	info->file_reclen = buf->rec_len;

	for (i = 0; i < buf->data_recs; i++) {
		if (rec->ccw.flag & CCW_IMMED_FLAG) {
			rec = (struct splink_record *) ((char *) rec +
							sizeof(rec->ccw));
			continue; /* skip immediate CCWs */
		}
		if ((rec->data.flag & IS_CONTROL_RECORD) &&
		    (memcmp(rec->data.magic, netdata_id, 5) == 0))
			return TYPE_NETDATA;
		rec = (struct splink_record *) ((char *) rec + rec->record_len);
	}

	return TYPE_NORMAL;
}

/*
 * Convert record for text mode: Do EBCDIC->ASCII translation
 */
static int convert_text(struct vmur *info, struct splink_record *rec,
			char **out_ptr)
{
	size_t in_count = rec->ccw.data_len;
	size_t out_count = rec->ccw.data_len;
	char *data_ptr = (char *) &rec->data;
	int rc;

	if ((rec->ccw.data_len == 1) && (data_ptr[0] == 0x40))
		goto out; /* one blank -> just a newline */

	rc = iconv(info->iconv, &data_ptr, &in_count, out_ptr, &out_count);
	if ((rc == -1) || (in_count != 0)) {
		ERR("Code page translation EBCDIC-ASCII failed\n");
		return -1;
	}

out:
	**out_ptr = ASCII_LF;
	*out_ptr += 1;
	return 0;
}

/*
 * Convert record for binary mode: Fill up missing 0x40 bytes
 */
static void convert_binary(struct vmur *info, struct splink_record *rec,
			  char **out_ptr)
{
	int residual;

	memcpy(*out_ptr, &rec->data, rec->ccw.data_len);
	*out_ptr += rec->ccw.data_len;

	/* Since CP removed trailing EBCDIC blanks, we have */
	/* to insert them again */

	residual = info->file_reclen - rec->ccw.data_len;
	memset(*out_ptr, 0x40, residual);
	*out_ptr += residual;
}

/*
 * Convert record for blocked mode: remove padding bytes and add separator
 */
static void convert_blocked(struct vmur *info, struct splink_record *rec,
			   char **out_ptr)
{
	int residual, i;

	memcpy(*out_ptr, &rec->data, rec->ccw.data_len);
	*out_ptr += rec->ccw.data_len;

	/* Since CP removed trailing EBCDIC blanks, we have */
	/* to insert them again */

	residual = info->file_reclen - rec->ccw.data_len;
	memset(*out_ptr, 0x40, residual);
	*out_ptr += residual;

	/* Now remove trailing padding bytes */

	for (i = 0; i < info->file_reclen; i++) {
		if (*(*out_ptr - 1) != info->blocked_padding)
			break;
		*out_ptr -= 1;
	}

	/* ... and insert separator */

	**out_ptr = info->blocked_separator;
	*out_ptr += 1;
}

/*
 * Extract data from VM spool file data blocks (SPLINK).
 */
ssize_t convert_sfdata(struct vmur *info, struct splink_page *in, char *out)
{
	struct splink_record *rec;
	char *out_ptr = out;
	unsigned int i, rc = 0;

	rec = (struct splink_record *) &in->data;

	for (i = 0; i < in->data_recs; i++) {
		if (rec->ccw.opcode == NOP) {
			rec = (struct splink_record *) ((char *) rec +
				rec->record_len);
			continue; /* skip NOP CCWs */
		} else if (rec->ccw.flag & CCW_IMMED_FLAG) {
			rec = (struct splink_record *) ((char *) rec +
				sizeof(rec->ccw));
			continue; /* skip immediate CCWs */
		}
		if (info->text_specified) {
			rc = convert_text(info, rec, &out_ptr);
			if (rc)
				return rc;
		} else if (info->blocked_specified) {
			convert_blocked(info, rec, &out_ptr);
		} else
			convert_binary(info, rec, &out_ptr);
		rec = (struct splink_record *) ((char *) rec + rec->record_len);
	}
	return out_ptr - out;
}

/*
 * Write normal spool file data.
 */
int write_normal(struct vmur *info, struct splink_page *sfdata, int count,
		 int fho)
{
	char *outbuf;
	int len, i;

	for (i = 0; i < count; i++) {
		struct splink_page *data;

		data = &sfdata[i];
		outbuf = (char *) malloc((info->file_reclen + 1) *
					 data->data_recs);
		if (!outbuf) {
			ERR("Out of memory\n");
			return -ENOMEM;
		}
		len = convert_sfdata(info, data, outbuf);
		if (len < 0) {
			ERR("Data conversion failed\n");
			return -EINVAL;
		}
		if (write(fho, outbuf, len) == -1) {
			ERR("Write to file %s failed: %s\n", info->file_name,
			    strerror(errno));
			return -errno;
		}
		free(outbuf);
	}

	return 0;
}

/*
 * Write vmdump data.
 */
int write_vmdump(struct vmur *info, struct splink_page *sfdata, int count,
		 int fho)
{
	if (write(fho, sfdata, count * sizeof(sfdata[0])) == -1) {
		ERR("Write to file %s failed: %s\n", info->file_name,
		    strerror(errno));
		return -errno;
	}

	return 0;
}

/*
 * Clean up and restore spool options
 */
static void cleanup_atexit_fn(void)
{
	restore_spool_options(&vmur_info);
	release_lock(&vmur_info);
}

/*
 * Close VM virtual reader in case of a signal e.g. CTRL-C
*/
static void ur_receive_sig_handler(int UNUSED(sig), siginfo_t *UNUSED(sip),
				   void *UNUSED(p))
{
	close_reader(&vmur_info, "HOLD");
	cleanup_atexit_fn();
	ERR_EXIT("Operation terminated, spool file received incompletely.\n");
}

/*
 * Receive reader file.
 */
static void ur_receive(struct vmur *info)
{
	struct splink_page sfdata[READ_BLOCKS];
	enum spoolfile_fmt type;
	int fhi, fho = STDOUT_FILENO, count;
	int rc;

	if (check_class(info))
		ERR_EXIT("Reader device class does not match the specified "
			 "spool file class\n");
	close_reader(info, "HOLD");
	order_change_reader_file(info);

	fhi = open(info->devnode, O_RDONLY | O_NONBLOCK);
	if (fhi == -1)
		ERR_EXIT("Could not open device %s\n%s\n", info->devnode,
			 strerror(errno));

	set_signal_handler(info, ur_receive_sig_handler);

	if (!info->stdout_specified) {
		if (!info->file_name_specified &&
		    get_filename_from_reader(info))
			goto fail;
		check_overwrite(info);
	}

	/* Read first block and check spool file format */

	count = read(fhi, &sfdata, READ_BLOCKS * sizeof(sfdata[0]));
	if (count == -1) {
		ERR("Could not read from device %s\n%s\n", info->devnode,
		    strerror(errno));
		goto fail;
	}

	type = get_spoolfile_fmt(info, &sfdata[0]);
	if (info->convert_specified) {
		if (type != TYPE_VMDUMP) {
			ERR("Reader file %s does not have VMDUMP format, "
			    "conversion not possible.\n", info->spoolid);
			goto fail;
		} else {
			close(fhi);
			if (info->stdout_specified)
				rc = vmdump_convert(info->devnode, NULL,
						    prog_name);
			else
				rc = vmdump_convert(info->devnode,
						    info->file_name, prog_name);
			if (rc)
				goto fail;
			else
				goto vm_convert_done;
		}
	}
	if (type == TYPE_VMDUMP)
		ERR("INFO: Reader file %s has VMDUMP format.\n", info->spoolid);
	if (type == TYPE_NETDATA)
		ERR("INFO: Reader file %s has NETDATA format.\n",
		    info->spoolid);

	if (type != TYPE_VMDUMP) {
		int spoolid = atoi(info->spoolid);

		if (spoolid != sfdata->spoolid) {
			check_hold_state(info->spoolid);
			ERR_EXIT("Could not receive spool file %s. Spoolid "
				 "mismatch (%i)\n", info->spoolid,
				 sfdata->spoolid);
		}
	}

	/* read spool file data, convert it, and write it to output file or
	 * stdout */
	if (!info->stdout_specified) {
		fho = open(info->file_name, O_WRONLY | O_CREAT | O_TRUNC,
			   S_IRUSR | S_IWUSR);
		if (fho == -1) {
			ERR("Could not open file %s\n%s\n", info->file_name,
			    strerror(errno));
			goto fail;
		}
	}
	while (count != 0) {
		int blocks;

		blocks = count / sizeof(sfdata[0]);
		if (type == TYPE_VMDUMP)
			rc = write_vmdump(info, &sfdata[0], blocks, fho);
		else
			rc = write_normal(info, &sfdata[0], blocks, fho);

		if (rc)
			goto fail;

		/* read next records */
		count = read(fhi, &sfdata, READ_BLOCKS * sizeof(sfdata[0]));
		if (count == -1) {
			ERR("Could not read from device %s\n%s\n",
			    info->devnode, strerror(errno));
			goto fail;
		}
	}
	if (fho != STDOUT_FILENO)
		close(fho);
	close(fhi);
vm_convert_done:
	if (info->hold_specified)
		close_reader(info, "HOLD");
	else
		close_reader(info, "NOHOLD NOKEEP");
	return;

fail:
	close_reader(info, "HOLD");
	exit(1);
}

/*
 * Issue CP command CLOSE PUNCH
 */
static void close_ur_device(struct vmur *info)
{
	char cmd[MAXCMDLEN], spoolid[5] = {}, *response;
	int cprc;

	if (info->node_specified) {
		sprintf(cmd, "SPOOL %X NOCONT", info->devno);
		cpcmd(cmd, NULL, NULL, 0);
	}
	if (info->rdr_specified) {
		sprintf(cmd, "CLOSE %X TO ", info->devno);
		if (info->node_specified)
			strcat(cmd, RSCS_USERID);
		else if (info->user_specified)
			strcat(cmd, to_upper(info->user));
		else
			strcat(cmd, "*");
		strcat(cmd, " RDR");
	} else {
		sprintf(cmd, "CLOSE %X", info->devno);
	}
	strcat(cmd, " NAME ");
	strcat(cmd, info->spoolfile_name);
	if (info->spoolfile_type_specified) {
		strcat(cmd, " ");
		strcat(cmd, info->spoolfile_type);
	}
	cpcmd_cs(cmd, &response, &cprc, 0);
	memcpy(spoolid, &response[9], 4);
	free(response);
	if (cprc == 439) {
		if (info->action == PUNCH)
			sprintf(cmd, "PURGE * PUN %s", spoolid);
		else
			sprintf(cmd, "PURGE * PRT %s", spoolid);
		cpcmd(cmd, NULL, NULL, 0);
		ERR_EXIT("User %s spool fileid limit exceeded.\n"
			 , info->user);
	}
	if (info->rdr_specified) {
		if (info->node_specified)
			printf("Reader file with spoolid %s created and "
			       "transferred to %s.\n", spoolid, RSCS_USERID);
		else if (info->user_specified)
			printf("Reader file with spoolid %s created and "
			       "transferred to %s.\n", spoolid, info->user);
		else
			printf("Reader file with spoolid %s created.\n",
			       spoolid);
	} else if (info->action == PUNCH)
		printf("Punch file with spoolid %s created.\n", spoolid);
	else
		printf("Printer file with spoolid %s created.\n", spoolid);
}

/*
 * Issue CP command CLOSE PUNCH
 */
static void close_ur_device_simple(struct vmur *info)
{
	char cmd[MAXCMDLEN];

	sprintf(cmd, "CLOSE %X", info->devno);
	cpcmd(cmd, NULL, NULL, 0);
}

/*
 * Issue CP command CLOSE PUNCH PURGE
 */
static void close_ur_device_purge(struct vmur *info)
{
	char cmd[MAXCMDLEN];

	if (info->node_specified) {
		sprintf(cmd, "SPOOL %X NOCONT", info->devno);
		cpcmd(cmd, NULL, NULL, 0);
	}
	sprintf(cmd, "CLOSE %X PURGE", info->devno);
	cpcmd(cmd, NULL, NULL, 0);
}

/*
 * Issue "CP QUERY VIRTUAL devno" to retrieve punch device information
 * Exit, if devno has CONT status
 */
static int is_punch_cont(struct vmur *info)
{
	char *buf;
	char cmd[MAXCMDLEN];
	int rc = 0;

	sprintf(cmd, "QUERY VIRTUAL %X", info->devno);
	cpcmd(cmd, &buf, NULL, 0);
	if (!strncmp(buf + 15, "  CONT", 6))
		rc = 1;
	free(buf);
	return rc;
}

/*
 * Provide tag information for RSCS
 */
static void rscs_punch_setup(struct vmur *info)
{
	char cmd[MAXCMDLEN];

	sprintf(cmd, "SPOOL %X CONT", info->devno);
	cpcmd(cmd, NULL, NULL, 0);
	if ('\0' != info->node[0]) {
	        sprintf(cmd, "TAG DEV %X %s %s", info->devno, info->node, info->user);
	} else {
		sprintf(cmd,"TAG DEV %X %s", info->devno, info->tag_data);
	}
	cpcmd(cmd, NULL, NULL, 0);
	return;
}

/*
 * Purge punch file in case of a signal e.g. CTRL-C
 */
static void ur_write_sig_handler(int UNUSED(sig), siginfo_t *UNUSED(sip),
				 void *UNUSED(p))
{
	close_ur_device_purge(&vmur_info);
	cleanup_atexit_fn();
	ERR_EXIT("Operation terminated, no spool file created.\n");
}

/*
 * Read on line from fd not including newline
 */
static int read_line(int fd, char *buf, int len, int lf)
{
	int offs = 0;

	memset(buf, 0, len);
	do {
		int rc;

		rc = read(fd, buf + offs, 1);
		if (rc < 0)
			return -EIO;
		if (rc == 0)
			return -ENODATA;
		if (*(buf + offs) == lf)
			goto found;
		offs++;
	} while (offs < len);

	return -EINVAL;

found:
	*(buf + offs) = 0;
	return offs;
}

/*
 * Read text file for punch/print
 */
static int read_text_file(struct vmur *info, int fd, char *out_buf, size_t len)
{
	unsigned int pos = 0;
	static int line = 1;
	char sep, pad;
	char *buf;
	int rc;

	sep = '\n';
	pad = ' ';

	buf = (char *) malloc(info->ur_reclen + 1);
	if (!buf)
		return -ENOMEM;

	do {
		int line_len;
		size_t rec_len, out_len;
		char *in_ptr, *out_ptr;

		line_len = read_line(fd, buf, info->ur_reclen  + 1, sep);
		if (line_len == -ENODATA) {
			break;
		} else if (line_len == -EINVAL) {
			ERR("Input line %i too long. Unit record length"
			    " must not exceed %i\n", line, info->ur_reclen);
			goto fail;
		} else if (line_len < 0) {
			ERR("Read failed: %s", strerror(errno));
			goto fail;
		}
		line++;
		memset(buf + line_len, pad, info->ur_reclen - line_len);
		rec_len = out_len = info->ur_reclen;
		in_ptr = buf;
		out_ptr = &out_buf[pos];
		rc = iconv(info->iconv, &in_ptr, &rec_len, &out_ptr, &out_len);
		if ((rc == -1) || (out_len != 0)) {
			ERR("Code page conversion failed at line %i\n", line);
			goto fail;
		}
		pos += info->ur_reclen;
	} while (pos < len);
	free(buf);
	return pos;
fail:
	free(buf);
	return -1;
}

/*
 * Read blocked file for punch/print
 */
static int read_blocked_file(struct vmur *info, int fd, char *out_buf,
			     size_t len)
{
	unsigned int pos = 0;
	static int line = 1;
	char sep, pad;
	int line_len;
	char *buf;

	sep = info->blocked_separator;
	pad = info->blocked_padding;

	buf = (char *) malloc(info->ur_reclen + 1);
	if (!buf)
		return -ENOMEM;

	do {
		line_len = read_line(fd, buf, info->ur_reclen  + 1, sep);
		if (line_len == -ENODATA) {
			break;
		} else if (line_len == -EINVAL) {
			ERR("Input line %i too long. Unit record length"
			    " must not exceed %i\n", line, info->ur_reclen);
			goto fail;
		} else if (line_len < 0) {
			ERR("Read failed: %s", strerror(errno));
			goto fail;
		}
		line++;
		memset(buf + line_len, pad, info->ur_reclen - line_len);
		memcpy(&out_buf[pos], buf, info->ur_reclen);
		pos += info->ur_reclen;
	} while (pos < len);
	free(buf);
	return pos;
fail:
	free(buf);
	return -1;
}

/*
 * Read file for punch/print
 */
static int read_input_file(struct vmur *info, int fd, char *out_buf, size_t len)
{
	int rc;

	if (info->text_specified) {
		rc = read_text_file(info, fd, out_buf, len);
	} else if (info->blocked_specified) {
		rc = read_blocked_file(info, fd, out_buf, len);
	} else {
		rc = read(fd, out_buf, len);
		if (rc == -1) {
			ERR("Could not read file %s\n%s\n", info->file_name,
			    strerror(errno));
			return -EIO;
		}
	}
	return rc;
}

/*
 * Write function for punch and printer
 */
static void ur_write(struct vmur *info)
{
	int fhi, fho, residual, anything_written = 0;
	char *sfdata;
	ssize_t count;

	/* close punch preventively */
	close_ur_device_simple(info);

	/* Check punch. If punch is spooled CONT, exit */
	if (is_punch_cont(info))
		ERR_EXIT("Virtual punch device %X is spooled CONT.\n",
			 info->devno);

	sfdata = (char *) malloc(info->ur_reclen * VMUR_REC_COUNT);
	if (!sfdata)
		ERR_EXIT("Could not allocate memory for buffer (%i)\n",
			    info->ur_reclen);

	/* Open Linux file */
	if (info->file_name_specified) {
		fhi = open(info->file_name, O_RDONLY);
		if (fhi == -1)
			ERR_EXIT("Could not open file %s\n%s\n",
				 info->file_name, strerror(errno));
	} else {
		fhi = STDIN_FILENO;
	}

	if (info->node_specified || '\0' != info->tag_data[0])
		rscs_punch_setup(info);

	/* Open UR device */
	fho = open(info->devnode, O_WRONLY | O_NONBLOCK);
	if (fho == -1) {
		ERR("Could not open device %s\n%s\n", info->devnode,
		    strerror(errno));
		goto fail;
	}

	set_signal_handler(info, ur_write_sig_handler);

	/* read linux file data, and write it to VM punch device */
	do {
		count = read_input_file(info, fhi, sfdata,
					info->ur_reclen * VMUR_REC_COUNT);
		if (count < 0)
			goto fail;
		else if (count == 0)
			break; /* EOF */

		residual = (info->ur_reclen - (count % info->ur_reclen))
			% info->ur_reclen;
		memset(sfdata + count, 0, residual);
		if (write(fho, sfdata, count + residual) == -1) {
			ERR("Could not write on device %s (%s)\n",
			    info->devnode, strerror(errno));
			if (errno == EIO)
				ERR("Spool file limit exceeded or spool space "
				    "full?\n");
			goto fail;
		} else
			anything_written = 1;
	} while (1);

	close(fho);
	if (anything_written)
		close_ur_device(info);
	else
		ERR_EXIT("No spool file created - probably empty input.\n");
	free(sfdata);
	if (fhi != STDIN_FILENO)
		close(fhi);
	return;
fail:
	close_ur_device_purge(info);
	exit(1);
}

/*
 * Ask if file should be purged, if -f is not specified
 */
static void ur_purge_question(struct vmur *info)
{
	char buf[5] = {};
	char *str;

	if (info->force_specified)
		return;

	fprintf(stderr, "%s: purge selected %s file(s)? ", prog_name,
		info->queue);
	/*
	 * Release the vmur session lock while waiting for user input.  It is
	 * safe to release the lock here, because the ur_purge operation does
	 * not modify spool options.
	 */
	release_lock(info);
	str = fgets(buf, sizeof(buf), stdin);
	acquire_lock(info);
	if (!str)
		exit(1);
	if (strcasecmp(buf, "y\n") == 0)
		return;
	if (strcasecmp(buf, "yes\n") == 0)
		return;
	exit(0);
}

/*
 * Purge spool file
 */
static int ur_purge(struct vmur *info)
{
	char *buf, cmd[MAXCMDLEN];
	int n, m;

	ur_purge_question(info);

	/* Prepare the CP PURGE command */
	n = m = sprintf(cmd, "PURGE * %s", info->queue);

	/* Add selection criteria to match spool files */
	if (info->spoolid_specified)
		n += sprintf(cmd + n, " %s", info->spoolid);
	if (info->spool_class_specified)
		n += sprintf(cmd + n, " CLASS %c", info->spool_class);
	if (info->spool_form_specified)
		n += sprintf(cmd + n, " FORM %s", info->spool_form);
	if (info->spool_dest_specified)
		n += sprintf(cmd + n, " DEST %s", info->spool_dest);

	/* Purge all files if no spoolid or any of the class, form, or dest
	 * option is specified.
	 */
	if (n == m)
		n += sprintf(cmd + n, " ALL");

	cpcmd(cmd, &buf, NULL, 0);
	ERR("%s", buf);
	free(buf);
	return 0;
}

/*
 * Order spool file to top of the queue
 */
static int ur_order(struct vmur *info)
{
	char cmd[MAXCMDLEN];

	sprintf(cmd, "ORDER * %s %s", info->queue, info->spoolid);
	cpcmd(cmd, NULL, NULL, 0);
	return 0;
}

/*
 * List spool files
 */
static int ur_list(struct vmur *info)
{
	char *buf;
	char cmd[MAXCMDLEN];

	if (info->spoolid_specified)
		sprintf(cmd, "QUERY %s * %s ALL", info->queue, info->spoolid);
	else
		sprintf(cmd, "QUERY %s * ALL", info->queue);

	cpcmd(cmd, &buf, NULL, 1);
	printf("%s", buf);
	free(buf);
	return 0;
}

/*
 * Initialize iconv: "from" -> "to"
 */
static void setup_iconv(struct vmur *info, const char *from, const char *to)
{
	info->iconv = iconv_open(to, from);
	if (info->iconv == ((iconv_t) -1))
		ERR_EXIT("Could not initialize conversion table %s->%s.\n",
			 from, to);
}

int main(int argc, char **argv)
{
	/* Set name of program */
	prog_name = basename(argv[0]);

	/* Set default values */
	init_info(&vmur_info);

	/* Parse command line options and check syntax */
	parse_opts(&vmur_info, argc, argv);

	/* Register cleanup function */
	if (atexit(cleanup_atexit_fn))
		ERR_EXIT("Could not set up vmur session cleanup\n");

	/* Retrieve ur device number */
	setup_ur_device(&vmur_info);

	/* Acquire a lock to serialize concurrent vmur invocations */
	acquire_lock(&vmur_info);
	
	switch (vmur_info.action) {
	case RECEIVE:
		/* Setup spool options */
		setup_spool_options(&vmur_info);
		if (vmur_info.text_specified)
			setup_iconv(&vmur_info, EBCDIC_CODE_PAGE,
				    ASCII_CODE_PAGE);
		ur_receive(&vmur_info);
		break;
	case PUNCH:
	case PRINT:
		/* Setup spool options */
		setup_spool_options(&vmur_info);
		if (vmur_info.text_specified)
			setup_iconv(&vmur_info, ASCII_CODE_PAGE,
				    EBCDIC_CODE_PAGE);
		ur_write(&vmur_info);
		break;
	case PURGE:
		ur_purge(&vmur_info);
		break;
	case ORDER:
		ur_order(&vmur_info);
		break;
	case LIST:
		ur_list(&vmur_info);
		break;
	default:
		ERR("Internal error: unknown action '%i'\n", vmur_info.action);
		return -EINVAL;
	}
	return 0;
}
