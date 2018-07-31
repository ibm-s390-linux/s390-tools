/*
 * zfcpdump - Write /proc/vmcore to SCSI partition
 *
 * This tool should be used in an intitramfs together with a kernel with
 * enabled CONFIG_ZFCPDUMP kernel build option. The tool is able to write
 * standalone system dumps on SCSI disks.
 *
 * See Documentation/s390/zfcpdump.txt for more information!
 *
 * Copyright IBM Corp. 2003, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <asm/types.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/reboot.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef GZIP_SUPPORT
#include <zlib.h>
#endif

#include "lib/zt_common.h"
#include "zfcpdump.h"

struct globals g;

/*
 * Print a newline
 *
 * The leading blank is needed to force the SCLP console printing the newline
 */
void print_newline(void)
{
	PRINT(" \n");
}

/*
 * Initialize start time and return start time string
 */
static void start_time_init(char *str, unsigned int len)
{
	struct tm *tm;
	time_t ti;

	gettimeofday(&g.start_time, NULL);
	time(&ti);
	tm = localtime(&ti);
	strftime(str, len, "%a, %d %b %Y %H:%M:%S %z", tm);
}

/*
 * parse one kernel parameter in the form keyword=value
 */
static int parse_parameter(char *parameter)
{
	char *token;

	token = strtok(parameter, "=");
	if (token == NULL)
		return 0;

	if (strcmp(token, PARM_DEBUG) == 0) {
		/* Dump Debug */
		char *s = strtok(NULL, "=");
		if (s == NULL) {
			PRINT_WARN("No value for '%s' parameter "
				"specified\n", PARM_DEBUG);
			PRINT_WARN("Using default: %d\n", PARM_DEBUG_DFLT);
		} else {
			g.parm_debug = atoi(s);
			if ((g.parm_debug < PARM_DEBUG_MIN) ||
			    (g.parm_debug > PARM_DEBUG_MAX)) {
				PRINT_WARN("Invalid value (%i) for %s "
				"parameter specified (allowed range is "
				"%i - %i)\n", g.parm_debug, PARM_DEBUG,
				PARM_DEBUG_MIN, PARM_DEBUG_MAX);
				PRINT_WARN("Using default: %i\n",
				PARM_DEBUG_DFLT);
				g.parm_debug = PARM_DEBUG_DFLT;
			}
		}
	}
	return 0;
}

/*
 * Get dump parameters from /proc/cmdline
 * Return: 0       - ok
 *         (!= 0)  - error
 */
static int parse_parmline(void)
{
	int fh, i, count, token_cnt;
	char *parms[KERN_PARM_MAX];
	char *token;

	/* setting defaults */
	g.parm_debug    = PARM_DEBUG_DFLT;

	fh = open(PROC_CMDLINE, O_RDONLY);
	if (fh == -1) {
		PRINT_PERR("open %s failed\n", PROC_CMDLINE);
		return -1;
	}
	count = read(fh, g.parmline, CMDLINE_MAX_LEN);
	if (count == -1) {
		PRINT_PERR("read %s failed\n", PROC_CMDLINE);
		close(fh);
		return -1;
	}
	g.parmline[count-1] = '\0'; /* remove \n */
	token_cnt = 0;
	token = strtok(g.parmline, " \t\n");
	while (token != NULL) {
		parms[token_cnt] = token;
		token = strtok(NULL, " \t\n");
		token_cnt++;
		if (token_cnt >= KERN_PARM_MAX) {
			PRINT_WARN("More than %i kernel parmameters "
				   "specified\n", KERN_PARM_MAX);
			break;
		}
	}
	for (i = 0; i < token_cnt; i++) {
		if (parse_parameter(parms[i])) {
			close(fh);
			return -1;
		}
	}
	PRINT_TRACE("dump debug: %d\n", g.parm_debug);
	close(fh);
	return 0;
}

static int write_to_file(const char *file, const char *command)
{
	int fh;

	PRINT_TRACE("Write: %s - %s\n", file, command);
	fh = open(file, O_WRONLY);
	if (fh == -1) {
		PRINT_PERR("Could not open %s\n", file);
		return -1;
	}
	if (write(fh, command, strlen(command)) == -1) {
		PRINT_PERR("Write to %s failed\n", file);
		close(fh);
		return -1;
	};
	close(fh);
	return 0;
}

static int read_file(const char *file, char *buf, int size)
{
	ssize_t count;
	int fh;

	PRINT_TRACE("Read: %s:\n", file);
	fh = open(file, O_RDONLY);
	if (fh == -1) {
		PRINT_PERR("open %s failed\n", file);
		return -1;
	}
	count = read(fh, buf, size - 1);
	if (count < 0) {
		PRINT_PERR("read %s failed\n", file);
		close(fh);
		return -1;
	}
	buf[count] = 0;
	if (buf[strlen(buf) - 1] == '\n')
		buf[strlen(buf) - 1] = 0; /* strip newline */
	close(fh);
	PRINT_TRACE("'%s'\n", buf);

	return 0;
}

/*
 * Get HSA size
 */
__u64 get_hsa_size(void)
{
	char buf[128];

	if (read_file(DEV_ZCORE_HSA, buf, sizeof(buf)))
		return 0;
	return strtoul(buf, NULL, 16);
}

/*
 * Release HSA
 */
void release_hsa(void)
{
	write_to_file(DEV_ZCORE_HSA, "0");
}

/*
 * Enable the scsi disk for dumping
 * Return:    0 - ok
 *         != 0 - error
 */
static int enable_zfcp_device(void)
{
	char command[1024], file[1024];
	struct stat s;

	/* Prevent setting all LUNs online for NPIV */
	if (stat("/sys/module/zfcp/parameters/allow_lun_scan", &s) == 0)
		write_to_file("/sys/module/zfcp/parameters/allow_lun_scan",
			      "0\n");
	/* device */
	if (read_file(IPL_DEVNO, g.dump_devno, sizeof(g.dump_devno)))
		return -1;
	sprintf(file, "/sys/bus/ccw/drivers/zfcp/%s/online", g.dump_devno);
	if (write_to_file(file, "1\n"))
		return -1;

	/* wwpn */
	if (read_file(IPL_WWPN, g.dump_wwpn, sizeof(g.dump_wwpn)))
		return -1;
	sprintf(file, "/sys/bus/ccw/drivers/zfcp/%s/port_add", g.dump_devno);
	/* The port_add attribute has been removed in recent kernels */
	if (stat(file, &s) == 0) {
		sprintf(command, "%s\n", g.dump_wwpn);
		if (write_to_file(file, command))
			return -1;
	}

	/* lun */
	if (read_file(IPL_LUN, g.dump_lun, sizeof(g.dump_lun)))
		return -1;
	sprintf(file, "/sys/bus/ccw/drivers/zfcp/%s/%s/unit_add", g.dump_devno,
		g.dump_wwpn);
	sprintf(command, "%s\n", g.dump_lun);
	if (write_to_file(file, command))
		return -1;

	/* bootprog */
	read_file("/sys/firmware/ipl/bootprog", g.dump_bootprog,
		sizeof(g.dump_bootprog));

	return 0;
}

/*
 * Terminate the system dumper
 */
int terminate(int rc)
{
	int fd;

	print_newline();
	if (rc)
		PRINT("Dump failed\n");
	else
		PRINT("Dump successful\n");
	fflush(stdout);

	sleep(WAIT_TIME_END); /* give the messages time to be displayed */
	fd = open(DEV_ZCORE_REIPL, O_WRONLY, 0);
	if (fd == -1)
		goto no_reipl;
	if (write(fd, REIPL, 1) == -1)
		PRINT_PERR("Write to %s failed\n", DEV_ZCORE_REIPL);
	close(fd);
no_reipl:
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	return 0;
}

/*
 * Signal handler for zfcp_dumper
 */
static void dump_sig_handler(int sig, siginfo_t *UNUSED(sip), void *UNUSED(p))
{
	PRINT_ERR("Got signal: %i\n", sig);
	terminate(1);
}

/*
 * Setup the Signal handler for zfcp_dumper
 * Return:   0 - ok
 *         !=0 - error
 */
static int init_sig(void)
{
	g.sigact.sa_flags = (SA_NODEFER | SA_SIGINFO | SA_RESETHAND);
	g.sigact.sa_sigaction = dump_sig_handler;
	if (sigemptyset(&g.sigact.sa_mask) < 0)
		return -1;
	if (sigaction(SIGINT, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGTERM, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGPIPE, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGABRT, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGSEGV, &g.sigact, NULL) < 0)
		return -1;
	if (sigaction(SIGBUS, &g.sigact, NULL) < 0)
		return -1;

	return 0;
}

/*
 * Write progress information to screen
 * Parameter: done - So many bytes have been written since last call
 */
void show_progress(unsigned long done)
{
	unsigned long byte_per_sec, eta_sec, eta_min, eta_hrs;
	struct timeval tv, tv_sub;
	char eta_str[128];
	static unsigned long vmcore_done;
	static time_t time_next;

	gettimeofday(&tv, NULL);
	vmcore_done += done;
	if ((tv.tv_sec < time_next) && (vmcore_done < g.vmcore_size))
		return;
	timersub(&tv, &g.start_time, &tv_sub);
	byte_per_sec = tv_sub.tv_sec ? (vmcore_done / tv_sub.tv_sec) : 0;
	if (byte_per_sec) {
		eta_sec = (g.vmcore_size - vmcore_done) / byte_per_sec;
		eta_hrs = eta_sec / 3600;
		eta_sec -= eta_hrs * 3600;
		eta_min = eta_sec / 60;
		eta_sec -= eta_min * 60;
		snprintf(eta_str, sizeof(eta_str), "%lu:%02lu:%02lu",
			 eta_hrs, eta_min, eta_sec);
	} else {
		strcpy(eta_str, "unknown");
	}
	PRINT(" %6llu of %llu MB %5.1f%% %4llu MB/s %-5s ETA\n",
	      TO_MIB(vmcore_done), TO_MIB(g.vmcore_size),
	      ((double) vmcore_done / (double) g.vmcore_size) * 100.0,
	      TO_MIB(byte_per_sec), eta_str);
	time_next = tv.tv_sec + 10;
}

/*
 * Initialize zfcpdump
 */
int zfcpdump_init(void)
{
	char start_time_str[128], linux_version[256];

#ifdef __s390x__
	PRINT("Linux System Dumper starting\n");
	PRINT("\n");
	PRINT("Version %s (64 bit)\n", ZFCPDUMP_VERSION);
#else
	PRINT("Linux System Dumper starting\n");
	PRINT("\n");
	PRINT("Version %s (32 bit)\n", ZFCPDUMP_VERSION);
#endif
	if (init_sig()) {
		PRINT_ERR("Init Signals failed!\n");
		return -1;
	}
	if (mount("proc", "/proc", "proc", 0, NULL)) {
		if (errno != EBUSY) {
			PRINT_PERR("Unable to mount proc\n");
			return -1;
		}
	}
	read_file("/proc/version", linux_version, sizeof(linux_version));
	PRINT("%s\n", linux_version);
	print_newline();

	if (mount("sysfs", "/sys", "sysfs", 0, NULL)) {
		if (errno != EBUSY) {
			PRINT_PERR("Unable to mount sysfs\n");
			return -1;
		}
	}
	if (mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL)) {
		if (errno != EBUSY) {
			PRINT_PERR("Unable to mount debugfs\n");
			return -1;
		}
	}
	if (parse_parmline()) {
		PRINT_ERR("Could not parse parmline\n");
		return -1;
	}
	if (enable_zfcp_device()) {
		PRINT_ERR("Could not enable dump device\n");
		return -1;
	}
	start_time_init(start_time_str, sizeof(start_time_str));
	PRINT("Dump start at:\n");
	PRINT(" %s\n", start_time_str);
	print_newline();
	sleep(WAIT_TIME_ONLINE);
	return 0;
}
