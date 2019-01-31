/*
 * mon_fsstatd - Write file system utilization data to the z/VM monitor stream
 *
 * Copyright IBM Corp. 2006, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/types.h>
#include <mntent.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "mon_fsstatd.h"

static int attach;
static int mw_dev;
static char small_mon_record[SMALL_MON_RECORD_LEN];
static char large_mon_record[LARGE_MON_RECORD_LEN];
static long sample_interval = 60;

static const char *pid_file = "/run/mon_fsstatd.pid";

struct mw_name_lens {
	__u16  mw_name_len;
	__u16  mw_dir_len;
	__u16  mw_type_len;
	__u16  mw_fsdata_len;
	__u16  mw_total;
};

/*
 * Clean up when SIGTERM or SIGINT received
 */
void stop_fsstatd(int UNUSED(a))
{
	remove(pid_file);
	exit(0);
}

/*
 * Set up for handling SIGTERM or SIGINT
 */
static void fsstatd_handle_signals(void)
{
	struct sigaction act;

	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);

	act.sa_handler = stop_fsstatd;
	if (sigaction(SIGTERM, &act, NULL) < 0) {
		fprintf(stderr, "sigaction( SIGTERM, ... ) failed - "
			"reason %s\n", strerror(errno));
		exit(1);
	}
	act.sa_handler = stop_fsstatd;
	if (sigaction(SIGINT, &act, NULL) < 0) {
		fprintf(stderr, "sigaction( SIGINT, ... ) failed - "
			"reason %s\n", strerror(errno));
		exit(1);
	}
}

/*
 * Open /dev/monwriter
 */
static void fsstatd_open_monwriter(void)
{
	mw_dev = open("/dev/monwriter", O_EXCL | O_RDWR);
	if (mw_dev == -1) {
		printf("cannot open /dev/monwriter: %s\n", strerror(errno));
		exit(1);
	}
}

/*
 * Store daemon's pid so it can be stopped
 */
static int store_pid(void)
{
	FILE *f = fopen(pid_file, "w");

	if (!f) {
		syslog(LOG_ERR, "cannot open pid file %s: %s", pid_file,
		       strerror(errno));
		return -1;
	}
	fprintf(f, "%d\n", getpid());
	fclose(f);
	return 0;
}

/*
 * Stop sampling of any buffers that are not longer needed
 */
static void stop_unused(int curr_max, int prev_max)
{
	struct monwrite_hdr *mw_hdrp;
	int i;

	mw_hdrp = (struct monwrite_hdr *)small_mon_record;
	mw_hdrp->mon_function = MONWRITE_STOP_INTERVAL;
	mw_hdrp->applid = FSSTATD_APPLID;
	mw_hdrp->hdrlen = sizeof(struct monwrite_hdr);
	mw_hdrp->datalen = 0;
	for (i = 0; i < prev_max - curr_max; i += 2) {
		mw_hdrp->mod_level = curr_max + i;
		if (write(mw_dev, mw_hdrp, sizeof(struct monwrite_hdr)) == -1)
			syslog(LOG_ERR, "write error on STOP: %s\n",
			       strerror(errno));
	}
}

/*
 * Calculate lengths of data to be written to monitor stream
 */
static struct mw_name_lens fsstatd_get_lens(struct mntent *ent)
{
	struct mw_name_lens name_lens;

	name_lens.mw_name_len = strlen(ent->mnt_fsname);
	name_lens.mw_dir_len = strlen(ent->mnt_dir);
	name_lens.mw_type_len = strlen(ent->mnt_type);
	/* if name & dir too long to fit both, truncate them */
	if (name_lens.mw_name_len +
	    name_lens.mw_dir_len +
	    name_lens.mw_type_len > MAX_NAMES_LEN) {
		if (name_lens.mw_name_len > MAX_NAME_LEN)
			name_lens.mw_name_len = MAX_NAME_LEN;
		if (name_lens.mw_dir_len > MAX_DIR_LEN)
			name_lens.mw_dir_len = MAX_DIR_LEN;
		if (name_lens.mw_type_len > MAX_TYPE_LEN)
			name_lens.mw_type_len = MAX_TYPE_LEN;
	}
	/* total fs data to be written */
	name_lens.mw_fsdata_len = sizeof(__u16) + name_lens.mw_name_len +
				  sizeof(__u16) + name_lens.mw_dir_len +
				  sizeof(__u16) + name_lens.mw_type_len +
				  sizeof(struct fsstatd_data);
	/* total monitor data to be written in monitor record */
	name_lens.mw_total = sizeof(struct fsstatd_hdr) +
			     name_lens.mw_fsdata_len;
	return name_lens;
}

/*
 * Write fs data for ent to monitor stream
 */
static void fsstatd_write_ent(struct mntent *ent, time_t curr_time,
			int *small_maxp, int *big_maxp, struct statvfs buf)
{
	struct monwrite_hdr *mw_hdrp;
	struct fsstatd_hdr *mw_fshdrp;
	struct fsstatd_data *mw_fsdatap;

	char *mw_tmpp;
	char *mw_bufp;
	struct mw_name_lens mw_lens;
	int write_len;

	mw_lens = fsstatd_get_lens(ent);

	if ((mw_lens.mw_total + sizeof(struct monwrite_hdr))
	    <= sizeof(small_mon_record)) {
		mw_bufp = small_mon_record;
		memset(&small_mon_record, 0, sizeof(small_mon_record));
		mw_hdrp = (struct monwrite_hdr *)mw_bufp;

		mw_hdrp->datalen = sizeof(small_mon_record) -
				   sizeof(struct monwrite_hdr);
		write_len = sizeof(small_mon_record);
		mw_hdrp->mod_level = *small_maxp;
		*small_maxp += 2;
	} else {
		mw_bufp = large_mon_record;
		memset(&large_mon_record, 0, sizeof(large_mon_record));
		mw_hdrp = (struct monwrite_hdr *)mw_bufp;
		mw_hdrp->datalen = sizeof(large_mon_record) -
				   sizeof(struct monwrite_hdr);
		write_len = sizeof(large_mon_record);
		mw_hdrp->mod_level = *big_maxp;
		*big_maxp += 2;
	}

	/* fill in rest of monwrite_hdr */
	mw_tmpp = mw_bufp;
	mw_hdrp->applid = FSSTATD_APPLID;
	mw_hdrp->hdrlen = sizeof(struct monwrite_hdr);
	mw_hdrp->mon_function = MONWRITE_START_INTERVAL;

	/* fill in fsstatd_hdr */
	mw_tmpp += sizeof(struct monwrite_hdr);
	mw_fshdrp = (struct fsstatd_hdr *)mw_tmpp;
	mw_fshdrp->time_stamp = (__u64) curr_time;
	mw_fshdrp->fsstat_data_len = (__u16) mw_lens.mw_fsdata_len;
	mw_fshdrp->fsstat_data_offset = (__u16) sizeof(struct fsstatd_hdr);

	/* fill in fs name, dir name and fs type and lengths */
	mw_tmpp += sizeof(struct fsstatd_hdr);
	memcpy(mw_tmpp, &mw_lens.mw_name_len, sizeof(__u16));
	mw_tmpp += sizeof(__u16);
	strncpy(mw_tmpp, ent->mnt_fsname, mw_lens.mw_name_len);
	mw_tmpp += mw_lens.mw_name_len;
	memcpy(mw_tmpp, &mw_lens.mw_dir_len, sizeof(__u16));
	mw_tmpp += sizeof(__u16);
	strncpy(mw_tmpp, ent->mnt_dir, mw_lens.mw_dir_len);
	mw_tmpp += mw_lens.mw_dir_len;
	memcpy(mw_tmpp, &mw_lens.mw_type_len, sizeof(__u16));
	mw_tmpp += sizeof(__u16);
	strncpy(mw_tmpp, ent->mnt_type, mw_lens.mw_type_len);

	/* fill in fsstatd_data */
	mw_tmpp += mw_lens.mw_type_len;
	mw_fsdatap = (struct fsstatd_data *)mw_tmpp;
	mw_fsdatap->fs_bsize = (__u64)buf.f_bsize;
	mw_fsdatap->fs_frsize = (__u64) buf.f_frsize;
	mw_fsdatap->fs_blocks = (__u64) buf.f_blocks;
	mw_fsdatap->fs_bfree = (__u64) buf.f_bfree;
	mw_fsdatap->fs_bavail = (__u64) buf.f_bavail;
	mw_fsdatap->fs_files = (__u64) buf.f_files;
	mw_fsdatap->fs_ffree = (__u64) buf.f_ffree;
	mw_fsdatap->fs_favail = (__u64) buf.f_favail;
	mw_fsdatap->fs_flag = (__u64) buf.f_flag;

	if (write(mw_dev, mw_bufp, write_len) == -1)
		syslog(LOG_ERR, "write error: %s\n", strerror(errno));
}

/*
 * Run as background process
 */
static void fsstatd_daemonize(void)
{
	int pipe_fds[2], startup_rc = 1;
	pid_t pid;

	if (pipe(pipe_fds) == -1) {
		syslog(LOG_ERR, "pipe error: %s\n", strerror(errno));
		exit(1);
	}

	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "fork error: %s\n", strerror(errno));
		exit(1);
	}
	if (pid > 0) {
		/* Wait for startup return code from daemon */
		if (read(pipe_fds[0], &startup_rc, sizeof(startup_rc)) == -1)
			syslog(LOG_ERR, "pipe read error: %s\n", strerror(errno));
		/* With startup_rc == 0, pid file was written at this point */
		exit(startup_rc);
	}

	/* Change the file mode mask */
	umask(0);

	/* Catch SIGINT and SIGTERM to clean up pid file on exit */
	fsstatd_handle_signals();

	/* Create a new SID for the child process */
	if (setsid() < 0) {
		syslog(LOG_ERR, "setsid error: %s\n",  strerror(errno));
		goto notify_parent;
	}

	/* Change the current working directory */
	if (chdir("/") < 0) {
		syslog(LOG_ERR, "chdir error: %s\n",  strerror(errno));
		goto notify_parent;
	}

	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	/* Store daemon pid */
	if (store_pid() < 0)
		goto notify_parent;
	startup_rc = 0;

notify_parent:
	/* Inform waiting parent about startup return code */
	if (write(pipe_fds[1], &startup_rc, sizeof(startup_rc)) == -1) {
		syslog(LOG_ERR, "pipe write error: %s\n", strerror(errno));
		exit(1);
	}
	if (startup_rc != 0)
		exit(startup_rc);
}

static int fsstatd_do_work(void)
{
	FILE *mnttab;

	time_t curr_time;
	struct statvfs buf;
	struct mntent *ent;

	int result;
	int curr_small_max, prev_small_max;
	int curr_big_max, prev_big_max;

	/*
	 * small buffers use even mod_levels,
	 * big buffers use odd mod_levels
	 */
	prev_small_max = 0;
	prev_big_max = 1;
	syslog(LOG_INFO, "sample interval: %lu\n", sample_interval);
	while (1) {
		time(&curr_time);
		mnttab = fopen("/etc/mtab", "r");
		if (mnttab == NULL) {
			syslog(LOG_ERR, "cannot open /etc/mtab: %s\n",
				strerror(errno));
			break;
		}
		curr_small_max = 0;
		curr_big_max = 1;

		ent = getmntent(mnttab);
		if (ent == NULL) {
			syslog(LOG_ERR, "getmntent error: %s\n",
				strerror(errno));
			fclose(mnttab);
			break;
		}

		while (ent) {
			/* Only sample physical filesystem size data */
			if ((strncmp(ent->mnt_type, "autofs", 6) == 0 ||
			     strncmp(ent->mnt_type, "none", 4) == 0 ||
			     strncmp(ent->mnt_type, "proc", 4) == 0 ||
			     strncmp(ent->mnt_type, "subfs", 5) == 0 ||
			     strncmp(ent->mnt_type, "nfsd", 4) == 0 ||
			     strncmp(ent->mnt_type, "tmpfs", 5) == 0 ||
			     strncmp(ent->mnt_type, "sysfs", 5) == 0 ||
			     strncmp(ent->mnt_type, "pstore", 6) == 0 ||
			     strncmp(ent->mnt_type, "cgroup", 6) == 0 ||
			     strncmp(ent->mnt_type, "mqueue", 6) == 0 ||
			     strncmp(ent->mnt_type, "devpts", 6) == 0 ||
			     strncmp(ent->mnt_type, "debugfs", 7) == 0 ||
			     strncmp(ent->mnt_type, "devtmpfs", 8) == 0 ||
			     strncmp(ent->mnt_type, "configfs", 8) == 0 ||
			     strncmp(ent->mnt_type, "selinuxfs", 9) == 0 ||
			     strncmp(ent->mnt_type, "hugetlbfs", 9) == 0 ||
			     strncmp(ent->mnt_type, "securityfs", 10) == 0 ||
			     strncmp(ent->mnt_type, "rpc_pipefs", 10) == 0 ||
			     strncmp(ent->mnt_type, "binfmt_misc", 11) == 0 ||
			     strncmp(ent->mnt_type, "ignore", 6) == 0)) {
				ent = getmntent(mnttab);
				continue;
			}
			result = statvfs(ent->mnt_dir, &buf);
			if (result != 0) {
				syslog(LOG_ERR, "statvfs error on %s: %s\n",
					ent->mnt_dir, strerror(errno));
				ent = getmntent(mnttab);
				continue;
			}

			if (buf.f_blocks > 0)
				fsstatd_write_ent(ent, curr_time,
					&curr_small_max, &curr_big_max, buf);
			ent = getmntent(mnttab);
		}

		if (curr_small_max < prev_small_max)
			stop_unused(curr_small_max, prev_small_max);
		if (curr_big_max < prev_big_max)
			stop_unused(curr_big_max, prev_big_max);

		prev_small_max = curr_small_max;
		prev_big_max = curr_big_max;
		fclose(mnttab);
		sleep(sample_interval);
	}
	return 1;
}


/*
 Parse options
*/
static int parse_options(int argc, char **argv)
{
	int opt;

	do {
		opt = getopt_long(argc, argv, opt_string, options, NULL);
		switch (opt) {
		case -1:
			/* Reached end of parameter list. */
			break;
		case 'h':
			printf("%s", help_text);
			exit(0);
		case 'v':
			printf("mon_fsstatd: version %s\n", RELEASE_STRING);
			printf("Copyright IBM Corp. 2006, 2017\n");
			exit(0);
		case 'a':
			attach = 1;
			break;
		case 'i':
			sample_interval = strtol(optarg, NULL, 10);
			if (sample_interval <= 0) {
				fprintf(stderr, "Error: Invalid interval "
					"(needs to be greater than 0)\n");
				return(1);
			}
			break;
		default:
			fprintf(stderr, "Try ' --help' for more"
				" information.\n");
			return(1) ;
		}
	} while (opt != -1);
	return(0);
}

int main(int argc, char **argv)
{
	int rc;

	rc = parse_options(argc, argv);
	if (rc > 0)
		return rc;
	fsstatd_open_monwriter();
	openlog("mon_fsstatd", 0, LOG_DAEMON);
	if (!attach)
		fsstatd_daemonize();
	rc = fsstatd_do_work();
	close(mw_dev);
	return rc;
}
