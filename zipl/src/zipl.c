/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Main function
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/zt_common.h"

#include "boot.h"
#include "bootmap.h"
#include "disk.h"
#include "error.h"
#include "install.h"
#include "job.h"
#include "misc.h"
#include "zipl.h"


/* Flag deciding the level of verbosity */
int verbose = 0;

/* Flag deciding whether confirmation questions are asked */
int interactive = 1;

/* Flag deciding whether actions should only be simulated */
int dry_run = 1;

/* Full tool name */
static const char tool_name[] = "zipl: zSeries Initial Program Loader";

/* Copyright notice */
static const char copyright_notice[] = "Copyright IBM Corp. 2001, 2017";

/* Usage information */
static const char* usage_text[] = {
"Usage: zipl [OPTIONS] [SECTION]",
"",
"Prepare a device for initial program load. Use OPTIONS described below or ",
"provide the name of a SECTION defined in the zIPL configuration file.",
"",
"-h, --help                      Print this help, then exit",
"-v, --version                   Print version information, then exit",
"-c, --config CONFIGFILE         Read configuration from CONFIGFILE",
"-b, --blsdir BLSDIR             Parse BootLoaderSpec files from BLSDIR",
"-t, --target TARGETDIR          Write bootmap file to TARGETDIR and install",
"                                bootloader on device containing TARGETDIR",
"    --targetbase BASEDEVICE     Install bootloader on BASEDEVICE",
"    --targettype TYPE           Use device type: CDL, LDL, FBA, SCSI",
"    --targetgeometry C,H,S      Use disk geometry: cylinders,heads,sectors",
"    --targetblocksize SIZE      Use number of bytes per block",
"    --targetoffset OFFSET       Use offset between logical and physical disk",
"-i, --image IMAGEFILE[,ADDR]    Install Linux kernel image from IMAGEFILE",
"-r, --ramdisk RAMDISK[,ADDR]    Install initial ramdisk from file RAMDISK",
"-p, --parmfile PARMFILE[,ADDR]  Use kernel parmline stored in PARMFILE",
"-P, --parameters PARMLINE       Use specified kernel PARMLINE",
"-T, --tape TAPEDEV              Install bootloader on tape device TAPEDEV",
"-s, --segment SEGMENT,ADDR      Install a segment from file SEGMENT",
"-d, --dumpto DUMPDEV[,SIZE]     Install a system dump record on tape device",
"                                or disk partition DUMPDEV",
"-M, --mvdump DEVLIST[,SIZE]     Install a multi-volume dump record on each",
"                                disk partition listed in file DEVLIST",
"-f, --force                     Disable sanity check while producing a",
"                                multi-volume dump",
"-m, --menu MENU                 Install multi-boot configuration MENU",
"-n, --noninteractive            Answer all confirmation questions with 'yes'",
"-V, --verbose                   Provide more verbose output",
"-a, --add-files                 Add all referenced files to bootmap file",
"    --dry-run                   Simulate run but don't modify IPL records"
};


/* Print usage information. */
static void
print_usage(void)
{
	unsigned int i;

	for (i=0; i < ARRAY_SIZE(usage_text); i++)
		printf("%s\n", usage_text[i]);
}


/* Print version information. */
static void
print_version(void)
{
	printf("%s version %s\n", tool_name, RELEASE_STRING);
	printf("%s\n", copyright_notice);
}


/* Check whether calling user is root. Return 0 if user is root, non-zero
 * otherwise. */
static int
check_for_root(void)
{
	if (geteuid() != 0) {
		error_clear_text();
		error_reason("Must be root to perform this operation");
		return -1;
	} else
		return 0;
}


int
main(int argc, char* argv[])
{
	struct disk_info* info;
	disk_blockptr_t program_table, scsi_dump_sb_blockptr, *stage1b_list;
	blocknum_t stage1b_count;
	struct job_data* job;
	char* device;
	int rc;

	/* Check internals */
	rc = boot_check_data();
	if (rc) {
		error_text("Internal error");
		error_print();
		return 1;
	}
	/* Find out what we're supposed to do */
	rc = job_get(argc, argv, &job);
	if (rc) {
		error_print();
		return 1;
	}
	/* Check for priority options --help and --version */
	if (job->id == job_print_usage) {
		print_usage();
		job_free(job);
		return 0;
	} else if (job->id == job_print_version) {
		print_version();
		job_free(job);
		return 0;
	}
	/* Make sure we're running as root */
	if (check_for_root()) {
		job_free(job);
		error_print();
		return 1;
	}
	/* Set global option variables */
	verbose = job->verbose;
	interactive = !job->noninteractive;
	dry_run = job->dry_run;
	if (dry_run)
		printf("Starting dry-run, target device contents will NOT be "
		       "modified\n");
	/* Make sure new files are only user-accessible */
	umask(077);
	/* Do it */
	switch (job->id) {
	case job_dump_partition:
		if (disk_is_tape(job->data.dump.device) ||
		    !disk_is_scsi(job->data.dump.device, &job->target)) {
			rc = install_dump(job->data.dump.device, &job->target,
					  job->data.dump.mem);
			break;
		}
		/* Dump to a raw SCSI partition */
		if (job->data.dump.mem != -1uLL) {
			error_reason("Dump size can not be limited for "
				     "partition dump on a SCSI disk");
			rc = -1;
			break;
		}
		rc = check_job_dump_images(&job->data.dump, job->name);
		if (rc != 0)
			break;
		/* Fall through. */
	case job_ipl:
	case job_segment:
	case job_menu:
		/* Create bootmap */
		stage1b_list = NULL;
		rc = bootmap_create(job, &program_table, &scsi_dump_sb_blockptr,
				    &stage1b_list, &stage1b_count, &device,
				    &info);
		if (rc)
			break;
		/* Install boot loader */
		rc = install_bootloader(device, &program_table,
					&scsi_dump_sb_blockptr, stage1b_list,
					stage1b_count, info, job);
		if (stage1b_list != NULL)
			free(stage1b_list);
		misc_free_temp_dev(device);
		disk_free_info(info);
		break;
	case job_ipl_tape:
		rc = install_tapeloader(job->data.ipl_tape.device,
					job->data.ipl_tape.image,
					job->data.ipl_tape.parmline,
					job->data.ipl_tape.ramdisk,
					job->data.ipl_tape.image_addr,
					job->data.ipl_tape.parm_addr,
					job->data.ipl_tape.ramdisk_addr);
		break;
	case job_mvdump:
		rc = install_mvdump(job->data.mvdump.device,
				    &job->target,
				    job->data.mvdump.device_count,
				    job->data.mvdump.mem,
				    job->data.mvdump.force);
		break;
	case job_print_usage:
	case job_print_version:
		/* Should not happen */
		break;
	}
	switch (rc) {
	case 0: /* Operation completed successfully */
		if (verbose)
			printf("Syncing disks...\n");
		if (!dry_run)
			sync();
		printf("Done.\n");
		break;
	case -2: /* Operation canceled by user */
		break;
	default: /* An error occurred */
		error_print();
		break;
	}
	job_free(job);
	return abs(rc);
}
