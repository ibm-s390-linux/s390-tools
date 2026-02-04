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
"-k, --kdump=auto                Install a kdump kernel that can be used as a",
"                                stand-alone dump tool",
"-d, --dumpto DUMPDEV[,SIZE]     Install a system dump record on tape device",
"                                or disk partition DUMPDEV",
"    --ldipl-dump                Install a List-directed dump",
"    --no-compress               Do not use zlib compression for DASD dump",
"-M, --mvdump DEVLIST[,SIZE]     Install a multi-volume dump record on each",
"                                disk partition listed in file DEVLIST",
"-f, --force                     Disable sanity check while producing a",
"                                multi-volume dump",
"-m, --menu MENU                 Install multi-boot configuration MENU",
"-n, --noninteractive            Answer all confirmation questions with 'yes'",
"-V, --verbose                   Provide more verbose output",
"-a, --add-files                 Add all referenced files to bootmap file",
"    --dry-run                   Simulate run but don't modify IPL records",
"-S, --secure SWITCH             Control the zIPL secure boot support.",
"                                 auto (default):",
"                                  Write signatures if available and supported",
"                                 1: Write signatures regardless of support",
"                                 0: Do not write signatures"
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
	struct disk_ext_type ext_type = {0};
	struct install_set bis;
	struct job_data* job;
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
		rc = dump_disk_get_ext_type(job->data.dump.device, &ext_type);
		if (rc)
			break;
		job_dump_check_set_ngdump(job, &ext_type);
		if (!job_dump_is_ngdump(job) &&
		    (disk_type_is_tape(&ext_type) ||
		     !disk_type_is_scsi(&ext_type))) {
			rc = install_dump(job->data.dump.device, &job->target,
					  job->data.dump.mem, job->data.dump.no_compress);
			break;
		}
		/* Dump to a raw SCSI partition */
		if (job->data.dump.mem != -1uLL) {
			error_reason("Dump size can not be limited for "
				     "partition dump on a SCSI disk");
			rc = -1;
			break;
		}
		if (job_dump_is_ngdump(job)) {
			if (disk_type_is_eckd_ldl(&ext_type)) {
				error_reason("List-directed dump on ECKD with LDL not supported");
				rc = -1;
				break;
			}
			rc = check_job_images_ngdump(&job->data.dump, job->name);
		} else {
			rc = check_job_dump_images(&job->data.dump, job->name);
		}
		if (rc != 0)
			break;
		/* Fall through. */
	case job_ipl:
	case job_segment:
	case job_menu:
		rc = prepare_bootloader(job, &bis);
		if (rc) {
			free_bootloader(&bis, job);
			break;
		}
		rc = install_bootloader(job, &bis);
		if (rc) {
			free_bootloader(&bis, job);
			break;
		}
		rc = post_install_bootloader(job, &bis);
		free_bootloader(&bis, job);
		break;
	case job_ipl_tape:
		rc = install_tapeloader(job->data.ipl_tape.device,
					job->data.ipl_tape.common.image,
					job->data.ipl_tape.common.parmline,
					job->data.ipl_tape.common.ramdisk,
					job->data.ipl_tape.common.image_addr,
					job->data.ipl_tape.common.parm_addr,
					job->data.ipl_tape.common.ramdisk_addr);
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

/**
 * Program Component Footers
 */
struct component_footer component_footers[NR_PROGRAM_COMPONENTS] = {
	[COMPONENT_ID_HEAP_AREA] = {
		.type = COMPONENT_TYPE_LOAD,
		.desc = "heap area"
	},
	[COMPONENT_ID_STACK_AREA] = {
		.type = COMPONENT_TYPE_LOAD,
		.desc = "stack area"
	},
	[COMPONENT_ID_LOADER_SIGNATURE] = {
		.type = COMPONENT_TYPE_SIGNATURE,
		.desc = "loader signature"
	},
	[COMPONENT_ID_LOADER] = {
		.type = COMPONENT_TYPE_LOAD,
		.desc = "internal loader"
	},
	[COMPONENT_ID_PARAMETERS] = {
		.type = COMPONENT_TYPE_LOAD,
		.desc = "parameters"
	},
	[COMPONENT_ID_IMAGE_SIGNATURE] = {
		.type = COMPONENT_TYPE_SIGNATURE,
		.desc = "image signature"
	},
	[COMPONENT_ID_KERNEL_IMAGE] = {
		.type = COMPONENT_TYPE_LOAD,
		.desc = "kernel image"
	},
	[COMPONENT_ID_PARMLINE] = {
		.type = COMPONENT_TYPE_LOAD,
		.desc = "parmline"
	},
	[COMPONENT_ID_RAMDISK_SIGNATURE] = {
		.type = COMPONENT_TYPE_SIGNATURE,
		.desc = "ramdisk signature"
	},
	[COMPONENT_ID_RAMDISK] = {
		.type = COMPONENT_TYPE_LOAD,
		.desc = "initial ramdisk"
	},
	[COMPONENT_ID_ENVBLK] = {
		.type = COMPONENT_TYPE_LOAD,
		.desc = "environment blk",
		.fs_block_aligned = 1
	},
	[COMPONENT_ID_SEGMENT_FILE] = {
		.type  = COMPONENT_TYPE_EXECUTE,
		.desc = "segment file"
	}
};
