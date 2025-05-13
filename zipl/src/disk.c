/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions to handle disk layout specific operations
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/fiemap.h>
#include <linux/nvme_ioctl.h>
#include <linux/raid/md_u.h>
#include <assert.h>

#include "lib/util_proc.h"
#include "lib/util_sys.h"
#include "lib/util_libc.h"
#include "disk.h"
#include "error.h"
#include "install.h"
#include "job.h"
#include "misc.h"

/* from linux/hdregs.h */
#define HDIO_GETGEO		0x0301

#define DASD_IOCTL_LETTER	'D'
#define BIODASDINFO		_IOR(DASD_IOCTL_LETTER, 1, \
				     struct dasd_information)
#define DASD_PARTN_MASK		0x03
#define SCSI_PARTN_MASK		0x0f

/* Definitions for dasd device driver, taken from linux/include/asm/dasd.h */
struct dasd_information {
	unsigned int devno; 		/* S/390 devno */
	unsigned int real_devno; 	/* for aliases */
	unsigned int schid;		/* S/390 subchannel identifier */
	unsigned int cu_type : 16;	/* from SenseID */
	unsigned int cu_model : 8;	/* from SenseID */
	unsigned int dev_type : 16;	/* from SenseID */
	unsigned int dev_model : 8;	/* from SenseID */
	unsigned int open_count;
	unsigned int req_queue_len;
	unsigned int chanq_len; 	/* length of chanq */
	char type[4]; 			/* from discipline.name */
	unsigned int status; 		/* current device level */
	unsigned int label_block;	/* where to find the VOLSER */
	unsigned int FBA_layout; 	/* fixed block size (like AIXVOL) */
	unsigned int characteristics_size;
	unsigned int confdata_size;
	char characteristics[64];	/* from read_device_characteristics */
	char configuration_data[256];	/* from read_configuration_data */
};

static int
disk_determine_dasd_type(struct disk_info *data,
	struct dasd_information dasd_info)
{
	if (strncmp(dasd_info.type, "FBA ",4) == 0)
		data->type = disk_type_fba;
	else if (strncmp(dasd_info.type, "DIAG",4) == 0)
		data->type = disk_type_diag;
	else if (strncmp(dasd_info.type, "ECKD",4) == 0) {
		if (dasd_info.FBA_layout)
			data->type = disk_type_eckd_ldl;
		else
			data->type = disk_type_eckd_cdl;
	} else {
		error_reason("Unknown DASD type");
		return -1;
	}
	return 0;
}

static int
read_block_by_offset(int fd, int blksize, uint64_t offset, char *buffer)
{

	if (lseek(fd, offset, SEEK_SET) == -1) {
		/* Seek error. */
		error_text("Error: Could not seek to %llu: %s!\n",
			   (unsigned long long) offset);
		return -1;
	}

	misc_read(fd, buffer, blksize);

	return 0;
}

static int determine_virtblk_type(struct disk_info *data,
				  const struct stat *stats)
{
	char *device;
	char *buffer;
	int fd, rc, shift, sb;

	rc = 0;
	buffer = (char *) malloc(data->phy_block_size);
	if (!buffer)
		return -1;

	/*
	 * The geo.start value reported for virtblk devices is based on a
	 * 512 byte blocksize.
	 * For DASD devices it is based on the real (most likely 4k) blocksize
	 * and the DASD device driver reports a shifted value.
	 * For virtblk devices we need to shift the value manually according to
	 * the physical blocksize of the device.
	 */
	shift = 0;
	for (sb = 512; sb < data->phy_block_size; sb = sb << 1)
		shift++;

	if (data->geo.heads == 15) {
		/* assume DASD */
		data->partnum = stats->st_rdev & DASD_PARTN_MASK;
		data->device = stats->st_rdev & ~DASD_PARTN_MASK;

		rc = misc_temp_dev(data->device, 1, &device);
		if (rc)
			goto out_err;

		fd = open(device, O_RDONLY);

		/* read 3rd record, containing the volume label */
		read_block_by_offset(fd, data->phy_block_size,
				     2 * data->phy_block_size, buffer);
		misc_ebcdic_to_ascii((unsigned char *) buffer,
				     (unsigned char *) buffer + 4);
		/* determine dasd type by label */
		if (!strncmp(buffer, "VOL1", 4)) {
			data->type = disk_type_eckd_cdl;
			data->geo.start >>= shift;
		} else if (!strncmp(buffer, "LNX1", 4)) {
			data->type = disk_type_eckd_ldl;
			data->geo.start >>= shift;
		} else if (!strncmp(buffer, "CMS1", 4)) {
			data->type = disk_type_eckd_ldl;
			data->geo.start >>= shift;
		} else {
			/* DASD label was not found,
			 * type has to be specified by hand
			 */
			error_text("Failed to read DASD label, "
				   "please specify type manually");
			rc = -1;
		}
		close(fd);
		misc_free_temp_dev(device);
	} else {
		data->type = disk_type_scsi;
		data->partnum = stats->st_rdev & SCSI_PARTN_MASK;
		data->device = stats->st_rdev & ~SCSI_PARTN_MASK;
	}

out_err:
	free(buffer);
	return rc;
}

/**
 * Process a script output represented by FH and consisting
 * of pairs 'key=value' (each such pair is on a separate line).
 * Check its consistency and set the extracted target parameters
 * to the array of "targets" at TD.
 *
 * NOTE: this function defines specifications on valid output of
 * zipl helper scripts. See zipl-support-for-mirrored-devices.txt
 * for details. Before modifying this function, make sure that it
 * won't lead to format change.
 */
static int set_target_parameters(FILE *fh, struct job_target_data *td)
{
	int idx[LAST_TARGET_PARAM] = {0};
	struct target *t;
	char buffer[80];
	char value[40];
	char *error;
	int i;

	/**
	 * Process a stream of 'key=value' pairs and distribute
	 * them into groups.
	 * The i-th occurrence of some "key" in the stream means
	 * that the respective pair belongs to the group #i
	 */
	error = "Exceeded the maximum number of base disks";
	while (fgets(buffer, 80, fh)) {
		if (sscanf(buffer, "targetbase=%s", value) == 1) {
			t = target_at(td, idx[TARGET_BASE]++);
			if (!t)
				goto error;
			t->targetbase = misc_strdup(value);
			goto found;
		}
		if (sscanf(buffer, "targettype=%s", value) == 1) {
			t = target_at(td, idx[TARGET_TYPE]++);
			if (!t)
				goto error;
			type_from_target(value,	&t->targettype);
			goto found;
		}
		if (sscanf(buffer, "targetgeometry=%s", value) == 1) {
			t = target_at(td, idx[TARGET_GEOMETRY]++);
			if (!t)
				goto error;
			t->targetcylinders = atoi(strtok(value, ","));
			t->targetheads = atoi(strtok(NULL, ","));
			t->targetsectors = atoi(strtok(NULL, ","));
			goto found;
		}
		if (sscanf(buffer, "targetblocksize=%s", value) == 1) {
			t = target_at(td, idx[TARGET_BLOCKSIZE]++);
			if (!t)
				goto error;
			t->targetblocksize = atoi(value);
			goto found;
		}
		if (sscanf(buffer, "targetoffset=%s", value) == 1) {
			t = target_at(td, idx[TARGET_OFFSET]++);
			if (!t)
				goto error;
			t->targetoffset = atol(value);
			goto found;
		}
		continue;
found:
		t->check_params++;
	}
	/* Check for consistency */
	error = "Inconsistent script output";
	/*
	 * First, calculate total number of groups
	 */
	td->nr_targets = 0;
	for (i = 0; i < MAX_TARGETS; i++) {
		t = target_at(td, i);
		if (t->check_params == 0)
			break;
		td->nr_targets++;
	}
	if (!td->nr_targets)
		/* No keywords found in the stream */
		goto error;
	/*
	 * Each group has to include targetbase, targettype,
	 * targetblocksize and targetoffset.
	 */
	if (td->nr_targets != idx[TARGET_BASE] ||
	    td->nr_targets != idx[TARGET_TYPE] ||
	    td->nr_targets != idx[TARGET_BLOCKSIZE] ||
	    td->nr_targets != idx[TARGET_OFFSET])
		goto error;
	/*
	 * In addition, any group of "ECKD" type has to include
	 * targetgeometry
	 */
	for (i = 0; i < td->nr_targets; i++) {
		t = target_at(td, i);
		assert(t->check_params >= 4);
		if (disk_type_is_eckd(t->targettype) && t->check_params != 5)
			goto error;
	}
	return 0;
error:
	error_reason("%s", error);
	return -1;
}

static void print_base_disk_params(struct job_target_data *td, int index)
{
	disk_type_t type = get_targettype(td, index);

	if (!verbose)
		return;
	{
		fprintf(stderr, "Base disk '%s':\n", get_targetbase(td, index));
		fprintf(stderr, "  layout........: %s\n", disk_get_type_name(type));
	}
	if (disk_type_is_eckd(type)) {
		fprintf(stderr, "  heads.........: %u\n", get_targetheads(td, index));
		fprintf(stderr, "  sectors.......: %u\n", get_targetsectors(td, index));
		fprintf(stderr, "  cylinders.....: %u\n", get_targetcylinders(td, index));
	}
	{
		fprintf(stderr, "  start.........: %lu\n", get_targetoffset(td, index));
		fprintf(stderr, "  blksize.......: %u\n", get_targetblocksize(td, index));
	}
}

/**
 * Set disk info using ready target parameters provided either by
 * user, or by script
 */
static int disk_set_info_by_hint(struct job_target_data *td,
				 struct disk_info *data, int fd)
{
	int majnum, minnum;
	struct stat stats;
	int i;
	/*
	 * Currently multiple base disks with different parameters
	 * are not supported
	 */
	data->devno = -1;
	data->phy_block_size = get_targetblocksize(td, 0);
	data->type = get_targettype(td, 0);

	assert(td->nr_targets != 0);
	for (i = 1; i < td->nr_targets; i++) {
		if (data->type != get_targettype(td, i) ||
		    data->phy_block_size != get_targetblocksize(td, i)) {
			print_base_disk_params(td, 0);
			print_base_disk_params(td, i);
			error_reason("Inconsistent base disk geometry in target device");
			return -1;
		}
	}
	data->partnum = 0;
	data->targetbase_def = undefined;

	for (i = 0; i < td->nr_targets; i++) {
		definition_t defined_as;

		if (sscanf(get_targetbase(td, i),
			   "%d:%d", &majnum, &minnum) == 2) {
			data->basedisks[i] = makedev(majnum, minnum);
			defined_as = defined_as_device;
		} else {
			if (stat(get_targetbase(td, i), &stats)) {
				error_reason(strerror(errno));
				error_text("Could not get information for "
					   "file '%s'", get_targetbase(td, i));
				return -1;
			}
			if (!S_ISBLK(stats.st_mode)) {
				error_reason("Target base device '%s' is not "
					     "a block device",
					     get_targetbase(td, i));
				return -1;
			}
			data->basedisks[i] = stats.st_rdev;
			defined_as = defined_as_name;
		}
		if (data->targetbase_def != undefined &&
		    data->targetbase_def != defined_as) {
			error_reason("Target base disks are defined by different ways");
			return -1;
		}
		data->targetbase_def = defined_as;
	}
	if (data->type == disk_type_scsi && ioctl(fd, NVME_IOCTL_ID) >= 0)
		data->is_nvme = 1;
	return 0;
}

/**
 * Calculate target parameters in the case when no hints were provided
 */
static int disk_set_info_auto(struct disk_info *data,
			      const struct stat *stats, int fd)
{
	struct dasd_information dasd_info;

	if (ioctl(fd, BLKSSZGET, &data->phy_block_size)) {
		error_reason("Could not get blocksize");
		return -1;
	}
	if (!data->drv_name) {
		/* Driver name cannot be read */
		if (ioctl(fd, BIODASDINFO, &dasd_info)) {
			data->devno = -1;
			if (data->geo.start) {
				/* SCSI partition */
				data->type = disk_type_scsi;
				data->partnum = stats->st_rdev & SCSI_PARTN_MASK;
				data->device = stats->st_rdev & ~SCSI_PARTN_MASK;
			} else {
				/* SCSI disk */
				data->type = disk_type_scsi;
				data->partnum = 0;
				data->device = stats->st_rdev;
			}
		} else {
			/* DASD */
			data->devno = dasd_info.devno;
			if (disk_determine_dasd_type(data, dasd_info))
				return -1;
			data->partnum = stats->st_rdev & DASD_PARTN_MASK;
			data->device = stats->st_rdev & ~DASD_PARTN_MASK;
		}
	} else if (strcmp(data->drv_name, UTIL_PROC_DEV_ENTRY_DASD) == 0) {
		/* Driver name is 'dasd' */
		if (ioctl(fd, BIODASDINFO, &dasd_info)) {
			error_reason("Could not determine DASD type");
			return -1;
		}
		data->devno = dasd_info.devno;
		if (disk_determine_dasd_type(data, dasd_info))
			return -1;
		data->partnum = stats->st_rdev & DASD_PARTN_MASK;
		data->device = stats->st_rdev & ~DASD_PARTN_MASK;
	} else if (strcmp(data->drv_name, UTIL_PROC_DEV_ENTRY_SD) == 0) {
		/* Driver name is 'sd' */
		data->devno = -1;
		data->type = disk_type_scsi;
		data->partnum = stats->st_rdev & SCSI_PARTN_MASK;
		data->device = stats->st_rdev & ~SCSI_PARTN_MASK;

	} else if (strcmp(data->drv_name, UTIL_PROC_DEV_ENTRY_VIRTBLK) == 0) {
		/* Driver name is 'virtblk' */
		if (ioctl(fd, HDIO_GETGEO, &data->geo) != 0)
			perror("Could not retrieve disk geometry information.");
		if (ioctl(fd, BLKSSZGET, &data->phy_block_size) != 0)
			perror("Could not retrieve blocksize information.");

		if (determine_virtblk_type(data, stats)) {
			error_reason("Virtblk device type not clearly "
				     "determined.");
			return -1;
		}
	} else if (strcmp(data->drv_name, UTIL_PROC_DEV_ENTRY_BLKEXT) == 0 &&
		   ioctl(fd, NVME_IOCTL_ID) >= 0) {
		/* NVMe path, driver name is 'blkext' */
		data->devno = -1;
		data->type = disk_type_scsi;
		data->is_nvme = 1;

		if (util_sys_dev_is_partition(stats->st_rdev)) {
			if (util_sys_get_base_dev(stats->st_rdev, &data->device))
				return -1;
			data->partnum = util_sys_get_partnum(stats->st_rdev);
			if (data->partnum == -1)
				return -1;
		} else {
			data->device = stats->st_rdev;
			data->partnum = 0;
		}
	} else {
		/* Driver name is unknown */
		error_reason("Unsupported device driver '%s'", data->drv_name);
		return -1;
	}
	return 0;
}

/**
 * Evaluate and set source type
 */
static void set_source_type(struct job_target_data *td,
			    const char *drv_name, char **script_file)
{
	const char *script_prefix = util_libdir_path("zipl_helper.");
	struct stat script_stats;

	if (td->source == source_user) {
		/* do not reset user-specified target parameters */
		return;
	}
	/* Check if targetbase script is available */
	if (drv_name)
		misc_asprintf(script_file, "%s%s", script_prefix,
			      drv_name);
	else
		misc_asprintf(script_file, "%s", script_prefix);
	if (!stat(*script_file, &script_stats)) {
		/* target parameters to be evaluated by script */
		td->source = source_script;
		return;
	}
	td->source = source_auto;
}

static void set_driver_name(int fd, struct disk_info *info, dev_t device)
{
	struct util_proc_dev_entry dev_entry;

	if (info->drv_name)
		/* already set */
		return;
	if (util_proc_dev_get_entry(device, 1, &dev_entry) == 0) {
		mdu_array_info_t array;

		if (strcmp(dev_entry.name, UTIL_PROC_DEV_ENTRY_BLKEXT) == 0 &&
		    ioctl(fd, GET_ARRAY_INFO, &array) >= 0)
			/*
			 * Driver name is 'blkext',
			 * it is actually an md-partition
			 */
			info->drv_name = misc_strdup(UTIL_PROC_DEV_ENTRY_MD);
		else
			info->drv_name = misc_strdup(dev_entry.name);
		util_proc_dev_free_entry(&dev_entry);
	} else {
		misc_warn_on_failed_pdge(device);
	}
}

static int run_targetbase_script(struct job_target_data *td,
				 char *script_file, struct stat *stats)
{
	char *ppn_cmd = NULL;
	FILE *fh;

	misc_asprintf(&ppn_cmd, "%s %d:%d", script_file,
		      major(stats->st_rdev), minor(stats->st_rdev));
	printf("Run %s\n", ppn_cmd);
	fh = popen(ppn_cmd, "r");
	free(ppn_cmd);

	if (!fh) {
		error_reason("Failed to run popen(%s,\"r\",)");
		return -1;
	}
	/* translate the script output to target parameters */
	if (set_target_parameters(fh, td)) {
		pclose(fh);
		return -1;
	}
	switch (pclose(fh)) {
	case 0:
		/* success */
		return 0;
	case -1:
		error_reason("Failed to run pclose");
		return -1;
	default:
		error_reason("Script could not determine target "
			     "parameters");
		return -1;
	}
}

/**
 * Set disk geometry using target parameters provided either by
 * user, or by script.
 *
 * Note: geo.start contains a sector number offset measured in
 * physical blocks, not sectors (512 bytes)
 */
static int disk_set_geometry_by_hint(struct job_target_data *td,
				     struct disk_info *data)
{
	int i;
	/*
	 * Currently multiple base disks with different parameters
	 * are not supported
	 */
	data->geo.heads = get_targetheads(td, 0);
	data->geo.sectors = get_targetsectors(td, 0);
	data->geo.cylinders = get_targetcylinders(td, 0);
	data->geo.start = get_targetoffset(td, 0);

	assert(td->nr_targets != 0);
	for (i = 1; i < td->nr_targets; i++) {
		if (data->geo.heads     != get_targetheads(td, i) ||
		    data->geo.sectors   != get_targetsectors(td, i) ||
		    data->geo.cylinders != get_targetcylinders(td, i) ||
		    data->geo.start     != get_targetoffset(td, i)) {
			print_base_disk_params(td, 0);
			print_base_disk_params(td, i);
			error_reason("Inconsistent base disk geometry in target device");
			return -1;
		}
	}
	return 0;
}

static int disk_set_geometry_auto(int fd, struct disk_info *info)
{
	if (ioctl(fd, HDIO_GETGEO, &info->geo)) {
		error_reason("Could not get disk geometry");
		return -1;
	}
	return 0;
}

/**
 * The final step of setting disk info.
 * Common for all source types
 *
 * DATA: disk info to be completed
 * Pre-condition: disk type is already known and set at DATA->type
 */
static int disk_set_info_complete(struct job_target_data *td,
				  struct disk_info *data,
				  struct stat *stats, int fd)
{
	struct util_proc_part_entry part_entry;
	long devsize;

	/* Get size of device in sectors (512 byte) */
	if (ioctl(fd, BLKGETSIZE, &devsize)) {
		error_reason("Could not get device size");
		return -1;
	}
	/* Check for valid CHS geometry data. */
	if (disk_type_is_eckd(data->type) && (data->geo.cylinders == 0 ||
	    data->geo.heads == 0 || data->geo.sectors == 0)) {
		error_reason("Invalid disk geometry (CHS=%d/%d/%d)",
			     data->geo.cylinders, data->geo.heads,
			     data->geo.sectors);
		return -1;
	}
	/* Convert device size to size in physical blocks */
	data->phy_blocks = devsize / (data->phy_block_size / 512);
	/*
	 * Adjust start on SCSI according to block_size.
	 * device-mapper devices, which are evaluated only
	 * in "source_script" mode, are skipped
	 */
	if (data->type == disk_type_scsi && td->source == source_auto)
		data->geo.start =
			data->geo.start / (data->phy_block_size / 512);
	if (data->partnum != 0)
		data->partition = stats->st_rdev;
	/* Try to get device name */
	if (util_proc_part_get_entry(data->device, &part_entry) == 0) {
		data->name = misc_strdup(part_entry.name);
		util_proc_part_free_entry(&part_entry);
		if (data->name == NULL)
			return -1;
	}
	/* Initialize file system block size with invalid value */
	data->fs_block_size = -1;
	return 0;
}

/**
 * Prepare INFO required to perform IPL installation on physical disks
 * participating in the logical DEVICE.
 * Preparation is performed in 2 steps:
 *
 * 1. Find out a set of physical "base" disks participating in the
 *    logical DEVICE. For each found disk calculate "target" parameters
 *    (type, geometry, physical block size, data offset, etc) and store
 *    it in the array of "targets" of TD;
 * 2. Complete INFO using the found base disks and calculated target
 *    parameters.
 *
 * TD: optionally contains target parameters specified by user via
 * config file, or special "target options" of zipl tool.
 * If target parameters were specified by user, then the step 1 above
 * is skipped.

 * To exclude any user assumptions about the DEVICE, this function
 * should be called with TD pointing to a zeroed structure.
 *
 * DEVICE: logical, or physical device, optionally formatted with a
 * file system.
 */
int disk_get_info(const char *device, struct job_target_data *td,
		  struct disk_info **info)
{
	char *script_file = NULL;
	struct disk_info *data;
	struct stat stats;
	int fd;

	if (stat(device, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
	fd = open(device, O_RDONLY);
	if (fd == -1) {
		error_reason(strerror(errno));
		return -1;
	}
	data = (struct disk_info *)misc_malloc(sizeof(struct disk_info));
	if (!data)
		goto error;
	memset((void *)data, 0, sizeof(struct disk_info));
	set_driver_name(fd, data, stats.st_rdev);
	set_source_type(td, data->drv_name, &script_file);
	switch (td->source) {
	case source_script:
		if (run_targetbase_script(td, script_file, &stats))
			goto error;
		/* target parameters were set by the script output */
		assert(target_parameters_are_set(td));

		if (disk_set_geometry_by_hint(td, data))
			goto error;
		if (disk_set_info_by_hint(td, data, fd))
			goto error;
		data->device = stats.st_rdev;
		break;
	case source_user:
		/*
		 * target parameters were specified by user via
		 * "target" options
		 */
		assert(target_parameters_are_set(td));

		if (disk_set_geometry_by_hint(td, data))
			goto error;
		if (disk_set_info_by_hint(td, data, fd))
			goto error;
		/*
		 * multiple base disks are not supported
		 * with this source type
		 */
		assert(td->nr_targets == 1);
		data->device = data->basedisks[0];
		break;
	case source_auto:
		/* no ready target parameters are available */
		if (disk_set_geometry_auto(fd, data))
			goto error;
		if (disk_set_info_auto(data, &stats, fd))
			goto error;
		/*
		 * multiple base disks are not supported
		 * with this source type
		 */
		data->basedisks[0] = data->device;
		td->nr_targets = 1;
		break;
	default:
		assert(0);
	}
	if (disk_set_info_complete(td, data, &stats, fd))
		goto error;
	free(script_file);
	close(fd);
	*info = data;
	return 0;
error:
	free(script_file);
	close(fd);
	free(data);
	return -1;
}

int
disk_is_tape(const char* device)
{
	int fd, rc = 0;

	/* Check for tape */
	fd = open(device, O_RDWR);
	if (fd == -1)
		return 0;
	if (rewind_tape(fd) == 0)
		rc = 1;
	fsync(fd);
	close(fd);
	return rc;
}

/**
 * Get "extended type" of base disk by logical DEVICE
 *
 * This function may fail for various reasons. E.g. in case when
 * DEVICE is not eligible for boot record installation (not a
 * partition, etc). In case of success the resulted disk type is
 * stored in EXT_TYPE.
 */
int disk_get_ext_type(const char *device, struct disk_ext_type *ext_type)
{
	struct job_target_data tmp = {.source = source_unknown};
	struct disk_info *info;

	if (disk_get_info(device, &tmp, &info))
		return -1;
	ext_type->type = info->type;
	ext_type->is_nvme = info->is_nvme;

	disk_free_info(info);
	free_target_data(&tmp);
	return 0;
}

int disk_type_is_scsi(struct disk_ext_type *ext_type)
{
	return ext_type->type == disk_type_scsi;
}

int disk_type_is_eckd_ldl(struct disk_ext_type *ext_type)
{
	return ext_type->type == disk_type_eckd_ldl;
}

int disk_type_is_nvme(struct disk_ext_type *ext_type)
{
	return ext_type->is_nvme;
}

int disk_type_is_eckd(disk_type_t type)
{
	return (type == disk_type_eckd_ldl ||
		type == disk_type_eckd_cdl);
}

/**
 * Retrieve and set block size of the file system which contains FILENAME
 */
int disk_info_set_fs_block(const char *filename, struct disk_info *info)
{
	int blocksize;
	int fd;
	int rc;

	/* Retrieve file system block size */
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		error_reason(strerror(errno));
		return -1;
	}
	rc = ioctl(fd, FIGETBSZ, &blocksize);
	close(fd);
	if (rc == -1) {
		error_reason("Could not get file system block size for '%s'",
			     filename);
		return -1;
	}
	info->fs_block_size = blocksize;
	return 0;
}

/**
 * Retrieve disk info of the device which contains FILENAME
 * and set the filesystem block size
 */
int disk_get_info_from_file(const char *filename,
			    struct job_target_data *target,
			    struct disk_info **info)
{
	struct stat stats;
	char *device;

	if (stat(filename, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
	if (misc_temp_dev(stats.st_dev, 1, &device))
		return -1;
	if (disk_get_info(device, target, info)) {
		misc_free_temp_dev(device);
		return -1;
	}
	misc_free_temp_dev(device);
	return disk_info_set_fs_block(filename, *info);
}

void disk_free_info(struct disk_info *info)
{
	if (!info)
		return;
	if (info->name)
		free(info->name);
	if (info->drv_name)
		free(info->drv_name);
	free(info);
}

/* Retrieve the physical blocknumber (block on disk) of the specified logical
 * block (block in file). FD provides the file descriptor, LOGICAL is the
 * logical block number. Upon success, return 0 and store the physical
 * blocknumber in the variable pointed to by PHYSICAL. Return non-zero
 * otherwise. */
static int
disk_get_blocknum(int fd, int fd_is_basedisk, blocknum_t logical,
		  blocknum_t* physical, struct disk_info* info)
{
	blocknum_t phy_per_fs;
	blocknum_t mapped;
	int subblock;

	/* No file system: partition or raw disk */
	if (info->fs_block_size == -1) {
		if (fd_is_basedisk)
			*physical = logical;
		else
			*physical = logical + info->geo.start;
		return 0;
	}
	/*
	 * Get mapping in file system blocks
	 */
	phy_per_fs = info->fs_block_size / info->phy_block_size;
	subblock = logical % phy_per_fs;

	if (fs_map(fd, logical * info->phy_block_size,
		   &mapped, info->fs_block_size) != 0)
		return -1;
	if (mapped == 0) {
		/* This is a hole in the file */
		*physical = 0;
	} else {
		/* Convert file system block to physical */
		*physical = mapped * phy_per_fs + subblock;
		/* Add partition start */
		*physical += info->geo.start;
	}
	return 0;
}


/* Return the cylinder on which the block number BLOCKNUM is stored on the
 * CHS device identified by INFO. */
int
disk_cyl_from_blocknum(blocknum_t blocknum, struct disk_info* info)
{
	return blocknum / (info->geo.heads * info->geo.sectors);
}


/* Return the head on which the block number BLOCKNUM is stored on the
 * CHS device identified by INFO. */
int
disk_head_from_blocknum(blocknum_t blocknum, struct disk_info* info)
{
	return (blocknum / info->geo.sectors) % info->geo.heads;
}


/* Return the sector on which the block number BLOCKNUM is stored on the
 * CHS device identified by INFO. */
int
disk_sec_from_blocknum(blocknum_t blocknum, struct disk_info* info)
{
	return blocknum % info->geo.sectors + 1;
}


/* Create a block pointer in memory at location PTR which represents the
 * given blocknumber BLOCKNUM. INFO provides information about the disk
 * layout. */
void
disk_blockptr_from_blocknum(disk_blockptr_t* ptr, blocknum_t blocknum,
			    struct disk_info* info)
{
	switch (info->type) {
	case disk_type_scsi:
	case disk_type_fba:
	case disk_type_diag:
		ptr->linear.block = blocknum;
		ptr->linear.size = info->phy_block_size;
		ptr->linear.blockct = 0;
		break;
	case disk_type_eckd_ldl:
	case disk_type_eckd_cdl:
		if (blocknum == 0) {
			/* Special case: zero blocknum will be expanded to
			 * size * (blockct+1) bytes of zeroes. */
			ptr->chs.cyl = 0;
			ptr->chs.head = 0;
			ptr->chs.sec = 0;
		} else {

			ptr->chs.cyl = disk_cyl_from_blocknum(blocknum, info);
			ptr->chs.head = disk_head_from_blocknum(blocknum,
								info);
			ptr->chs.sec = disk_sec_from_blocknum(blocknum, info);
		}
		ptr->chs.size = info->phy_block_size;
		ptr->chs.blockct = 0;
		break;
	}
}

/**
 * Write BYTECOUNT bytes of data from memory at location DATA as a block to
 * the file identified by file descriptor FD at the current position in that
 * file aligned on ALIGN block size boundary and make sure that at most
 * INFO->PHY_BLOCK_SIZE bytes are written. INFO provides information about
 * the disk layout. Upon success, store the pointer to the resulting disk
 * block to BLOCK (if BLOCK is not NULL) and return 0. Return non-zero
 * otherwise. On success OFFSET contains offset of the first written byte
 */
static int
disk_write_block_aligned_base(struct misc_fd *mfd, int is_base_disk, const void *data,
			      size_t bytecount, disk_blockptr_t *block,
			      struct disk_info *info, int align, off_t *offset)
{
	blocknum_t current_block;
	blocknum_t blocknum;
	off_t current_pos;

	if (align == 0)
		align = info->phy_block_size;

	current_pos = lseek(mfd->fd, 0, SEEK_CUR);
	if (current_pos == -1) {
		error_text(strerror(errno));
		return -1;
	}
	/* Ensure block alignment of current file pos */

	if (current_pos % align != 0) {
		current_pos = lseek(mfd->fd, align - current_pos % align, SEEK_CUR);
		if (current_pos == -1) {
	       		error_text(strerror(errno));
			return -1;
		}
	}
	current_block = current_pos / info->phy_block_size;
	/* Ensure maximum size */
	if (bytecount > (size_t)info->phy_block_size)
		bytecount = info->phy_block_size;
	/* Write data block */
	if (misc_write_or_simulate(mfd, data, bytecount))
		return -1;
	if (block != NULL) {
		/* Store block pointer */
		if (disk_get_blocknum(mfd->fd, is_base_disk, current_block,
				      &blocknum, info))
			return -1;
		disk_blockptr_from_blocknum(block, blocknum, info);
	}
	if (offset)
		*offset = current_pos;
	return 0;
}

int disk_write_block_aligned(struct misc_fd *mfd, const void *data, size_t bytecount,
			     disk_blockptr_t *block, struct disk_info *info)
{
	return disk_write_block_aligned_base(mfd, 0, data, bytecount, block,
					     info, info->phy_block_size, NULL);
}

/**
 * Write BYTECOUNT bytes from memory at location BUFFER to the file identified
 * by file descriptor FD at the current position in that file aligned on ALIGN
 * block size boundary and return the list of pointers to the disk blocks that
 * make up the respective part of the file. Upon success return the number of
 * blocks, set BLOCKLIST to point to the uncompressed list, and store offset of
 * the first written byte in OFFSET (if OFFSET is not NULL). Return zero
 * otherwise.
 */
blocknum_t
disk_write_block_buffer_align(struct misc_fd *mfd, int fd_is_basedisk, const void *buffer,
			      size_t bytecount, disk_blockptr_t **blocklist,
			      struct disk_info *info, int align, off_t *offset)
{
	blocknum_t count;
	blocknum_t i;
	size_t written;
	size_t chunk_size;
	off_t pos;
	int rc;

	count = (bytecount + info->phy_block_size - 1) / info->phy_block_size;
	*blocklist = (disk_blockptr_t *)util_zalloc(sizeof(disk_blockptr_t) *
						    count);

	if (*blocklist == NULL) {
		misc_close(mfd);
		return 0;
	}
	/* Build list */
	for (i=0, written=0; i < count; i++, written += chunk_size) {
		chunk_size = bytecount - written;
		if (chunk_size > (size_t) info->phy_block_size)
			chunk_size = info->phy_block_size;
		rc = disk_write_block_aligned_base(mfd, fd_is_basedisk,
					VOID_ADD(buffer, written),
					chunk_size, &(*blocklist)[i],
					info,
					i == 0 ? align : info->phy_block_size,
					&pos);
		if (rc)
			return 0;
		if (offset != NULL && i == 0)
			*offset = pos;
	}
	return count;
}

blocknum_t
disk_write_block_buffer(struct misc_fd *mfd, int fd_is_basedisk, const void *buffer,
			size_t bytecount, disk_blockptr_t **blocklist,
			struct disk_info *info)
{
	return disk_write_block_buffer_align(mfd, fd_is_basedisk, buffer,
					     bytecount, blocklist, info,
					     info->phy_block_size, NULL);
}

/* Print device node. */
void
disk_print_devt(dev_t d)
{
	printf("%02x:%02x", major(d), minor(d));
}

void disk_print_devname(dev_t dev)
{
	struct util_proc_part_entry part_entry;

	if (!util_proc_part_get_entry(dev, &part_entry)) {
		printf("%s", part_entry.name);
		util_proc_part_free_entry(&part_entry);
	} else {
		disk_print_devt(dev);
	}
}

void prepare_footnote_ptr(int source, char *ptr)
{
	if (source == source_user || source == source_script)
		strcpy(ptr, " *)");
	else
		strcpy(ptr, "");
}

void print_footnote_ref(int source, const char *prefix)
{
	if (source == source_user)
		printf("%s*) Data provided by user.\n", prefix);
	else if (source == source_script)
		printf("%s*) Data provided by script.\n", prefix);
}

/* Return a name for a given disk TYPE. */
char *
disk_get_type_name(disk_type_t type)
{
	switch (type) {
	case disk_type_scsi:
		return "SCSI disk layout";
	case disk_type_fba:
		return "FBA disk layout";
	case disk_type_diag:
		return "DIAG disk layout";
	case disk_type_eckd_ldl:
		return "ECKD/linux disk layout";
	case disk_type_eckd_cdl:
		return "ECKD/compatible disk layout";
	default:
		return "Unknown disk type";
	}
}

/* Return IPL types supported for a given disk TYPE */
char *disk_get_ipl_type(disk_type_t type, int is_dump)
{
	switch (type) {
	case disk_type_scsi:
		return "LD-";
	case disk_type_fba:
	case disk_type_eckd_ldl:
		return "CCW-";
	case disk_type_eckd_cdl:
		return is_dump ? "LD-" : "CCW- and LD-";
	default:
		return "";
	}
}

/* Return non-zero for ECKD large volumes. */
int
disk_is_large_volume(struct disk_info* info)
{
	return (info->type == disk_type_eckd_ldl ||
		info->type == disk_type_eckd_cdl) &&
		info->geo.cylinders == 0xfffe;
}


/* Print textual representation of INFO contents. */
void disk_print_info(struct disk_info *info, int source)
{
	char footnote[4] = "";

	prepare_footnote_ptr(source, footnote);
	printf("  Device..........................: ");
	disk_print_devt(info->device);
	if (info->targetbase_def == defined_as_device)
		printf("%s", footnote);
	printf("\n");
	if (info->partnum != 0) {
		printf("  Partition.......................: ");
		disk_print_devt(info->partition);
		printf("\n");
	}
	if (info->name) {
		printf("  Device name.....................: %s",
		       info->name);
		if (info->targetbase_def == defined_as_name)
			printf("%s", footnote);
		printf("\n");
	}
	if (info->drv_name) {
		printf("  Device driver name..............: %s\n",
		       info->drv_name);
	}
	if (((info->type == disk_type_fba) ||
	     (info->type == disk_type_diag) ||
	     (info->type == disk_type_eckd_ldl) ||
	     (info->type == disk_type_eckd_cdl)) &&
	     (source == source_auto)) {
		printf("  DASD device number..............: %04x\n",
		       info->devno);
	}
	printf("  Type............................: disk %s\n",
	       (info->partnum != 0) ? "partition" : "device");
	printf("  Disk layout.....................: %s%s\n",
	       disk_get_type_name(info->type), footnote);
	if (disk_type_is_eckd(info->type)) {
		printf("  Geometry - heads................: %d%s\n",
		       info->geo.heads, footnote);
		printf("  Geometry - sectors..............: %d%s\n",
		       info->geo.sectors, footnote);
		if (disk_is_large_volume(info)) {
			/* ECKD large volume. There is not enough information
			 * available in INFO to calculate disk cylinder size. */
			printf("  Geometry - cylinders............: > 65534\n");
		} else {
			printf("  Geometry - cylinders............: %d%s\n",
			       info->geo.cylinders, footnote);
		}
	}
	printf("  Geometry - start................: %ld%s\n",
	       info->geo.start, footnote);
	if (info->fs_block_size >= 0)
		printf("  File system block size..........: %d\n",
		       info->fs_block_size);
	printf("  Physical block size.............: %d%s\n",
	       info->phy_block_size, footnote);
	printf("  Device size in physical blocks..: %ld\n",
	       (long) info->phy_blocks);
	print_footnote_ref(source, "  ");
}

/* Check whether a block is a zero block which identifies a hole in a file.
 * Return non-zero if BLOCK is a zero block, 0 otherwise. */
int
disk_is_zero_block(disk_blockptr_t* block, struct disk_info* info)
{
	switch (info->type) {
	case disk_type_scsi:
	case disk_type_fba:
		return block->linear.block == 0;
	case disk_type_eckd_ldl:
	case disk_type_eckd_cdl:
		return (block->chs.cyl == 0) && (block->chs.head == 0) &&
		       (block->chs.sec == 0);
	default:
		break;
	}
	return 0;
}


#define DASD_MAX_LINK_COUNT	255
#define SCSI_MAX_LINK_COUNT	65535

/* Check whether two block pointers FIRST and SECOND can be merged into
 * one block pointer by increasing the block count field of the first
 * pointer. INFO provides information about the disk type. Return non-zero if
 * blocks can be merged, 0 otherwise. */
static int
can_merge_blocks(disk_blockptr_t* first, disk_blockptr_t* second,
		 struct disk_info* info)
{
	int max_count;

	/* Zero blocks can never be merged */
	if (disk_is_zero_block(first, info) || disk_is_zero_block(second, info))
		return 0;
	if (info->type == disk_type_scsi)
		max_count = SCSI_MAX_LINK_COUNT;
	else
		max_count = DASD_MAX_LINK_COUNT;
	switch (info->type) {
	case disk_type_scsi:
	case disk_type_fba:
		/* Check link count limits */
		if (((int) first->linear.blockct) +
		    ((int) second->linear.blockct) + 1 > max_count)
		       return 0;
		if (first->linear.block + first->linear.blockct + 1 ==
		    second->linear.block)
			return 1;
		break;
	case disk_type_eckd_ldl:
	case disk_type_eckd_cdl:
		/* Check link count limits */
		if (((int) first->chs.blockct) +
		    ((int) second->chs.blockct) + 1 > max_count)
		       return 0;
		if ((first->chs.cyl == second->chs.cyl) &&
		    (first->chs.head == second->chs.head) &&
		    (first->chs.sec + first->chs.blockct + 1 ==
		     second->chs.sec))
			return 1;
		break;
	case disk_type_diag:
		break;
	}
	return 0;
}


/* Merge two block pointers FIRST and SECOND into one pointer. The resulting
 * pointer is stored in FIRST. INFO provides information about the disk
 * type. */
static void
merge_blocks(disk_blockptr_t* first, disk_blockptr_t* second,
	     struct disk_info* info)
{
	switch (info->type) {
	case disk_type_scsi:
	case disk_type_fba:
		first->linear.blockct += second->linear.blockct + 1;
		break;
	case disk_type_eckd_ldl:
	case disk_type_eckd_cdl:
		first->chs.blockct += second->chs.blockct + 1;
		break;
	case disk_type_diag:
		/* Should not happen */
		break;
	}
}


/* Analyze COUNT elements in LIST and try to merge pointers to adjacent
 * blocks. INFO provides information about the disk type. Return the new
 * number of elements in the list. */
blocknum_t
disk_compact_blocklist(disk_blockptr_t* list, blocknum_t count,
		       struct disk_info* info)
{
	blocknum_t i;
	blocknum_t last;

	if (count < 2)
		return count;
	for (i=1, last=0; i < count; i++) {
		if (can_merge_blocks(&list[last], &list[i], info)) {
			merge_blocks(&list[last], &list[i], info);
		} else {
			list[++last] = list[i];
		}
	}
	return last + 1;
}

/**
 * Retrieve a list of pointers to the disk blocks that make up a continuous
 * region REG in a file specified by FILENAME. If REG is NULL, then retrieve
 * a list of pointers for the whole file.
 * Upon success, return the number of blocks and set BLOCKLIST to point to
 * the uncompacted list. INFO provides information about the device which
 * contains the file. Return zero otherwise
 */
blocknum_t
disk_get_blocklist_from_file(const char *filename, struct file_range *reg,
			     disk_blockptr_t **blocklist,
			     struct disk_info* info)
{
	struct stat stats;
	int fd;
	off_t off;
	size_t count;
	blocknum_t blk_off;
	blocknum_t blk_count;
	blocknum_t i;
	blocknum_t blocknum;

	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		error_reason(strerror(errno));
		error_text("Could not open file '%s'", filename);
		return 0;
	}
	if (fstat(fd, &stats)) {
		error_reason(strerror(errno));
		error_text("Could not get information for file '%s'",
			   filename);
		close (fd);
		return 0;
	}
	if (reg) {
		/*
		 * case of not block-aligned offsets is not implemented
		 */
		assert(reg->offset % info->phy_block_size == 0);

		off = reg->offset;
		count = reg->len;
	} else {
		off = 0;
		count = stats.st_size;
	}
	assert(off < stats.st_size);

	if (off + count > (size_t)stats.st_size)
		count = stats.st_size - off;

	blk_off = off / info->phy_block_size;
	blk_count = ((blocknum_t) count +
		     info->phy_block_size - 1) / info->phy_block_size;

	*blocklist = (disk_blockptr_t *)util_zalloc(sizeof(disk_blockptr_t) *
						    blk_count);
	if (*blocklist == NULL) {
		close(fd);
		return 0;
	}
	/* Build list */
	for (i = 0; i < blk_count; i++) {
		if (disk_get_blocknum(fd, 0, blk_off + i, &blocknum, info)) {
			close(fd);
			return 0;
		}
		disk_blockptr_from_blocknum(&(*blocklist)[i], blocknum, info);
	}
	close(fd);
	return blk_count;
}

/* Check whether input device is in subchannel set 0.
 * Path to "dev" attribute containing the major/minor number depends on
 * whether option CONFIG_SYSFS_DEPRECATED is set or not */

int disk_check_subchannel_set(int devno, dev_t device, char* dev_name)
{
	struct dirent *direntp;
	DIR* fdd;
	static const char sys_bus_ccw_dev_filename[] = "/sys/bus/ccw/devices";
	char dev_file[PATH_MAX];
	char *buffer;
	int minor, major;

	snprintf(dev_file, PATH_MAX, "%s/0.0.%04x", sys_bus_ccw_dev_filename,
		 devno);
	fdd = opendir(dev_file);
	if (!fdd)
		goto out_with_warning;
	while ((direntp = readdir(fdd)))
		if (strncmp(direntp->d_name, "block:", 6) == 0)
			break;
	if (direntp != NULL)
		snprintf(dev_file, PATH_MAX, "%s/0.0.%04x/%s/dev",
			 sys_bus_ccw_dev_filename, devno, direntp->d_name);
	else {
		closedir(fdd);
		snprintf(dev_file, PATH_MAX, "%s/0.0.%04x/block",
			 sys_bus_ccw_dev_filename, devno);
		fdd = opendir(dev_file);
		if (!fdd)
			goto out_with_warning;
		while ((direntp = readdir(fdd)))
			if (strncmp(direntp->d_name, "dasd", 4) == 0)
				break;
		if (direntp == NULL)
			goto out_with_warning;
		snprintf(dev_file, PATH_MAX, "%s/0.0.%04x/block/%s/dev",
			 sys_bus_ccw_dev_filename, devno, direntp->d_name);
	}
	closedir(fdd);
	if (misc_read_special_file(dev_file, &buffer, NULL, 1))
		goto out_with_warning;
	if (sscanf(buffer, "%i:%i", &major, &minor) != 2) {
		free(buffer);
		goto out_with_warning;
	}
	free(buffer);
	if (makedev(major, minor) != device) {
		error_reason("Dump target '%s' must belong to "
			     "subchannel set 0.", dev_name);
		return -1;
	}
	return 0;
out_with_warning:
	fprintf(stderr, "Warning: Could not determine whether dump target %s "
		"belongs to subchannel set 0.\n", dev_name);
	return 0;
}
