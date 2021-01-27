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
#include <linux/fiemap.h>

#include "lib/util_proc.h"
#include "lib/util_sys.h"

#include "disk.h"
#include "error.h"
#include "install.h"
#include "job.h"
#include "misc.h"

/* from linux/fs.h */
#define FIBMAP			_IO(0x00,1)
#define FIGETBSZ		_IO(0x00,2)
#define BLKGETSIZE		_IO(0x12,96)
#define BLKSSZGET		_IO(0x12,104)

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

/* Return non-zero for ECKD type. */
int
disk_is_eckd(disk_type_t type)
{
	return (type == disk_type_eckd_ldl ||
		type == disk_type_eckd_cdl);
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

int
determine_virtblk_type(struct disk_info *data, struct stat *stats)
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

int
disk_get_info(const char* device, struct job_target_data* target,
	      struct disk_info** info)
{
	struct stat stats;
	struct stat script_stats;
	struct util_proc_part_entry part_entry;
	struct util_proc_dev_entry dev_entry;
	struct dasd_information dasd_info;
	struct disk_info *data;
	int fd;
	long devsize;
	FILE *fh;
	char *script_pre = TOOLS_LIBDIR "/zipl_helper.";
	char *script_file = NULL;
	char *ppn_cmd = NULL;
	char buffer[80];
	char value[40];
	int majnum, minnum;
	int checkparm;

	/* Get file information */
	if (stat(device, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
	/* Open device file */
	fd = open(device, O_RDONLY);
	if (fd == -1) {
		error_reason(strerror(errno));
		return -1;
	}
	/* Get memory for result */
	data = (struct disk_info *) misc_malloc(sizeof(struct disk_info));
	if (data == NULL) {
		close(fd);
		return -1;
	}
	memset((void *) data, 0, sizeof(struct disk_info));
	/* Try to get device driver name */
	if (util_proc_dev_get_entry(stats.st_rdev, 1, &dev_entry) == 0) {
		data->drv_name = misc_strdup(dev_entry.name);
		util_proc_dev_free_entry(&dev_entry);
	} else {
		fprintf(stderr, "Warning: Could not determine driver name for "
			"major %d from /proc/devices\n", major(stats.st_rdev));
		fprintf(stderr, "Warning: Preparing a logical device for boot "
			"might fail\n");
	}
	data->source = source_user;
	/* Check if targetbase script is available */
	if (data->drv_name)
		misc_asprintf(&script_file, "%s%s", script_pre, data->drv_name);
	else
		misc_asprintf(&script_file, "%s", script_pre);
	if ((target->targetbase == NULL) &&
	    (!stat(script_file, &script_stats))) {
		data->source = source_script;
		/* Run targetbase script */
		if (target->bootmap_dir == NULL) {
			/* happens in case of partition dump */
			misc_asprintf(&ppn_cmd, "%s %d:%d",
				      script_file, major(stats.st_rdev),
				      minor(stats.st_rdev));
		} else {
			misc_asprintf(&ppn_cmd, "%s %s",
				      script_file, target->bootmap_dir);
		}
		printf("Run %s\n", ppn_cmd);
		fh = popen(ppn_cmd, "r");
		if (fh == NULL) {
			error_reason("Failed to run popen(%s,\"r\",)");
			goto out_close;
		}
		checkparm = 0;
		while (fgets(buffer, 80, fh) != NULL) {
			if (sscanf(buffer, "targetbase=%s", value) == 1) {
				target->targetbase = misc_strdup(value);
				checkparm++;
			}
			if (sscanf(buffer, "targettype=%s", value) == 1) {
				type_from_target(value, &target->targettype);
				checkparm++;
			}
			if (sscanf(buffer, "targetgeometry=%s", value) == 1) {
				target->targetcylinders =
					atoi(strtok(value, ","));
				target->targetheads = atoi(strtok(NULL, ","));
				target->targetsectors = atoi(strtok(NULL, ","));
				checkparm++;
			}
			if (sscanf(buffer, "targetblocksize=%s", value) == 1) {
				target->targetblocksize = atoi(value);
				checkparm++;
			}
			if (sscanf(buffer, "targetoffset=%s", value) == 1) {
				target->targetoffset = atol(value);
				checkparm++;
			}
		}
		switch (pclose(fh)) {
		case 0 :
			/* success */
			break;
		case -1 :
			error_reason("Failed to run pclose");
			goto out_close;
		default :
			error_reason("Script could not determine target "
				     "parameters");
			goto out_close;
		}
		if ((!disk_is_eckd(target->targettype) && checkparm < 4) ||
		    (disk_is_eckd(target->targettype) && checkparm != 5)) {
			error_reason("Target parameters missing from script");
			goto out_close;
		}
	}

	/* Get disk geometry. Note: geo.start contains a sector number
	 * offset measured in physical blocks, not sectors (512 bytes) */
	if (target->targetbase != NULL) {
		data->geo.heads     = target->targetheads;
		data->geo.sectors   = target->targetsectors;
		data->geo.cylinders = target->targetcylinders;
		data->geo.start     = target->targetoffset;
	} else {
		data->source = source_auto;
		if (ioctl(fd, HDIO_GETGEO, &data->geo)) {
			error_reason("Could not get disk geometry");
			goto out_close;
		}
	}
	if ((data->source == source_user) || (data->source == source_script)) {
		data->devno = -1;
		data->phy_block_size = target->targetblocksize;
		data->type = target->targettype;
		data->partnum = 0;
		/* Get file information */
		if (sscanf(target->targetbase, "%d:%d", &majnum, &minnum)
		    == 2) {
			data->device = makedev(majnum, minnum);
			data->targetbase = defined_as_device;
			data->partnum = minor(stats.st_rdev) - minnum;
		}
		else {
			if (stat(target->targetbase, &stats)) {
				error_reason(strerror(errno));
				error_text("Could not get information for "
					   "file '%s'", target->targetbase);
				goto out_close;
			}
			if (!S_ISBLK(stats.st_mode)) {
				error_reason("Target base device '%s' is not "
					     "a block device",
					     target->targetbase);
				goto out_close;
			}
			data->device = stats.st_rdev;
			data->targetbase = defined_as_name;
		}
		goto type_determined;
	}
	if (ioctl(fd, BLKSSZGET, &data->phy_block_size)) {
		error_reason("Could not get blocksize");
		goto out_close;
	}
	/* Determine disk type */
	if (!data->drv_name) {
		/* Driver name cannot be read */
		if (ioctl(fd, BIODASDINFO, &dasd_info)) {
			data->devno = -1;
			if (data->geo.start) {
				/* SCSI partition */
				data->type = disk_type_scsi;
				data->partnum = stats.st_rdev & SCSI_PARTN_MASK;
				data->device = stats.st_rdev & ~SCSI_PARTN_MASK;
			} else {
				/* SCSI disk */
				data->type = disk_type_scsi;
				data->partnum = 0;
				data->device = stats.st_rdev;
			}
		} else {
			/* DASD */
			data->devno = dasd_info.devno;
			if (disk_determine_dasd_type(data, dasd_info))
				goto out_close;
			data->partnum = stats.st_rdev & DASD_PARTN_MASK;
			data->device = stats.st_rdev & ~DASD_PARTN_MASK;
		}
	} else if (strcmp(data->drv_name, "dasd") == 0) {
		/* Driver name is 'dasd' */
		if (ioctl(fd, BIODASDINFO, &dasd_info)) {
			error_reason("Could not determine DASD type");
			goto out_close;
		}
		data->devno = dasd_info.devno;
		if (disk_determine_dasd_type(data, dasd_info))
			goto out_close;
		data->partnum = stats.st_rdev & DASD_PARTN_MASK;
		data->device = stats.st_rdev & ~DASD_PARTN_MASK;
	} else if (strcmp(data->drv_name, "sd") == 0) {
		/* Driver name is 'sd' */
		data->devno = -1;
		data->type = disk_type_scsi;
		data->partnum = stats.st_rdev & SCSI_PARTN_MASK;
		data->device = stats.st_rdev & ~SCSI_PARTN_MASK;

	} else if (strcmp(data->drv_name, "virtblk") == 0) {

		if (ioctl(fd, HDIO_GETGEO, &data->geo) != 0)
			perror("Could not retrieve disk geometry information.");
		if (ioctl(fd, BLKSSZGET, &data->phy_block_size) != 0)
			perror("Could not retrieve blocksize information.");

		if (determine_virtblk_type(data, &stats)) {
			error_reason("Virtblk device type not clearly "
				     "determined.");
			goto out_close;
		}
	/* NVMe path, driver name is 'blkext' */
	} else if (strcmp(data->drv_name, "blkext") == 0) {
		data->devno = -1;
		data->type = disk_type_scsi;

		if (util_sys_dev_is_partition(stats.st_rdev)) {
			if (util_sys_get_base_dev(stats.st_rdev, &data->device))
				goto out_close;
			data->partnum = util_sys_get_partnum(stats.st_rdev);
			if (data->partnum == -1)
				goto out_close;
		} else {
			data->device = stats.st_rdev;
			data->partnum = 0;
		}
	} else {
		/* Driver name is unknown */
		error_reason("Unsupported device driver '%s'", data->drv_name);
		goto out_close;
	}

type_determined:
	/* Get size of device in sectors (512 byte) */
	if (ioctl(fd, BLKGETSIZE, &devsize)) {
		error_reason("Could not get device size");
		goto out_close;
	}

	/* Check for valid CHS geometry data. */
	if (disk_is_eckd(data->type) && (data->geo.cylinders == 0 ||
	    data->geo.heads == 0 || data->geo.sectors == 0)) {
		error_reason("Invalid disk geometry (CHS=%d/%d/%d)",
			     data->geo.cylinders, data->geo.heads,
			     data->geo.sectors);
		goto out_close;
	}
	/* Convert device size to size in physical blocks */
	data->phy_blocks = devsize / (data->phy_block_size / 512);
	/* Adjust start on SCSI according to block_size. device-mapper devices are skipped */
	if (data->type == disk_type_scsi && target->targetbase == NULL)
		data->geo.start = data->geo.start / (data->phy_block_size / 512);
	if (data->partnum != 0)
		data->partition = stats.st_rdev;
	/* Try to get device name */
	if (util_proc_part_get_entry(data->device, &part_entry) == 0) {
		data->name = misc_strdup(part_entry.name);
		util_proc_part_free_entry(&part_entry);
		if (data->name == NULL)
			goto out_close;
	}
	/* There is no easy way to find out whether there is a file system
	 * on this device, so we set the respective block size to an invalid
	 * value. */
	data->fs_block_size = -1;
	close(fd);
	*info = data;
	free(script_file);
	return 0;
out_close:
	close(fd);
	free(ppn_cmd);
	free(script_file);
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
	close(fd);
	return rc;
}

int
disk_is_scsi(const char* device, struct job_target_data* target)
{
	struct disk_info* info;
	int rc = 0;

	if (disk_get_info(device, target, &info) == -1)
		return 0;
	if (info->type == disk_type_scsi)
		rc = 1;
	disk_free_info(info);
	return rc;
}

int
disk_get_info_from_file(const char* filename, struct job_target_data* target,
			struct disk_info** info)
{
	struct stat stats;
	char* device;
	int blocksize;
	int fd;
	int rc;

	if (stat(filename, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
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
	/* Create temporary device file */
	rc = misc_temp_dev(stats.st_dev, 1, &device);
	if (rc)
		return -1;
	/* Get device info */
	rc = disk_get_info(device, target, info);
	if (rc == 0)
		(*info)->fs_block_size = blocksize;
	/* Clean up */
	misc_free_temp_dev(device);
	return rc;
}


void
disk_free_info(struct disk_info* info)
{
	if (info->name)
		free(info->name);
	if (info->drv_name)
		free(info->drv_name);
	free(info);
}


#ifndef REISERFS_SUPER_MAGIC
#define REISERFS_SUPER_MAGIC	0x52654973
#endif /* not REISERFS_SUPER_MAGIC */

#ifndef REISERFS_IOC_UNPACK
#define REISERFS_IOC_UNPACK	_IOW(0xCD,1,long)
#endif /* not REISERFS_IOC_UNPACK */

/* Retrieve the physical blocknumber (block on disk) of the specified logical
 * block (block in file). FD provides the file descriptor, LOGICAL is the
 * logical block number. Upon success, return 0 and store the physical
 * blocknumber in the variable pointed to by PHYSICAL. Return non-zero
 * otherwise. */
int
disk_get_blocknum(int fd, int fd_is_basedisk, blocknum_t logical,
		  blocknum_t* physical, struct disk_info* info)
{
	struct statfs buf;
	blocknum_t phy_per_fs;
	blocknum_t mapped;
	int block;
	int subblock;
	int fiemap_size;
	int map_offset;
	struct fiemap *fiemap;

	/* No file system: partition or raw disk */
	if (info->fs_block_size == -1) {
		if (fd_is_basedisk)
			*physical = logical;
		else
			*physical = logical + info->geo.start;
		return 0;
	}

	/* Get file system type */
	if (fstatfs(fd, &buf)) {
		error_reason(strerror(errno));
		return -1;
	}
	/* Files on ReiserFS need unpacking */
	if (buf.f_type == REISERFS_SUPER_MAGIC) {
		if (ioctl(fd, REISERFS_IOC_UNPACK, 1)) {
			error_reason("Could not unpack ReiserFS file");
			return -1;
		}
	}
	/* Get mapping in file system blocks */
	phy_per_fs = info->fs_block_size / info->phy_block_size;
	subblock = logical % phy_per_fs;

	/* First try FIEMAP, more complicated to set up */
	fiemap_size = sizeof(struct fiemap) + sizeof(struct fiemap_extent);

	fiemap = misc_malloc(fiemap_size);
	if (!fiemap)
		return -1;
	memset(fiemap, 0, fiemap_size);

	fiemap->fm_extent_count = 1;
	fiemap->fm_flags = FIEMAP_FLAG_SYNC;
	/* fm_start, fm_length in bytes; logical is in physical block units */
	fiemap->fm_start = logical * info->phy_block_size;
	fiemap->fm_length = info->phy_block_size;

	if (ioctl(fd, FS_IOC_FIEMAP, (unsigned long)fiemap)) {
		/* FIEMAP failed, fall back to FIBMAP */
		block = logical / phy_per_fs;
		if (ioctl(fd, FIBMAP, &block)) {
			error_reason("Could not get file mapping");
			free(fiemap);
			return -1;
		}
		mapped = block;
	} else {
		if (fiemap->fm_mapped_extents) {
			if (fiemap->fm_extents[0].fe_flags &
			    FIEMAP_EXTENT_ENCODED) {
				error_reason("File mapping is encoded");
				free(fiemap);
				return -1;
			}
			/*
			 * returned extent may start prior to our request
			 */
			map_offset = fiemap->fm_start -
				     fiemap->fm_extents[0].fe_logical;
			mapped = fiemap->fm_extents[0].fe_physical +
				 map_offset;
			/* set mapped to fs block units */
			mapped = mapped / info->fs_block_size;
		} else {
			mapped = 0;
		}
	}

	free(fiemap);

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


/* Write BYTECOUNT bytes of data from memory at location DATA as a block to
 * the file identified by file descriptor FD. Make sure that the data is
 * aligned on a block size boundary and that at most INFO->PHY_BLOCK_SIZE
 * bytes are written. INFO provides information about the disk layout. Upon
 * success, return 0 and store the pointer to the resulting disk block to BLOCK
 * (if BLOCK is not NULL). Return non-zero otherwise. */
static int
disk_write_block_aligned_base(int fd, int is_base_disk, const void* data,
			      size_t bytecount, disk_blockptr_t* block,
			      struct disk_info* info)
{
	blocknum_t current_block;
	blocknum_t blocknum;
	off_t current_pos;
	int align;

	current_pos = lseek(fd, 0, SEEK_CUR);
	if (current_pos == -1) {
		error_text(strerror(errno));
		return -1;
	}
	/* Ensure block alignment of current file pos */
	align = info->phy_block_size;
	if (current_pos % align != 0) {
		current_pos = lseek(fd, align - current_pos % align, SEEK_CUR);
	       	if (current_pos == -1) {
	       		error_text(strerror(errno));
			return -1;
		}
	}
	current_block = current_pos / align;
	/* Ensure maximum size */
	if (bytecount > (size_t) align)
		bytecount = align;
	/* Write data block */
	if (misc_write(fd, data, bytecount))
		return -1;
	if (block != NULL) {
		/* Store block pointer */
		if (disk_get_blocknum(fd, is_base_disk, current_block,
				      &blocknum, info))
			return -1;
		disk_blockptr_from_blocknum(block, blocknum, info);
	}
	return 0;
}

int
disk_write_block_aligned(int fd, const void* data, size_t bytecount,
			 disk_blockptr_t* block, struct disk_info* info)
{
	return disk_write_block_aligned_base(fd, 0, data, bytecount, block,
					     info);
}

/* Write BYTECOUNT bytes from memory at location BUFFER to the file identified
 * by file descriptor FD and return the list of pointers to the disk blocks
 * that make up the respective part of the file. Upon success return the number
 * of blocks and set BLOCKLIST to point to the uncompressed list. Return zero
 * otherwise. Note that the data is written to a file position which is aligned
 * on a block size boundary. */
blocknum_t
disk_write_block_buffer(int fd, int fd_is_basedisk, const void* buffer,
			size_t bytecount, disk_blockptr_t** blocklist,
			struct disk_info* info)
{
	disk_blockptr_t* list;
	blocknum_t count;
	blocknum_t i;
	size_t written;
	size_t chunk_size;
	int rc;

	count = (bytecount + info->phy_block_size - 1) / info->phy_block_size;
	list = (disk_blockptr_t *) misc_malloc(sizeof(disk_blockptr_t) *
					       count);
	if (list == NULL) {
		close(fd);
		return 0;
	}
	memset((void *) list, 0, sizeof(disk_blockptr_t) * count);
	/* Build list */
	for (i=0, written=0; i < count; i++, written += chunk_size) {
		chunk_size = bytecount - written;
		if (chunk_size > (size_t) info->phy_block_size)
			chunk_size = info->phy_block_size;
		rc = disk_write_block_aligned_base(fd, fd_is_basedisk,
						   VOID_ADD(buffer, written),
				chunk_size,
				&list[i], info);
		if (rc) {
			free(list);
			return 0;
		}
	}
	*blocklist = list;
	return count;
}


/* Print device node. */
void
disk_print_devt(dev_t d)
{
	printf("%02x:%02x", major(d), minor(d));
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


/* Return non-zero for ECKD large volumes. */
int
disk_is_large_volume(struct disk_info* info)
{
	return (info->type == disk_type_eckd_ldl ||
		info->type == disk_type_eckd_cdl) &&
		info->geo.cylinders == 0xfffe;
}


/* Print textual representation of INFO contents. */
void
disk_print_info(struct disk_info* info)
{
	char footnote[4] = "";
	if ((info->source == source_user) || (info->source == source_script))
		strcpy(footnote, " *)");

	printf("  Device..........................: ");
	disk_print_devt(info->device);
	if (info->targetbase == defined_as_device)
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
		if (info->targetbase == defined_as_name)
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
	     (info->source == source_auto)) {
		printf("  DASD device number..............: %04x\n",
		       info->devno);
	}
	printf("  Type............................: disk %s\n",
	       (info->partnum != 0) ? "partition" : "device");
	printf("  Disk layout.....................: %s%s\n",
	       disk_get_type_name(info->type), footnote);
	if (disk_is_eckd(info->type)) {
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
	if (info->source == source_user)
		printf("  *) Data provided by user.\n");
	if (info->source == source_script)
		printf("  *) Data provided by script.\n");
}

/* Print textual representation of geo structure. */
void
disk_print_geo(struct disk_info *data)
{
		printf("  geo.heads.........:%u\n", data->geo.heads);
		printf("  geo.sectors.......:%u\n", data->geo.sectors);
		printf("  geo.cylinders.....:%u\n", data->geo.cylinders);
		printf("  geo.start.........:%lu\n", data->geo.start);
		printf("  blksize...........:%u\n", data->phy_block_size);
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


/* Retrieve a list of pointers to the disk blocks that make up the file
 * specified by FILENAME. Upon success, return the number of blocks and set
 * BLOCKLIST to point to the uncompacted list. INFO provides information
 * about the device which contains the file. Return zero otherwise. */
blocknum_t
disk_get_blocklist_from_file(const char* filename, disk_blockptr_t** blocklist,
			     struct disk_info* info)
{
	disk_blockptr_t* list;
	struct stat stats;
	int fd;
	blocknum_t count;
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
	/* Get number of blocks */
	count = ((blocknum_t) stats.st_size +
			info->phy_block_size - 1) / info->phy_block_size;
	if (count == 0) {
		error_reason("Could not read empty file '%s'", filename);
		close(fd);
		return 0;
	}
	list = (disk_blockptr_t *) misc_malloc(sizeof(disk_blockptr_t) *
					       count);
	if (list == NULL) {
		close(fd);
		return 0;
	}
	memset((void *) list, 0, sizeof(disk_blockptr_t) * count);
	/* Build list */
	for (i=0; i < count; i++) {
		if (disk_get_blocknum(fd, 0, i, &blocknum, info)) {
			free(list);
			close(fd);
			return 0;
		}
		disk_blockptr_from_blocknum(&list[i], blocknum, info);
	}
	close(fd);
	*blocklist = list;
	return count;
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
