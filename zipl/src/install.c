/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions handling the installation of the boot loader code onto disk
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <syslog.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "lib/util_sys.h"
#include "lib/vtoc.h"

#include "boot.h"
#include "bootmap.h"
#include "disk.h"
#include "error.h"
#include "install.h"
#include "misc.h"

#define ECKD_CDL_DUMP_REC 3 /* Start record (0 based) for stage 2 and 1b */
/* CDL record 2 = 148 byte, independent from bs, bootinfo is last structure */
#define CDL_BOOTINFO_ADDR 112
/* ADDRESS for bootinfo structure to be BIOS compatible in MBR */
#define DEFAULT_BOOTINFO_ADDR 408

static inline unsigned long blk_cnt(int size, struct disk_info *info)
{
	return (size + info->phy_block_size - 1) / info->phy_block_size;
}

/* From linux/fs.h */
#define BLKFLSBUF	_IO(0x12, 97)

static int
overwrite_partition_start(int fd, struct disk_info* info, int mv_dump_magic);

/* Create an IPL master boot record data structure for SCSI MBRs in memory
 * at location BUFFER. TABLE contains a pointer to the program table. INFO
 * provides information about the disk. */
static int
update_scsi_mbr(void* bootblock, disk_blockptr_t* table,
		struct disk_info* info, disk_blockptr_t* scsi_dump_sb_blockptr)
{
	struct scsi_mbr *mbr;
	struct scsi_dump_param param;
	void* buffer;

	switch (get_scsi_layout(bootblock)) {
	case scsi_layout_pcbios:
		if (verbose)
			printf("Detected SCSI PCBIOS disk layout.\n");
		buffer = bootblock;
		break;
	case scsi_layout_sun:
	case scsi_layout_sgi:
		error_reason("Unsupported SCSI disk layout");
		return -1;
	default:
		if (info->partnum) {
			error_reason("Unsupported SCSI disk layout");
			return -1;
		} else {
			if (verbose)
				printf ("Detected plain SCSI partition.\n");
			buffer=bootblock;
		}
	}

	mbr = (struct scsi_mbr *) buffer;
	memset(buffer, 0, sizeof(struct scsi_mbr));
	memcpy(&mbr->magic, ZIPL_MAGIC, ZIPL_MAGIC_SIZE);
	mbr->version_id = DISK_LAYOUT_ID;
	bootmap_store_blockptr(&mbr->program_table_pointer, table, info,
			       0 /* this argument is ignored for scsi */);
	if (scsi_dump_sb_blockptr && scsi_dump_sb_blockptr->linear.block != 0) {
		/* Write dump boot_info */
		param.block = scsi_dump_sb_blockptr->linear.block *
			      scsi_dump_sb_blockptr->linear.size;
		boot_get_dump_info(&mbr->boot_info, BOOT_INFO_DEV_TYPE_SCSI,
				   &param);
	}
	return 0;
}


/* Install bootloader for initial program load from a SCSI type disk. FD
 * specifies the file descriptor of the device file. PROGRAM_TABLE points
 * to the disk block containing the program table. INFO provides
 * information about the disk type. Return 0 on success, non-zero otherwise. */
static int
install_scsi(int fd, disk_blockptr_t* program_table, struct disk_info* info,
	     disk_blockptr_t* scsi_dump_sb_blockptr)
{
	unsigned char* bootblock;
	int rc;

	bootblock = (unsigned char*) misc_malloc(info->phy_block_size);
	if (bootblock == NULL)
		return -1;
	/* Read bootblock */
	if (misc_seek(fd, 0)) {
		free(bootblock);
		return -1;
	}
	rc = misc_read(fd, bootblock, info->phy_block_size);
	if (rc) {
		error_text("Could not read master boot record");
		free(bootblock);
		return rc;
	}
	/* Put zIPL data into MBR */
	rc = update_scsi_mbr(bootblock, program_table, info,
			     scsi_dump_sb_blockptr);
	if (rc) {
		free(bootblock);
		return -1;
	}
	/* Write MBR back to disk */
	if (verbose)
		printf("Writing SCSI master boot record.\n");
	if (misc_seek(fd, 0)) {
		free(bootblock);
		return -1;
	}
	rc = DRY_RUN_FUNC(misc_write(fd, bootblock, info->phy_block_size));
	if (rc)
		error_text("Could not write master boot record");
	free(bootblock);
	return rc;
}


/* Install bootloader for CCW-type IPL from a FBA type disk */
static int
install_fba_ccw(int fd, disk_blockptr_t *program_table,
		disk_blockptr_t *stage1b_list, blocknum_t stage1b_count,
		struct disk_info *info)
{
	struct boot_fba_stage0 stage0;

	/* Install stage 0 and store program table pointer */
	if (boot_init_fba_stage0(&stage0, stage1b_list, stage1b_count))
		return -1;

	boot_get_ipl_info_ccw(&stage0.boot_info,  BOOT_INFO_DEV_TYPE_FBA,
			      program_table, info);

	if (DRY_RUN_FUNC(misc_pwrite(fd, &stage0, sizeof(stage0), 0)))
		return -1;

	return 0;
}

/* Install stage1b bootloader for ECKD type disk */
int
install_eckd_stage1b(struct misc_fd *mfd, disk_blockptr_t **stage1b_list,
		     blocknum_t *stage1b_count, disk_blockptr_t *stage2_list,
		     blocknum_t stage2_count, struct disk_info *info)
{
	struct boot_eckd_stage1b *stage1b;
	int stage1b_size, rc = -1;

	*stage1b_list = NULL;
	*stage1b_count = 0;
	stage1b_size = ROUNDUP(sizeof(*stage1b), info->phy_block_size);
	stage1b = misc_malloc(stage1b_size);
	if (stage1b == NULL)
		goto out;
	memset(stage1b, 0, stage1b_size);
	if (boot_init_eckd_stage1b(stage1b, stage2_list, stage2_count))
		goto out_free_stage1b;
	*stage1b_count = disk_write_block_buffer(mfd, 1, stage1b, stage1b_size,
						 stage1b_list, info);
	if (*stage1b_count == 0)
		goto out_free_stage1b;
	rc = 0;
out_free_stage1b:
	free(stage1b);
out:
	return rc;
}

/*
 * Install bootloader for CCW-type IPL from ECKD type disk with
 * Linux Disk Layout
 */
static int
install_eckd_ldl_ccw(int fd, disk_blockptr_t *program_table,
		     disk_blockptr_t *stage1b_list, blocknum_t stage1b_count,
		     struct disk_info *info)
{
	struct boot_eckd_ldl_stage0 stage0;
	struct boot_eckd_stage1 stage1;

	/* Install stage 0 */
	boot_init_eckd_ldl_stage0(&stage0);
	if (DRY_RUN_FUNC(misc_pwrite(fd, &stage0, sizeof(stage0), 0)))
		return -1;
	/* Install stage 1 and store program table pointer */
	if (boot_init_eckd_stage1(&stage1, stage1b_list, stage1b_count))
		return -1;

	boot_get_ipl_info_ccw(&stage1.boot_info, BOOT_INFO_DEV_TYPE_ECKD,
			      program_table, info);

	if (DRY_RUN_FUNC(misc_pwrite(fd, &stage1, sizeof(stage1),
				     sizeof(stage0))))
		return -1;

	return 0;
}

/**
 * Install bootloader for CCW-type IPL from ECKD type disk with
 * OS/390 compatible disk layout
 */
static int install_eckd_cdl_ccw(int fd, disk_blockptr_t *program_table,
				disk_blockptr_t *stage1b_list,
				blocknum_t stage1b_count,
				struct disk_info *info)
{
	struct boot_eckd_cdl_stage0 stage0;
	struct boot_eckd_stage1 stage1;

	/* Install stage 0 */
	boot_init_eckd_cdl_stage0(&stage0);
	if (DRY_RUN_FUNC(misc_pwrite(fd, &stage0, sizeof(stage0), 4)))
		return -1;
	/* Install stage 1 and store program table pointer */
	if (boot_init_eckd_stage1(&stage1, stage1b_list, stage1b_count))
		return -1;

	boot_get_ipl_info_ccw(&stage1.boot_info, BOOT_INFO_DEV_TYPE_ECKD,
			      program_table, info);

	if (DRY_RUN_FUNC(misc_pwrite(fd, &stage1, sizeof(stage1),
				     4 + info->phy_block_size)))
		return -1;
	return 0;
}

/**
 * Install a program table for List-Directed IPL on a CDL-formatted DASD.
 *
 * The installation means storing an actual boot record address in the
 * volume label.
 *
 * BR: represents an actual boot record address.
 */
static int install_eckd_cdl_ld(int fd, disk_blockptr_t *br,
			       struct disk_info *info)
{
	struct vol_label_cdl vl;
	int rc;

	/* Read a volume label from CDL-formatted DASD */
	if (misc_seek(fd, 2 * info->phy_block_size))
		return -1;
	rc = misc_read(fd, &vl, sizeof(vl));
	if (rc) {
		error_text("Could not read volume label");
		return rc;
	}
	/* Verify that we have a VOL1 label */
	if (!is_vol1(vl.vollbl)) {
		error_text("Volume label 'vol1' not initialized");
		return -1;
	}
	/* Pack the actual boot record address */
	vtoc_set_cchhb(&vl.br, br->chs.cyl, br->chs.head, br->chs.sec);

	/* Write out the updated volume label */
	if (misc_seek(fd, 2 * info->phy_block_size))
		return -1;
	rc = DRY_RUN_FUNC(misc_write(fd, &vl, sizeof(vl)));
	if (rc)
		error_text("Could not update volume label 'vol1'");
	return 0;
}

/**
 * Install program tables for CCW-type and(or) List-Directed IPL
 * See the comment before install_bootloader() for details.
 *
 * TABLES: array of the program tables to be installed
 */
int install_bootloader_ipl(struct program_table *tables,
			   struct disk_info *info,
			   int fd)
{
	struct program_table *pt = &tables[LEGACY_BLKPTR_FORMAT_ID];

	int rc = -1;

	switch (info->type) {
	case disk_type_scsi:
		/* List-Directed IPL */
		pt = &tables[BLKPTR_FORMAT_ID];
		rc = install_scsi(fd, &pt->table, info, NULL);
		break;
	case disk_type_fba:
		rc = install_fba_ccw(fd,
				     &pt->table,
				     pt->stage1b_list,
				     pt->stage1b_count, info);
		break;
	case disk_type_eckd_ldl:
		rc = install_eckd_ldl_ccw(fd,
					  &pt->table,
					  pt->stage1b_list,
					  pt->stage1b_count, info);
		break;
	case disk_type_eckd_cdl:
		rc = install_eckd_cdl_ccw(fd,
					  &pt->table,
					  pt->stage1b_list,
					  pt->stage1b_count, info);
		if (rc)
			break;
		/* install one more table for List-Directed IPL */
		pt = &tables[BLKPTR_FORMAT_ID];
		rc = install_eckd_cdl_ld(fd, pt->stage1b_list, info);
		break;
	case disk_type_diag:
		error_reason("Inappropriarte device type (%d) for IPL",
			     info->type);
		break;
	}
	return rc;
}

/*
 * Check if CCW dump tool is installed on the disk and destroy it by
 * clearing the first block.
 */
static int clear_ccw_dumper(const struct disk_info *info, int fd)
{
	char dumper_magic[DF_S390_DUMPER_MAGIC_SIZE];
	void *buffer;
	int rc;

	/* Read the CCW dumper magic at the start of block 3 */
	if (misc_seek(fd, ECKD_CDL_DUMP_REC * info->phy_block_size))
		return -1;
	rc = misc_read(fd, dumper_magic, sizeof(dumper_magic));
	if (rc) {
		error_text("Could not read CCW dump record");
		return rc;
	}
	/*
	 * Check if the dump tool is present and clear its first block with zeroes.
	 */
	if (strncmp(dumper_magic, DF_S390_DUMPER_MAGIC_EXT, sizeof(dumper_magic)) == 0 ||
	    strncmp(dumper_magic, DF_S390_DUMPER_MAGIC_MV_EXT, sizeof(dumper_magic)) == 0) {
		if (misc_seek(fd, ECKD_CDL_DUMP_REC * info->phy_block_size))
			return -1;
		buffer = misc_calloc(1, info->phy_block_size);
		if (buffer == NULL)
			return -1;
		rc = DRY_RUN_FUNC(misc_write(fd, buffer, info->phy_block_size));
		free(buffer);
		if (rc)
			error_text("Could not clear CCW dumper");
	}
	return rc;
}

/**
 * Install a program table for List-Directed dump
 * See the comment before install_bootloader() for details
 */
static int install_bootloader_dump(struct program_table *tables,
				   struct disk_info *info,
				   disk_blockptr_t *scsi_dump_sb_blockptr,
				   int ngdump_enabled,
				   int fd)
{
	struct program_table *pt = &tables[BLKPTR_FORMAT_ID];
	int rc = -1;

	switch (info->type) {
	case disk_type_scsi:
		rc = install_scsi(fd, &pt->table, info, scsi_dump_sb_blockptr);
		if (rc == 0 && !ngdump_enabled)
			rc = overwrite_partition_start(fd, info, 0);
		break;
	case disk_type_eckd_cdl:
		rc = install_eckd_cdl_ld(fd, pt->stage1b_list, info);
		/* Clear CCW dumper upon successful List-Directed ECKD dump tool installation */
		if (rc == 0)
			rc = clear_ccw_dumper(info, fd);
		break;
	default:
		error_reason("Inappropriarte device type (%d) for List-Directed dump",
			     info->type);
		break;
	}
	return rc;
}

/**
 * Install a "compatible" boot record referring one, or two "similar"
 * program tables.
 *
 * For compatibility reasons zIPL installs multiple "similar"
 * program tables which differ only in block pointers format.
 * Each such table is identified by an offset in the array BIS->tables
 * of in-memory program table representations built by prepare_bootloader().
 * The common rule is that tables built for CCW-type IPL are placed
 * at offset 0, and tables built for List-Directed IPL are placed at
 * offset 1. The same works for dumps.
 */
int install_bootloader(struct job_data *job, struct install_set *bis)
{
	disk_blockptr_t *scsi_dump_sb_blockptr = &bis->scsi_dump_sb_blockptr;
	struct disk_info *info = bis->info;
	char footnote[4];
	int rc;
	int i;

	if (!info)
		return 0;

	prepare_footnote_ptr(job->target.source, footnote);
	/* Inform user about what we're up to */
	printf("Preparing boot device for %s%s: ",
	       disk_get_ipl_type(info->type,
				 job->id == job_dump_partition),
	       job->id == job_dump_partition ? "dump" : "IPL");
	if (info->name) {
		printf("%s", info->name);
		if (info->devno >= 0)
			printf(" (%04x)", info->devno);
		printf(".\n");
	} else if (info->devno >= 0) {
		printf("%04x.\n", info->devno);
	} else {
		disk_print_devt(info->device);
		printf(".\n");
	}
	/* Install independently on each physical target base */

	for (i = 0; i < job_get_nr_targets(job); i++) {
		int fd;

		if (verbose) {
			printf("Installing on base disk: ");
			disk_print_devname(info->basedisks[i]);
			printf("%s.\n", footnote);
		}
		/* Open device file */
		fd = open(bis->basetmp[i], O_RDWR);
		if (fd == -1) {
			error_reason(strerror(errno));
			error_text("Could not open temporary device file '%s'",
				   bis->basetmp[i]);
			return -1;
		}
		/* Ensure that potential cache inconsistencies between disk and
		 * partition are resolved by flushing the corresponding buffers.
		 */
		if (!dry_run) {
			if (ioctl(fd, BLKFLSBUF)) {
				fprintf(stderr, "Warning: Could not flush disk "
					"caches.\n");
			}
		}
		/*
		 * Depending on disk type, install one or two program tables
		 * for CCW-type IPL and (or) for List-Directed IPL (see the
		 * picture in comments above)
		 */
		if (job->id == job_dump_partition) {
			rc = install_bootloader_dump(bis->tables, info,
						     scsi_dump_sb_blockptr,
						     job_dump_is_ngdump(job),
						     fd);
		} else {
			rc = install_bootloader_ipl(bis->tables, info,
						    fd);
		}
		if (fsync(fd))
			error_text("Could not sync device file '%s'",
				   bis->basetmp[i]);
		if (close(fd))
			error_text("Could not close device file '%s'",
				   bis->basetmp[i]);
		if (rc)
			break;
	}
	if (verbose)
		print_footnote_ref(job->target.source, "");

	if (!dry_run && rc == 0) {
		if (info->devno >= 0)
			syslog(LOG_INFO, "Boot loader written to %s (%04x) - "
			       "%02x:%02x",
			       (info->name ? info->name : "-"), info->devno,
			       major(info->device), minor(info->device));
		else
			syslog(LOG_INFO, "Boot loader written to %s - "
			       "%02x:%02x",
			       (info->name ? info->name : "-"),
			       major(info->device), minor(info->device));
	}
	return rc;
}


/* Rewind the tape device identified by FD. Return 0 on success, non-zero
 * otherwise. */
int
rewind_tape(int fd)
{
	struct mtop op;

	/* Magnetic tape rewind operation */
	op.mt_count = 1;
	op.mt_op = MTREW;
	if (ioctl(fd, MTIOCTOP, &op) == -1)
		return -1;
	else
		return 0;
}

static int
ask_for_confirmation(const char* fmt, ...)
{
	va_list args;
	char answer;

	/* Always assume positive answer in non-interactive mode */
	if (!interactive)
		return 0;
	if (dry_run)
		/* nothing to confirm */
		return 0;
	/* Print question */
	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
	/* Process user reply */
	while (scanf("%c", &answer) != 1);
	if ((answer == 'y') || (answer == 'Y'))
		return 0;
	fprintf(stderr, "Operation canceled by user.\n");
	return -2;
}


/* Write data from file FILENAME to file descriptor FD. Data will be written
 * in blocks of BLOCKSIZE bytes. Return 0 on success, non-zero otherwise. */
static int
write_tapefile(int fd, const char* filename, size_t blocksize)
{
	struct stat stats;
	ssize_t written;
	off_t offset;
	size_t chunk;
	void* buffer;
	int read_fd;

	if (stat(filename, &stats)) {
		error_reason(strerror(errno));
		return -1;
	}
	if (!S_ISREG(stats.st_mode)) {
		error_reason("Not a regular file");
		return -1;
	}
	buffer = misc_malloc(blocksize);
	if (buffer == NULL)
		return -1;
	read_fd = open(filename, O_RDONLY);
	if (fd == -1) {
		error_reason(strerror(errno));
		free(buffer);
		return -1;
	}
	for (offset = 0; offset < stats.st_size; offset += chunk) {
		chunk = stats.st_size - offset;
		if (chunk > blocksize)
			chunk = blocksize;
		else
			memset(buffer, 0, blocksize);
		if (misc_read(read_fd, buffer, chunk)) {
			close(read_fd);
			free(buffer);
			return -1;
		}
		written = write(fd, buffer, chunk);
		if (written != (ssize_t) chunk) {
			if (written == -1)
				error_reason(strerror(errno));
			else
				error_reason("Write error");
			close(read_fd);
			free(buffer);
			return -1;
		}
	}
	close(read_fd);
	free(buffer);
	return 0;
}


/* Write SIZE bytes of data from memory location DATA to file descriptor FD.
 * Data will be written in blocks of BLOCKSIZE bytes. Return 0 on success,
 * non-zero otherwise. */
static int
write_tapebuffer(int fd, const char* data, size_t size, size_t blocksize)
{
	ssize_t written;
	size_t offset;
	size_t chunk;
	void* buffer;

	buffer = misc_malloc(blocksize);
	if (buffer == NULL)
		return -1;
	for (offset = 0; offset < size; offset += chunk) {
		chunk = size - offset;
		if (chunk > blocksize)
			chunk = blocksize;
		else
			memset(buffer, 0, blocksize);
		memcpy(buffer, VOID_ADD(data, offset), chunk);
		written = write(fd, buffer, chunk);
		if (written != (ssize_t) chunk) {
			if (written == -1)
				error_reason(strerror(errno));
			else
				error_reason("Write error");
			free(buffer);
			return -1;
		}
	}
	free(buffer);
	return 0;
}


/* Write COUNT tapemarks to file handle FD. */
static int
write_tapemark(int fd, int count)
{
	struct mtop op;

	op.mt_count = count;
	op.mt_op = MTWEOF;
	if (ioctl(fd, MTIOCTOP, &op) == -1) {
		error_reason("Could not write tapemark");
		return -1;
	}
	return 0;
}


#define IPL_TAPE_BLOCKSIZE	1024

/* Install IPL record on tape device. */
int
install_tapeloader(const char* device, const char* image, const char* parmline,
		   const char* ramdisk, address_t image_addr,
		   address_t parm_addr, address_t initrd_addr)
{
	void* buffer;
	size_t size;
	int rc;
	int fd;

	printf("Preparing boot tape: %s\n", device);
	/* Prepare boot loader */
	rc = boot_get_tape_ipl(&buffer, &size, parm_addr, initrd_addr,
			       image_addr);
	if (rc)
		return rc;
	/* Open device */
	fd = open(device, O_RDWR);
	if (fd == -1) {
		error_reason(strerror(errno));
		error_text("Could not open tape device '%s'", device);
		free(buffer);
		return -1;
	}
	if (rewind_tape(fd) != 0) {
		error_text("Could not rewind tape device '%s'", device);
		free(buffer);
		close(fd);
		return -1;
	}
	/* Write boot loader */
	rc = DRY_RUN_FUNC(write_tapebuffer(fd, buffer, size,
		IPL_TAPE_BLOCKSIZE));
	free(buffer);
	if (rc) {
		error_text("Could not write boot loader to tape");
		close(fd);
		return rc;
	}
	rc = DRY_RUN_FUNC(write_tapemark(fd, 1));
	if (rc) {
		error_text("Could not write boot loader to tape");
		close(fd);
		return rc;
	}
	/* Write image file */
	if (verbose) {
		printf("  kernel image......: %s at 0x%llx\n", image,
		       (unsigned long long) image_addr);
	}
	rc = DRY_RUN_FUNC(write_tapefile(fd, image, IPL_TAPE_BLOCKSIZE));
	if (rc) {
		error_text("Could not write image file '%s' to tape", image);
		close(fd);
		return rc;
	}
	rc = DRY_RUN_FUNC(write_tapemark(fd, 1));
	if (rc) {
		error_text("Could not write boot loader to tape");
		close(fd);
		return rc;
	}
	if (parmline != NULL) {
		if (verbose) {
			printf("  kernel parmline...: '%s' at 0x%llx\n",
			       parmline, (unsigned long long) parm_addr);
		}
		/* Write parameter line */
		rc = DRY_RUN_FUNC(write_tapebuffer(fd, parmline,
			strlen(parmline), IPL_TAPE_BLOCKSIZE));
		if (rc) {
			error_text("Could not write parameter string to tape");
			close(fd);
			return rc;
		}
	}
	rc = DRY_RUN_FUNC(write_tapemark(fd, 1));
	if (rc) {
		error_text("Could not write boot loader to tape");
		close(fd);
		return rc;
	}
	if (ramdisk != NULL) {
		/* Write ramdisk */
		if (verbose) {
			printf("  initial ramdisk...: %s at 0x%llx\n",
			       ramdisk, (unsigned long long) initrd_addr);
		}
		rc = DRY_RUN_FUNC(write_tapefile(fd, ramdisk,
			IPL_TAPE_BLOCKSIZE));
		if (rc) {
			error_text("Could not write ramdisk file '%s' to tape",
				   ramdisk);
			close(fd);
			return rc;
		}
	}
	rc = DRY_RUN_FUNC(write_tapemark(fd, 1));
	if (rc) {
		error_text("Could not write boot loader to tape");
		close(fd);
		return rc;
	}
	if (rewind_tape(fd) != 0) {
		error_text("Could not rewind tape device '%s' to tape", device);
		rc = -1;
	}
	if (!dry_run && fsync(fd))
		error_text("Could not sync device file '%s'", device);
	close(fd);
	return rc;
}

/* Write 64k null bytes with dump signature at offset 512 to
 * start of dump partition */
static int
overwrite_partition_start(int fd, struct disk_info* info, int mv_dump_magic)
{
	int rc;
	unsigned int bytes = 65536;
	char* buffer;
	const char dump_magic[] = {0xa8, 0x19, 0x01, 0x73,
		0x61, 0x8f, 0x23, 0xfe};

	if (misc_seek(fd, info->geo.start * info->phy_block_size))
		return -1;
	if (info->phy_block_size * info->phy_blocks < bytes)
		bytes = info->phy_block_size * info->phy_blocks;
	buffer = calloc(1, bytes);
	if (buffer == NULL) {
		error_text("Could not allocate buffer");
		return -1;
	}
	if (mv_dump_magic)
		memcpy(VOID_ADD(buffer, 512), dump_magic, sizeof(dump_magic));
	rc = DRY_RUN_FUNC(misc_write(fd, buffer, bytes));
	free(buffer);
	if (rc) {
		error_text("Could not write dump signature");
		return rc;
	}
	return 0;
}

/*
 * Ensure that end block is within bounds.
 * Force block size of 4KiB because otherwise there is not enough space
 * to write the dump tool.
 */
static int check_eckd_dump_partition(struct disk_info* info)
{
	unsigned long long end_blk = info->geo.start + info->phy_blocks - 1;

	if (end_blk > UINT32_MAX) {
		error_reason("partition end exceeds bounds (offset "
			     "%lld MB, max %lld MB)",
			(end_blk * info->phy_block_size) >> 20,
			(((unsigned long long) UINT32_MAX) *
				info->phy_block_size) >> 20);
		return -1;
	}
	if (info->phy_block_size != 4096) {
		error_reason("unsupported DASD block size %d (should be 4096)",
			     info->phy_block_size);
		return -1;
	}
	return 0;
}

static void eckd_dump_store_param(struct eckd_dump_param *param,
				  struct disk_info *info, blocknum_t count)
{
	param->blk_start = info->geo.start;
	param->blk_end = info->geo.start + info->phy_blocks - 1 - count;
	param->num_heads = info->geo.heads;
	param->blk_size = info->phy_block_size;
	param->bpt = info->geo.sectors;
}

static int install_svdump_eckd_ldl(struct misc_fd *mfd, struct disk_info *info,
				   const struct stage2dump_parm_tail *stage2dump_parms)
{
	disk_blockptr_t *stage2_list, *stage1b_list;
	blocknum_t stage2_count, stage1b_count;
	struct boot_eckd_ldl_stage0 stage0;
	struct boot_eckd_stage1 stage1;
	struct eckd_dump_param param;
	size_t stage2_size;
	void *stage2;
	int rc = -1;

	if (boot_get_eckd_dump_stage2(&stage2, &stage2_size, stage2dump_parms))
		goto out;
	if (blk_cnt(stage2_size, info) > STAGE2_BLK_CNT_MAX) {
		error_reason("ECKD dump record is too large");
		goto out_free_stage2;
	}
	if (overwrite_partition_start(mfd->fd, info, 0))
		goto out_free_stage2;
	/* Install stage 2 and stage 1b to beginning of partition */
	if (misc_seek(mfd->fd, info->geo.start * info->phy_block_size))
		goto out_free_stage2;
	stage2_count = disk_write_block_buffer(mfd, 1, stage2, stage2_size,
					       &stage2_list, info);
	if (stage2_count == 0)
		goto out_free_stage2_list;
	if (install_eckd_stage1b(mfd, &stage1b_list, &stage1b_count,
				 stage2_list, stage2_count, info))
		goto out_free_stage2_list;
	/* Install stage 0 - afterwards we are at stage 1 position*/
	boot_init_eckd_ldl_stage0(&stage0);
	if (DRY_RUN_FUNC(misc_pwrite(mfd->fd, &stage0, sizeof(stage0), 0)))
		goto out_free_stage1b_list;
	/* Install stage 1 and fill in dump partition parameter */
	if (boot_init_eckd_stage1(&stage1, stage1b_list, stage1b_count))
		goto out_free_stage1b_list;

	eckd_dump_store_param(&param, info, 0);
	boot_get_dump_info(&stage1.boot_info, BOOT_INFO_DEV_TYPE_ECKD, &param);

	if (DRY_RUN_FUNC(misc_pwrite(mfd->fd, &stage1, sizeof(stage1),
				     sizeof(stage0))))
		goto out_free_stage1b_list;
	rc = 0;
out_free_stage1b_list:
	free(stage1b_list);
out_free_stage2_list:
	free(stage2_list);
out_free_stage2:
	free(stage2);
out:
	return rc;
}

static int install_dump_eckd_cdl(struct misc_fd *mfd, struct disk_info *info,
				 void *stage2, size_t stage2_size, int mvdump,
				 int force)
{
	blocknum_t count, stage2_count, stage1b_count;
	disk_blockptr_t *stage2_list, *stage1b_list;
	struct boot_eckd_cdl_stage0 stage0_cdl;
	struct boot_eckd_stage1 stage1;
	struct eckd_dump_param param;
	int rc = -1;

	count = blk_cnt(stage2_size, info);
	if (count > STAGE2_BLK_CNT_MAX) {
		error_reason("ECKD dump record is too large");
		goto out;
	}
	count += blk_cnt(sizeof(struct boot_eckd_stage1b), info);
	if (count > (blocknum_t) info->geo.sectors - ECKD_CDL_DUMP_REC) {
		error_reason("ECKD dump record is too large");
		goto out;
	}
	/* Install stage 2 */
	if (misc_seek(mfd->fd, ECKD_CDL_DUMP_REC * info->phy_block_size))
		goto out;
	stage2_count = disk_write_block_buffer(mfd, 1, stage2, stage2_size,
					       &stage2_list, info);
	if (stage2_count == 0)
		goto out;
	/* Install stage 1b behind stage 2*/
	if (install_eckd_stage1b(mfd, &stage1b_list, &stage1b_count,
				 stage2_list, stage2_count, info))
		goto out_free_stage2_list;
	/* Install stage 0 */
	boot_init_eckd_cdl_stage0(&stage0_cdl);
	if (DRY_RUN_FUNC(misc_pwrite(mfd->fd, &stage0_cdl, sizeof(stage0_cdl), 4)))
		goto out_free_stage1b_list;
	/* Install stage 1 and fill in dump partition parameter */
	if (boot_init_eckd_stage1(&stage1, stage1b_list, stage1b_count))
		goto out_free_stage1b_list;

	eckd_dump_store_param(&param, info, 0);
	boot_get_dump_info(&stage1.boot_info, BOOT_INFO_DEV_TYPE_ECKD, &param);
	if (DRY_RUN_FUNC(misc_pwrite(mfd->fd, &stage1, sizeof(stage1),
				     info->phy_block_size + 4)))
		goto out_free_stage1b_list;
	if (!force && overwrite_partition_start(mfd->fd, info, mvdump))
		goto out_free_stage1b_list;
	rc = 0;
out_free_stage1b_list:
	free(stage1b_list);
out_free_stage2_list:
	free(stage2_list);
out:
	return rc;
}

static int
install_svdump_eckd_cdl(struct misc_fd *mfd, struct disk_info *info,
			const struct stage2dump_parm_tail *stage2dump_parms)
{
	size_t stage2_size;
	void *stage2;
	int rc;

	if (boot_get_eckd_dump_stage2(&stage2, &stage2_size, stage2dump_parms))
		return -1;
	rc = install_dump_eckd_cdl(mfd, info, stage2, stage2_size, 0, 0);
	free(stage2);
	return rc;
}

static int
install_mvdump_eckd_cdl(struct misc_fd *mfd, struct disk_info *info,
			const struct stage2dump_parm_tail *stage2dump_parms,
			const struct mvdump_parm_table *mv_parm_table)
{
	size_t stage2_size;
	void *stage2;
	int rc;

	/* Write stage 2 + parameter block */
	if (boot_get_eckd_mvdump_stage2(&stage2, &stage2_size, stage2dump_parms,
					mv_parm_table))
		return -1;
	rc = install_dump_eckd_cdl(mfd, info, stage2, stage2_size, 1,
				   stage2dump_parms->mvdump_force);
	free(stage2);
	return rc;
}

int
install_fba_stage1b(struct misc_fd *mfd, disk_blockptr_t **stage1b_list,
		    blocknum_t *stage1b_count, disk_blockptr_t *stage2_list,
		    blocknum_t stage2_count, struct disk_info *info)
{
	struct boot_fba_stage1b *stage1b;
	int stage1b_size, rc = -1;

	*stage1b_list = NULL;
	*stage1b_count = 0;
	stage1b_size = ROUNDUP(sizeof(*stage1b), info->phy_block_size);
	stage1b = misc_malloc(stage1b_size);
	if (stage1b == NULL)
		goto out;
	memset(stage1b, 0, stage1b_size);
	if (boot_init_fba_stage1b(stage1b, stage2_list, stage2_count))
		goto out_free_stage1b;
	*stage1b_count = disk_write_block_buffer(mfd, 1, stage1b, stage1b_size,
						 stage1b_list, info);
	if (*stage1b_count == 0)
		goto out_free_stage1b;
	rc = 0;
out_free_stage1b:
	free(stage1b);
out:
	return rc;
}

static int
install_svdump_fba(struct misc_fd *mfd, struct disk_info *info,
		   const struct stage2dump_parm_tail *stage2dump_parms)
{
	blocknum_t stage1b_count, stage2_count, blk;
	disk_blockptr_t *stage1b_list, *stage2_list;
	struct boot_fba_stage0 stage0;
	struct fba_dump_param param;
	size_t stage2_size;
	void *stage2;
	int rc = -1;

	/* Overwrite first 64k of partition */
	if (overwrite_partition_start(mfd->fd, info, 0))
		goto out;
	/* Install stage 2 at end of partition */
	if (boot_get_fba_dump_stage2(&stage2, &stage2_size, stage2dump_parms))
		goto out;
	if (blk_cnt(stage2_size, info) > STAGE2_BLK_CNT_MAX) {
		error_reason("FBA dump record is too large");
		goto out_free_stage2;
	}
	blk = (info->geo.start + info->phy_blocks - blk_cnt(stage2_size, info));
	if (misc_seek(mfd->fd, blk * info->phy_block_size))
		goto out_free_stage2;
	stage2_count = disk_write_block_buffer(mfd, 1, stage2, stage2_size,
					       &stage2_list, info);
	if (stage2_count == 0)
		goto out_free_stage2;
	/* Install stage 1b in front of stage 2 */
	blk -= blk_cnt(sizeof(struct boot_fba_stage1b), info);
	if (misc_seek(mfd->fd, blk * info->phy_block_size))
		goto out_free_stage2_list;
	if (install_fba_stage1b(mfd, &stage1b_list, &stage1b_count,
				stage2_list, stage2_count, info))
		goto out_free_stage2_list;
	/* Install stage 0/1 fill in dump partition parameter */
	if (boot_init_fba_stage0(&stage0, stage1b_list, stage1b_count))
		goto out_free_stage1b_list;

	param.blk_start = info->geo.start;
	param.blk_end = blk - 1;
	boot_get_dump_info(&stage0.boot_info, BOOT_INFO_DEV_TYPE_FBA, &param);

	if (DRY_RUN_FUNC(misc_pwrite(mfd->fd, &stage0, sizeof(stage0), 0)))
		goto out_free_stage1b_list;

	rc = 0;
out_free_stage1b_list:
	free(stage1b_list);
out_free_stage2_list:
	free(stage2_list);
out_free_stage2:
	free(stage2);
out:
	return rc;
}

static int
install_dump_tape(int fd, const struct stage2dump_parm_tail *stage2dump_parms)
{
	void* buffer;
	size_t size;
	int rc;

	rc = boot_get_tape_dump(&buffer, &size, stage2dump_parms);
	if (rc)
		return rc;
	rc = DRY_RUN_FUNC(misc_write(fd, buffer, size));
	if (rc)
		error_text("Could not write to tape device");
	free(buffer);
	return rc;
}


int
install_dump(const char *device, struct job_target_data *target, uint64_t mem,
	     bool no_compress)
{
	struct stage2dump_parm_tail stage2dump_parms = {0};
	struct misc_fd mfd = {0};
	struct disk_info* info;
	uint64_t part_size;
	char *tempdev;
	int rc;

	stage2dump_parms.mem_upper_limit = mem;
	stage2dump_parms.no_compress = no_compress;

	/* Check if @device is a tape device */
	if (misc_open_device(device, &mfd, 0) == -1) {
		error_text("Could not open dump device '%s'", device);
		return -1;
	}
	if (rewind_tape(mfd.fd) == 0) {
		/* Rewind worked - this is a tape */
		rc = ask_for_confirmation("Warning: All information on device "
					  "'%s' will be lost!\nDo you want to "
					  "continue creating a dump "
 					  "tape (y/n) ?", device);
		if (rc) {
			close(mfd.fd);
			return rc;
		}
		if (verbose)
			printf("Installing tape dump record\n");
		rc = install_dump_tape(mfd.fd, &stage2dump_parms);
		if (rc) {
			error_text("Could not install dump record on tape "
				   "device '%s'", device);
		} else {
			if (!misc_fsync(&mfd, device) && verbose) {
				printf("Dump record successfully installed on "
				       "tape device '%s'.\n", device);
			}
		}
		close(mfd.fd);
		return rc;
	}
	close(mfd.fd);
	/* This is a disk device */
	rc = disk_get_info(device, target, &info);
	if (rc) {
		error_text("Could not get information for dump target "
			   "'%s'", device);
		return rc;
	}
	if (info->partnum == 0) {
		error_reason("Dump target '%s' is not a disk partition",
			     device);
		disk_free_info(info);
		return -1;
	}
	if (verbose) {
		printf("Target device information\n");
		disk_print_info(info, target->source);
	}
	rc = misc_temp_dev(info->device, 1, &tempdev);
	if (rc) {
		disk_free_info(info);
		return -1;
	}
	if (misc_open_device(tempdev, &mfd, dry_run) == -1) {
		error_text("Could not open temporary device node '%s'",
			   tempdev);
		misc_free_temp_dev(tempdev);
		disk_free_info(info);
		return -1;
	}
	switch (info->type) {
	case disk_type_eckd_ldl:
	case disk_type_eckd_cdl:
		if (check_eckd_dump_partition(info)) {
			error_text("Dump target '%s'", device);
			rc = -1;
			break;
		}
		/* Fall through. */
	case disk_type_fba:
		part_size = info->phy_block_size * info->phy_blocks;
		printf("Dump target: partition '%s' with a size of %llu MB.\n",
		       device, (unsigned long long) part_size >> 20);
		rc = ask_for_confirmation("Warning: All information on "
					  "partition '%s' will be lost!\n"
					  "Do you want to continue creating "
					  "a dump partition (y/n)?", device);
		if (rc)
			break;
		if (verbose) {
			printf("Installing dump record on partition with %s\n",
			       disk_get_type_name(info->type));
		}
		if (info->type == disk_type_eckd_ldl)
			rc = install_svdump_eckd_ldl(&mfd, info, &stage2dump_parms);
		else if (info->type == disk_type_eckd_cdl)
			rc = install_svdump_eckd_cdl(&mfd, info, &stage2dump_parms);
		else
			rc = install_svdump_fba(&mfd, info, &stage2dump_parms);
		break;
	case disk_type_scsi:
		error_reason("%s: Unsupported disk type '%s' (try --dumptofs)",
			     device, disk_get_type_name(info->type));
		rc = -1;
		break;
	case disk_type_diag:
		error_reason("%s: Unsupported disk type '%s'",
			     device, disk_get_type_name(info->type));
		rc = -1;
		break;
	}
	misc_free_temp_dev(tempdev);
	disk_free_info(info);
	if (fsync(mfd.fd))
		error_text("Could not sync device file '%s'", device);
	if (close(mfd.fd))
		error_text("Could not close device file '%s'", device);
	return rc;
}


int
install_mvdump(char* const device[], struct job_target_data* target, int count,
	       uint64_t mem, uint8_t force)
{
	struct disk_info *info[MAX_DUMP_VOLUMES] = {0};
	struct stage2dump_parm_tail stage2dump_parms = {0};
	struct mvdump_parm_table mvdump_parms;
	uint64_t total_size = 0;
	struct timeval time;
	int rc = 0, i, j;
	char *tempdev;

	stage2dump_parms.mvdump_force = force;
	stage2dump_parms.mem_upper_limit = mem;
	memset(&mvdump_parms, 0, sizeof(struct mvdump_parm_table));
	gettimeofday(&time, NULL);
	mvdump_parms.num_param = count;
	mvdump_parms.timestamp = (time.tv_sec << 20) + time.tv_usec;
	for (i = 0; i < count; i++) {
		struct misc_fd mfd = {0};
		int dummy, ssid;
		char busid[16];

		if (misc_open_device(device[i], &mfd, dry_run) == -1) {
			error_text("Could not open dump target '%s'",
				   device[i]);
			rc = -1;
			goto out;
		}
		if (rewind_tape(mfd.fd) == 0) {
			/* Rewind worked - this is a tape */
			error_text("Dump target '%s' is a tape device",
				   device[i]);
			close(mfd.fd);
			rc = -1;
			goto out;
		}
		close(mfd.fd);
		/* This is a disk device */
		rc = disk_get_info(device[i], target, &info[i]);
		if (rc) {
			error_text("Could not get information for dump target "
				   "'%s'", device[i]);
			goto out;
		}
		if (info[i]->partnum == 0) {
			error_reason("Dump target '%s' is not a disk partition",
				     device[i]);
			rc = -1;
			goto out;
		}
		if (info[i]->type != disk_type_eckd_cdl) {
			error_reason("Dump target '%s' has to be ECKD DASD "
				     "with cdl format.", device[i]);
			rc = -1;
			goto out;
		}
		for (j = 0; j < i; j++) {
			if (info[j]->partition == info[i]->partition) {
				error_text("Dump targets '%s' and '%s' are "
					   "identical devices.",
					   device[i], device[j]);
				rc = -1;
				goto out;
			}
		}
		if (check_eckd_dump_partition(info[i])) {
			error_text("Dump target '%s'", device[i]);
			rc = -1;
			goto out;
		}
		mvdump_parms.param[i].start_blk = info[i]->geo.start;
		mvdump_parms.param[i].end_blk = info[i]->geo.start +
					info[i]->phy_blocks - 1;
		mvdump_parms.param[i].bpt = info[i]->geo.sectors;
		mvdump_parms.param[i].num_heads = info[i]->geo.heads;
		mvdump_parms.param[i].blocksize = info[i]->phy_block_size >> 8;
		mvdump_parms.param[i].devno = info[i]->devno;
		if (util_sys_get_dev_addr(device[i], busid) != 0) {
			error_text("Could not find bus-ID for '%s'", device[i]);
			rc = -1;
			goto out;
		}
		if (sscanf(busid, "%x.%x.%x", &dummy, &ssid, &dummy) != 3) {
			error_text("Could not find bus-ID for '%s'", device[i]);
			rc = -1;
			goto out;
		}
		mvdump_parms.ssid[i] = ssid;
	}
	if (verbose) {
		for (i = 0; i < count; i++) {
			printf("Multi-volume dump target %d:\n", i + 1);
			disk_print_info(info[i], target->source);
			printf("-------------------------------------------\n");
		}
	}
	for (i = 0; i < count; i++)
		total_size += info[i]->phy_block_size * info[i]->phy_blocks;
	printf("Dump target: %d partitions with a total size of %ld MB.\n",
	       count, (long) total_size >> 20);
	if (interactive && !dry_run) {
		printf("Warning: All information on the following "
		       "partitions will be lost!\n");
		for (i = 0; i < count; i++)
			printf("   %s\n", device[i]);
	}
	rc = ask_for_confirmation("Do you want to continue creating "
				  "multi-volume dump partitions "
				  "(y/n)?");
	if (rc)
		goto out;
	for (i = 0; i < count; i++) {
		struct misc_fd mfd = {0};

		rc = misc_temp_dev(info[i]->device, 1, &tempdev);
		if (rc) {
			rc = -1;
			goto out;
		}
		if (misc_open_device(tempdev, &mfd, dry_run) == -1) {
			error_text("Could not open temporary device node '%s'",
				   tempdev);
			misc_free_temp_dev(tempdev);
			rc = -1;
			goto out;
		}
		if (verbose)
			printf("Installing dump record on target partition "
			       "'%s'\n", device[i]);
		rc = install_mvdump_eckd_cdl(&mfd, info[i], &stage2dump_parms, &mvdump_parms);
		misc_free_temp_dev(tempdev);

		if (fsync(mfd.fd))
			error_text("Could not sync device file '%s'", device);
		if (close(mfd.fd))
			error_text("Could not close device file '%s'", device);

		if (rc)
			goto out;
	}
out:
	for (i = 0; i < count; i++)
		if (info[i] != NULL)
			disk_free_info(info[i]);
	return rc;
}
