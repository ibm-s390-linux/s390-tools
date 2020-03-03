/*
 * cmsfs-fuse - CMS EDF filesystem support for Linux
 *
 * DASD specific functions
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/zt_common.h"
#include "cmsfs-fuse.h"
#include "edf.h"
#include "helper.h"

#define BLKSSZGET	_IO(0x12, 104)

/* CMS disk label starts with ASCII string "CMS1" */
#define VOL_LABEL_EBCDIC 0xc3d4e2f1

static int disk_supported(int fd, struct cmsfs *cmsfs)
{
	unsigned int cms_id = VOL_LABEL_EBCDIC;
	struct cms_label label;
	int rc;

	rc = lseek(fd, cmsfs->label, SEEK_SET);
	if (rc < 0) {
		perror(COMP "lseek failed");
		return 0;
	}

	rc = read(fd, &label, sizeof(label));
	if (rc < 0) {
		perror(COMP "read failed");
		return 0;
	}

	/* check that the label contains the CMS1 string */
	if (memcmp(label.id, &cms_id, sizeof(cms_id)) != 0)
		return 0;

	/* label sanity checks */
	if (label.blocksize != 4096 &&
	    label.blocksize != 2048 &&
	    label.blocksize != 1024 &&
	    label.blocksize != 512) {
		fprintf(stderr, COMP "Invalid disk block size!\n");
		return 0;
	}

	if (label.dop != 4 && label.dop != 5) {
		fprintf(stderr, COMP "Invalid disk origin pointer!\n");
		return 0;
	}

	if (label.fst_entry_size != sizeof(struct fst_entry)) {
		fprintf(stderr, COMP "Invalid FST entry size!\n");
		return 0;
	}

	if (label.fst_per_block != label.blocksize / label.fst_entry_size) {
		fprintf(stderr, COMP "Invalid FST per block value!\n");
		return 0;
	}

	/* set the blocksize to the formatted one */
	cmsfs->blksize = label.blocksize;
	DEBUG("  DOP: %d", label.dop);
	/* block number 5 means 0x4000... */
	cmsfs->fdir = (label.dop - 1) * cmsfs->blksize;
	DEBUG("  fdir: %lx", cmsfs->fdir);
	/* get disk usage for statfs */
	cmsfs->total_blocks = label.total_blocks;
	cmsfs->used_blocks = label.used_blocks;
	DEBUG("  Total blocks: %d  Used blocks: %d",
		cmsfs->total_blocks, cmsfs->used_blocks);

	return 1;
}

static void get_device_info_ioctl(int fd, struct cmsfs *cmsfs)
{
	if (ioctl(fd, BLKSSZGET, &cmsfs->blksize) != 0)
		DIE("ioctl error get blocksize\n");
}

static int label_offsets[] = { 4096, 512, 2048, 1024, 8192 };

static void get_device_info_file(int fd, struct cmsfs *cmsfs)
{
	unsigned int cms_id = VOL_LABEL_EBCDIC;
	unsigned int i;
	char label[4];
	off_t offset;
	int rc;

	cmsfs->label = 0;

	/*
	 * Read the blocksize from label. Unfortunately the blocksize
	 * position depends on the blocksize... time for some heuristics.
	 */
	for (i = 0; i < ARRAY_SIZE(label_offsets); i++) {
		offset = label_offsets[i];

		rc = lseek(fd, offset, SEEK_SET);
		if (rc < 0)
			DIE_PERROR("lseek failed");

		rc = read(fd, &label, 4);
		if (rc < 0)
			DIE_PERROR("read failed");

		/* check if the label contains the CMS1 string */
		if (memcmp(label, &cms_id, sizeof(cms_id)) == 0) {
			cmsfs->label = offset;
			break;
		}
	}

	if (!cmsfs->label)
		DIE("Error CMS1 label not found!\n");
}

int get_device_info(struct cmsfs *cmsfs)
{
	struct stat stat;
	int fd;

	/*
	 * Open writable, if write access is not granted fall back to
	 * read only.
	 */
	fd = open(cmsfs->device, O_RDWR);
	if (fd < 0) {
		if (errno == EROFS || errno == EACCES) {
			cmsfs->readonly = 1;
			fd = open(cmsfs->device, O_RDONLY);
			if (fd < 0)
				DIE_PERROR("open failed");
		} else
			DIE_PERROR("open failed");
	}

	if (fstat(fd, &stat) < 0)
		DIE_PERROR("fstat failed");

	if (S_ISBLK(stat.st_mode)) {
		get_device_info_ioctl(fd, cmsfs);
		cmsfs->label = 2 * cmsfs->blksize;

		/* FBA disks have a different label location */
		if (!disk_supported(fd, cmsfs)) {
			cmsfs->label = cmsfs->blksize;
			if (!disk_supported(fd, cmsfs))
				goto error;
		}
	} else if (S_ISREG(stat.st_mode))
		get_device_info_file(fd, cmsfs);
	else
		goto error;

	if (!disk_supported(fd, cmsfs))
		goto error;
	return fd;

error:
	DIE("Unsupported disk\n");
}
