/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * NGDump dump tool
 *
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mount.h>

#include "lib/dasd_base.h"
#include "lib/util_libc.h"
#include "lib/util_part.h"
#include "lib/util_log.h"
#include "lib/vtoc.h"
#include "boot/boot_defs.h"
#include "boot/linux_layout.h"

#include "zg.h"
#include "ngdump.h"

#define NGDUMP_META_VERSION	1
#define NGDUMP_META_FILENAME	"ngdump.meta"

enum ngdump_disk_type {
	NG_TYPE_DASD,
	NG_TYPE_NVME,
};

static const char *const ngtype2str[] = {
	[NG_TYPE_DASD] = "DASD",
	[NG_TYPE_NVME] = "NVME"
};

static int read_meta_from_file(const char *filename, struct ngdump_meta *meta)
{
	FILE *fp = NULL;
	char *line = NULL;

	memset(meta, 0, sizeof(*meta));

	fp = fopen(filename, "r");
	if (!fp)
		return -1;

	while (fscanf(fp, "%m[^\n]\n", &line) == 1) {
		char *ptr, *param = NULL, *value = NULL;

		/* Skip comments and empty lines */
		ptr = util_strstrip(line);
		if (strlen(ptr) == 0 || ptr[0] == '#')
			goto next_line;

		int n = sscanf(ptr, "%m[^=\n]=%m[^\n]\n", &param, &value);
		if (n != 2)
			goto next_line;

		if (strcmp(param, "version") == 0) {
			char *endptr;
			int version;
			version = strtol(value, &endptr, 0);
			if (*endptr == '\0')
				meta->version = version;
		} else if (strcmp(param, "file") == 0) {
			meta->file = value;
			value = NULL;
		} else if (strcmp(param, "sha256sum") == 0) {
			meta->sha256sum = value;
			value = NULL;
		}

	next_line:
		free(param);
		free(value);
		free(line);
		line = NULL;
	}

	fclose(fp);

	return 0;
}

static int calc_sha256sum(const char *filename, char **cksum)
{
	FILE *fp = NULL;
	char *cmd = NULL;
	char *line = NULL;

	*cksum = NULL;

	util_asprintf(&cmd, "sha256sum %s", filename);

	fp = popen(cmd, "r");
	free(cmd);
	if (!fp)
		return -1;

	while (fscanf(fp, "%m[^\n]\n", &line) == 1) {
		int n = sscanf(line, "%m[^ ]", cksum);

		free(line);
		line = NULL;

		if (n == 1)
			break;

		free(*cksum);
		*cksum = NULL;
	}

	pclose(fp);

	return 0;
}

static int check_sha256sum(const char *filename, const char *expected_cksum)
{
	char *got_cksum = NULL;
	int rc;

	rc = calc_sha256sum(filename, &got_cksum);
	if (rc)
		goto out_free_cksum;

	rc = strcmp(expected_cksum, got_cksum);
	if (rc)
		warnx("Invalid dump file SHA256 checksum, expected %s, got %s",
		      expected_cksum, got_cksum);

out_free_cksum:
	free(got_cksum);

	return rc;
}

static int validate_meta(const char *mount_point, struct ngdump_meta *meta)
{
	char *filename = NULL;
	int rc;

	if (meta->version != NGDUMP_META_VERSION) {
		warnx("Invalid NGDump version");
		return -1;
	}
	/*
	 * File might be not set if no dump was made yet after preparing
	 * with zipl, therefore, it is not considered an error. It indicates
	 * that the given partition is a valid NGDump partition but with no
	 * dump present.
	 */
	if (!meta->file)
		return 0;
	if (!meta->sha256sum) {
		warnx("Invalid NGDump SHA256 checksum");
		return -1;
	}

	util_asprintf(&filename, "%s/%s", mount_point, meta->file);

	rc = access(filename, R_OK);
	if (rc) {
		warnx("Could not access dump file \"%s\"", meta->file);
		goto out;
	}

	rc = check_sha256sum(filename, meta->sha256sum);
	if (rc)
		goto out;

	rc = 0;

out:
	free(filename);

	return rc;
}

int ngdump_read_meta_from_device(const char *device, struct ngdump_meta *meta)
{
	char mount_point[] = "/tmp/zdump-ngdump-XXXXXX";
	char *filename = NULL;
	int rc = 0;

	/* Create a mount point directory */
	if (mkdtemp(mount_point) == NULL) {
		rc = -1;
		goto out;
	}

	rc = mount(device, mount_point, NGDUMP_FSTYPE, MS_RDONLY, NULL);
	if (rc)
		goto out_rmdir;

	util_asprintf(&filename, "%s/%s", mount_point, NGDUMP_META_FILENAME);

	rc = read_meta_from_file(filename, meta);
	free(filename);
	if (rc)
		goto out_umount;

	rc = validate_meta(mount_point, meta);
	if (rc)
		goto out_umount;

	rc = 0;

out_umount:
	umount(mount_point);
out_rmdir:
	rmdir(mount_point);
out:
	return rc;
}

/*
 * Convert disk blockpointer to the offset in blocks.
 * Use eckd blockpointer format if hd_geometry is provided, otherwise linear blockpointer.
 * Return u64(-1) in case the blockpointer contains zeroes.
 */
static uint64_t blockptr2blk(union disk_blockptr *ptr, const struct hd_geometry *geo)
{
	uint64_t blk;

	/* For NVMe or SCSI use linear blockpointer format. */
	/* For DASD use eckd blockpointer format. */
	if (!geo) {
		blk = ptr->linear.blockno;
		if (blk == 0)
			return U64_MAX;
	} else {
		if (ptr->eckd.sec == 0)
			return U64_MAX;
		blk = ptr->eckd.cyl * geo->heads + ptr->eckd.head; /* Track number */
		blk *= geo->sectors;		 /* Track offset in records */
		blk += ptr->eckd.sec - 1;	 /* Record offset (skipping R0) */
	}
	return blk;
}

/*
 * Based on the provided program table blockpointer find kernel image Boot Map Section
 * for dump Boot Map Script. Read the first data blockpointer from the section into
 * blockptr area.
 */
static int get_bootmap_dump_image_blkptr(struct zg_fh *zg_fh, union disk_blockptr *program_table,
					 struct hd_geometry *geo, int blk_size,
					 union disk_blockptr *blockptr)
{
	struct component_entry comp_entry;
	struct component_header comp_hdr;
	int i, max_entries;
	uint64_t blk;

	/* Read Boot Map Table and check its magic */
	blk = blockptr2blk(program_table, geo);
	if (blk == U64_MAX)
		return -1;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Reading program table at offset 0x%016lx\n",
		       __func__, blk * blk_size);
	zg_seek(zg_fh, blk * blk_size, ZG_CHECK);
	zg_read(zg_fh, blockptr, sizeof(*blockptr), ZG_CHECK);
	if (memcmp((const char *)blockptr, ZIPL_MAGIC, ZIPL_MAGIC_SIZE))
		return -1;
	/* Read Boot Map Script Pointer 0 */
	zg_read(zg_fh, blockptr, sizeof(*blockptr), ZG_CHECK);
	blk = blockptr2blk(blockptr, geo);
	if (blk == U64_MAX)
		return -1;
	/* Read 1st Boot Map Script, check its magic and type */
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Reading component header at offset 0x%016lx\n",
		       __func__, blk * blk_size);
	zg_seek(zg_fh, blk * blk_size, ZG_CHECK_ERR);
	zg_read(zg_fh, &comp_hdr, sizeof(comp_hdr), ZG_CHECK_ERR);
	if (memcmp(comp_hdr.magic, ZIPL_MAGIC, ZIPL_MAGIC_SIZE))
		return -1;
	/* We want only dump script */
	if (comp_hdr.type != COMPONENT_HEADER_DUMP)
		return -1;
	/* Find kernel's Boot Map Section Pointer */
	max_entries = (blk_size - sizeof(comp_hdr)) / sizeof(comp_entry);
	for (i = 0; i < max_entries; i++) {
		zg_read(zg_fh, &comp_entry, sizeof(comp_entry), ZG_CHECK_ERR);
		util_log_print(UTIL_LOG_TRACE,
			       "%s: Component type 0x%x load address 0x%016lx\n",
			       __func__, comp_entry.type,
			       comp_entry.compdat.load_address);
		/* Is this a kernel image ? */
		if (comp_entry.type == COMPONENT_TYPE_LOAD &&
		    comp_entry.compdat.load_address == IMAGE_ENTRY)
			break;
	}
	if (i >= max_entries) {
		util_log_print(UTIL_LOG_DEBUG,
			       "%s: Couldn't find kernel component\n", __func__);
		return -1;
	}

	/* Read 1st Boot Map Data Pointer in kernel's Boot Map Section */
	blk = blockptr2blk((union disk_blockptr *)comp_entry.data, geo);
	if (blk == U64_MAX)
		return -1;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Reading component block pointer at offset 0x%016lx\n",
		       __func__, blk * blk_size);
	zg_seek(zg_fh, blk * blk_size, ZG_CHECK_ERR);
	zg_read(zg_fh, blockptr, sizeof(*blockptr), ZG_CHECK);

	return 0;
}

/*
 * This function parses the bootloader program table stored on the nvme device
 * and returns the partition index where the dumper's kernel image is stored.
 */
static int ngdump_get_nvme_part_num(struct zg_fh *zg_fh)
{
	union disk_blockptr dump_image_blkptr;
	int blk_size, part_num, part_ext;
	struct linear_blockptr *blockptr;
	struct scsi_mbr mbr;

	if (zg_ioctl(zg_fh, BLKSSZGET, &blk_size, "BLKSSZGET", ZG_CHECK_NONE))
		return -1;
	util_log_print(UTIL_LOG_TRACE, "%s: Block size %d\n",
		       __func__, blk_size);
	/* Read Master Boot Record (MBR) and check its magic */
	zg_read(zg_fh, &mbr, sizeof(mbr), ZG_CHECK);
	if (memcmp(mbr.magic, ZIPL_MAGIC, ZIPL_MAGIC_SIZE))
		return -1;
	blockptr = &mbr.program_table_pointer;
	/*
	 * Cast linear_blockptr to disk_blockptr before passing it to the function.
	 * Since no hd_geometry provided, it will be treated as linear_blockptr later on.
	 */
	if (get_bootmap_dump_image_blkptr(zg_fh, (union disk_blockptr *)blockptr,
					  NULL, blk_size, &dump_image_blkptr))
		return -1;
	blockptr = &dump_image_blkptr.linear;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Component block address 0x%016lx block count %d\n",
		       __func__, blockptr->blockno,
		       blockptr->blockct);
	if (blockptr->blockno == 0)
		return -1;
	part_num = util_part_search_fh(zg_fh->fh, blockptr->blockno, blockptr->blockct,
				       blk_size, &part_ext);
	return part_num;
}

/*
 * This function scans a VTOC record of cdl formatted DASD to identify a partition
 * the specified blockno (0-indexed) belongs to.
 */
static int find_vol1_cdl_part_fh(struct zg_fh *zg_fh, uint64_t blockno, int blk_size,
				 cchhb_t *vtoc, struct hd_geometry *geo)
{
	unsigned int part_count, i;
	struct format1_label f1;
	uint64_t blk;

	blk = cchhb2blk(vtoc, geo);
	if (!blk)
		return -1;
	/* Get actual offset in blocks (special record zero accounted) */
	blk--;
	part_count = 0;
	for (i = 0; i < MAX_VTOC_ENTRIES; i++) {
		zg_seek(zg_fh, blk * blk_size, ZG_CHECK);
		zg_read(zg_fh, &f1, sizeof(f1), ZG_CHECK_ERR);
		/* Skip FMT4 / FMT5 / FMT7 / FMT9 labels */
		if (f1.DS1FMTID == 0xf4 ||
		    f1.DS1FMTID == 0xf5 ||
		    f1.DS1FMTID == 0xf7 ||
		    f1.DS1FMTID == 0xf9) {
			blk++;
			continue;
		}
		/* only FMT1 and FMT8 labels valid at this point */
		if (f1.DS1FMTID != 0xf1 &&
		    f1.DS1FMTID != 0xf8)
			break;
		/* OK, we got valid partition data. Check for partition boundaries */
		if (blockno >= cchh2blk(&f1.DS1EXT1.llimit, geo) &&
		    blockno < cchh2blk(&f1.DS1EXT1.ulimit, geo) + geo->sectors) {
			return part_count + 1;
		}
		part_count++;
		blk++;
	}
	/* No matching partition found */
	return -1;
}

/*
 * This function parses the bootloader program table stored on the eckd device
 * and returns the partition index where the dumper's kernel image is stored.
 */
static int ngdump_get_eckd_part_num(struct zg_fh *zg_fh)
{
	union disk_blockptr dump_image_blkptr;
	struct eckd_blockptr *blockptr;
	struct eckd_boot_record br;
	struct vol_label_cdl vl;
	struct hd_geometry geo;
	uint64_t blk, off;
	cchhb_t *vtoc;
	int blk_size;

	if (zg_ioctl(zg_fh, BLKSSZGET, &blk_size, "BLKSSZGET", ZG_CHECK_NONE))
		return -1;
	util_log_print(UTIL_LOG_TRACE, "%s: Block size %d\n",
		       __func__, blk_size);
	/* Obtain DASD geometry */
	if (dasd_get_geo(zg_fh->path, &geo) != 0)
		return -1;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: DASD geometry: cyl=%d, heads=%d, sect=%d\n",
		       __func__,  geo.cylinders, geo.heads, geo.sectors);
	/* Read a volume label from CDL-formatted DASD */
	off = 2 * blk_size;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Reading a volume label at offset 0x%016lx\n",
		       __func__, off);
	zg_seek(zg_fh, off, ZG_CHECK_ERR);
	zg_read(zg_fh, &vl, sizeof(vl), ZG_CHECK);
	/* Verify that we have a VOL1 label */
	if (!is_vol1(vl.vollbl))
		return -1;
	/* Read Master Boot Record and check its magic */
	blk = cchhb2blk(&vl.br, &geo);
	if (blk == 0)
		return -1;
	off = (blk - 1) * blk_size;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Reading Master Boot Record at offset 0x%016lx\n",
		       __func__, off);
	zg_seek(zg_fh, off, ZG_CHECK_ERR);
	zg_read(zg_fh, &br, sizeof(br), ZG_CHECK);
	if (memcmp(br.magic, ZIPL_MAGIC, ZIPL_MAGIC_SIZE))
		return -1;

	blockptr = (struct eckd_blockptr *)&br.program_table_pointer;
	/*
	 * Cast eckd_blockptr to disk_blockptr before passing it to the function.
	 * With hd_geometry provided, it will be treated as eckd_blockptr later on.
	 */
	if (get_bootmap_dump_image_blkptr(zg_fh, (union disk_blockptr *)blockptr,
					  &geo, blk_size, &dump_image_blkptr))
		return -1;
	blk = blockptr2blk(&dump_image_blkptr, &geo);
	if (blk == U64_MAX)
		return -1;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Segment0 block number 0x%016lx\n",
		       __func__, blk);
	vtoc = &((volume_label_t *)&vl)->vtoc;
	return find_vol1_cdl_part_fh(zg_fh, blk, blk_size, vtoc, &geo);
}

/*
 * This function composes the absolute partition device node name
 * based on the device name, device type and the partition number.
 */
static int ngdump_get_part_path(const char *disk_path, int part_num,
				enum ngdump_disk_type ng_type, char **part_path)
{
	char *real_path;

	util_log_print(UTIL_LOG_TRACE, "%s: Disk path %s; disk type: %s\n",
		       __func__, disk_path, ngtype2str[ng_type]);

	real_path = util_malloc(PATH_MAX);

	if (!realpath(disk_path, real_path)) {
		free(real_path);
		return -1;
	}

	util_log_print(UTIL_LOG_TRACE, "%s: Real disk path %s\n",
		       __func__, real_path);

	*part_path = NULL;
	switch (ng_type) {
	case NG_TYPE_DASD:
		util_asprintf(part_path, "%s%d", real_path, part_num);
		break;
	case NG_TYPE_NVME:
		util_asprintf(part_path, "%sp%d", real_path, part_num);
		break;
	default: /* Unknown type, bail out */
		free(real_path);
		return -1;
	}

	free(real_path);

	util_log_print(UTIL_LOG_TRACE, "%s: Disk partition path %s\n",
		       __func__, *part_path);

	return 0;
}

/*
 * This function checks for the ngdump device type in order to parse the
 * bootloader program table and identify the partition where the dumper's
 * kernel image is stored.
 * part_path is set to the absolute partition device node name and
 * the partition number is returned (or -1 when no partition found).
 */
int ngdump_get_dump_part(struct zg_fh *zg_fh, char **part_path)
{
	dasd_information2_t dasd_info;
	enum ngdump_disk_type ng_type;
	int part_num;

	if (dasd_get_info(zg_fh->path, &dasd_info) == 0) {
		ng_type = NG_TYPE_DASD;
		part_num = ngdump_get_eckd_part_num(zg_fh);
	} else {
		ng_type = NG_TYPE_NVME;
		part_num = ngdump_get_nvme_part_num(zg_fh);
	}
	if (part_num <= 0 ||
	    ngdump_get_part_path(zg_fh->path, part_num, ng_type, part_path) < 0)
		return -1;

	return part_num;
}
