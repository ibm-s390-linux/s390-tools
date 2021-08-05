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

#include "lib/util_libc.h"
#include "lib/util_part.h"
#include "lib/util_log.h"
#include "boot/boot_defs.h"
#include "boot/linux_layout.h"

#include "zg.h"
#include "ngdump.h"

#define NGDUMP_META_VERSION	1
#define NGDUMP_META_FILENAME	"ngdump.meta"

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
 * This function parses the bootloader program table stored on the given device
 * and returns the partition index where the dumper's kernel image is stored.
 */
int ngdump_get_dump_part(struct zg_fh *zg_fh)
{
	int i, blk_size, max_entries, part_ext;
	struct component_entry comp_entry;
	struct component_header comp_hdr;
	struct linear_blockptr blockptr;
	struct scsi_mbr mbr;
	uint64_t off;

	if (zg_ioctl(zg_fh, BLKSSZGET, &blk_size, "BLKSSZGET", ZG_CHECK_NONE))
		return -1;

	util_log_print(UTIL_LOG_TRACE, "%s: Block size %d\n",
		       __func__, blk_size);

	/* Read Master Boot Record (MBR) and check its magic */
	zg_read(zg_fh, &mbr, sizeof(mbr), ZG_CHECK);
	if (memcmp(mbr.magic, ZIPL_MAGIC, ZIPL_MAGIC_SIZE))
		return -1;

	/* Read Boot Map Table and check its magic */
	off = mbr.program_table_pointer.blockno * blk_size;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Reading program table at offset 0x%016lx\n",
		       __func__, off);
	zg_seek(zg_fh, off, ZG_CHECK);
	zg_read(zg_fh, &blockptr, sizeof(blockptr), ZG_CHECK);
	if (memcmp((const char*)&blockptr, ZIPL_MAGIC, ZIPL_MAGIC_SIZE))
		return -1;

	/* Read Boot Map Script Pointer 0 */
	zg_read(zg_fh, &blockptr, sizeof(blockptr), ZG_CHECK);
	if (blockptr.blockno == 0)
		return -1;
	/* Read 1st Boot Map Script, check its magic and type */
	off = blockptr.blockno * blk_size;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Reading component header at offset 0x%016lx\n",
		       __func__, off);
	zg_seek(zg_fh, off, ZG_CHECK_ERR);
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
		if (comp_entry.type == COMPONENT_LOAD &&
		    comp_entry.compdat.load_address == IMAGE_ENTRY)
			break;
	}
	if (i >= max_entries) {
		util_log_print(UTIL_LOG_DEBUG,
			       "%s: Couldn't find kernel component\n", __func__);
		return -1;
	}

	/* Read 1st Boot Map Data Pointer in kernel's Boot Map Section */
	off = ((struct linear_blockptr *)comp_entry.data)->blockno * blk_size;
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Reading component block pointer at offset 0x%016lx\n",
		       __func__, off);
	zg_seek(zg_fh, off, ZG_CHECK_ERR);
	zg_read(zg_fh, &blockptr, sizeof(blockptr), ZG_CHECK);
	util_log_print(UTIL_LOG_TRACE,
		       "%s: Component block address 0x%016lx block count %d\n",
		       __func__, blockptr.blockno, blockptr.blockct);

	return util_part_search_fh(zg_fh->fh, blockptr.blockno,
				   blockptr.blockct, blk_size, &part_ext);
}

int ngdump_get_disk_part_path(const char *disk_path, int part_num,
			      char **part_path)
{
	char *real_path;

	util_log_print(UTIL_LOG_TRACE, "%s: Disk path %s\n",
		       __func__, disk_path);

	real_path = util_malloc(PATH_MAX);

	if (!realpath(disk_path, real_path)) {
		free(real_path);
		return -1;
	}

	util_log_print(UTIL_LOG_TRACE, "%s: Real disk path %s\n",
		       __func__, real_path);

	*part_path = NULL;
	util_asprintf(part_path, "%sp%d", real_path, part_num);
	free(real_path);

	util_log_print(UTIL_LOG_TRACE, "%s: Disk partition path %s\n",
		       __func__, *part_path);

	return 0;
}
