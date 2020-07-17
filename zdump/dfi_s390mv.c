/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * S390 multi-volume dump input format
 *
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <err.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#include "lib/util_file.h"
#include "lib/util_path.h"

#include "zgetdump.h"
#include "dfi_s390mv.h"

/*
 * Volume information
 */
struct vol {
	dev_t			dev;
	struct zg_fh		*fh;
	char			*devnode;
	enum dev_status		status;
	enum dev_sign		sign;
	off_t			part_off;
	u64			part_size;
	u64			mem_start;
	u64			mem_end;
	char			bus_id[10];
	u32			nr;
	u16			blk_size;
	struct df_s390_dumper	dumper;
	struct df_s390_hdr	hdr;
};

/*
 * Mem chunk helper structure for extended dump format
 */
struct vol_mem_chunk {
	struct vol	*vol;
	u64		off; /* Offset to the memory chunk from the start of the volume */
};

/*
 * File local static data
 */
static struct {
	struct df_s390_hdr	hdr;
	struct df_s390_em	em;
	struct vol		vol_vec[MAX_VOLUMES];
	struct vol_parm_table	table;
	int			blk_size;
	struct df_s390_dumper	dumper;
	int			dump_incomplete;
	bool extended;
	u64 magic_number;	/* Reference value to compare with */
	char dumper_magic[7];	/* Reference value to compare with */
} l;

/*
 * Read volume parameter table
 */
static void table_read(struct zg_fh *fh, u16 blk_size,
		       struct vol_parm_table *table)
{
	int off;

	off = DF_S390_MAGIC_BLK_ECKD * blk_size + l.dumper.size;
	zg_seek(fh, off, ZG_CHECK);
	zg_read(fh, table, sizeof(*table), ZG_CHECK);
}

/*
 * Initialize dump end marker
 */
static void em_init(struct vol *vol)
{
	off_t em_off;

	em_off = vol->part_off + (vol->mem_end + 1 - vol->mem_start) +
		DF_S390_HDR_SIZE;
	zg_seek(vol->fh, em_off, ZG_CHECK);
	zg_read(vol->fh, &l.em, sizeof(l.em), ZG_CHECK);
	if (df_s390_em_verify(&l.em, &l.hdr) != 0)
		l.dump_incomplete = 1;
}

/*
 * Check whether a device with a given busid is online
 */
static unsigned int dev_is_online(const char *busid)
{
	unsigned int online;
	char *path;

	path = util_path_sysfs("%s/%s/online", SYSFS_BUSDIR, busid);
	if (util_file_read_ui(&online, 10, path) != 0) {
		warnx("Could not open \"%s\" (%s)", path, strerror(errno));
		free(path);
		exit(EXIT_FAILURE);
	}
	free(path);

	return online;
}

/*
 * Check sysfs, whether a device specified by its bus ID is defined and online.
 * Find out the corresponding dev_t
 */
static enum dev_status dev_from_busid(char *bus_id, dev_t *dev)
{
	struct dirent *direntp;
	int minor, major;
	char buf[10];
	DIR *fh_dir;
	char *sysfs;

	sysfs = util_path_sysfs("%s/%s", SYSFS_BUSDIR, bus_id);
	if (!util_path_is_dir(sysfs)) {
		free(sysfs);
		return DEV_UNDEFINED;
	}
	free(sysfs);

	if (!dev_is_online(bus_id))
		return DEV_OFFLINE;

	sysfs = util_path_sysfs("%s/%s/block", SYSFS_BUSDIR, bus_id);
	fh_dir = opendir(sysfs);
	if (!fh_dir) {
		warnx("Could not open \"%s\" (%s) ", sysfs, strerror(errno));
		goto err;
	}
	while ((direntp = readdir(fh_dir)))
		if (strncmp(direntp->d_name, "dasd", 4) == 0)
			break;
	if (direntp == NULL) {
		warnx("Problem with contents of \"%s\"", sysfs);
		goto err;
	}
	if (util_file_read_line(buf, sizeof(buf), "%s/%s/dev", sysfs, direntp->d_name)) {
		warnx("Could not read dev file (%s)", strerror(errno));
		goto err;
	}
	closedir(fh_dir);

	if (sscanf(buf, "%i:%i", &major, &minor) != 2) {
		warnx("Malformed content of \"%s\": %s", sysfs, buf);
		goto err;
	}
	*dev = makedev(major, minor);

	free(sysfs);

	return DEV_ONLINE;

err:
	if (fh_dir)
		closedir(fh_dir);
	free(sysfs);
	exit(EXIT_FAILURE);
}

/*
 * Check whether dump table on user specified dump device is
 * identical to the one found on this device.
 */
static void check_vol_table(struct vol *vol)
{
	struct vol_parm_table vol_table;

	table_read(vol->fh, vol->blk_size, &vol_table);
	if (memcmp(&vol_table, &l.table, sizeof(vol_table)))
		ERR_EXIT("Orphaned multi-volume dump device '%s'",
			 g.opts.device);
}

/*
 * Read dump tool, multi-volume dump parameter table, and dump header from the
 * input dump volume. Check input dump volume for:
 * - identical dump parameter table (that is it belongs to the same dump set)
 * - valid magic number in the dump tool
 * - valid dump sign in the dump header
 *
 * We read partition data via the device node. If another process
 * has changed partition data via the partition node, the corresponding
 * device node might still have old data in its buffers. Flush buffers
 * to keep things in sync.
 */
static void vol_read(struct vol *vol)
{
	zg_ioctl(vol->fh, BLKFLSBUF, NULL, "BLKFLSBUF", ZG_CHECK);
	df_s390_dumper_read(vol->fh, vol->blk_size, &vol->dumper);
	check_vol_table(vol);
	zg_seek(vol->fh, vol->part_off, ZG_CHECK);
	zg_read(vol->fh, &vol->hdr, DF_S390_HDR_SIZE, ZG_CHECK);
}

/*
 * Read memory chunk
 */
static void dfi_s390mv_mem_read(struct dfi_mem_chunk *mem_chunk, u64 off,
			       void *buf, u64 cnt)
{
	struct vol *vol = mem_chunk->data;

	zg_seek(vol->fh, vol->part_off + off + DF_S390_HDR_SIZE, ZG_CHECK);
	zg_read(vol->fh, buf, cnt, ZG_CHECK);
}

/*
 * Read memory chunk (extended)
 */
static void dfi_s390mv_ext_mem_read(struct dfi_mem_chunk *mem_chunk, u64 off,
				    void *buf, u64 cnt)
{
	struct vol_mem_chunk *vol_mem_chunk = mem_chunk->data;
	struct vol *vol = vol_mem_chunk->vol;

	zg_seek(vol->fh, vol_mem_chunk->off + off, ZG_CHECK);
	zg_read(vol->fh, buf, cnt, ZG_CHECK);
}

/*
 * Initialize DASD volume
 */
static void vol_init(struct vol *vol, struct vol_parm *vol_parm, int ssid,
		     u64 *mem_off)
{
	u64 blk_cnt = vol_parm->end_blk - vol_parm->start_blk + 1;

	sprintf(vol->bus_id, "0.%x.%04x", ssid, vol_parm->devno);
	vol->blk_size = vol_parm->blk_size << 8;
	vol->part_off = (u64)vol_parm->start_blk * vol->blk_size;
	vol->part_size = blk_cnt * vol->blk_size;
	vol->status = dev_from_busid(vol->bus_id, &vol->dev);
	vol->sign = SIGN_VALID;

	if (vol->status != DEV_ONLINE)
		return;

	vol->devnode = zg_devnode_create(vol->dev);
	vol->fh = dfi_dump_open(vol->devnode);

	vol_read(vol);

	if ((vol->hdr.volnr == vol->nr) && (vol->hdr.mem_size != 0))
		vol->sign = SIGN_ACTIVE;

	if (vol->hdr.mvdump_sign != l.magic_number) {
		vol->sign = SIGN_INVALID;
		l.dump_incomplete = 1;
	}

	if (strncmp(vol->dumper.magic, l.dumper_magic, 7) != 0) {
		vol->sign = SIGN_INVALID;
		l.dump_incomplete = 1;
	}

	if (vol->nr == 0)
		l.hdr = vol->hdr;

	if (l.extended)
		return;

	if (*mem_off == l.hdr.mem_size) {
		/* Unused volume */
		vol->mem_start = 0;
		vol->mem_end = 0;
		if (vol->sign == SIGN_ACTIVE)
			vol->sign = SIGN_VALID;
	} else {
		/* Used volume */
		vol->mem_start = *mem_off;
		vol->mem_end = *mem_off + PAGE_ALIGN(vol->part_size) -
			DF_S390_HDR_SIZE - 1;
		vol->mem_end = MIN(vol->mem_end, l.hdr.mem_size - 1);
		if (vol->mem_end == l.hdr.mem_size - 1)
			em_init(vol);
		*mem_off += vol->mem_end - vol->mem_start + 1;
	}
}

/*
 * Print volume information
 */
static void vol_print(struct vol *vol)
{
	STDERR("  Volume %i: %s (%s", vol->nr, vol->bus_id,
	      dev_status_str(vol->status));
	if (vol->status == DEV_ONLINE)
		STDERR("/%s)\n", dev_sign_str(vol->sign));
	else
		STDERR(")\n");
}

/*
 * Print information for all volumes
 */
static void vol_print_all(void)
{
	unsigned int i;

	for (i = 0; i < l.table.vol_cnt; i++)
		vol_print(&l.vol_vec[i]);
}

/*
 * Add memory chunks
 */
static void mem_chunks_add(void)
{
	struct vol *vol;
	unsigned int i;

	for (i = 0; i < l.table.vol_cnt; i++) {
		vol = &l.vol_vec[i];
		if (vol->sign != SIGN_ACTIVE)
			continue;
		dfi_mem_chunk_add_vol(vol->mem_start,
				      vol->mem_end - vol->mem_start + 1,
				      vol, dfi_s390mv_mem_read, NULL, vol->nr);
	}
}

/*
 * Add memory chunks (extended dump format) and verify the end marker
 */
static int mem_chunks_add_ext(void)
{
	u64 off, rc, part_end, old = 0, dump_size = 0;
	struct df_s390_dump_segm_hdr dump_segm;
	struct vol_mem_chunk *vol_mem_chunk;
	unsigned int i;

	for (i = 0; i < l.table.vol_cnt; i++) {
		struct vol *vol = &l.vol_vec[i];
		if (vol->sign != SIGN_ACTIVE)
			continue;
		off = vol->part_off + DF_S390_HDR_SIZE;
		part_end = vol->part_off + vol->part_size;
		rc = zg_seek(vol->fh, off, ZG_CHECK_NONE);
		if (rc != off)
			return -EINVAL;
		/*
		 * Reading dump segments from the start of partition (skipping
		 * the dump header) till the end of partition (considering that
		 * minimum dump segment size is one megabyte + one page and one
		 * more page is reserved for the end marker)
		 */
		while (off < part_end - MIB - PAGE_SIZE) {
			rc = zg_read(vol->fh, &dump_segm, sizeof(dump_segm),
				     ZG_CHECK_ERR);
			if (rc != PAGE_SIZE)
				return -EINVAL;
			off += PAGE_SIZE;
			vol_mem_chunk = zg_alloc(sizeof(*vol_mem_chunk));
			vol_mem_chunk->vol = vol;
			vol_mem_chunk->off = off;
			/* Add zero memory chunk */
			dfi_mem_chunk_add_vol(old, dump_segm.start - old, NULL,
					      dfi_mem_chunk_read_zero, NULL,
					      vol->nr);
			/* Add memory chunk for a dump segment */
			dfi_mem_chunk_add_vol(dump_segm.start, dump_segm.len,
					      vol_mem_chunk,
					      dfi_s390mv_ext_mem_read, NULL,
					      vol->nr);
			old = dump_segm.start + dump_segm.len;
			dump_size += dump_segm.len;
			off = zg_seek_cur(vol->fh, dump_segm.len,
					  ZG_CHECK_NONE);
			if (dump_segm.stop_marker)
				break;
		}
		if (dump_segm.stop_marker) {
			/* Add zero memory chunk at the end*/
			dfi_mem_chunk_add_vol(old, l.hdr.mem_size - old, NULL,
					      dfi_mem_chunk_read_zero, NULL,
					      vol->nr);
			/* Set the actual size of the dump file */
			dfi_attr_file_size_set(dump_size);
			/* Read and verify the end marker */
			rc = zg_read(vol->fh, &l.em, sizeof(l.em), ZG_CHECK);
			if (rc != sizeof(l.em) ||
			    df_s390_em_verify(&l.em, &l.hdr) != 0)
				return -EINVAL;
			return 0;
		}
	}
	/* No dump segment with the stop marker found */
	return -EINVAL;
}

/*
 * Print hint for setting all offline volumes online
 */
static void vol_offline_msg(void)
{
	unsigned int i, first = 1;

	STDERR("\n");
	STDERR("Set all devices online using:\n");
	STDERR("# chccwdev -e ");
	for (i = 0; i < l.table.vol_cnt; i++) {
		if (l.vol_vec[i].status == DEV_OFFLINE) {
			if (first)
				first = 0;
			else
				STDERR(",");
			STDERR("%s", l.vol_vec[i].bus_id);
		}
	}
	STDERR("\n");
}

/*
 * Print error for all undefined volumes
 */
static void vol_undefined_msg(void)
{
	unsigned int i;

	STDERR("\n");
	STDERR("Ensure that the following devices are available to the "
	      "system:\n");
	for (i = 0; i < l.table.vol_cnt; i++) {
		if (l.vol_vec[i].status == DEV_UNDEFINED)
			STDERR("* %s\n", l.vol_vec[i].bus_id);
	}
}

/*
 * Check that all volumes are in online state
 */
static int vol_online_check(void)
{
	unsigned int i, offline = 0, undefined = 0;

	for (i = 0; i < l.table.vol_cnt; i++) {
		if (l.vol_vec[i].status == DEV_OFFLINE)
			offline = 1;
		if (l.vol_vec[i].status == DEV_UNDEFINED)
			undefined = 1;
	}
	if (!offline && !undefined)
		return 0;

	STDERR("Found multi-volume dump tool:\n\n");
	vol_print_all();
	if (offline)
		vol_offline_msg();
	if (undefined)
		vol_undefined_msg();
	return -ENODEV;
}

/*
 * Check if on device is a multi-volume dump
 */
static int mvdump_hdr_check(const char *file)
{
	struct df_s390_hdr hdr;
	struct zg_fh *fh;
	int rc = -ENODEV;

	fh = zg_open(file, O_RDONLY, ZG_CHECK);
	if (zg_read(fh, &hdr, sizeof(hdr), ZG_CHECK_ERR) != sizeof(hdr))
		goto fail;
	if (hdr.magic != l.magic_number)
		goto fail;
	if (hdr.mvdump_sign != l.magic_number)
		goto fail;
	rc = 0;
fail:
	zg_close(fh);
	return rc;
}

/*
 * Read dump tool from DASD and check if we have a multi-volume dump tool
 */
static int mv_dumper_read(void)
{
	if (zg_ioctl(g.fh, BLKSSZGET, &l.blk_size, "BLKSSZGET",
		     ZG_CHECK_NONE) == -1)
		return -ENODEV;
	df_s390_dumper_read(g.fh, l.blk_size, &l.dumper);
	if (strncmp(l.dumper.magic, l.dumper_magic, 7) != 0)
		return -ENODEV;
	table_read(g.fh, l.blk_size, &l.table);
	return 0;
}

/*
 * Initialize all volumes
 */
static void volumes_init(void)
{
	u64 mem_off = 0;
	unsigned int i;

	for (i = 0; i < l.table.vol_cnt; i++) {
		l.vol_vec[i].nr = i;
		vol_init(&l.vol_vec[i], &l.table.vol_parm[i], l.table.ssid[i],
			 &mem_off);
	}
	if (l.extended)
		return;
	if (mem_off != l.hdr.mem_size)
		l.dump_incomplete = 1;
}

/*
 * Open dump - If partition is specified open device instead
 */
static int open_dump(void)
{
	const struct stat *stat = zg_stat(g.fh);
	unsigned int dev_minor;
	enum zg_type type;
	char *path;

	type = zg_type(g.fh);
	if (type != ZG_TYPE_DASD && type != ZG_TYPE_DASD_PART)
		return -ENODEV;

	if (type == ZG_TYPE_DASD_PART) {
		dev_minor = minor(stat->st_rdev) - (minor(stat->st_rdev) % 4);
		if (mvdump_hdr_check(zg_path(g.fh)) != 0)
			return -ENODEV;
		path = zg_devnode_create(makedev(major(stat->st_rdev),
						 dev_minor));
		zg_close(g.fh);
		g.fh = zg_open(path, O_RDONLY, ZG_CHECK);
	}
	if (mv_dumper_read() != 0)
		return -ENODEV;
	zg_close(g.fh);
	return 0;
}

/*
 * Specify reference values for dumper magic and dump magic numbers
 */
static void set_magic_numbers(void)
{
	if (l.extended) {
		l.magic_number = DF_S390_MAGIC_EXT;
		memcpy(l.dumper_magic, DF_S390_DUMPER_MAGIC_MV_EXT, 7);
	} else {
		l.magic_number = DF_S390_MAGIC;
		memcpy(l.dumper_magic, DF_S390_DUMPER_MAGIC_MV, 7);
	}
}

/*
 * Initialize s390 multi-volume input dump format generic function
 */
int dfi_s390mv_init_gen(bool extended)
{
	l.extended = extended;
	set_magic_numbers();
	if (open_dump() != 0)
		return -ENODEV;
	volumes_init();
	if (vol_online_check() != 0)
		zg_exit(1);
	if (l.hdr.mem_size == 0)
		return -ENODEV;
	df_s390_hdr_add(&l.hdr);
	if (!extended)
		mem_chunks_add();
	else if (mem_chunks_add_ext() != 0)
		return -EINVAL;
	if (l.dump_incomplete)
		return -EINVAL;
	df_s390_cpu_info_add(&l.hdr, l.hdr.mem_end);
	df_s390_em_add(&l.em);
	return 0;
}

/*
 * Initializt s390 multi-volume input dump
 */
static int dfi_s390mv_init(void)
{
	return dfi_s390mv_init_gen(DUMP_NON_EXTENDED);
}

/*
 * Print dump information (dfi operation)
 */
void dfi_s390mv_info(void)
{
	vol_print_all();
}

/*
 * Initialize s390 multi-volume dump tool generic function
 */
int dt_s390mv_init_gen(bool extended)
{
	l.extended = extended;
	set_magic_numbers();
	if (open_dump() != 0)
		return -ENODEV;
	volumes_init();
	dt_arch_set(DFI_ARCH_64);
	dt_version_set(l.dumper.version);
	dt_attr_mem_limit_set(l.dumper.mem);
	dt_attr_force_set(l.dumper.force);
	return 0;
}

/*
 * s390 multi-volume dump tool info function (for -d option)
 */
void dt_s390mv_info(void)
{
	vol_print_all();
}

/*
 * S390 multi-volume DFI operations
 */
struct dfi dfi_s390mv = {
	.name		= "s390mv",
	.init		= dfi_s390mv_init,
	.info_dump	= dfi_s390mv_info,
	.feat_bits	= DFI_FEAT_COPY | DFI_FEAT_SEEK,
};
