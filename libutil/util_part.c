/*
 * util - Utility function library
 *
 * Partition detection functions
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_part.h"

#define GPT_SIGNATURE		0x4546492050415254ULL /* EFI PART */
#define MBR_SIGNATURE		0x55aa
#define MBR_PART_TYPE_DOS_EXT	0x05 /* DOS extended partition */
#define MBR_PART_TYPE_WIN98_EXT	0x0f /* Windows 98 extended partition */
#define MBR_PART_TYPE_LINUX_EXT	0x85 /* Linux extended partition */
#define MBR_PART_TYPE_GPT	0xee /* GPT partition */
#define MBR_EXT_PART_NUM_FIRST	5 /* Partition number for first logical vol */

/*
 * MBR/MSDOS partition entry
 */
struct mbr_part_entry {
	uint8_t status;
	uint8_t chs_start[3];
	uint8_t type;
	uint8_t chs_end[3];
	uint32_t blk_start;
	uint32_t blk_cnt;
} __attribute__((packed));

/*
 * Master Boot Record (MBR)
 */
struct mbr {
	uint8_t reserved[0x1be];
	struct mbr_part_entry part_entry_vec[4];
	uint16_t signature;
} __attribute__((packed));

/*
 * GUID Partition Table (GPT) header
 */
struct gpt {
	uint64_t signature;
	uint32_t version;
	uint32_t hdr_size;
	uint32_t hdr_crc;
	uint32_t reserved1;
	uint64_t blk_cur;
	uint64_t blk_back;
	uint64_t blk_first;
	uint64_t blk_last;
	uint8_t guid[16];
	uint64_t part_tab_blk_start;
	uint32_t part_tab_cnt;
	uint32_t part_tab_entry_size;
	uint32_t part_tab_crc;
} __attribute__((packed));

/*
 * GPT partition entry
 */
struct gpt_part_entry {
	uint8_t type[16];
	uint8_t guid[16];
	uint64_t blk_start;
	uint64_t blk_end;
	uint64_t attr;
	char name[72];
} __attribute__((packed));

/*
 * Check for extended partition
 */
static int mbr_part_is_ext(uint8_t type)
{
	if ((type == MBR_PART_TYPE_DOS_EXT) ||
	    (type == MBR_PART_TYPE_WIN98_EXT) ||
	    (type == MBR_PART_TYPE_LINUX_EXT))
		return 1;
	return 0;
}

/*
 * Check if disk has a classic MBR partion table
 */
static int mbr_table_valid(struct mbr *mbr)
{
	return mbr->signature == MBR_SIGNATURE;
}

/*
 * Search partition in logical volumes of an extended partition
 */
static int mbr_table_ext_search(int fh, size_t blk_start_mbr,
				size_t blk_start, size_t blk_cnt,
				size_t blk_size, int part_num)
{
	size_t start, cnt, start_next;
	struct mbr mbr;

	/* Read MBR for logical volume */
	if (lseek(fh, blk_start_mbr * blk_size, SEEK_SET) == (off_t)-1)
		return -1;
	if (read(fh, &mbr, sizeof(mbr)) == -1)
		return -1;

	/* Check for invalid MBR or last entry */
	if (mbr.signature != MBR_SIGNATURE)
		return -1;
	if (mbr.part_entry_vec[0].blk_start == 0)
		return -1;

	/* First entry contains a relative offset for current logical volume */
	start = blk_start_mbr + le32toh(mbr.part_entry_vec[0].blk_start);
	cnt = le32toh(mbr.part_entry_vec[0].blk_cnt);

	if ((start == blk_start) && (cnt == blk_cnt))
		return part_num;

	/* Second entry contains relative offset for next logical volume */
	start_next = le32toh(mbr.part_entry_vec[1].blk_start);
	if (start_next == 0)
		return 0;
	start_next += blk_start_mbr;

	/* Recursively search for next logical volume in chain */
	return mbr_table_ext_search(fh, start_next, blk_start, blk_cnt,
				    blk_size, part_num + 1);
}

/*
 * Search partition in MBR partition table
 */
static int mbr_table_search(int fh, struct mbr *mbr, size_t blk_start,
			    size_t blk_cnt, size_t blk_size, int *part_ext)
{
	int part_num_ext, part_num;
	size_t start, cnt;
	uint8_t type;

	for (part_num = 1; part_num <= 4; part_num++) {
		type = mbr->part_entry_vec[part_num - 1].type;
		start = le32toh(mbr->part_entry_vec[part_num - 1].blk_start);
		cnt = le32toh(mbr->part_entry_vec[part_num - 1].blk_cnt);
		if (start == 0) /* Empty slot */
			continue;
		/*
		 * The kernel sets count for extended partitions explicitly.
		 * Therefore we do not check count here.
		 */
		if (mbr_part_is_ext(type) && (start == blk_start)) {
			*part_ext = 1;
			return part_num;
		}
		if ((start == blk_start) && (cnt == blk_cnt))
			return part_num;
		if (!mbr_part_is_ext(type))
			continue;
		part_num_ext = mbr_table_ext_search(fh, start, blk_start,
						    blk_cnt, blk_size,
						    MBR_EXT_PART_NUM_FIRST);
		if (part_num_ext != 0)
			return part_num_ext;
	}
	return 0;
}

/*
 * Search partition in GPT partition table
 */
static int gpt_table_search(int fh, struct gpt *gpt, size_t blk_start,
			    size_t blk_cnt, size_t blk_size)
{
	size_t start, end, part_tab_blk_start, blk_end;
	uint32_t part_tab_cnt, part_tab_entry_size;
	struct gpt_part_entry *part_entry;
	unsigned int part_num;

	blk_end = blk_start + blk_cnt - 1;
	part_tab_entry_size = le32toh(gpt->part_tab_entry_size);
	part_tab_cnt = le32toh(gpt->part_tab_cnt);
	part_tab_blk_start = le64toh(gpt->part_tab_blk_start);

	if (lseek(fh, part_tab_blk_start * blk_size, SEEK_SET) == (off_t)-1)
		return -1;
	for (part_num = 1; part_num <= part_tab_cnt; part_num++) {
		char buf[part_tab_entry_size];

		part_entry = (struct gpt_part_entry *) buf;
		if (read(fh, buf, sizeof(buf)) == -1)
			return -1;
		start = le64toh(part_entry->blk_start);
		end = le64toh(part_entry->blk_end);
		if (start == 0) /* Empty slot */
			continue;
		if ((start == blk_start) && (end == blk_end))
			return part_num;
	}
	return 0;
}

/*
 * Check if disk has a GPT partition table
 */
static int gpt_table_valid(struct gpt *gpt, struct mbr *mbr)
{
	int cnt, part_num;
	uint32_t start;
	uint8_t type;

	if (gpt->signature != GPT_SIGNATURE)
		return 0;

	/* Check for protective MBR (one reserved GPT partition) */
	for (part_num = 1, cnt = 0; part_num <= 4; part_num++) {
		start = le32toh(mbr->part_entry_vec[part_num - 1].blk_start);
		type = mbr->part_entry_vec[part_num - 1].type;
		if (!start)
			continue;
		if (type != MBR_PART_TYPE_GPT)
			return 0;
		if (++cnt > 1)
			return 0;
	}
	return 1;
}

/*
 * Search for partition with given start block and count
 *
 * Return partition number when found, 0 when not found, and on error -1
 * Set "part_ext" to 1 for extended partitions otherwise to 0.
 */
int util_part_search_fh(int fh, size_t blk_start, size_t blk_cnt,
			size_t blk_size, int *part_ext)
{
	struct gpt gpt;
	struct mbr mbr;

	if (lseek(fh, 0, SEEK_SET) == (off_t)-1)
		return -1;
	if (read(fh, &mbr, sizeof(mbr)) == -1)
		return -1;
	if (lseek(fh, blk_size, SEEK_SET) == (off_t)-1)
		return -1;
	if (read(fh, &gpt, sizeof(gpt)) == -1)
		return -1;
	*part_ext = 0;
	if (gpt_table_valid(&gpt, &mbr))
		return gpt_table_search(fh, &gpt, blk_start, blk_cnt, blk_size);
	if (mbr_table_valid(&mbr))
		return mbr_table_search(fh, &mbr, blk_start, blk_cnt, blk_size,
					part_ext);
	return -1;
}

/*
 * Search for partition with given start block and count
 *
 * Return partition number when found, 0 when not found, and on error -1
 * Set "part_ext" to 1 for extended partitions otherwise to 0.
 */
int util_part_search(const char *device, size_t blk_start, size_t blk_cnt,
		     size_t blk_size, int *part_ext)
{
	int rc, fh;

	fh = open(device, O_RDONLY);
	if (fh == -1)
		return -1;
	rc = util_part_search_fh(fh, blk_start, blk_cnt, blk_size, part_ext);
	close(fh);
	return rc;
}
