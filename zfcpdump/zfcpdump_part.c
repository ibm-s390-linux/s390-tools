/*
 * zfcpdump - Write /proc/vmcore to SCSI partition
 *
 * This tool should be used in an intitramfs together with a kernel with
 * enabled CONFIG_ZFCPDUMP kernel build option. The tool is able to write
 * standalone system dumps on SCSI disks.
 *
 * See Documentation/s390/zfcpdump.txt for more information!
 *
 * Copyright IBM Corp. 2003, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <asm/types.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hdreg.h>
#include <linux/reboot.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/zt_common.h"
#include "boot/boot_defs.h"

#include "zfcpdump.h"

#define COPY_BUF_SIZE		0x10000UL

/*
 * Copy table entry
 */
struct copy_table_entry {
	unsigned long size;
	unsigned long off;
	bool hsa;
};

struct copy_table {
	int cnt;
	int max;
	struct copy_table_entry *entry;
};

/*
 * Globals
 */
static struct scsi_dump_sb dump_sb;
static struct scsi_mbr mbr;

/*
 * Read file at given offset
 */
static int pread_file(const char *path, char *buf, int size, uint64_t off)
{
	int fd;

	PRINT_TRACE("Read: %s:\n", path);
	fd = open(path, O_RDONLY);
	if (fd == -1) {
		PRINT_PERR("open %s failed\n", path);
		return -1;
	}
	if (lseek(fd, off, SEEK_SET) < 0) {
		PRINT_PERR("seek %s offset %llu failed\n", path,
			   (unsigned long long) off);
		return -1;
	}
	if (read(fd, buf, size) < 0) {
		PRINT_PERR("read %s failed\n", path);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

/*
 * Create checksum for buffer
 */
static inline uint32_t csum_partial(const void *buf, int len, uint32_t sum)
{
	register unsigned long reg2 asm("2") = (unsigned long) buf;
	register unsigned long reg3 asm("3") = (unsigned long) len;

	asm volatile(
		"0: cksm %0,%1\n" /* do checksum on longs */
			" jo 0b\n"
		: "+d" (sum), "+d" (reg2), "+d" (reg3) : : "cc",
		  "memory");
	return sum;
}

/*
 * Create checksum on SCSI device
 */
static int csum_get(uint64_t off, uint64_t len, uint64_t *result)
{
	char buf[len];

	if (pread_file(DEV_SCSI, (char *)&buf, sizeof(buf), off) < 0) {
		PRINT_ERR("Error reading checksum from disk\n");
		return -1;
	}
	*result = (uint64_t)csum_partial(&buf, len, SCSI_DUMP_SB_SEED);
	PRINT_TRACE("Got crc %llx\n", (unsigned long long) *result);
	return 0;
}

/*
 * Update superblock checksum on SCSI disk
 */
static int csum_update(int fd)
{
	/* Write crc into zfcpdump header */
	if (csum_get(dump_sb.part_start + dump_sb.csum_offset,
		     dump_sb.csum_size, &dump_sb.csum)) {
		PRINT_ERR("Get check sum failed\n");
		return -1;
	}
	if (lseek(fd, mbr.boot_info.bp.dump.param.scsi.block, SEEK_SET) < 0) {
		PRINT_PERR("Seek failed\n");
		return -1;
	}
	if (write(fd, &dump_sb, sizeof(dump_sb)) < 0) {
		PRINT_PERR("Write failed\n");
		return -1;
	}
	return 0;
}

static int cmp_ct_entries(const void *_entry1, const void *_entry2)
{
	const struct copy_table_entry *entry1 = (const struct copy_table_entry *)_entry1;
	const struct copy_table_entry *entry2 = (const struct copy_table_entry *)_entry2;

	/* Sort copy table entries by their file offset in ascending order */

	if (entry1->off <= entry2->off)
		return -1;
	else if (entry1->off > entry2->off)
		return 1;
	else
		return 0;
}

static inline void copy_table_add_entry(struct copy_table *table, unsigned long off,
					unsigned long size, bool hsa)
{
	const int i = table->cnt;
	table->entry[i].off = off;
	table->entry[i].size = size;
	table->entry[i].hsa = hsa;
	table->cnt++;
}

static void copy_table_add_non_hsa_file_regions(struct copy_table *table)
{
	const int hsa_entry_count = table->cnt;
	unsigned long off, size;
	int i;
	/*
	 * We write the front page of /proc/vmcore at the end of the dump processing.
	 * This ensures that the dump stays invalid until all data
	 * is written. It is guaranteed that a copy table entry for file offset 0
	 * never covers HSA memory and at least of size of a single page because
	 * HSA memory is always page aligned.
	 */
	off = PAGE_SIZE;
	size = table->entry[0].off - off;
	if (size > 0)
		copy_table_add_entry(table, off, size, false);
	/*
	 * Add copy table entries covering non-HSA file regions located before
	 * each copy table entry covering a HSA file region. Start with the second
	 * HSA copy table entry.
	 */
	for (i = 1; i < hsa_entry_count; i++) {
		off = table->entry[i - 1].off + table->entry[i - 1].size;
		size = table->entry[i].off - off;
		if (size > 0)
			copy_table_add_entry(table, off, size, false);
	}
	/*
	 * Add a copy table entry that covers the end of /proc/vmcore which is
	 * not covered by a copy table entry for HSA.
	 */
	i = hsa_entry_count - 1;
	off = table->entry[i].off + table->entry[i].size;
	if (off < g.vmcore_size) {
		size = g.vmcore_size - off;
		copy_table_add_entry(table, off, size, false);
	}
	/*
	 * Add a copy table entry covering the front page of /proc/vmcore which
	 * is not covered by HSA as the last entry.
	 */
	copy_table_add_entry(table, 0, PAGE_SIZE, false);
}

static int copy_table_init(int fd, struct copy_table *table)
{
	const unsigned long hsa_size = get_hsa_size();
	unsigned long off, size;
	int i, max_table_size;
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;

	g.vmcore_size = lseek(fd, (off_t) 0, SEEK_END);
	lseek(fd, 0L, SEEK_SET);
	if (g.vmcore_size < sizeof(ehdr))
		return -1;
	if (read(fd, &ehdr, sizeof(ehdr)) < 0)
		return -1;
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
		return -1;
	if (ehdr.e_type != ET_CORE)
		return -1;
	if (ehdr.e_machine != EM_S390 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
		PRINT_ERR("Only 64 bit core dump files are supported\n");
		return -1;
	}
	/*
	 * Each ELF LOAD segment may contain at most one HSA file region which will
	 * result in exactly one HSA copy table entry. Furthermore, this will result
	 * in at most 1 extra non-HSA copy table entry preceding the HSA copy
	 * table entry apart from the first and the last HSA copy table entries
	 * which will result in 2 non-HSA copy table entries.
	 *
	 *                            /proc/vmcore
	 *  -------------------------------------------------------------------
	 * | page sized | non-HSA  | HSA      | non-HSA  | HSA      | non-HSA  |
	 * | non-HSA    | region 2 | region 1 | region 3 | region 2 | region 4 |
	 * | region 1   |          |          |          |          |          |
	 *  -------------------------------------------------------------------
	 */
	table->cnt = 0;
	table->max = ehdr.e_phnum * 2 + 2;
	max_table_size = table->max * sizeof(struct copy_table_entry);
	table->entry = malloc(max_table_size);
	if (!table->entry) {
		PRINT_ERR("Memory allocation of %d byte(s) failed\n", max_table_size);
		return -1;
	}
	/*
	 * First add all HSA file regions to copy table.
	 * Each ELF LOAD segment may contain at most one HSA segment.
	 */
	for (i = 0; i < ehdr.e_phnum; i++) {
		if (read(fd, &phdr, sizeof(phdr)) < 0)
			return -1;
		if (phdr.p_type != PT_LOAD)
			continue;
		PRINT_TRACE("ELF LOAD segment: p_offset=0x%016lx p_filesz=0x%016lx p_paddr=0x%016lx p_vaddr=0x%016lx\n",
			    phdr.p_offset, phdr.p_filesz, phdr.p_paddr, phdr.p_vaddr);
		if (phdr.p_paddr >= hsa_size)
			continue;
		off = phdr.p_offset;
		size = MIN(phdr.p_filesz, hsa_size - phdr.p_paddr);
		if (size > 0)
			copy_table_add_entry(table, off, size, true);
	}
	if (table->cnt == 0) {
		PRINT_ERR("Could not find ELF LOAD segments containing HSA\n");
		return -1;
	}
	/* Sort all HSA copy table entries by their file offset */
	qsort(table->entry, table->cnt, sizeof(struct copy_table_entry), cmp_ct_entries);
	/*
	 * Add copy table entries which cover all of /proc/vmcore not covered
	 * by HSA copy table entries added above.
	 */
	copy_table_add_non_hsa_file_regions(table);
	return 0;
}

/*
 * Copy one copy table entry form /proc/vmcore to dump partition
 */
static int copy_table_entry_write(int fdin, int fdout,
				  const struct copy_table_entry *entry,
				  unsigned long disk_offset)
{
	static unsigned char buf[COPY_BUF_SIZE];
	unsigned long bytes_left, count;
	ssize_t bytes_read, bytes_written;

	bytes_left = entry->size;
	if (bytes_left == 0)
		return 0;
	if (lseek(fdin, entry->off, SEEK_SET) < 0)
		return -1;
	if (lseek(fdout, disk_offset + entry->off, SEEK_SET) < 0)
		return -1;
	PRINT_TRACE("Write dump: vmcore offset=0x%016lx disk offset=0x%016lx bytes=0x%016lx\n",
		    entry->off, disk_offset + entry->off, bytes_left);
	while (bytes_left > 0) {
		count = MIN(COPY_BUF_SIZE, bytes_left);
		bytes_read = read(fdin, buf, count);
		if (bytes_read < 0) {
			PRINT_PERR("Read from /proc/vmcore failed: offset=0x%016lx bytes=0x%016lx\n",
				   entry->off + entry->size - bytes_left, count);
			return -1;
		}
		bytes_written = write(fdout, buf, bytes_read);
		if (bytes_written < 0) {
			PRINT_PERR("Write to partition failed: offset=0x%016lx bytes=0x%016lx\n",
				   disk_offset + entry->off + entry->size - bytes_left,
				   bytes_read);
			return -1;
		}
		bytes_left -= bytes_written;
		show_progress(bytes_written);
	}
	return 0;
}

static int copy_dump(const char *in, const char *out, unsigned long offset)
{
	struct copy_table table = { 0 };
	char busy_str[] = "zfcpdump busy";
	int fdout, fdin, i, rc = -1, hsa_released = 0;

	fdin = open(in, O_RDONLY);
	if (fdin < 0) {
		PRINT_ERR("Open %s failed\n", in);
		return -1;
	}
	g.vmcore_size = lseek(fdin, (off_t) 0, SEEK_END);
	lseek(fdin, 0L, SEEK_SET);
	if (g.vmcore_size > dump_sb.dump_size) {
		PRINT_ERR("Disk too small: dump=%lldMB (diskspace=%lldMB)\n",
			  TO_MIB(g.vmcore_size), TO_MIB(dump_sb.dump_size));
		goto out_close_fdin;
	}
	fdout = open(out, O_WRONLY);
	if (fdout < 0) {
		PRINT_ERR("Open %s failed\n", out);
		goto out_close_fdin;
	}
	/* Overwrite old header */
	if (lseek(fdout, offset, SEEK_SET) < 0)
		goto out_close_fdin;
	if (write(fdout, busy_str, sizeof(busy_str)) == -1)
		goto out_close_fdin;
	if (csum_update(fdout))
		goto out_close_fdin;
	if (copy_table_init(fdin, &table))
		goto out_close_fdin;
	show_progress(0);
	for (i = 0; i < table.cnt; i++) {
		PRINT_TRACE("Write copy table entry %d: off=0x%016lx size=0x%016lx hsa=%d\n",
			    i, table.entry[i].off, table.entry[i].size, table.entry[i].hsa ? 1 : 0);
		if (!hsa_released && !table.entry[i].hsa) {
			/*
			 * First encountered non-HSA copy table entry guarantees
			 * that no more HSA memory copy table entries will appear
			 * and, therefore, HSA memory can be finally released.
			 */
			PRINT_TRACE("Release HSA memory\n");
			release_hsa();
			hsa_released = 1;
		}
		if (copy_table_entry_write(fdin, fdout, &table.entry[i], offset))
			goto out_close_fdout;
	}
	rc = 0;
out_close_fdout:
	if (csum_update(fdout))
		rc = -1;
	fsync(fdout);
	close(fdout);
	free(table.entry);
out_close_fdin:
	if (!hsa_released)
		release_hsa();
	close(fdin);
	return rc;
}

/*
 * Finds the matching partition to a given start and end. If a matching
 * partition is found, the partition number is returned.
 */
int find_part_num(uint64_t start, uint64_t size)
{
	struct hd_geometry geo;
	uint32_t block_size;
	uint64_t part_size;
	char path[11];
	int fd, i;

	PRINT_TRACE("Partiton to dump start: 0x%llx end: 0x%llx\n",
		    (unsigned long long) start, (unsigned long long) size);
	for (i = 1; i < 16; i++) {
		snprintf(path, sizeof(path), DEV_SCSI "%d", i);
		fd = open(path, O_RDONLY);
		if (fd == -1)
			continue;
		if (ioctl(fd, HDIO_GETGEO, &geo) != 0) {
			PRINT_PERR("Could not retrieve partition"
				   " geometry information\n");
			return -1;
		}
		if (ioctl(fd, BLKGETSIZE64, &part_size)) {
			PRINT_PERR("Could not retrieve partition"
				   " size information\n");
			return -1;
		}
		if (ioctl(fd, BLKSSZGET, &block_size)) {
			PRINT_PERR("Could not get blocksize");
			return -1;
		}
		PRINT_TRACE("Partiton %s start: 0x%llx end: 0x%llx\n", path,
			    (unsigned long long) geo.start * block_size,
			    (unsigned long long) part_size);
		if ((start == geo.start * block_size) && (size == part_size))
			return i;
	}
	return -1;
}

/*
 * Read the on-disk zfcpdump boot info and superblock into global variables
 */
static int get_scsi_dump_params(void)
{
	uint64_t csum;
	int part_num;

	if (pread_file(DEV_SCSI, (char *)&mbr, sizeof(mbr), 0) < 0) {
		PRINT_ERR("Cannot read MBR\n");
		return -1;
	}
	if (memcmp(&mbr.boot_info.magic, BOOT_INFO_MAGIC,
		   sizeof(mbr.boot_info.magic))) {
		PRINT_ERR("Boot_Info wrong magic\n");
		return -1;
	}
	if (mbr.boot_info.dev_type != BOOT_INFO_DEV_TYPE_SCSI) {
		PRINT_ERR("Boot_Info wrong dev type: %d\n",
			   mbr.boot_info.dev_type);
		return -1;
	}
	if (mbr.boot_info.bp_type != BOOT_INFO_BP_TYPE_DUMP) {
		PRINT_ERR("Boot_Info wrong bp type: %d\n",
			   mbr.boot_info.bp_type);
		return -1;
	}
	if (mbr.boot_info.version != BOOT_INFO_VERSION) {
		PRINT_ERR("Boot_Info wrong version: %d\n",
			   mbr.boot_info.version);
		return -1;
	}
	if (pread_file(DEV_SCSI, (char *)&dump_sb, sizeof(dump_sb),
		       mbr.boot_info.bp.dump.param.scsi.block) < 0) {
		PRINT_ERR("Cannot read superblock\n");
		return -1;
	}
	if (dump_sb.magic != SCSI_DUMP_SB_MAGIC) {
		PRINT_ERR("Dump data block wrong magic\n");
		return -1;
	}
	part_num = find_part_num(dump_sb.part_start, dump_sb.part_size);
	if (part_num < 0) {
		PRINT_ERR("Specified dump partition not found\n");
		return -1;
	}
	if (csum_get(dump_sb.part_start + dump_sb.csum_offset,
		     dump_sb.csum_size, &csum)) {
		PRINT_ERR("Getting Checksum failed\n");
		return -1;
	}
	if (csum != dump_sb.csum) {
		PRINT_ERR("Checksum wrong, filesystem changed\n");
		return -1;
	}
	PRINT(" partition: " DEV_SCSI "%d\n", part_num);
	return 0;
}

/*
 * Main routine of the zfcpdump tool
 */
int main(int UNUSED(argc), char *UNUSED(argv[]))
{
	int rc;

	if (zfcpdump_init())
		return terminate(1);
	PRINT("Dump parameters:\n");
	PRINT(" devno....: %s\n", g.dump_devno);
	PRINT(" wwpn.....: %s\n", g.dump_wwpn);
	PRINT(" lun......: %s\n", g.dump_lun);
	PRINT(" conf.....: %s\n", g.dump_bootprog);
	if (get_scsi_dump_params())
		return terminate(1);
	print_newline();
	PRINT("Writing dump:\n");
	rc = copy_dump("/proc/vmcore", DEV_SCSI,
		       dump_sb.part_start + dump_sb.dump_offset);
	return terminate(rc);
}
