/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * kdump and kdump_flat input format
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "zgetdump.h"

struct df_kdump_hdr {
	char			signature[8];
	int			header_version;
	struct new_utsname	utsname;
	struct timeval		timestamp;
	unsigned int		status;
	int			block_size;
	int			sub_hdr_size;
	unsigned int		bitmap_blocks;
	unsigned int		max_mapnr;
	unsigned int		total_ram_blocks;
	unsigned int		device_blocks;
	unsigned int		written_blocks;
	unsigned int		current_cpu;
	int			nr_cpus;
	void			*tasks[0];
};

struct df_kdump_sub_hdr {
	unsigned long	phys_base;
	int		dump_level;
	int		split;
	unsigned long	start_pfn;
	unsigned long	end_pfn;
	off_t		offset_vmcoreinfo;
	unsigned long	size_vmcoreinfo;
};

struct df_kdump_flat_hdr {
	char	signature[16];
	u64	type;
	u64	version;
};

struct df_kdump_flat_data_hdr {
	s64	offs;
	s64	size;
};

/*
 * File local static data
 */
static struct {
	struct df_kdump_hdr	hdr;	/* kdump (diskdump) dump header */
	struct df_kdump_sub_hdr	shdr;	/* kdump subheader */
} l;

#ifdef DEBUG
static void print_header(void)
{
	STDERR("diskdump main header\n");
	STDERR("  signature        : %s\n", l.hdr.signature);
	STDERR("  header_version   : %d\n", l.hdr.header_version);
	STDERR("  status           : %d\n", l.hdr.status);
	STDERR("  block_size       : %d\n", l.hdr.block_size);
	STDERR("  sub_hdr_size     : %d\n", l.hdr.sub_hdr_size);
	STDERR("  bitmap_blocks    : %d\n", l.hdr.bitmap_blocks);
	STDERR("  max_mapnr        : 0x%x\n", l.hdr.max_mapnr);
	STDERR("  total_ram_blocks : %d\n", l.hdr.total_ram_blocks);
	STDERR("  device_blocks    : %d\n", l.hdr.device_blocks);
	STDERR("  written_blocks   : %d\n", l.hdr.written_blocks);
	STDERR("  current_cpu      : %d\n", l.hdr.current_cpu);
	STDERR("  nr_cpus          : %d\n", l.hdr.nr_cpus);
}

static void print_sub_header(void)
{
	STDERR("kdump sub header\n");
	STDERR("  phys_base        : 0x%lx\n", l.shdr.phys_base);
	STDERR("  dump_level       : %d\n", l.shdr.dump_level);
	STDERR("  split            : %d\n", l.shdr.split);
	STDERR("  start_pfn        : 0x%lx\n", l.shdr.start_pfn);
	STDERR("  end_pfn          : 0x%lx\n", l.shdr.end_pfn);
}
#endif

/*
 * Check for kdump flat end marker
 */
static inline int kdump_flat_endmarker(struct df_kdump_flat_data_hdr *d_hdr)
{
	return (d_hdr->offs == -1) && (d_hdr->size == -1);
}

/*
 * Init kdump dump header
 */
static int init_kdump_hdr(struct df_kdump_hdr *hdr)
{
	if (memcmp(hdr->signature, "KDUMP", 5) != 0)
		return -ENODEV;
	dfi_attr_version_set(hdr->header_version);
	dfi_attr_real_cpu_cnt_set(hdr->nr_cpus);
	dfi_attr_utsname_set(&hdr->utsname);
	dfi_attr_time_set(&hdr->timestamp);
	dfi_arch_set(DFI_ARCH_64);
	dfi_mem_chunk_add(0, (unsigned long) hdr->max_mapnr * PAGE_SIZE,
			  NULL, NULL, NULL);
	return 0;
}

/*
 * Initialize kdump DFI
 */
static int dfi_kdump_init(void)
{
	if ((zg_type(g.fh) == ZG_TYPE_FILE) && (zg_size(g.fh) < sizeof(l.hdr)))
		return -ENODEV;
	if (zg_read(g.fh, &l.hdr, sizeof(l.hdr), ZG_CHECK_ERR) != sizeof(l.hdr))
		return -ENODEV;
	if (memcmp(l.hdr.signature, "KDUMP", 5) != 0)
		return -ENODEV;
	zg_seek(g.fh, l.hdr.block_size, ZG_CHECK);
	zg_read(g.fh, &l.shdr, sizeof(l.shdr), ZG_CHECK);
#ifdef DEBUG
	print_header();
	print_sub_header();
#endif
	return init_kdump_hdr(&l.hdr);
}

/*
 * kdump DFI operations
 */
struct dfi dfi_kdump = {
	.name		= "kdump",
	.init		= dfi_kdump_init,
	.feat_bits	= 0,
};

#ifdef DEBUG
static void print_kdump_flat_header(struct df_kdump_flat_hdr *hdr)
{
	STDERR("diskdump main header\n");
	STDERR("  signature        : %s\n", hdr->signature);
	STDERR("  version          : %lld\n", hdr->version);
	STDERR("  type             : %lld\n", hdr->type);
}
#endif

/*
 * Read makedumpfile dump header
 */
static int read_kdump_flat_hdr(void)
{
	struct df_kdump_flat_hdr hdr;

	if ((zg_type(g.fh) == ZG_TYPE_FILE) && (zg_size(g.fh) < sizeof(l.hdr)))
		return -ENODEV;
	if (zg_read(g.fh, &hdr, sizeof(hdr), ZG_CHECK_ERR) != sizeof(hdr))
		return -ENODEV;
	if (memcmp(hdr.signature, "makedumpfile", 12) != 0)
		return -ENODEV;
	if (hdr.type != 1)
		return -ENODEV;
#ifdef DEBUG
	print_kdump_flat_header(&hdr);
#endif
	return 0;
}

/*
 * Read kdump header from fh
 */
static int read_kdump_hdr(struct zg_fh *fh, s64 size)
{
	struct df_kdump_hdr hdr;

	if (size < (s64) sizeof(hdr))
		ERR_EXIT("Can't get kdump header");
	if (zg_read(fh, &hdr, sizeof(hdr), ZG_CHECK_ERR) != sizeof(hdr))
		return -EINVAL;
	if (init_kdump_hdr(&hdr))
		return -EINVAL;
	zg_seek_cur(fh, -sizeof(hdr), ZG_CHECK_NONE);
	return 0;
}

/*
 * Initialize kdump_flat DFI
 */
static int dfi_kdump_flat_init(void)
{
	struct df_kdump_flat_data_hdr d_hdr;

	if (read_kdump_flat_hdr() != 0)
		return -ENODEV;
	zg_seek(g.fh, 4096, ZG_CHECK);
	zg_read(g.fh, &d_hdr, sizeof(d_hdr), ZG_CHECK);
	do {
		if (d_hdr.offs == 0 && read_kdump_hdr(g.fh, d_hdr.size) != 0)
			return -EINVAL;
		zg_seek_cur(g.fh, d_hdr.size, ZG_CHECK_NONE);
		if (zg_read(g.fh, &d_hdr, sizeof(d_hdr),
			    ZG_CHECK_ERR) != sizeof(d_hdr))
			return -EINVAL;
	} while ((d_hdr.offs >= 0) && (d_hdr.size > 0));
	if (kdump_flat_endmarker(&d_hdr))
		return 0;
	return -EINVAL;
}

/*
 * kdump_flat DFI operations
 */
struct dfi dfi_kdump_flat = {
	.name		= "kdump_flat",
	.init		= dfi_kdump_flat_init,
	.feat_bits	= 0,
};
