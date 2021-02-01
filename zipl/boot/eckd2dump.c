/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Common ECKD dump I/O functions
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "cio.h"
#include "eckd2dump.h"
#include "error.h"
#include "boot/s390.h"
#include "stage2dump.h"

#define ECKD_CCW_LOCATE_RECORD		0x47
#define ECKD_CCW_LOCATE_RECORD_EXT	0x4b
#define ECKD_CCW_DEFINE_EXTENT		0x63
#define ECKD_CCW_WRITE_TRACK_DATA	0xa5
#define ECKD_CCW_READ_TRACK_DATA	0xa6
#define ECKD_CCW_WRITE_KD_MT		0x8d
#define ECKD_CCW_READ_KD_MT		0x8e

#define ECKD_BLK_PER_TRK		12

typedef unsigned long sector_t;

/*
 * For track I/O we can write 12 blocks per full track. Because I/O can start
 * at the end of a track with "tr_count" tracks we can guarantee to write:
 *
 * block_count = (tr_count - 1) * 12 + 1
 *
 * Therefore: tr_count >= (block_count + 11) / 12
 */
#define ECKD_BLK_PER_IO_TRK	128 /* 128 * 4 KB = up to 512 KB per I/O */
#define ECKD_CCW_MAX_COUNT_TRK	12  /* (128 + 11) / 12 = 12 track I/O CCWs */

/*
 * For record I/O we write one 4 KB block with one write CCW
 */
#define ECKD_BLK_PER_IO_REC	64  /* 64 * 4 KB = up to 256 KB per I/O */
#define ECKD_CCW_MAX_COUNT_REC	64  /* 64 record I/O CCWs */

unsigned long eckd_blk_max;	/* Maximum number of blocks per I/O */
struct eckd_device device;

static int track_io;

#define sector_div(n, b)( \
{ \
	int _res; \
	_res = (n) % (b); \
	(n) /= (b); \
	_res; \
} \
)

struct ch_t {
	uint16_t cyl;
	uint16_t head;
} __packed;

struct chr_t {
	uint16_t cyl;
	uint16_t head;
	uint8_t record;
} __packed;

static void set_ch_t(struct ch_t *geo, uint32_t cyl, uint8_t head)
{
	geo->cyl = (uint16_t) cyl;
	geo->head = cyl >> 16;
	geo->head <<= 4;
	geo->head |= head;
}

/*
 * Data for Locate Record Extended CCW
 */
struct LRE_eckd_data {
	struct {
		unsigned char orientation:2;
		unsigned char operation:6;
	} __packed operation;
	struct {
		unsigned char length_valid:1;
		unsigned char length_scope:1;
		unsigned char imbedded_ccw_valid:1;
		unsigned char check_bytes:2;
		unsigned char imbedded_count_valid:1;
		unsigned char reserved:1;
		unsigned char read_count_suffix:1;
	} __packed auxiliary;
	uint8_t imbedded_ccw;
	uint8_t count;
	struct ch_t seek_addr;
	struct chr_t search_arg;
	uint8_t sector;
	uint16_t length;
	uint8_t imbedded_count;
	uint8_t extended_operation;
	uint16_t extended_parameter_length;
	uint8_t extended_parameter[0];
} __packed;

static struct LRE_eckd_data lodata;

struct DE_eckd_data {
	struct {
		unsigned char perm:2;	/* Permissions on this extent */
		unsigned char reserved:1;
		unsigned char seek:2;	/* Seek control */
		unsigned char auth:2;	/* Access authorization */
		unsigned char pci:1;	/* PCI Fetch mode */
	} __packed mask;
	struct {
		unsigned char mode:2;	/* Architecture mode */
		unsigned char ckd:1;	/* CKD Conversion */
		unsigned char operation:3;	/* Operation mode */
		unsigned char cfw:1;	/* Cache fast write */
		unsigned char dfw:1;	/* DASD fast write */
	} __packed attributes;
	uint16_t blk_size;		/* Blocksize */
	uint16_t fast_write_id;
	uint8_t ga_additional;	/* Global Attributes Additional */
	uint8_t ga_extended;	/* Global Attributes Extended	*/
	struct ch_t beg_ext;
	struct ch_t end_ext;
} __packed;

static struct DE_eckd_data dedata;

/*
 * ORB /IRB
 */
static struct orb orb = {
	.intparm	= 0x0049504c,	/* Interruption Parameter */
	.fmt		= 0x1,		/* Use format 1 CCWs */
	.c64		= 0x1,		/* Use IDAs */
	.lpm		= 0xff,		/* Logical path mask */
};

static struct irb irb;

/*
 * CCW program and IDA list
 */
struct ccw_program_rw_trk {
	struct ccw1 wrtdccw[ECKD_CCW_MAX_COUNT_TRK];
	unsigned long ida_list[ECKD_CCW_MAX_COUNT_TRK * ECKD_BLK_PER_TRK];
};

struct ccw_program_rw_rec {
	struct ccw1 wrtdccw[ECKD_CCW_MAX_COUNT_REC];
	unsigned long ida_list[ECKD_CCW_MAX_COUNT_REC];
};

struct ccw_program {
	struct ccw1 deccw;
	struct ccw1 loccw;
	union {
		struct ccw_program_rw_trk trk;
		struct ccw_program_rw_rec rec;
	} rw;
} __packed __aligned(8);

static struct ccw_program ccw_program;

/*
 * Create the list of idal words for an address/length pair
 */
static unsigned long *idal_create_words(unsigned long *idaws, void *vaddr,
					unsigned int length,
					unsigned long zero_page)
{
	unsigned long paddr;
	unsigned int cidaw;

	paddr = __pa(vaddr);
	cidaw = ((paddr & (PAGE_SIZE-1)) + length + (PAGE_SIZE-1)) >> 12;
	if (zero_page)
		*idaws++ = page_is_valid(paddr) ? paddr : zero_page;
	else
		*idaws++ = paddr;
	paddr &= -PAGE_SIZE;
	while (--cidaw > 0) {
		paddr += PAGE_SIZE;
		if (zero_page)
			*idaws++ = page_is_valid(paddr) ? paddr : zero_page;
		else
			*idaws++ = paddr;
	}
	return idaws;
}

/*
 * Fill Locate Record (Extended) data
 */
static void fill_LRE_data(struct LRE_eckd_data *data, unsigned int trk,
			  unsigned int rec_on_trk, int count, int cmd,
			  unsigned int reclen, unsigned int tlf)
{
	memset(data, 0, sizeof(*data));
	/*
	 * note: meaning of count depends on the operation
	 *       for record based I/O it's the number of records, but for
	 *       track based I/O it's the number of tracks
	 */
	data->count = count;
	data->sector = 0xff;
	switch (cmd) {
	case ECKD_CCW_WRITE_KD_MT:
		data->auxiliary.length_valid = 0x1;
		data->length = reclen;
		data->operation.operation = 0x1;
		break;
	case ECKD_CCW_READ_KD_MT:
		data->auxiliary.length_valid = 0x1;
		data->length = reclen;
		data->operation.operation = 0x6;
		break;
	case ECKD_CCW_WRITE_TRACK_DATA:
		data->auxiliary.length_valid = 0x1;
		data->length = reclen;	/* not tlf, as one might think */
		data->operation.operation = 0x3f;
		data->extended_operation = 0x23;
		break;
	case ECKD_CCW_READ_TRACK_DATA:
		data->auxiliary.length_valid = 0x1;
		data->length = tlf;
		data->operation.operation = 0xc;
		break;
	}
	set_ch_t(&data->seek_addr, trk / device.num_heads,
		 trk % device.num_heads);
	data->search_arg.cyl = data->seek_addr.cyl;
	data->search_arg.head = data->seek_addr.head;
	data->search_arg.record = rec_on_trk;
}

/*
 * Fill Define Extend and Locate Record (Extended) data
 */
static void fill_DE_LRE_data(unsigned int trk, unsigned int totrk, int cmd,
			     unsigned int rec_on_trk, int count,
			     unsigned int blksize, unsigned int tlf)
{
	uint16_t heads, beghead, endhead;
	uint32_t begcyl, endcyl;

	memset(&dedata, 0, sizeof(dedata));
	switch (cmd) {
	case ECKD_CCW_READ_KD_MT:
		dedata.mask.perm = 0x1;
		break;
	case ECKD_CCW_WRITE_KD_MT:
		dedata.mask.perm = 0x2;
		break;
	case ECKD_CCW_READ_TRACK_DATA:
		dedata.mask.perm = 0x1;
		dedata.blk_size = 0;
		break;
	case ECKD_CCW_WRITE_TRACK_DATA:
		dedata.mask.perm = 0x2;
		dedata.blk_size = device.blk_size;
		break;
	}
	dedata.attributes.mode = 0x3;	/* ECKD */
	dedata.ga_extended |= 0x40; /* Regular Data Format Mode */

	heads = device.num_heads;
	begcyl = trk / heads;
	beghead = trk % heads;
	endcyl = totrk / heads;
	endhead = totrk % heads;

	set_ch_t(&dedata.beg_ext, begcyl, beghead);
	set_ch_t(&dedata.end_ext, endcyl, endhead);

	fill_LRE_data(&lodata, trk, rec_on_trk, count, cmd, blksize, tlf);
}

/*
 * Read or write ECKD blocks using record I/O
 */
static void io_block_rec(int cmd, unsigned long addr,
			 unsigned long zero_page,
			 sector_t first_rec, sector_t last_rec,
			 sector_t first_trk, sector_t last_trk,
			 unsigned int first_offs)
{
	unsigned int i, rec_count;
	unsigned long *idaws;
	struct ccw1 *ccw;

	rec_count = last_rec - first_rec + 1;
	idaws = ccw_program.rw.rec.ida_list;

	fill_DE_LRE_data(first_trk, last_trk, cmd, first_offs + 1, rec_count,
			 device.blk_size, 0);
	ccw = ccw_program.rw.rec.wrtdccw;
	for (i = 0; i < rec_count; i++) {
		/* Read/write ccw. */
		ccw[-1].flags |= CCW_FLAG_CC;
		ccw->cmd_code = cmd;
		ccw->count = device.blk_size;
		ccw->cda = __pa32(idaws);
		ccw->flags = CCW_FLAG_IDA;
		idaws = idal_create_words(idaws, (void *) addr, device.blk_size,
					  zero_page);
		ccw++;
		addr += device.blk_size;
	}
}

/*
 * Read or write ECKD blocks using track I/O
 */
static void io_block_trk(uint8_t cmd, unsigned long addr,
			 unsigned long zero_page,
			 sector_t first_rec, sector_t last_rec,
			 sector_t first_trk, sector_t last_trk,
			 unsigned int first_offs, unsigned int last_offs)
{
	unsigned int recoffs, count_to_trk_end, len_to_track_end, count;
	unsigned int blk_count, recid, trkid, trk_count, tlf;
	unsigned int idaw_len, seg_len, part_len;
	unsigned char new_track, end_idaw;
	unsigned long *idaws;
	char *dst, *idaw_dst;
	struct ccw1 *ccw;

	blk_count = last_rec - first_rec + 1;
	trk_count = last_trk - first_trk + 1;
	idaws = ccw_program.rw.trk.ida_list;
	recid = first_rec;
	dst = (char *) addr;
	new_track = 1;
	end_idaw = 0;
	len_to_track_end = 0;
	idaw_dst = NULL;
	idaw_len = 0;

	if (first_trk == last_trk)
		tlf = device.blk_size * (last_offs - first_offs + 1);
	else
		tlf = device.blk_size * (last_offs + 1);
	fill_DE_LRE_data(first_trk, last_trk, cmd, first_offs + 1, trk_count,
			 device.blk_size, tlf);

	ccw = ccw_program.rw.trk.wrtdccw;
	seg_len = blk_count * device.blk_size;
	while (seg_len) {
		if (new_track) {
			trkid = recid;
			recoffs = trkid % device.bpt;
			count_to_trk_end = device.bpt - recoffs;
			count = MIN((last_rec - recid + 1), count_to_trk_end);
			len_to_track_end = count * device.blk_size;
			ccw[-1].flags |= CCW_FLAG_CC;
			ccw->cmd_code = cmd;
			ccw->count = len_to_track_end;
			ccw->cda = __pa32(idaws);
			ccw->flags = CCW_FLAG_IDA;
			ccw++;
			recid += count;
			new_track = 0;
			if (!idaw_dst)
				idaw_dst = dst;
		}
		if (!idaw_dst)
			idaw_dst = dst;
		part_len = MIN(seg_len, len_to_track_end);
		seg_len -= part_len;
		dst += part_len;
		idaw_len += part_len;
		len_to_track_end -= part_len;
		if (!(__pa(idaw_dst + idaw_len) & (PAGE_SIZE - 1)))
			end_idaw = 1;
		if (!len_to_track_end) {
			new_track = 1;
			end_idaw = 1;
		}
		if (end_idaw) {
			idaws = idal_create_words(idaws, idaw_dst,
						  idaw_len, zero_page);
			idaw_dst = NULL;
			idaw_len = 0;
			end_idaw = 0;
		}
	}
}

/*
 * Read or write ECKD blocks
 */
static int io_block(uint8_t cmd, unsigned long first_blk, unsigned long addr,
		    unsigned long blk_count, unsigned long zero_page, int panic)
{
	sector_t first_trk, last_trk, first_rec, last_rec;
	unsigned int first_offs, last_offs;

	if (first_blk + blk_count - 1 > device.blk_end)
		panic(EMEM, "%s", "Device too small");

	/* Compute start track and end block on track */
	first_rec = first_trk = first_blk;
	first_offs = sector_div(first_trk, device.bpt);
	last_rec = last_trk = first_blk + blk_count - 1;
	last_offs = sector_div(last_trk, device.bpt);
	memset(&ccw_program.rw.trk.wrtdccw, 0,
	       sizeof(ccw_program.rw.trk.wrtdccw));

	if (track_io)
		io_block_trk(cmd, addr, zero_page, first_rec, last_rec,
			     first_trk, last_trk, first_offs, last_offs);
	else
		io_block_rec(cmd, addr, zero_page, first_rec, last_rec,
			     first_trk, last_trk, first_offs);
	return start_io(device.sid, &irb, &orb, panic);
}

/*
 * Write data to given block address
 */
void writeblock(unsigned long blk, unsigned long addr, unsigned long blk_count,
		unsigned long zero_page)
{
	int cmd = track_io ? ECKD_CCW_WRITE_TRACK_DATA : ECKD_CCW_WRITE_KD_MT;

	io_block(cmd, blk, addr, blk_count, zero_page, 1);
}

/*
 * Read data from given block address
 */
void readblock(unsigned long blk, unsigned long addr, unsigned long blk_count)
{
	int cmd = track_io ? ECKD_CCW_READ_TRACK_DATA : ECKD_CCW_READ_KD_MT;

	io_block(cmd, blk, addr, blk_count, 0, 1);
}

/*
 * Write dump segment with the header to DASD and return the next free
 * block number
 */
unsigned long write_dump_segment(unsigned long blk,
				 struct df_s390_dump_segm_hdr *segm)
{
	unsigned long addr, start_blk, blk_count, zero_page;

	/* Write the dump segment header itself (1 page) */
	zero_page = get_zeroed_page();
	writeblock(blk, (unsigned long)segm, m2b(PAGE_SIZE), zero_page);
	free_page(zero_page);
	blk += m2b(PAGE_SIZE);
	/* Write the dump segment */
	addr = segm->start;
	start_blk = blk;
	while (addr < segm->start + segm->len) {
		/* Remaining blocks to write */
		blk_count = m2b(segm->len) - (blk - start_blk);
		blk_count = MIN(blk_count, eckd_blk_max);
		zero_page = get_zeroed_page();
		writeblock(blk, addr, blk_count, zero_page);
		free_page(zero_page);
		progress_print(addr);
		blk += blk_count;
		addr += b2m(blk_count);
	}
	return blk;
}

/*
 * Init ECKD common
 */
void stage2dump_eckd_init(void)
{
	unsigned long addr;
	int rc;

	ccw_program.deccw.cmd_code = ECKD_CCW_DEFINE_EXTENT;
	ccw_program.deccw.flags = CCW_FLAG_CC;
	ccw_program.deccw.count = sizeof(dedata);
	ccw_program.deccw.cda = __pa32(&dedata);

	ccw_program.loccw.cmd_code = ECKD_CCW_LOCATE_RECORD_EXT;
	ccw_program.loccw.flags = CCW_FLAG_CC;
	ccw_program.loccw.count = sizeof(lodata);
	ccw_program.loccw.cda = __pa32(&lodata);

	orb.cpa = __pa32(&ccw_program);
	track_io = 1;
	eckd_blk_max = ECKD_BLK_PER_IO_TRK;

	/* Probe Track I/O - Read first block of device */
	addr = get_zeroed_page();
	rc = io_block(ECKD_CCW_READ_TRACK_DATA, device.blk_start,
		      addr, 1, 0, 0);
	free_page(addr);

	/*
	 * If storage server does not support track I/O use record I/O fallback.
	 * Use Locate Record instead of Locate Record Extended in that case.
	 */
	if (rc) {
		printf("Using Record I/O");
		track_io = 0;
		eckd_blk_max = ECKD_BLK_PER_IO_REC;
		ccw_program.loccw.cmd_code = ECKD_CCW_LOCATE_RECORD;
		ccw_program.loccw.count = 0x10;
	}
}
