/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Multi-volume ECKD DASD dump tool
 *
 * Copyright IBM Corp. 2013, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/zt_common.h"

#include "eckd2dump.h"
#include "error.h"
#include "stage2dump.h"

#define MVDUMP_TOOL_SIZE	0x3000	/* Size of dump record */
#define MAX_DUMP_VOLUMES	32	/* Up to 32 dump volumes possible */

/*
 * Magic number at start of dump record
 */
uint64_t __section(.stage2.head) magic = 0x584d554c54363401ULL; /* XMULT64, version 1 */

/*
 * Parameter format for ECKD MV dumper (13 bytes):
 *
 * DDSS SSEE EEBN O
 *
 * - DD  : Devno of dump target
 * - SSSS: Start block number of dump target
 * - EEEE: End block number of dump target
 * - B   : Blocksize of dump target (needs to be left-shifted by 8 bits)
 * - N   : End Record Number
 * - O   : Number of Heads of DASD
 *
 * We assume that the End Record Number is at track boundary.
 * This allows us to determine the number of Blocks Per Track.
 */
struct mvdump_param {
	uint16_t	devno;
	uint32_t	blk_start;
	uint32_t	blk_end;
	uint8_t		blk_size;
	uint8_t		bpt;
	uint8_t		num_heads;
} __packed;

/*
 * Provide storage for parameter table: 10 + 32*PTE_LENGTH = 426 bytes
 * We take 512 bytes to match with struct mvdump_parm_table in include/boot.h
 */
struct mvdump_parm_table {
	uint64_t	tod;
	uint16_t	num_param;
	struct mvdump_param param[MAX_DUMP_VOLUMES];
	uint8_t		ssid[MAX_DUMP_VOLUMES];
	unsigned char	reserved[512 - sizeof(uint64_t) - sizeof(uint16_t) -
			(MAX_DUMP_VOLUMES * (sizeof(struct mvdump_param) + 1))];
} __packed;

static struct mvdump_parm_table __section(.eckd2dump_mv.tail) mvdump_table;

static int volnr_current;

/*
 * Get device characteristics for current DASD device from zipl parameter block
 */
void dt_device_parm_setup(void)
{
	struct mvdump_param *param = &mvdump_table.param[volnr_current];

	device.devno = param->devno;
	device.blk_start = param->blk_start;
	device.blk_end = param->blk_end;
	device.blk_size = ((unsigned int) param->blk_size) << 8;
	device.bpt = param->bpt;
	device.num_heads = param->num_heads;
}

/*
 * Get subchannel ID for MV dump
 */
static int set_sid_from_devno(uint8_t ssid, uint16_t devno)
{
	struct subchannel_id sid;
	struct schib schib;

	memset(&sid, 0, sizeof(sid));

	sid.one = 1;
	sid.sch_no = 0;
	sid.ssid = ssid;
	do {
		if (store_subchannel(sid, &schib) == 0) {
			if (schib.pmcw.dev == devno) {
				device.sid = sid;
				break;
			}
		}
		if (sid.sch_no == 0xffff)
			return -1;
		sid.sch_no++;
	} while (1);
	return 0;
}

/*
 * CHSC data structures
 */
struct chsc_header {
	uint16_t length;
	uint16_t code;
} __packed;

struct chsc_sda_area {
	struct chsc_header request;
	uint8_t :4;
	uint8_t format:4;
	uint8_t :8;
	uint16_t operation_code;
	uint32_t :32;
	uint32_t :32;
	uint32_t operation_data_area[252];
	struct chsc_header response;
	uint32_t :4;
	uint32_t format2:4;
	uint32_t :24;
} __packed __aligned(PAGE_SIZE);

#define CHSC_SDA_OC_MSS   0x2

/*
 * Issue synchronous CHSC
 */
static inline int chsc(void *chsc_area)
{
	typedef struct { char _[4096]; } addr_type;
	int cc;

	asm volatile(
		"	.insn	rre,0xb25f0000,%2,0\n"
		"	ipm	%0\n"
		"	srl	%0,28\n"
		: "=d" (cc), "=m" (*(addr_type *) chsc_area)
		: "d" (chsc_area), "m" (*(addr_type *) chsc_area)
		: "cc");
	return cc;
}

/*
 * Enable multiple subchannel set facility
 */
static void enable_mss_facility(void)
{
	struct chsc_sda_area *sda_area = (void *) get_zeroed_page();

	sda_area->request.length = 0x0400;
	sda_area->request.code = 0x0031;
	sda_area->operation_code = CHSC_SDA_OC_MSS;

	if (chsc(sda_area) || (sda_area->response.code != 1)) {
		free_page((unsigned long) sda_area);
		panic(ENOMSS, "Could not enable MSS");
	}
	free_page((unsigned long) sda_area);
}

/*
 * Enable current DASD device
 */
void dt_device_enable(void)
{
	struct mvdump_param *param = &mvdump_table.param[volnr_current];
	int ssid = mvdump_table.ssid[volnr_current];
	static int first = 1;

	if (first && ssid) {
		enable_mss_facility();
		first = 0;
	}

	if (set_sid_from_devno(ssid, param->devno) != 0)
		panic(ENODEVNO, "%04x is undefined", param->devno);
	io_irq_enable();
	set_device(device.sid, ENABLED);
	stage2dump_eckd_init();
}

/*
 * Check for the volume timestamp and validate the dump signature
 * before writing a dump.
 */
static void check_volume(void)
{
	struct mvdump_parm_table *mvdump_table_new;
	struct df_s390_hdr *hdr_new;
	unsigned long page;

	page = get_zeroed_page();

	/*
	 * Check whether parameter table on dump device has a valid
	 * time stamp. The parameter table is located right behind
	 * the dump tool, the corresponding block number is:
	 *   MAGIC_BLK_ECKD + (MVDUMP_TOOL_SIZE / blocksize)
	 */
	mvdump_table_new = (void *) page;
	readblock(DF_S390_MAGIC_BLK_ECKD + m2b(MVDUMP_TOOL_SIZE),
		  __pa(mvdump_table_new), 1);
	/*
	 * Check if time stamps match
	 */
	if (mvdump_table.tod != mvdump_table_new->tod)
		panic(ENOTIME, "Inconsistent time stamps");
	/*
	 * Check if dump partition has a valid dump signature.
	 * Bypass signature check if "--force" had been specified during
	 * zipl -M.
	 */
	hdr_new = (void *) page;
	if (!parm_tail.mvdump_force) {
		readblock(device.blk_start, __pa(hdr_new), 1);
		if (dump_hdr->magic != hdr_new->mvdump_sign)
			panic(ENOSIGN, "Wrong signature");
	}

	free_page(page);
}

/*
 * Write the dump header and memory to the current volume and return the next
 * address to write for the next volume or memory size if the dump ended
 * on this volume
 */
static unsigned long write_volume(unsigned long addr,
				  struct df_s390_dump_segm_hdr *dump_segm)
{
	unsigned long free_space, blk, page;

	/*
	 * Write dump header
	 */
	blk = device.blk_start;
	writeblock(blk, __pa(dump_hdr), m2b(DF_S390_HDR_SIZE), 0);
	blk += m2b(DF_S390_HDR_SIZE);
	/*
	 * The free space left on the volume minus 2 blocks (for the segment
	 * header and the end marker)
	 */
	free_space = b2m(device.blk_end - blk + 1) - b2m(2);

	/*
	 * Write dump data
	 */
	while (addr < dump_hdr->mem_size) {
		/*
		 * Find the next non-zero dump segment with the limit
		 * of segment length set to the amount of free space left
		 */
		addr = find_dump_segment(addr, dump_hdr->mem_size,
					 ROUND_DOWN(free_space, MIB),
					 dump_segm);
		blk = write_dump_segment(blk, dump_segm);
		/* Update free space left on vol */
		free_space -= dump_segm->len;
		/* Reserve one block for the next segment header */
		if (free_space)
			free_space -= b2m(1);
		total_dump_size += dump_segm->len;
		/* Check if no more dump segments follow */
		if (dump_segm->stop_marker) {
			/* Write end marker */
			page = get_zeroed_page();
			df_s390_em_page_init(page);
			writeblock(blk, page, 1, 0);
			free_page(page);
			return dump_hdr->mem_size;
		}
		/*
		 * Go to the new volume if not enough space
		 */
		if (free_space < MIB)
			break;
	}
	return addr;
}

/*
 * Dump all memory to multiple DASD partitions
 */
void dt_dump_mem(void)
{
	struct df_s390_dump_segm_hdr *dump_segm;
	unsigned long addr;

	dump_hdr->mvdump_sign = DF_S390_MAGIC_EXT;
	dump_hdr->mvdump = 1;
	addr = 0;
	total_dump_size = 0;
	dump_segm = (void *)get_zeroed_page();

	while (1) {
		printf("Dumping to: 0.%x.%04x", device.sid.ssid, device.devno);
		check_volume();
		addr = write_volume(addr, dump_segm);
		if (addr == dump_hdr->mem_size)
			break;
		/*
		 * Switch to next volume if available
		 */
		dump_hdr->volnr += 1;
		volnr_current++;
		if (dump_hdr->volnr >= mvdump_table.num_param)
			panic(EMEM, "Device too small");
		dt_device_parm_setup();
		set_device(device.sid, DISABLED);
		dt_device_enable();
	}
	free_page(__pa(dump_segm));
	progress_print(addr);
}
