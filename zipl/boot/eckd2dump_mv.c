/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Multi-volume ECKD DASD dump tool
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "eckd2dump.h"
#include "error.h"
#include "stage2dump.h"

#define MVDUMP_SIZE		0x3000	/* Size of dump record */
#define MAX_DUMP_VOLUMES	32	/* Up to 32 dump volumes possible */

/*
 * Magic number at start of dump record
 */
uint64_t magic __attribute__((section(".stage2.head")))
	= 0x5a4d554c54363405ULL; /* ZMULT64, version 5 */

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

static struct mvdump_parm_table mvdump_table
	__attribute__((section(".eckd2dump_mv.tail")));

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
 * Dump all memory to multiple DASD partitions
 */
void dt_dump_mem(void)
{
	unsigned long blk, addr, addr_end, blk_num, dev_mem_size, page;
	struct mvdump_parm_table *mvdump_table_new;
	struct df_s390_hdr *hdr_new;

	dump_hdr->mvdump_sign = DF_S390_MAGIC;
	dump_hdr->mvdump = 1;
	addr = 0;

	page = get_zeroed_page();
	do {
		printf("Dumping to: 0.%x.%04x", device.sid.ssid, device.devno);

		/*
		 * Check whether parameter table on dump device has a valid
		 * time stamp. The parameter table is located right behind
		 * the dump tool, the corresponding block number is:
		 *   MAGIC_BLOCK_OFFSET + (MVDUMP_TOOL_SIZE / blocksize)
		 *   So dump tool starts on track 0, block 3
		 */
		mvdump_table_new = (void *) page;
		readblock(3 + MVDUMP_SIZE / 0x1000,
			  __pa(mvdump_table_new), m2b(0x1000));
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

		/*
		 * Write dump header
		 */
		blk = device.blk_start;
		writeblock(blk, __pa(dump_hdr), m2b(DF_S390_HDR_SIZE), 0);
		blk += m2b(DF_S390_HDR_SIZE);

		dev_mem_size = b2m(device.blk_end - blk + 1);
		addr_end = MIN(dump_hdr->mem_size, addr + dev_mem_size);

		/*
		 * Write memory
		 */
		memset((void *) page, 0, PAGE_SIZE);
		while (addr < addr_end) {
			blk_num = MIN(eckd_blk_max, device.blk_end - blk + 1);
			blk_num = MIN(m2b(addr_end - addr), blk_num);
			writeblock(blk, addr, blk_num, page);
			progress_print(addr);
			blk += blk_num;
			addr += b2m(blk_num);
		}
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
	} while (1);
	progress_print(addr);
	/*
	 * Write end marker
	 */
	df_s390_em_page_init(page);
	writeblock(blk, page, 1, 0);
	free_page(page);
}
