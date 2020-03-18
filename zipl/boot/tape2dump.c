/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Dump tool for channel-attached tape devices
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"
#include "lib/zt_common.h"
#include "boot/loaders_layout.h"
#include "boot/s390.h"

#include "cio.h"
#include "error.h"
#include "stage2dump.h"

#define BLK_SIZE	0x8000 /* We write 32 KB at a time */
#define ETAPE_WRITE	0x0003 /* Error code for failed write */

#define WRITE_CMD	0x01	/* Write block */
#define SENSE_OVERRUN	0x04	/* Sense */
#define WRITETAPEMARK	0x1f	/* Write Tape Mark */
#define READ_DEV_CHAR	0x64	/* Read device characteristics */
#define LOAD_DISPLAY	0x9f	/* Load tape display */
#define MODE_SET_DB	0xdb	/* Mode set */

/*
 * Tape head code (PSW and two CCWs to load dump tool)
 */
struct tape_head {
	uint64_t	psw;
	uint64_t	ccw1;
	uint64_t	ccw2;
} __packed;

struct tape_head __section(.stage2.head) tape_head = {
	.psw	= PSW_LOAD | STAGE2_ENTRY, /* Start code at 0x2018 */
	.ccw1	= 0x0700000060000001ULL, /* Rewind ccw */
	.ccw2	= 0x0200200020003000ULL, /* CCW to load dump tool to 0x2000 */
};

/*
 * ORB, CCW, and CCW data
 */
static struct orb orb = {
	.fmt	= 1,		/* Use format 1 CCWs */
	.c64	= 1,		/* Use IDAs */
	.lpm	= 0xff,		/* Logical path mask */
};
static char ccw_data[64] __aligned(8);
static uint32_t mode_set_byte = 0x08000000;
static struct irb irb;

/*
 * CCW program for writes
 */
static struct {
	struct ccw1	compress;
	struct ccw1	write;
	unsigned long	ida_list[BLK_SIZE / PAGE_SIZE];
} ccw_program __aligned(8);

/*
 * Get device characteristics (nothing to do for tape)
 */
void dt_device_parm_setup(void)
{
}

/*
 * Enable tape device
 */
void dt_device_enable(void)
{
	io_irq_enable();
	set_device(IPL_SC, ENABLED);
}

/*
 * Initialize CCW
 */
static void ccw_init(struct ccw1 *ccw, uint8_t code, uint8_t flags,
		     uint16_t count, void *cda)
{
	ccw->cmd_code = code;
	ccw->flags = flags;
	ccw->count = count;
	ccw->cda = __pa32(cda);
}

/*
 * Execute CCW
 */
static void start_ccw(uint8_t code, uint8_t flags, uint16_t count, void *cda)
{
	static struct ccw1 ccw;

	ccw_init(&ccw, code, flags, count, cda);
	orb.cpa = __pa32(&ccw);
	start_io(IPL_SC, &irb, &orb, 1);
}

/*
 * Read tape device characteristics to find out if IDRC compression can be used
 */
static void setup_idrc_compression(void)
{
	uint16_t type;

	start_ccw(READ_DEV_CHAR, 0x0, 0x40, ccw_data);

	memcpy(&type, &ccw_data[3], sizeof(type));
	switch (type) {
	case 0x3490:
	case 0x3590: // XXX 3592
		ccw_init(&ccw_program.compress, MODE_SET_DB, CCW_FLAG_CC, 0x1,
			 &mode_set_byte);
		orb.cpa = __pa32(&ccw_program.compress);
		break;
	default:
	case 0x3480:
		orb.cpa = __pa32(&ccw_program.write);
		break;
	}
}

/*
 * Print message on tape display
 */
static void ccw_load_display(const char *msg)
{
	char _msg[24] = {0x20};

	strcpy(&_msg[1], msg);
	start_ccw(LOAD_DISPLAY, CCW_FLAG_SLI, 0x11, (void *) _msg);
}

/*
 * Write sense data to buffer
 */
static void sense(void *sense_data)
{
	start_ccw(SENSE_OVERRUN, CCW_FLAG_SLI, 0x20, sense_data);
}

/*
 * Write tape mark at current tape position
 */
static void ccw_write_tapemark(void)
{
	start_ccw(WRITETAPEMARK, CCW_FLAG_SLI, 0x1, NULL);
}

/*
 * Write buffer at current tape position
 */
static void ccw_write_block(unsigned long addr, unsigned long size,
			    unsigned long zero_page)
{
	struct scsw *scsw = (struct scsw *) &irb;
	unsigned long code;

	create_ida_list(ccw_program.ida_list, size, addr, zero_page);
	ccw_init(&ccw_program.write, WRITE_CMD, CCW_FLAG_SLI | CCW_FLAG_IDA,
		 size, ccw_program.ida_list);
	orb.cpa = __pa32(&ccw_program.write);
	start_io(IPL_SC, &irb, &orb, 1);

	if (scsw->dstat & 0xd2) {
		/* Something went wrong */
		sense(ccw_data);
		code = ccw_data[3]; /* ERA */
		code = ETAPE_WRITE | (code << 24);
		panic(code, "I/O Error: RC=%08x", code);
	}
	if (scsw->dstat & 0x01) /* Unit exception, end of tape */
		panic(EMEM, "Device too small");
}

/*
 * Every 16 MB we update the tape display
 */
static void progress_print_disp(unsigned long addr)
{
	char msg[24];

	if (addr % (1024 * 1024 * 16) != 0)
		return;
	snprintf(msg, sizeof(msg), "%08u", addr >> 20);
	ccw_load_display(msg);
}

/*
 * Dump all memory to tape
 */
void dt_dump_mem(void)
{
	unsigned long addr, page;

	page = get_zeroed_page();
	setup_idrc_compression();
	ccw_write_tapemark();

	ccw_write_block((unsigned long) dump_hdr, DF_S390_HDR_SIZE, 0);
	for (addr = 0; addr < dump_hdr->mem_size; addr += BLK_SIZE) {
		ccw_write_block(addr, BLK_SIZE, page);
		progress_print(addr);
		progress_print_disp(addr);
	}
	progress_print(addr);
	df_s390_em_page_init(page);
	ccw_write_block(page, sizeof(struct df_s390_em), 0);
	free_page(page);
	ccw_write_tapemark();
	ccw_load_display("DUMP*END");
}
