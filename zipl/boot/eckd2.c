/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Subroutines for ECKD disks
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "eckd.h"
#include "boot/s390.h"
#include "stage2.h"

int extract_length(void *data)
{
	struct eckd_blockptr *blockptr = (struct eckd_blockptr *)data;

	return blockptr->size * (blockptr->blockct + 1);
}

int is_zero_block(void *data)
{
	struct eckd_blockptr *blockptr = (struct eckd_blockptr *)data;

	return blockptr->cyl  || blockptr->head || blockptr->sec;
}

void * load_direct(disk_blockptr_t *data, struct subchannel_id subchannel_id,
	    void *load_addr)
{
	struct eckd_blockptr *blockptr = (struct eckd_blockptr *)data;
	struct ccw1 *ccws;
	unsigned long record_size;
	struct seek_arg seek_addr;
	struct chr_t search_arg;
	int record_number;
	struct irb *irb;
	struct orb orb;
	int i = 3;

	irb = (struct irb *)&S390_lowcore.irb;

	memset(irb, 0, sizeof(struct irb));
	memset(&orb, 0, sizeof(struct orb));
	memset(&seek_addr, 0, sizeof(struct ch_t));
	memset(&search_arg, 0, sizeof(struct chr_t));

	ccws = (struct ccw1 *)get_zeroed_page();

	/* initialise SEEK, SEARCH and TIC CCW*/
	ccws[0].cmd_code = DASD_ECKD_CCW_SEEK;
	ccws[0].flags = CCW_FLAG_CC | CCW_FLAG_SLI;
	ccws[0].count = 6;
	seek_addr.ch.cyl = blockptr->cyl;
	seek_addr.ch.head = blockptr->head;
	ccws[0].cda = (uint32_t) (unsigned long) &seek_addr;

	record_number = blockptr->blockct;
	record_size = blockptr->size;

	ccws[1].cmd_code = DASD_ECKD_CCW_SEARCH;
	ccws[1].flags = CCW_FLAG_CC | CCW_FLAG_SLI;
	ccws[1].count = 5;
	search_arg.cyl = blockptr->cyl;
	search_arg.head = blockptr->head;
	search_arg.record = blockptr->sec;
	ccws[1].cda = (uint32_t) (unsigned long) &search_arg;

	ccws[2].cmd_code = DASD_ECKD_CCW_TIC;
	ccws[2].flags = 0;
	ccws[2].count = 0;
	ccws[2].cda = (uint32_t) (unsigned long) &ccws[1];

	/* initialise READ CCWs */
	while (1) {
		ccws[i].cmd_code = DASD_ECKD_CCW_READ_MT;
		ccws[i].flags = CCW_FLAG_SLI;
		ccws[i].count = record_size;
		ccws[i].cda = (uint32_t) (unsigned long) load_addr;

		record_number--;
		load_addr += record_size;
		i++;

		if (record_number >= 0)
			ccws[i-1].flags |= CCW_FLAG_CC;
		else
			break;
	}
	orb.fmt = 1;
	orb.cpa = (uint32_t) (unsigned long) ccws;

	start_io(subchannel_id, irb, &orb, 1);

	free_page((unsigned long)ccws);
	return load_addr;
}
