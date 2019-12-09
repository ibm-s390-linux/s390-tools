/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Subroutines for FBA disks
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "fba.h"
#include "libc.h"
#include "boot/s390.h"

int extract_length(void *data) {
	struct linear_blockptr *blockptr = (struct linear_blockptr *)data;

	return blockptr->size * (blockptr->blockct + 1);
}

int is_zero_block(void *data) {
	struct linear_blockptr *blockptr = (struct linear_blockptr *)data;

	return blockptr->blockno;
}

void *load_direct(disk_blockptr_t *data, struct subchannel_id subchannel_id,
	    void *load_addr)
{
	struct linear_blockptr *blockptr = (struct linear_blockptr *)data;
	struct DE_fba_data *de_data;
	struct LO_fba_data *lo_data;
	struct ccw1 *ccws;
	unsigned long record_size;
	int record_number;
	struct orb orb;
	struct irb *irb;
	void *page;
	int ccw_counter, lo_counter;

	irb = (struct irb *)&S390_lowcore.irb;

restart:
	/*
	 * allocate one page for:
	 *    16 byte de_data
	 *    128 * 8 Byte lo_data
	 *    128 * 8 Byte ccws
	 *
	 * = 2064 Byte used
	 */
	page = (void *)get_zeroed_page();
	de_data = (struct DE_fba_data *)page;
	lo_data	= (struct LO_fba_data *)(page + sizeof(struct DE_fba_data));
	ccws = (struct ccw1 *)(page + sizeof(struct DE_fba_data) +
			       128 * sizeof(struct LO_fba_data));

	ccw_counter = 0;
	lo_counter = 0;
	memset(irb, 0, sizeof(struct irb));
	memset(&orb, 0, sizeof(struct orb));

	if (blockptr->blockct >= MAX_BLOCKCT) {
		record_number = MAX_BLOCKCT - 1;
		blockptr->blockct -= MAX_BLOCKCT;
	} else {
		record_number = blockptr->blockct;
		blockptr->blockct -= record_number;
	}

	record_size = blockptr->size;

	/* initialise DEFINE_EXTENT */
	ccws[0].cmd_code = DASD_FBA_CCW_DE;
	ccws[0].flags = CCW_FLAG_CC;
	ccws[0].count = 16;
	de_data->mask.perm = 0x1;
	de_data->blk_size = blockptr->size;
	de_data->ext_loc = blockptr->blockno;
	ccws[0].cda = (uint32_t) (unsigned long) de_data;
	ccw_counter++;

	/* add 1 LO and 1 READ CCW per block */
	while (1) {
		/* initialise LOCATE_RECORD */
		ccws[ccw_counter].cmd_code = DASD_FBA_CCW_LOCATE;
		ccws[ccw_counter].flags = CCW_FLAG_CC;
		ccws[ccw_counter].count = 8;
		lo_data[lo_counter].operation.cmd = 0x6;
		lo_data[lo_counter].blk_nr = lo_counter;
		de_data->ext_end = lo_counter;
		lo_data[lo_counter].blk_ct = 1;
		ccws[ccw_counter].cda = (unsigned long) &lo_data[lo_counter];
		lo_counter++;
		ccw_counter++;

		/* initialise READ_CCW */
		ccws[ccw_counter].cmd_code = DASD_FBA_CCW_READ;
		ccws[ccw_counter].count = record_size;
		ccws[ccw_counter].cda = (uint32_t) (unsigned long) load_addr;
		ccw_counter++;

		blockptr->blockno++;
		record_number--;
		load_addr += record_size;

		if (record_number >= 0)
			ccws[ccw_counter-1].flags |= CCW_FLAG_CC;
		else
			break;
	}

	orb.fmt = 1;
	orb.cpa = (uint32_t) (unsigned long) ccws;

	start_io(subchannel_id, irb, &orb, 1);
	free_page((unsigned long)page);

	if (blockptr->blockct > 0)
		goto restart;

	return load_addr;
}
