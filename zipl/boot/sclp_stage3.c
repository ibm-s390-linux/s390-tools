/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions for console input and output
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "libc.h"
#include "sclp.h"
#include "sclp_stage3.h"

#define EQ_STORE_DATA	0x0
#define EQ_SIZE		0x1
#define DI_FCP_DUMP	0x0
#define EVTYP_SDIAS	0x1c

/* Global flag for synchrous(1) or asynchronus(0) hsa copy */
static int hsa_sync_mode = 1;

static int sclp_hsa_copy_wait(struct read_sccb *sccb)
{
	unsigned int cmd;
	int rc;

	memset(sccb, 0, sizeof(struct read_sccb));
	sccb->header.length = 0x1000;

	cmd = SCLP_CMD_READ_DATA;
	rc = start_sclp(cmd, sccb);

	if (rc)
		return rc;

	if (sccb->header.response_code != 0x20)
		return 1;

	return 0;
}

static int __sclp_hsa_copy(struct sdias_sccb *sccb, void *dest_addr,
			   unsigned long first_block, unsigned long nr_blocks)
{
	unsigned int cmd;
	int rc;

	sccb->header.length = sizeof(*sccb);

	sccb->evbuf.header.length = sizeof(sccb->evbuf);
	sccb->evbuf.header.type = EVTYP_SDIAS;
	sccb->evbuf.event_qual = EQ_STORE_DATA;
	sccb->evbuf.event_id = 0x4712;
	sccb->evbuf.asa_size = 1;
	sccb->evbuf.asa = (unsigned long) dest_addr;
	sccb->evbuf.fbn = first_block;
	sccb->evbuf.blk_cnt = nr_blocks;
	sccb->evbuf.dbs = 1;

	cmd = SCLP_CMD_WRITE_DATA;
	rc = start_sclp(cmd, sccb);
	if (rc)
		return 1;

	if (sccb->header.response_code != 0x20)
		return 1;

	if (!hsa_sync_mode) {
		if (!(S390_lowcore.ext_params & 0x3)) {
			sclp_wait_for_int(0);
			if (!(S390_lowcore.ext_params & 0x3))
				return 1;
		}
		if (sclp_hsa_copy_wait((struct read_sccb *)sccb))
			return 1;
	}
	/* Check for expected event status */
	if ((sccb->evbuf.event_status != SDIAS_EVSTATE_PART_STORED) &&
	    (sccb->evbuf.event_status != SDIAS_EVSTATE_ALL_STORED))
		return 1;

	return 0;
}

int sclp_hsa_copy(void *dest_addr, unsigned long first_block,
		  unsigned long nr_blocks)
{
	struct sdias_sccb *sccb;
	int rc;

	sccb = (void *)get_zeroed_page();
	rc = __sclp_hsa_copy(sccb, dest_addr, first_block, nr_blocks);
	free_page((unsigned long) sccb);
	return rc;
}

int sclp_hsa_get_size(unsigned long *hsa_size)
{
	struct sdias_sccb *sccb;
	unsigned int cmd;
	int rc = -EIO;

	sccb = (void *)get_zeroed_page();
	sccb->header.length = sizeof(*sccb);

	sccb->evbuf.header.length = sizeof(struct sdias_evbuf);
	sccb->evbuf.header.type = EVTYP_SDIAS;
	sccb->evbuf.event_qual = EQ_SIZE;
	sccb->evbuf.data_id = DI_FCP_DUMP;
	sccb->evbuf.event_id = 4712;
	sccb->evbuf.dbs = 1;

	cmd = SCLP_CMD_WRITE_DATA;
	if (start_sclp(cmd, sccb))
		goto out;
	if (sccb->header.response_code != 0x20)
		goto out;

	if (!hsa_sync_mode) {
		if (!(S390_lowcore.ext_params & 0x3)) {
			sclp_wait_for_int(0);
			if (!(S390_lowcore.ext_params & 0x3))
				goto out;
		}
		if (sclp_hsa_copy_wait((struct read_sccb *)sccb))
			goto out;
	}
	if (sccb->evbuf.blk_cnt) {
		*hsa_size = (sccb->evbuf.blk_cnt - 1) * PAGE_SIZE;
		rc = 0;
	}
out:
	free_page((unsigned long) sccb);
	return rc;
}

void sclp_hsa_copy_init(void *dest_addr)
{
	struct sdias_sccb *sccb;

	sclp_setup(SCLP_HSA_INIT);
	sccb = (void *)get_zeroed_page();
	__sclp_hsa_copy(sccb, dest_addr, 2, 1);
	/* Check buffer that was filled by sclp_hsa_copy */
	if (sccb->evbuf.event_status != 0) {
		/* Use synchonous mode */
		hsa_sync_mode = 1;
		free_page((unsigned long) sccb);
		return;
	}

	/* Use async mode */
	hsa_sync_mode = 0;
	free_page((unsigned long) sccb);
	sclp_setup(SCLP_DISABLE);
	sclp_setup(SCLP_HSA_INIT_ASYNC);
}

void sclp_hsa_copy_exit(void)
{
	sclp_setup(SCLP_DISABLE);
	diag308(DIAG308_REL_HSA, NULL);
}
