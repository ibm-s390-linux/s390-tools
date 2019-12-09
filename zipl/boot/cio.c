/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Common IO functions for channel based devices
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "cio.h"
#include "error.h"
#include "libc.h"
#include "boot/s390.h"

static unsigned long initial_lpm = 0x00;
static const char *msg_essch = "Start subchannel failed";
static const char *msg_eenable_dev = "Enable device failed";

static int clear_subchannel(struct subchannel_id subchannel_id)
{
	register struct subchannel_id reg1 asm ("1") = subchannel_id;
	int rc;

	asm volatile(
		"     csch\n"
		"     ipm    %0\n"
		"     srl    %0,28\n"
		: "=d" (rc)
		: "d" (reg1)
		: "cc");
	return rc;
}

static int test_subchannel(struct subchannel_id subchannel_id, struct irb *irb)
{
	register struct subchannel_id reg1 asm ("1") = subchannel_id;
	int rc;

	asm volatile(
		"       tsch    0(%3)\n"
		"       ipm     %0\n"
		"       srl     %0,28\n"
		: "=d" (rc), "=m" (*irb)
		: "d" (reg1), "a" (irb)
		: "cc");
	return rc;
}

static int start_subchannel(struct subchannel_id subchannel_id, struct orb *orb)
{
	register struct subchannel_id reg1 asm ("1") = subchannel_id;
	int rc;

	asm volatile(
		"      ssch    0(%2)\n"
		"      ipm     %0\n"
		"      srl     %0,28\n"
		: "=d" (rc)
		: "d" (reg1), "a" (orb), "m" (*orb)
		: "cc", "memory");
	return rc;
}

int store_subchannel(struct subchannel_id subchannel_id, struct schib *schib)
{
	register struct subchannel_id reg1 asm ("1") = subchannel_id;
	int ccode;

	asm volatile(
		"      stsch    0(%3)\n"
		"      ipm      %0\n"
		"      srl      %0,28\n"
		: "=d" (ccode), "=m" (*schib)
		: "d" (reg1), "a" (schib)
		: "cc");
	return ccode;
}

static int modify_subchannel(struct subchannel_id subchannel_id,
			     struct schib *schib)
{
	register struct subchannel_id reg1 asm ("1") = subchannel_id;
	int rc;

	asm volatile(
		"      msch    0(%2)\n"
		"      ipm     %0\n"
		"      srl     %0,28\n"
		: "=d" (rc)
		: "d" (reg1), "a" (schib), "m" (*schib)
		: "cc");
	return rc;
}

void io_irq_enable(void)
{
	unsigned long ctl = 0xff000000;

	__ctl_load(ctl, 6, 6);
}


void io_irq_disable(void)
{
	unsigned long ctl = 0x00000000;

	__ctl_load(ctl, 6, 6);
}

/*
 * load wait psw and test subchannel after interrupt was received
 * return condition code
 */
static int wait_for_int(struct subchannel_id subchannel_id, struct irb *irb)
{
	int rc;

	do {
		load_wait_psw(0x0202000180000000ULL, &S390_lowcore.io_new_psw);
		rc = test_subchannel(subchannel_id, irb);
	} while (rc == 1);

	return rc;
}

/*
 * get next path for IO
 * call panic if no path is left
 */
static uint32_t next_path(uint32_t mask, struct subchannel_id subchannel_id,
			  struct irb *irb)
{
	if (!initial_lpm) {
		mask >>= 1;
		if (mask == 0)
			panic(ESSCH, "%s", msg_essch);
	}

	/* clear initial path mask to iterate throu other paths, too */
	initial_lpm = 0;

	if (clear_subchannel(subchannel_id))
		panic(ESSCH, "%s", msg_essch);

	wait_for_int(subchannel_id, irb);

	return mask;
}

int start_io(struct subchannel_id subchannel_id, struct irb *irb,
	     struct orb *orb, int panic)
{
	uint32_t mask = FIRST_PATH_MASK;
	struct scsw *scsw;
	int rc, retry = MAX_RETRIES;

	while (1) {
		/*
		 * set path mask in orb to initial path mask or to current mask
		 * initial_lpm gets cleared in next_path()
		 */
		if (!initial_lpm)
			orb->lpm = mask;
		else
			orb->lpm = initial_lpm;

		rc = start_subchannel(subchannel_id, orb);
		if (rc == CC_NOT_OPER) {
			mask = next_path(mask, subchannel_id, irb);
			retry = MAX_RETRIES;
			continue;
		} else if (rc != CC_INITIATED) {
			/*
			 * possible status pending
			 * call test_subchannel to clear and retry
			 */
			goto retry;
		}

		scsw = (struct scsw *)irb;
		/* wait for interrupt and device is ready */
		do {
			rc = wait_for_int(subchannel_id, irb);
			if (rc) {
				if (panic)
					panic(ESSCH, "%s", msg_essch);
				else
					return -1;
			}
			/* device end */
			if (scsw->dstat & 0x04)
				break;
			/* deferred condition code */
			if (scsw->cc != 0)
				break;
			/* status alert set */
			if (scsw->stctl & 0x10)
				break;
			/* channel state */
			if (scsw->cstat & 0xff)
				break;
		} while (1);

		/* path not operational */
		if (scsw->cc == 3) {
			mask = next_path(mask, subchannel_id, irb);
			retry = MAX_RETRIES;
			continue;
		}

		/*
		 * If no deferred condition code is set as well as
		 * no channel status, no alert status control and no device
		 * status except channel_end and device_end, we are done.
		 */
		if (scsw->cc == 0 &&
		    scsw->cstat == 0 &&
		    scsw->dstat & 0x04 &&
		    !(scsw->stctl & 0x10) &&
		    !(scsw->dstat & 0xf3))
			return 0;

retry:
		/* else we clear the subchannel and do a retry */
		test_subchannel(subchannel_id, irb);
		retry--;

		/*
		 * if no retry is left we try another path;
		 * if no path is left it will panic
		 */
		if (retry <= 0) {
			mask = next_path(mask, subchannel_id, irb);
			retry = MAX_RETRIES;
		}
	}
}

void set_device(struct subchannel_id subchannel_id, int enabled)
{
	struct schib schib;
	struct irb *irb;
	int i, rc;

	irb = (struct irb *)&S390_lowcore.irb;
	rc = store_subchannel(subchannel_id, &schib);

	if (rc == CC_NOT_OPER)
		/* Panic if path not operational */
		panic(EENABLE_DEV, "%s", msg_eenable_dev);

	/* enable/disable subchannel */
	schib.pmcw.ena = enabled ? ENABLED : DISABLED;

	for (i = 0; i < 256; i++) {
		rc = modify_subchannel(subchannel_id, &schib);
		if (!rc) {
			/* successful */
			break;
		} else if (rc == CC_STATUS_PENDING || rc == CC_BUSY) {
			/* call test_subchannel to clear pending status */
			rc = test_subchannel(subchannel_id, irb);
			if (rc == CC_NOT_OPER)
				panic(EENABLE_DEV, "%s", msg_eenable_dev);
		} else if (rc == CC_NOT_OPER) {
			/* Panic if path not operational */
			panic(EENABLE_DEV, "%s", msg_eenable_dev);
		}
	}

	if (!enabled)
		return;

	/* set initial lpm to lpum if path is enabled and 0 if not */
	initial_lpm = rc ? 0 : schib.pmcw.lpum;
}
