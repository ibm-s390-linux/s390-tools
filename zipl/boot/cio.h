/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Common I/O functions
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef CIO_H
#define CIO_H

#include "libc.h"
#include "boot/s390.h"

/* Condition codes */
#define CC_INITIATED		0
#define CC_STATUS_PENDING	1
#define CC_BUSY			2
#define CC_NOT_OPER		3

/* CCW FLAGS */
#define CCW_FLAG_IDA		0x04
#define CCW_FLAG_CC		0x40
#define CCW_FLAG_SLI		0x20

#define FIRST_PATH_MASK		0x80

#define DISABLED		0
#define ENABLED			1

#define MAX_RETRIES		255

struct subchannel_id {
	uint32_t cssid:8;
	uint32_t:4;
	uint32_t m:1;
	uint32_t ssid:2;
	uint32_t one:1;
	uint32_t sch_no:16;
} __packed __aligned(4);

struct ccw1 {
	uint8_t cmd_code;
	uint8_t flags;
	uint16_t count;
	uint32_t cda;
}  __packed __aligned(8);

struct irb {
	uint8_t data[64];
} __packed __aligned(4);

struct orb {
	uint32_t intparm;	/* interruption parameter */
	uint32_t key:4;		/* flags, like key, suspend control, etc. */
	uint32_t spnd:1;	/* suspend control */
	uint32_t res1:1;	/* reserved */
	uint32_t mod:1;		/* modification control */
	uint32_t sync:1;	/* synchronize control */
	uint32_t fmt:1;		/* format control */
	uint32_t pfch:1;	/* prefetch control */
	uint32_t isic:1;	/* initial-status-interruption control */
	uint32_t alcc:1;	/* address-limit-checking control */
	uint32_t ssic:1;	/* suppress-suspended-interr. control */
	uint32_t res2:1;	/* reserved */
	uint32_t c64:1;		/* IDAW/QDIO 64 bit control  */
	uint32_t i2k:1;		/* IDAW 2/4kB block size control */
	uint32_t lpm:8;		/* logical path mask */
	uint32_t ils:1;		/* incorrect length */
	uint32_t zero:6;	/* reserved zeros */
	uint32_t orbx:1;	/* ORB extension control */
	uint32_t cpa;		/* channel program address */
	uint8_t reserved[20];
} __packed __aligned(4);

struct scsw {
	uint32_t key:4;
	uint32_t sctl:1;
	uint32_t eswf:1;
	uint32_t cc:2;
	uint32_t fmt:1;
	uint32_t pfch:1;
	uint32_t isic:1;
	uint32_t alcc:1;
	uint32_t ssi:1;
	uint32_t zcc:1;
	uint32_t ectl:1;
	uint32_t pno:1;
	uint32_t res:1;
	uint32_t fctl:3;
	uint32_t actl:7;
	uint32_t stctl:5;
	uint32_t cpa;
	uint32_t dstat:8;
	uint32_t cstat:8;
	uint32_t count:16;
} __packed;

struct pmcw {
	uint32_t intparm;	/* interruption parameter */
	uint32_t qf:1;
	uint32_t w:1;
	uint32_t isc:3;		/* interruption sublass */
	uint32_t res5:3;	/* reserved zeros */
	uint32_t ena:1;		/* enabled */
	uint32_t lm:2;		/* limit mode */
	uint32_t mme:2;		/* measurement-mode enable */
	uint32_t mp:1;		/* multipath mode */
	uint32_t tf:1;		/* timing facility */
	uint32_t dnv:1;		/* device number valid */
	uint32_t dev:16;	/* device number */
	uint8_t  lpm;		/* logical path mask */
	uint8_t  pnom;		/* path not operational mask */
	uint8_t  lpum;		/* last path used mask */
	uint8_t  pim;		/* path installed mask */
	uint16_t mbi;		/* measurement-block index */
	uint8_t  pom;		/* path operational mask */
	uint8_t  pam;		/* path available mask */
	uint8_t  chpid[8];	/* CHPID 0-7 (if available) */
	uint32_t unused1:8;	/* reserved zeros */
	uint32_t st:3;
	uint32_t unused2:18;	/* reserved zeros */
	uint32_t mbfc:1;	/* measurement block format control */
	uint32_t xmwme:1;	/* extended measurement word mode enable */
	uint32_t csense:1;	/* concurrent sense; can be enabled ...*/
				/*  ... per MSCH, however, if facility */
				/*  ... is not installed, this results */
				/*  ... in an operand exception.       */
} __packed;

struct schib {
	struct pmcw pmcw;	/* path management control word */
	struct scsw scsw;	/* subchannel status word */
	uint64_t mba;		/* measurement block address */
	uint8_t mda[4];		/* model dependent area */
} __packed __aligned(4);

int start_io(struct subchannel_id, struct irb *, struct orb *, int panic);
int store_subchannel(struct subchannel_id, struct schib *);
void io_irq_enable(void);
void io_irq_disable(void);
void set_device(struct subchannel_id, int);

#endif /* CIO_H */
