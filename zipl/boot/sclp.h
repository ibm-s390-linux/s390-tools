/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions for console input and output.
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef SCLP_H
#define SCLP_H

#include "libc.h"
#include "s390.h"

/* vector keys and ids */
#define GDS_ID_MDSMU		0x1310
#define GDS_ID_CPMSU		0x1212
#define GDS_ID_TEXTCMD		0x1320
#define GDS_KEY_SELFDEFTEXTMSG	0x31
#define EBC_MDB                 0xd4c4c240

#define SCLP_CMD_WRITE_MASK     0x00780005
#define SCLP_CMD_WRITE_DATA     0x00760005
#define SCLP_CMD_READ_INFO      0x00120001
#define SCLP_CMD_READ_INFO2     0x00020001
#define SCLP_CMD_READ_DATA      0x00770005

#define PSW_EXT_MASK            0x00080000ULL
#define PSW_EXT_ADDR            0x80000000ULL
#define PSW_WAIT_MASK           0x010a0000ULL
#define PSW_WAIT_ADDR           0x00000000ULL

#define CTL_SERVICE_SIGNAL      0x0200
#define CTL_CLOCK_COMPARATOR    0x0800

#define SCLP_INIT               0x0
#define SCLP_DISABLE            0x1
#define SCLP_HSA_INIT           0x2
#define SCLP_HSA_INIT_ASYNC     0x3

typedef uint32_t sccb_mask_t;

struct gds_vector {
	uint16_t     length;
	uint16_t     gds_id;
} __packed;

struct gds_subvector {
	uint8_t      length;
	uint8_t      key;
} __packed;

struct sccb_header {
	uint16_t     length;
	uint8_t      function_code;
	uint8_t      control_mask[3];
	uint16_t     response_code;
} __packed;

struct evbuf_header {
	uint16_t     length;
	uint8_t      type;
	uint8_t      flags;
	uint16_t     _reserved;
} __packed;

struct mto {
	uint16_t length;
	uint16_t type;
	uint16_t line_type_flags;
	uint8_t  alarm_control;
	uint8_t  _reserved[3];
} __packed;

struct go {
	uint16_t length;
	uint16_t type;
	uint32_t domid;
	uint8_t  hhmmss_time[8];
	uint8_t  th_time[3];
	uint8_t  reserved_0;
	uint8_t  dddyyyy_date[7];
	uint8_t  _reserved_1;
	uint16_t general_msg_flags;
	uint8_t  _reserved_2[10];
	uint8_t  originating_system_name[8];
	uint8_t  job_guest_name[8];
} __packed;

struct mdb_header {
	uint16_t length;
	uint16_t type;
	uint32_t tag;
	uint32_t revision_code;
} __packed;

struct mdb {
	struct mdb_header header;
	struct go go;
} __packed;

struct msg_buf {
	struct evbuf_header header;
	struct mdb mdb;
} __packed;

struct write_sccb {
	struct sccb_header header;
	struct msg_buf msg_buf;
} __packed;


struct init_sccb {
	struct sccb_header header;
	uint16_t _reserved;
	uint16_t mask_length;
	sccb_mask_t receive_mask;
	sccb_mask_t send_mask;
	sccb_mask_t sclp_send_mask;
	sccb_mask_t sclp_receive_mask;
} __packed;

struct read_info_sccb {
	struct  sccb_header header;
	uint16_t     rnmax;
	uint8_t      rnsize;
	uint8_t      _reserved0[24-11];
	uint8_t      loadparm[8];
	uint8_t      reserved1[42-32];
	uint8_t      fac42;
	uint8_t      _reserved6[48-43];
	uint64_t     facilities;
	uint8_t      _reserved2[66-56];
	uint8_t      fac66;
	uint8_t      _reserved7[84-67];
	uint8_t      fac84;
	uint8_t      fac85;
	uint8_t      _reserved3[91-86];
	uint8_t      flags;
	uint8_t      _reserved4[100-92];
	uint32_t     rnsize2;
	uint64_t     rnmax2;
	uint8_t      _reserved5[4096-112];
} __packed __aligned(PAGE_SIZE);

struct read_sccb {
	struct  sccb_header header;
	uint8_t      data[4096-8];
} __packed __aligned(PAGE_SIZE);

int start_sclp(unsigned int, void *);
int sclp_setup(int);
int sclp_print(char *);
int sclp_param(char *);
int sclp_read(unsigned long, void *, int *);
int sclp_read_info(struct read_info_sccb *sccb);
int sclp_wait_for_int(unsigned long long);

#endif /* SCLP_H */
