/*
 * Copyright IBM Corp. 2002, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_VTOC_H
#define LIB_VTOC_H

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


#define LINE_LENGTH 80
#define VTOC_START_CC 0x0
#define VTOC_START_HH 0x1
#define FIRST_USABLE_CYL 1
#define FIRST_USABLE_TRK 2

#define DASD_3380_TYPE 13184
#define DASD_3390_TYPE 13200
#define DASD_9345_TYPE 37701

#define DASD_3380_VALUE 0xbb60
#define DASD_3390_VALUE 0xe5a2
#define DASD_9345_VALUE 0xbc98

#define VOLSER_LENGTH 6
#define BIG_DISK_SIZE 0x10000
#define LV_COMPAT_CYL 0xFFFE

#define VTOC_ERROR "VTOC error:"

/* definition from hdreq.h */
struct hd_geometry {
      unsigned char heads;
      unsigned char sectors;
      unsigned short cylinders;
      unsigned long start;
};

typedef struct ttr 
{
        u_int16_t tt;
        u_int8_t  r;
} __attribute__ ((packed)) ttr_t;

typedef struct cchhb 
{
        u_int16_t cc;
        u_int16_t hh;
        u_int8_t b;
} __attribute__ ((packed)) cchhb_t;

typedef struct cchh 
{
        u_int16_t cc;
        u_int16_t hh;
} __attribute__ ((packed)) cchh_t;

typedef struct labeldate 
{
        u_int8_t  year;
        u_int16_t day;
} __attribute__ ((packed)) labeldate_t;

/*
 * The following structure is a merger of the cdl and ldl volume label.
 * On an ldl disk there is no key information, so when reading an
 * ldl label from disk, the data should be copied at the address of vollbl.
 * On the other side, the field ldl_version is reserved in a cdl record
 * and the field formatted_cyl exists only for ldl labels. So when
 * reading a cdl label from disk, the formatted_cyl field will contain
 * arbitrary data.
 * This layout may be a bit awkward, but the advantage of having the
 * same label type for both disk layout types is bigger than the effort
 * for taking a bit of extra care at the fringes.
 */
typedef struct volume_label
{
        char volkey[4];         /* volume key = volume label                 */
	char vollbl[4];	        /* volume label                              */
	char volid[6];	        /* volume identifier                         */
	u_int8_t security;	        /* security byte                             */
	cchhb_t vtoc;           /* VTOC address                              */
	char res1[5];	        /* reserved                                  */
        char cisize[4];	        /* CI-size for FBA,...                       */
                                /* ...blanks for CKD                         */
	char blkperci[4];       /* no of blocks per CI (FBA), blanks for CKD */
	char labperci[4];       /* no of labels per CI (FBA), blanks for CKD */
	char res2[4];	        /* reserved                                  */
	char lvtoc[14];	        /* owner code for LVTOC                      */
	char res3[28];	        /* reserved                                  */
 	char ldl_version;	/* version number, valid for ldl format      */
 	unsigned long long formatted_blocks; /* valid when ldl_version >= f2 */
} __attribute__ ((packed)) volume_label_t;

typedef struct extent 
{
        u_int8_t  typeind;          /* extent type indicator                     */
        u_int8_t  seqno;            /* extent sequence number                    */
        cchh_t llimit;          /* starting point of this extent             */
        cchh_t ulimit;          /* ending point of this extent               */
} __attribute__ ((packed)) extent_t;


typedef struct dev_const 
{
        u_int16_t DS4DSCYL;           /* number of logical cyls                  */
        u_int16_t DS4DSTRK;           /* number of tracks in a logical cylinder  */
        u_int16_t DS4DEVTK;           /* device track length                     */
        u_int8_t  DS4DEVI;            /* non-last keyed record overhead          */
        u_int8_t  DS4DEVL;            /* last keyed record overhead              */
        u_int8_t  DS4DEVK;            /* non-keyed record overhead differential  */
        u_int8_t  DS4DEVFG;           /* flag byte                               */
        u_int16_t DS4DEVTL;           /* device tolerance                        */
        u_int8_t  DS4DEVDT;           /* number of DSCB's per track              */
        u_int8_t  DS4DEVDB;           /* number of directory blocks per track    */
} __attribute__ ((packed)) dev_const_t;

/*
 * format 1 and format 8 label have the same layout so we use the following
 * structure for both.
 */
typedef struct format1_label
{
	char  DS1DSNAM[44];       /* data set name                           */
	u_int8_t  DS1FMTID;       /* format identifier                       */
	unsigned char  DS1DSSN[6];/* data set serial number                  */
	u_int16_t DS1VOLSQ;           /* volume sequence number                  */
	labeldate_t DS1CREDT;     /* creation date: ydd                      */
	labeldate_t DS1EXPDT;     /* expiration date                         */
	u_int8_t  DS1NOEPV;           /* number of extents on volume             */
	u_int8_t  DS1NOBDB;           /* no. of bytes used in last direction blk */
	u_int8_t  DS1FLAG1;           /* flag 1                                  */
	unsigned char  DS1SYSCD[13];  /* system code                         */
	labeldate_t DS1REFD;      /* date last referenced                    */
	u_int8_t  DS1SMSFG;           /* system managed storage indicators       */
	u_int8_t  DS1SCXTF;           /* sec. space extension flag byte          */
	u_int16_t DS1SCXTV;           /* secondary space extension value         */
	u_int8_t  DS1DSRG1;           /* data set organisation byte 1            */
	u_int8_t  DS1DSRG2;           /* data set organisation byte 2            */
	u_int8_t  DS1RECFM;           /* record format                           */
	u_int8_t  DS1OPTCD;           /* option code                             */
	u_int16_t DS1BLKL;            /* block length                            */
	u_int16_t DS1LRECL;           /* record length                           */
	u_int8_t  DS1KEYL;            /* key length                              */
	u_int16_t DS1RKP;             /* relative key position                   */
	u_int8_t  DS1DSIND;           /* data set indicators                     */
	u_int8_t  DS1SCAL1;           /* secondary allocation flag byte          */
	char DS1SCAL3[3];         /* secondary allocation quantity           */
	ttr_t DS1LSTAR;           /* last used track and block on track      */
	u_int16_t DS1TRBAL;           /* space remaining on last used track      */
	u_int16_t res1;               /* reserved                                */
	extent_t DS1EXT1;         /* first extent description                */
	extent_t DS1EXT2;         /* second extent description               */
	extent_t DS1EXT3;         /* third extent description                */
	cchhb_t DS1PTRDS;         /* possible pointer to f2 or f3 DSCB       */
} __attribute__ ((packed)) format1_label_t;


typedef struct format3_label
{
	char DS3KEYID[4];         /* key identifier                          */
	extent_t DS3EXTNT[4];     /* first 4 extent descriptions             */
	u_int8_t DS3FMTID;        /* format identifier                       */
	extent_t DS3ADEXT[9];     /* last 9 extent description               */
	cchhb_t  DS3PTRDS;        /* pointer to next format3 DSCB            */
} __attribute__ ((packed)) format3_label_t;


typedef struct format4_label 
{
	char  DS4KEYCD[44];       /* key code for VTOC labels: 44 times 0x04 */
        u_int8_t  DS4IDFMT;           /* format identifier                       */
	cchhb_t DS4HPCHR;         /* highest address of a format 1 DSCB      */
        u_int16_t DS4DSREC;           /* number of available DSCB's              */
        cchh_t DS4HCCHH;          /* CCHH of next available alternate track  */
        u_int16_t DS4NOATK;           /* number of remaining alternate tracks    */
        u_int8_t  DS4VTOCI;           /* VTOC indicators                         */
        u_int8_t  DS4NOEXT;           /* number of extents in VTOC               */
        u_int8_t  DS4SMSFG;           /* system managed storage indicators       */
        u_int8_t  DS4DEVAC;           /* number of alternate cylinders. 
                                     Subtract from first two bytes of 
                                     DS4DEVSZ to get number of usable
				     cylinders. can be zero. valid
				     only if DS4DEVAV on.                    */
        dev_const_t DS4DEVCT;     /* device constants                        */
        char DS4AMTIM[8];         /* VSAM time stamp                         */
        char DS4AMCAT[3];         /* VSAM catalog indicator                  */
        char DS4R2TIM[8];         /* VSAM volume/catalog match time stamp    */
        char res1[5];             /* reserved                                */
        char DS4F6PTR[5];         /* pointer to first format 6 DSCB          */
        extent_t DS4VTOCE;        /* VTOC extent description                 */
        char res2[10];            /* reserved                                */
        u_int8_t DS4EFLVL;        /* extended free-space management level    */
        cchhb_t DS4EFPTR;         /* pointer to extended free-space info     */
	char res3;		  /* reserved */
	u_int32_t DS4DCYL;	  /* number of logical cyls */
	char res4[2];		  /* reserved */
        u_int8_t DS4DEVF2;        /* device flags */
	char res5;		  /* reserved */
} __attribute__ ((packed)) format4_label_t;


typedef struct ds5ext 
{
	u_int16_t t;                  /* RTA of the first track of free extent   */
	u_int16_t fc;                 /* number of whole cylinders in free ext.  */
	u_int8_t  ft;                 /* number of remaining free tracks         */
} __attribute__ ((packed)) ds5ext_t;


typedef struct format5_label 
{
	char DS5KEYID[4];         /* key identifier                          */
	ds5ext_t DS5AVEXT;        /* first available (free-space) extent.    */
	ds5ext_t DS5EXTAV[7];     /* seven available extents                 */
	u_int8_t DS5FMTID;            /* format identifier                       */
	ds5ext_t DS5MAVET[18];    /* eighteen available extents              */
	cchhb_t DS5PTRDS;         /* pointer to next format5 DSCB            */
} __attribute__ ((packed)) format5_label_t;


typedef struct ds7ext 
{
	u_int32_t a;                  /* starting RTA value                      */
	u_int32_t b;                  /* ending RTA value + 1                    */
} __attribute__ ((packed)) ds7ext_t;


typedef struct format7_label 
{
	char DS7KEYID[4];         /* key identifier                          */
	ds7ext_t DS7EXTNT[5];     /* space for 5 extent descriptions         */
	u_int8_t DS7FMTID;            /* format identifier                       */
	ds7ext_t DS7ADEXT[11];    /* space for 11 extent descriptions        */
	char res1[2];             /* reserved                                */
	cchhb_t DS7PTRDS;         /* pointer to next FMT7 DSCB               */
} __attribute__ ((packed)) format7_label_t;


typedef struct format9_label
{
	u_int8_t  DS9KEYID;       /* key code for format 9 labels (0x09) */
	u_int8_t  DS9SUBTY;       /* subtype (0x01) */
	u_int8_t  DS9NUMF9;       /* number of F9 datasets  */
	u_int8_t  res1[41];       /* reserved  */
	u_int8_t  DS9FMTID;       /* format identifier  */
	u_int8_t  res2[90];       /* reserved */
	cchhb_t   DS9PTRDS;       /* pointer to next DSCB               */
} __attribute__ ((packed)) format9_label_t;

char * vtoc_ebcdic_enc (char *source, char *target, int l);
char * vtoc_ebcdic_dec (char *source, char *target, int l);
void vtoc_set_extent (
        extent_t * ext,
        u_int8_t typeind,
        u_int8_t seqno,
        cchh_t * lower,
        cchh_t * upper);
void vtoc_set_cchh (
        cchh_t * addr,
	u_int32_t cc,
	u_int16_t hh);
u_int32_t vtoc_get_cyl_from_cchh(cchh_t *addr);
u_int16_t vtoc_get_head_from_cchh(cchh_t *addr);
void vtoc_set_cchhb (
        cchhb_t * addr,
        u_int32_t cc,
        u_int16_t hh,
        u_int8_t b);
u_int32_t vtoc_get_cyl_from_cchhb(cchhb_t *addr);
u_int16_t vtoc_get_head_from_cchhb(cchhb_t *addr);
u_int64_t cchhb2blk(cchhb_t *p, struct hd_geometry *geo);
u_int64_t cchh2blk (cchh_t *p, struct hd_geometry *geo);
u_int32_t cchh2trk (cchh_t *p, struct hd_geometry *geo);

void vtoc_set_date (
        labeldate_t * d,
        u_int8_t year,
        u_int16_t day);

void vtoc_volume_label_init (
	volume_label_t *vlabel);

int vtoc_read_volume_label (
        char * device,
        unsigned long vlabel_start,
        volume_label_t * vlabel);

int vtoc_write_volume_label (
        char *device,
        unsigned long vlabel_start,
        volume_label_t *vlabel);

void vtoc_volume_label_set_volser (
	volume_label_t *vlabel,
	char *volser);

char *vtoc_volume_label_get_volser (
	volume_label_t *vlabel,
	char *volser);

void vtoc_volume_label_set_key (
        volume_label_t *vlabel,
        char *key);     

void vtoc_volume_label_set_label (
	volume_label_t *vlabel,
	char *lbl);

char *vtoc_volume_label_get_label (
	volume_label_t *vlabel,
	char *lbl);

void vtoc_read_label (
        char *device,
        unsigned long position,
        format1_label_t *f1,
        format4_label_t *f4,
        format5_label_t *f5,
        format7_label_t *f7);

void vtoc_write_label (
        char *device,
        unsigned long position,
        format1_label_t *f1,
	format4_label_t *f4,
	format5_label_t *f5,
	format7_label_t *f7,
	format9_label_t *f9);


void vtoc_init_format1_label (
        unsigned int blksize,
        extent_t *part_extent,
        format1_label_t *f1);

void vtoc_init_format4_label (
        format4_label_t *f4lbl,
	unsigned int compat_cylinders,
	unsigned int real_cylinders,
	unsigned int tracks,
	unsigned int blocks,
	unsigned int blksize,
	u_int16_t dev_type);

void vtoc_update_format4_label (
	format4_label_t *f4,
	cchhb_t *highest_f1,
	u_int16_t unused_update);

void vtoc_init_format5_label (
	format5_label_t *f5);

void vtoc_update_format5_label_add (
	format5_label_t *f5,
	int verbose,
	int trk,
	u_int16_t a, 
	u_int16_t b, 
	u_int8_t c);

void vtoc_update_format5_label_del (
	format5_label_t *f5,
	int verbose,
	int trk,
	u_int16_t a, 
	u_int16_t b, 
	u_int8_t c);

void vtoc_init_format7_label (
	format7_label_t *f7);

void vtoc_update_format7_label_add (
	format7_label_t *f7,
	int verbose,
	u_int32_t a, 
	u_int32_t b);

void vtoc_update_format7_label_del (
	format7_label_t *f7, 
	int verbose,
	u_int32_t a, 
	u_int32_t b);

void vtoc_init_format8_label (
        unsigned int blksize,
        extent_t *part_extent,
        format1_label_t *f1);

void vtoc_update_format8_label (
	cchhb_t *associated_f9,
	format1_label_t *f8);

void vtoc_init_format9_label (
	format9_label_t *f9);

void vtoc_set_freespace(
	format4_label_t *f4,
	format5_label_t *f5,
	format7_label_t *f7,
	char ch,
	int verbose,
	u_int32_t start,
	u_int32_t stop,
	u_int32_t cyl,
	u_int32_t trk);

#endif /* LIB_VTOC_H */
