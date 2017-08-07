/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the pkey kernel module.
 * It defines a set of IOCTL commands with its associated structures.
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PKEY_H
#define PKEY_H

#include "lib/zt_common.h"

/*
 * Definitions for the /dev/pkey kernel module interface
 */
struct secaeskeytoken {
	u8  type;     /* 0x01 for internal key token */
	u8  res0[3];
	u8  version;  /* should be 0x04 */
	u8  res1[1];
	u8  flag;     /* key flags */
	u8  res2[1];
	u64 mkvp;     /* master key verification pattern */
	u8  key[32];  /* key value (encrypted) */
	u8  cv[8];    /* control vector */
	u16 bitsize;  /* key bit size */
	u16 keysize;  /* key byte size */
	u8  tvv[4];   /* token validation value */
} __packed;

#define SECURE_KEY_SIZE sizeof(struct secaeskeytoken)

struct pkey_seckey {
	u8  seckey[SECURE_KEY_SIZE];  /* the secure key blob */
};

struct pkey_clrkey {
	u8  clrkey[32]; /* 16, 24, or 32 byte clear key value */
};

#define PKEY_IOCTL_MAGIC 'p'
#define AUTOSELECT 0xFFFF
#define PKEYDEVICE "/dev/pkey"
#define PKEY_KEYTYPE_AES_128  1
#define PKEY_KEYTYPE_AES_192  2
#define PKEY_KEYTYPE_AES_256  3

struct pkey_genseck {
	u16 cardnr;			/* in: card to use or FFFF for any */
	u16 domain;			/* in: domain or FFFF for any */
	u32 keytype;			/* in: key type to generate */
	struct pkey_seckey seckey;	/* out: the secure key blob */
};

#define PKEY_GENSECK _IOWR(PKEY_IOCTL_MAGIC, 0x01, struct pkey_genseck)

struct pkey_clr2seck {
	u16 cardnr;			/* in: card to use or FFFF for any */
	u16 domain;			/* in: domain or FFFF for any*/
	u32 keytype;			/* in: key type to generate */
	struct pkey_clrkey clrkey;	/* in: the clear key value */
	struct pkey_seckey seckey;	/* out: the secure key blob */
};

#define PKEY_CLR2SECK _IOWR(PKEY_IOCTL_MAGIC, 0x02, struct pkey_clr2seck)

struct pkey_verifykey {
	struct pkey_seckey seckey;	/* in: the secure key blob */
	u16  cardnr;			/* out: card number */
	u16  domain;			/* out: domain number */
	u16  keysize;			/* out: key size in bits */
	u32  attributes;		/* out: attribute bits */
};

#define PKEY_VERIFY_ATTR_AES       0x0001 /* key is an AES key */
#define PKEY_VERIFY_ATTR_OLD_MKVP  0x0100 /* key has old MKVP value */

#define PKEY_VERIFYKEY _IOWR(PKEY_IOCTL_MAGIC, 0x07, struct pkey_verifykey)

#endif