/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines the interface to the pkey kernel module.
 * It defines a set of IOCTL commands with its associated structures.
 *
 * Copyright IBM Corp. 2017, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PKEY_H
#define PKEY_H

#include "lib/zt_common.h"

#include "cca.h"
#include "ep11.h"

/*
 * Definitions for the /dev/pkey kernel module interface
 */
struct tokenheader {
	u8  type;
	u8  res0[3];
	u8  version;
	u8  res1[3];
} __packed;

#define TOKEN_TYPE_NON_CCA		0x00
#define TOKEN_TYPE_CCA_INTERNAL		0x01

/* CCA-Internal token versions */
#define TOKEN_VERSION_AESDATA		0x04
#define TOKEN_VERSION_AESCIPHER		0x05

/* Non-CCA token versions */
#define TOKEN_VERSION_PROTECTED_KEY	0x01
#define TOKEN_VERSION_CLEAR_KEY		0x02
#define TOKEN_VERSION_EP11_AES		0x03

struct aesdatakeytoken {
	u8  type;     /* TOKEN_TYPE_INTERNAL (0x01) for internal key token */
	u8  res0[3];
	u8  version;  /* should be TOKEN_VERSION_AESDATA (0x04) */
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

struct aescipherkeytoken {
	u8  type;     /* TOKEN_TYPE_INTERNAL (0x01) for internal key token */
	u8  res0;
	u16 length;   /* length of token */
	u8  version;  /* should be TOKEN_VERSION_CIPHER (0x05) */
	u8  res1[3];
	u8  kms;      /* key material state, should be 0x03 */
	u8  kvptype;  /* key verification pattern type */
	u8  kvp[16];  /* key verification pattern */
	u8  kwm;      /* key wrapping method, should be 0x02 */
	u8  kwh;      /* key wrapping hash algorithm */
	u8  pfv;      /* payload format version, should be 0x00*/
	u8  res2;
	u8  adv;      /* associated data section version */
	u8  res3;
	u16 adl;      /* associated data length */
	u8  kll;      /* length of optional key label */
	u8  eadl;     /* extended associated data length */
	u8  uadl;     /* user associated data length */
	u8  res4;
	u16 pl;       /* payload bit length */
	u8  res5;
	u8  at;       /* algorithm type, should be 0x02 (AES) */
	u16 kt;       /* key type, should be 0x001 (CIPHER) */
	u8  kufc;     /* key usage field count */
	u16 kuf1;     /* key usage field 1 */
	u16 kuf2;     /* key usage field 2 */
	u8  kmfc;     /* key management field count */
	u16 kmf1;     /* key management field 1 */
	u16 kmf2;     /* key management field 2 */
	u16 kmf3;     /* key management field 3 */
	u8  varpart[80]; /* variable part */
} __packed;

struct ep11keytoken {
	union {
		u8 session[32];
		struct {
			u8  type;      /* TOKEN_TYPE_NON_CCA (0x00) */
			u8  res0;      /* unused */
			u16 length;    /* length of token */
			u8  version;   /* TOKEN_VERSION_EP11_AES (0x03) */
			u8  res1;      /* unused */
			u16 keybitlen; /* clear key bit len, 0 for unknown */
		} head;
	};
	u8  wkvp[16]; /* wrapping key verification pattern */
	u64 attr;     /* boolean key attributes */
	u64 mode;     /* mode bits */
	u16 version;  /* 0x1234, ep11 blob struct version */
	u8  iv[14];
	u8  encrypted_key_data[144];
	u8  mac[32];
	u8  padding[64];
} __packed;

#define AESDATA_KEY_SIZE	sizeof(struct aesdatakeytoken)
#define AESCIPHER_KEY_SIZE	sizeof(struct aescipherkeytoken)
#define EP11_KEY_SIZE		sizeof(struct ep11keytoken)

/* MAX/MIN from zt_common.h produces warnings for variable length arrays */
#define _MIN(a, b)  ((a) < (b) ? (a) : (b))
#define _MAX(a, b)  ((a) > (b) ? (a) : (b))

#define MAX_SECURE_KEY_SIZE	_MAX(EP11_KEY_SIZE, \
				     _MAX(AESDATA_KEY_SIZE, AESCIPHER_KEY_SIZE))
#define MIN_SECURE_KEY_SIZE	_MIN(EP11_KEY_SIZE, \
				     _MIN(AESDATA_KEY_SIZE, AESCIPHER_KEY_SIZE))

struct pkey_seckey {
	u8  seckey[AESDATA_KEY_SIZE];  /* the secure key blob */
};

struct pkey_clrkey {
	u8  clrkey[32]; /* 16, 24, or 32 byte clear key value */
};

#define PKEY_IOCTL_MAGIC	'p'
#define AUTOSELECT		0xFFFF
#define PKEYDEVICE		"/dev/pkey"
#define PKEY_KEYTYPE_AES_128	1
#define PKEY_KEYTYPE_AES_192	2
#define PKEY_KEYTYPE_AES_256	3

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

enum pkey_key_type {
	PKEY_TYPE_CCA_DATA   = (u32) 1,
	PKEY_TYPE_CCA_CIPHER = (u32) 2,
	PKEY_TYPE_EP11       = (u32) 3,
};

enum pkey_key_size {
	PKEY_SIZE_AES_128 = (u32) 128,
	PKEY_SIZE_AES_192 = (u32) 192,
	PKEY_SIZE_AES_256 = (u32) 256,
	PKEY_SIZE_UNKNOWN = (u32) 0xFFFFFFFF,
};

#define PKEY_FLAGS_MATCH_CUR_MKVP  0x00000002
#define PKEY_FLAGS_MATCH_ALT_MKVP  0x00000004

#define PKEY_KEYGEN_XPRT_SYM	0x00008000
#define PKEY_KEYGEN_XPRT_UASY	0x00004000
#define PKEY_KEYGEN_XPRT_AASY	0x00002000
#define PKEY_KEYGEN_XPRT_RAW	0x00001000
#define PKEY_KEYGEN_XPRT_CPAC	0x00000800
#define PKEY_KEYGEN_XPRT_DES	0x00000080
#define PKEY_KEYGEN_XPRT_AES	0x00000040
#define PKEY_KEYGEN_XPRT_RSA	0x00000008

struct pkey_apqn {
	u16 card;
	u16 domain;
};

struct pkey_genseck2 {
	struct pkey_apqn *apqns;	/* in: ptr to list of apqn targets */
	u32 apqn_entries;		/* in: # of apqn target list entries */
	enum pkey_key_type type;	/* in: key type to generate */
	enum pkey_key_size size;	/* in: key size to generate */
	u32 keygenflags;		/* in: key generation flags */
	u8 *key;			/* in: pointer to key blob buffer */
	u32 keylen;			/* in: available key blob buffer size */
					/* out: actual key blob size */
};

#define PKEY_GENSECK2 _IOWR(PKEY_IOCTL_MAGIC, 0x11, struct pkey_genseck2)

struct pkey_clr2seck2 {
	struct pkey_apqn *apqns;	/* in: ptr to list of apqn targets */
	u32 apqn_entries;		/* in: # of apqn target list entries */
	enum pkey_key_type type;	/* in: key type to generate */
	enum pkey_key_size size;	/* in: key size to generate */
	u32 keygenflags;		/* in: key generation flags */
	struct pkey_clrkey clrkey;	/* in: the clear key value */
	u8 *key;			/* in: pointer to key blob buffer */
	u32 keylen;			/* in: available key blob buffer size */
					/* out: actual key blob size */
};

#define PKEY_CLR2SECK2 _IOWR(PKEY_IOCTL_MAGIC, 0x12, struct pkey_clr2seck2)

struct pkey_verifykey2 {
	u8 *key;			/* in: pointer to key blob */
	u32 keylen;			/* in: key blob size */
	u16 cardnr;			/* in/out: card number */
	u16 domain;			/* in/out: domain number */
	enum pkey_key_type type;	/* out: the key type */
	enum pkey_key_size size;	/* out: the key size */
	u32 flags;			/* out: additional key info flags */
};

#define PKEY_VERIFYKEY2 _IOWR(PKEY_IOCTL_MAGIC, 0x17, struct pkey_verifykey2)

struct pkey_apqns4key {
	u8 *key;			/* in: pointer to key blob */
	u32 keylen;			/* in: key blob size */
	u32 flags;			/* in: match controlling flags */
	struct pkey_apqn *apqns;	/* in/out: ptr to list of apqn targets*/
	u32 apqn_entries;		/* in: max # of apqn entries in list */
					/* out: # apqns stored into the list */
};

#define PKEY_APQNS4K _IOWR(PKEY_IOCTL_MAGIC, 0x1B, struct pkey_apqns4key)

struct pkey_apqns4keytype {
	enum pkey_key_type type;	/* in: key type */
	u8  cur_mkvp[32];		/* in: current mkvp */
	u8  alt_mkvp[32];		/* in: alternate mkvp */
	u32 flags;			/* in: match controlling flags */
	struct pkey_apqn *apqns;	/* in/out: ptr to list of apqn targets*/
	u32 apqn_entries;		/* in: max # of apqn entries in list */
					/* out: # apqns stored into the list */
};

#define PKEY_APQNS4KT _IOWR(PKEY_IOCTL_MAGIC, 0x1C, struct pkey_apqns4keytype)

#define KEY_TYPE_CCA_AESDATA        "CCA-AESDATA"
#define KEY_TYPE_CCA_AESCIPHER      "CCA-AESCIPHER"
#define KEY_TYPE_EP11_AES           "EP11-AES"

#define DEFAULT_KEYBITS             256
#define PAES_BLOCK_SIZE             16
#define ENC_ZERO_LEN                (2 * PAES_BLOCK_SIZE)
#define VERIFICATION_PATTERN_LEN    (2 * ENC_ZERO_LEN + 1)

#define MKVP_LENGTH		16

static const u8 zero_mkvp[MKVP_LENGTH] = { 0x00 };

#define MKVP_EQ(mkvp1, mkvp2)	(memcmp(mkvp1, mkvp2, MKVP_LENGTH) == 0)
#define MKVP_ZERO(mkvp)		(mkvp == NULL || MKVP_EQ(mkvp, zero_mkvp))

enum card_type {
	CARD_TYPE_ANY	= -1,
	CARD_TYPE_CCA   = 1,
	CARD_TYPE_EP11  = 2,
};

struct ext_lib {
	struct cca_lib *cca;
	struct ep11_lib *ep11;
};

int open_pkey_device(bool verbose);

int generate_secure_key_random(int pkey_fd, const char *keyfile,
			       size_t keybits, bool xts, const char *key_type,
			       const char **apqns, bool verbose);

int generate_secure_key_clear(int pkey_fd, const char *keyfile,
			      size_t keybits, bool xts,
			      const char *clearkeyfile, const char *key_type,
			      const char **apqns, bool verbose);

u8 *read_secure_key(const char *keyfile, size_t *secure_key_size,
		    bool verbose);

int write_secure_key(const char *keyfile, const u8 *secure_key,
		     size_t secure_key_size, bool verbose);

int validate_secure_key(int pkey_fd,
			u8 *secure_key, size_t secure_key_size,
			size_t *clear_key_bitsize, int *is_old_mk,
			const char **apqns, bool verbose);

int generate_key_verification_pattern(const u8 *key, size_t key_size,
				      char *vp, size_t vp_len, bool verbose);

int get_master_key_verification_pattern(const u8 *key, size_t key_size,
					u8 *mkvp, bool verbose);

bool is_cca_aes_data_key(const u8 *key, size_t key_size);
bool is_cca_aes_cipher_key(const u8 *key, size_t key_size);
bool is_ep11_aes_key(const u8 *key, size_t key_size);
bool is_xts_key(const u8 *key, size_t key_size);
int get_key_bit_size(const u8 *key, size_t key_size, size_t *bitsize);
const char *get_key_type(const u8 *key, size_t key_size);
int get_min_card_level_for_keytype(const char *key_type);
const struct fw_version *get_min_fw_version_for_keytype(const char *key_type);
enum card_type get_card_type_for_keytype(const char *key_type);
int check_aes_cipher_key(const u8 *key, size_t key_size);

enum reencipher_method {
	REENCIPHER_OLD_TO_CURRENT = 1,
	REENCIPHER_CURRENT_TO_NEW = 2,
};

int reencipher_secure_key(struct ext_lib *lib, u8 *secure_key,
			  size_t secure_key_size, const char *apqns,
			  enum reencipher_method method, bool *apqn_selected,
			  bool verbose);

#endif
