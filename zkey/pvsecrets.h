/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * This header file defines functions for the PV secrets support as well
 * as the interface to the uv kernel module.
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef PVSECRETS_H
#define PVSECRETS_H

#include "lib/zt_common.h"

#include "pkey.h"
#include "keystore.h"

/*
 * Definitions for the /dev/uv kernel module interface
 */
#define UVDEVICE		"/dev/uv"
#define SYSFS_UV		"firmware/uv"
#define SYSFS_UV_PV_GUEST	"%s/prot_virt_guest"
#define SYSFS_UV_MAX_SECRETS	"%s/query/max_retr_secrets"

struct uvio_ioctl_cb {
	u32 flags;
	u16 uv_rc;			/* UV header rc value */
	u16 uv_rrc;			/* UV header rrc value */
	void *argument_addr;		/* Userspace address of uvio argument */
	u32 argument_len;
	u8  reserved14[0x40 - 0x14];	/* must be zero */
};

#define UVIO_IOCTL_LIST_SECRETS_NR	3

#define UVIO_TYPE_UVC			'u'
#define UVIO_IOCTL(nr)			_IOWR(UVIO_TYPE_UVC,		\
						nr, struct uvio_ioctl_cb)
#define UVIO_IOCTL_LIST_SECRETS		UVIO_IOCTL(			\
						UVIO_IOCTL_LIST_SECRETS_NR)

#define UVIO_RC_SUCCESS			0x0001
#define UVIO_RC_MORE_DATA		0x0100

#define UV_SECRET_TYPE_INVALID		0x00
#define UV_SECRET_TYPE_NULL		0x01
#define UV_SECRET_TYPE_AP_ASSOCIATION	0x02
#define UV_SECRET_TYPE_PLAIN_TEXT	0x03
#define UV_SECRET_TYPE_AES_128		0x04
#define UV_SECRET_TYPE_AES_192		0x05
#define UV_SECRET_TYPE_AES_256		0x06
#define UV_SECRET_TYPE_AES_XTS_128	0x07
#define UV_SECRET_TYPE_AES_XTS_256	0x08
#define UV_SECRET_TYPE_HMAC_SHA_256	0x09
#define UV_SECRET_TYPE_HMAC_SHA_512	0x0a
#define UV_SECRET_TYPE_ECDSA_P256	0x11
#define UV_SECRET_TYPE_ECDSA_P384	0x12
#define UV_SECRET_TYPE_ECDSA_P521	0x13
#define UV_SECRET_TYPE_EDDSA_ED25519	0x14
#define UV_SECRET_TYPE_EDDSA_ED448	0x15

#define UVIO_LIST_SECRETS_MAX_LEN	0x8000

struct uvio_list_secret_entry {
	u16 secret_idx;
	u16 secret_type;
	u32 secret_len;
	u64 reserved;
	u8 secret_id[UV_SECRET_ID_LEN];
} __packed;

#define UVIO_MAX_SECRET_ENTRIES		((UVIO_LIST_SECRETS_MAX_LEN - 16) /    \
					  sizeof(struct uvio_list_secret_entry))

struct uvio_list_secrets {
	u16 num_secrets_stored;
	u16 num_secrets_total;
	u16 next_secret_idx;
	u16 reserved1;
	u64 reserved2;
	struct uvio_list_secret_entry secret_entries[UVIO_MAX_SECRET_ENTRIES];
} __packed;

int uv_open_device(bool verbose);

int pvsecrets_list(int uv_fd, bool all, bool hex, const char *type_filter,
		   const char *secret_id, const char *secret_name,
		   bool verbose);
int pvsecrets_import(struct keystore *keystore, int uv_fd,
		     const char *secret_id, const char *secret_name,
		     const char *name, const char *description,
		     const char *volumes, const char *volume_type,
		     long sector_size, bool gen_passphrase,
		     const char *passphrase_file, bool verbose);

#endif
