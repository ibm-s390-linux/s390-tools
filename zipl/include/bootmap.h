/*
 * s390-tools/zipl/include/bootmap.h
 *   Functions to build the bootmap file.
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef BOOTMAP_H
#define BOOTMAP_H

#include "lib/zt_common.h"

#include "disk.h"
#include "job.h"
#include "zipl.h"

#define SIGNATURE_MAGIC  "~Module signature appended~\n"
#define	PKCS7_FORMAT 0x01

struct signature_header {
	uint8_t format;
	uint8_t reserved[3];
	uint32_t length;
} __packed;

typedef union {
	uint64_t load_address;
	uint64_t load_psw;
	struct signature_header sig_head;
} component_data;

/*
 * The file_signature structure and the PKEY_ID definition
 * are based on linux/scripts/sign-file.c
 */
struct file_signature {
	u8 algorithm;
	u8 hash;
	u8 id_type;
	u8 signer_len;
	u8 key_id_len;
	u8 __pad[3];
	u32 sig_len;
	char magic[28];
};

#define PKEY_ID_PKCS7 0x02

int bootmap_create(struct job_data* job, disk_blockptr_t* program_table,
		   disk_blockptr_t *scsi_dump_sb_blockptr,
		   disk_blockptr_t** stage2_list, blocknum_t* stage2_count,
		   char** device, struct disk_info** new_info);
void bootmap_store_blockptr(void* buffer, disk_blockptr_t* ptr,
			    struct disk_info* info);

#endif /* if not BOOTMAP_H */
