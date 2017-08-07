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

#include "disk.h"
#include "job.h"
#include "zipl.h"


int bootmap_create(struct job_data* job, disk_blockptr_t* program_table,
		   disk_blockptr_t *scsi_dump_sb_blockptr,
		   disk_blockptr_t** stage2_list, blocknum_t* stage2_count,
		   char** device, struct disk_info** new_info);
void bootmap_store_blockptr(void* buffer, disk_blockptr_t* ptr,
			    struct disk_info* info);

#endif /* if not BOOTMAP_H */
