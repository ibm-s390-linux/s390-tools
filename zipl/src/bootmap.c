/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions to build the bootmap file
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <assert.h>

#include "lib/zt_common.h"
#include "lib/util_libc.h"
#include "lib/util_part.h"
#include "lib/util_path.h"
#include "boot/s390.h"
#include "stage3.h"

#include "boot.h"
#include "bootmap.h"
#include "envblk.h"
#include "disk.h"
#include "error.h"
#include "install.h"
#include "misc.h"

#define NGDUMP_FSTYPE	"ext4"

/* Pointer to dedicated empty block in bootmap. */
static disk_blockptr_t empty_block;

/* State of secure boot in the system */
static bool secure_boot_supported;

/* Get size of a bootmap block pointer for disk with given INFO. */
static int
get_blockptr_size(struct disk_info* info)
{
	switch (info->type) {
	case disk_type_scsi:
	case disk_type_fba:
		return sizeof(struct linear_blockptr);
	case disk_type_eckd_ldl:
	case disk_type_eckd_cdl:
		assert(sizeof(struct eckd_blockptr_legacy) ==
		       sizeof(struct eckd_blockptr));

		return sizeof(struct eckd_blockptr);
	case disk_type_diag:
		break;
	}
	return 0;
}


/**
 * Pack a "plain" disk block pointer defined by PTR to BUFFER in the format
 * defined by FORMAT_ID (relevant only for ECKD disk types)
 */
void bootmap_store_blockptr(void *buffer, disk_blockptr_t *ptr,
			    struct disk_info *info,
			    int format_id)
{
	struct eckd_blockptr_legacy *eckd_legacy;
	struct eckd_blockptr *eckd;
	struct linear_blockptr *lin;

	memset(buffer, 0, get_blockptr_size(info));
	if (ptr != NULL) {
		switch (info->type) {
		case disk_type_scsi:
		case disk_type_fba:
			lin = (struct linear_blockptr *) buffer;
			lin->blockno = ptr->linear.block;
			lin->size = ptr->linear.size;
			lin->blockct = ptr->linear.blockct;
			break;
		case disk_type_eckd_ldl:
		case disk_type_eckd_cdl:
			switch (format_id) {
			case LEGACY_BLKPTR_FORMAT_ID:
				eckd_legacy =
					(struct eckd_blockptr_legacy *)buffer;

				eckd_legacy->cyl = ptr->chs.cyl;
				eckd_legacy->head = ptr->chs.head |
					((ptr->chs.cyl >> 12) & 0xfff0);
				eckd_legacy->sec = ptr->chs.sec;
				eckd_legacy->size = ptr->chs.size;
				eckd_legacy->blockct = ptr->chs.blockct;
				break;
			case BLKPTR_FORMAT_ID:
				eckd = (struct eckd_blockptr *)buffer;

				eckd->cyl = ptr->chs.cyl;
				eckd->head = ptr->chs.head;
				eckd->sec = ptr->chs.sec;
				eckd->blockct = ptr->chs.blockct;
				break;
			default:
				assert(0);
			}
			break;
		case disk_type_diag:
			break;
		}
	}
}

#define PROGRAM_TABLE_BLOCK_SIZE	512

/* Calculate the maximum number of entries in the program table. INFO
 * specifies the type of disk. */
static int
get_program_table_size(struct disk_info* info)
{
	return PROGRAM_TABLE_BLOCK_SIZE / get_blockptr_size(info) - 1;
}



static int
check_menu_positions(struct job_menu_data* menu, char* name,
		     struct disk_info* info)
{
	int i;

	for (i=0; i < menu->num; i++) {
		if (menu->entry[i].pos >= get_program_table_size(info)) {
			error_reason("Position %d in menu '%s' exceeds "
				     "maximum for device (%d)",
				     menu->entry[i].pos, name,
				     get_program_table_size(info) - 1);
			return -1;
		}
	}
	return 0;
}

static bool
check_secure_boot_support(void)
{
	unsigned int val;
	FILE *fp;

	if (verbose)
		printf("Secure boot support: ");

	fp = fopen(ZIPL_SIPL_PATH, "r");
	if (!fp) {
		if (verbose)
			printf("not available\n");
		return false;
	}

	if (fscanf(fp, "%d", &val) != 1) {
		if (verbose)
			printf("error\n");
		fclose(fp);
		return false;
	}
	fclose(fp);

	if (verbose)
		printf("%s\n", val ? "yes" : "no");

	return val ? true : false;
}


/* Write COUNT elements of the blocklist specified by LIST as a linked list
 * of segment table blocks to the file identified by file descriptor FD. Upon
 * success, return 0 and set SECTION_POINTER to point to the first block in
 * the resulting segment table. Return non-zero otherwise. */
static int add_segment_table(int fd, disk_blockptr_t *list, blocknum_t count,
			     disk_blockptr_t *segment_pointer,
			     struct disk_info *info, int program_table_id)
{
	disk_blockptr_t next;
	void* buffer;
	blocknum_t max_offset;
	blocknum_t offset;
	int pointer_size;
	int rc;

	/* Allocate block memory */
	buffer = misc_malloc(info->phy_block_size);
	if (buffer == NULL)
		return -1;
	memset(&next, 0, sizeof(disk_blockptr_t));
	memset(buffer, 0, info->phy_block_size);
	pointer_size = get_blockptr_size(info);
	max_offset = info->phy_block_size / pointer_size - 1;
	/* Fill segment tables, starting from the last one */
	for (offset = (count - 1) % max_offset; count > 0; count--, offset--) {
		/* Replace holes with empty block if necessary*/
		if (disk_is_zero_block(&list[count-1], info))
			bootmap_store_blockptr(
				       VOID_ADD(buffer, offset * pointer_size),
				       &empty_block, info,
				       program_table_id);
		else
			bootmap_store_blockptr(
				       VOID_ADD(buffer, offset * pointer_size),
				       &list[count - 1], info,
				       program_table_id);
		if (offset > 0)
			continue;
		/* Finalize segment table */
		offset = max_offset;
		bootmap_store_blockptr(VOID_ADD(buffer, offset * pointer_size),
				       &next, info,
				       program_table_id);
		rc = disk_write_block_aligned(fd, buffer, info->phy_block_size,
					      &next, info);
		if (rc) {
			free(buffer);
			return rc;
		}
	}
	free(buffer);
	*segment_pointer = next;
	return 0;
}


static int add_program_table(int fd, disk_blockptr_t *table, int entries,
			     disk_blockptr_t *pointer, struct disk_info *info,
			     int program_table_id)
{
	void* block;
	int i;
	int rc;
	int offset;

	block = misc_malloc(PROGRAM_TABLE_BLOCK_SIZE);
	if (block == NULL)
		return -1;
	memset(block, 0, PROGRAM_TABLE_BLOCK_SIZE);
	memcpy(block, ZIPL_MAGIC, ZIPL_MAGIC_SIZE);
	offset = get_blockptr_size(info);
	for (i=0; i < entries; i++) {
		bootmap_store_blockptr(VOID_ADD(block, offset), &table[i],
				       info,
				       program_table_id);
		offset += get_blockptr_size(info);
	}
	/* Write program table */
	rc = disk_write_block_aligned(fd, block, PROGRAM_TABLE_BLOCK_SIZE,
				      pointer, info);
	free(block);
	return rc;
}

static void create_component_entry(void *buffer, disk_blockptr_t *pointer,
				   component_type type, component_data data,
				   struct disk_info *info, int program_table_id)
{
	struct component_entry* entry;

	entry = (struct component_entry*) buffer;
	memset(entry, 0, sizeof(struct component_entry));
	entry->type = (uint8_t) type;
	switch (type) {
	case COMPONENT_TYPE_LOAD:
		bootmap_store_blockptr(&entry->data, pointer, info,
				       program_table_id);
		entry->compdat.load_address = data.load_address;
		break;
	case COMPONENT_TYPE_EXECUTE:
		entry->compdat.load_psw = data.load_psw;
		break;
	case COMPONENT_TYPE_SIGNATURE:
		bootmap_store_blockptr(&entry->data, pointer, info,
				       program_table_id);
		entry->compdat.sig_head = data.sig_head;
		break;
	}
}

static void
create_component_header(void* buffer, component_header_type type)
{
	struct component_header* header;

	header = (struct component_header*) buffer;
	memset(header, 0, sizeof(struct component_header));
	memcpy(&header->magic, ZIPL_MAGIC, ZIPL_MAGIC_SIZE);
	header->type = (uint8_t) type;
}

static int add_component_file_range(struct install_set *bis,
				    const char *filename,
				    struct file_range *reg,
				    address_t load_address,
				    size_t trailer, void *component,
				    int add_files,
				    struct job_target_data *target,
				    int comp_id, int menu_idx,
				    int program_table_id)
{
	struct program_component *pc = get_component(bis, comp_id, menu_idx);
	struct component_loc *location = &pc->loc;
	disk_blockptr_t **list = &pc->list;
	blocknum_t *count = &pc->count;
	struct disk_info* file_info;
	disk_blockptr_t segment;
	char* buffer;
	size_t size;
	int rc;

	if (program_table_id)
		/* skip the preparation work */
		goto write_segment_table;
	if (add_files) {
		assert(reg == NULL); /* not implemented */
		/* Read file to buffer */
		rc = misc_read_file(filename, &buffer, &size, 0);
		if (rc) {
			error_text("Could not read file '%s'", filename);
			return rc;
		}
		size -= trailer;
		/* Write buffer */
		*count = disk_write_block_buffer(bis->fd, 0, buffer,
						 size, list, bis->info);
		free(buffer);
		if (*count == 0) {
			error_text("Could not write to bootmap file");
			return -1;
		}
	} else {
		/* Make sure file is on correct device */
		rc = disk_get_info_from_file(filename, target, &file_info);
		if (rc)
			return -1;
		if (file_info->device != bis->info->device) {
			disk_free_info(file_info);
			error_reason("File is not on target device");
			return -1;
		}
		/* Get block list from existing file */
		*count = disk_get_blocklist_from_file(filename, reg,
						      list, file_info);
		disk_free_info(file_info);
		if (*count == 0)
			return -1;
		*count -= DIV_ROUND_UP(trailer, bis->info->phy_block_size);
	}
	/* Fill in component location */
	location->addr = load_address;
	location->size = *count * bis->info->phy_block_size;
	/* Try to compact list */
	*count = disk_compact_blocklist(*list, *count, bis->info);
write_segment_table:
	assert(*list != NULL);
	assert(*count != 0);
	rc = add_segment_table(bis->fd, *list, *count, &segment, bis->info,
			       program_table_id);
	if (rc == 0)
		create_component_entry(component, &segment,
				       component_type_by_id(comp_id),
				       (component_data)load_address,
				       bis->info, program_table_id);
	return rc;
}

static int add_component_file(struct install_set *bis, const char *filename,
			      address_t load_address, size_t trailer,
			      void *component, int add_files,
			      struct job_target_data *target, int comp_id,
			      int menu_idx, int program_table_id)
{
	return add_component_file_range(bis, filename, NULL, load_address,
					trailer, component, add_files,
					target, comp_id, menu_idx,
					program_table_id);
}

static int add_component_buffer_align(struct install_set *bis, void *buffer,
				      size_t size, component_data data,
				      void *component, int align,
				      off_t *offset, int comp_id, int menu_idx,
				      int program_table_id)
{
	struct program_component *pc = get_component(bis, comp_id, menu_idx);
	struct component_loc *location = &pc->loc;
	disk_blockptr_t **list = &pc->list;
	blocknum_t *count = &pc->count;
	disk_blockptr_t segment;
	int rc;

	if (program_table_id)
		/* skip the preparation work */
		goto write_segment_table;
	/* Write buffer */
	*count = disk_write_block_buffer_align(bis->fd, 0, buffer, size, list,
					       bis->info, align, offset);
	if (*count == 0) {
		error_text("Could not write to bootmap file");
		return -1;
	}
	if (component_type_by_id(comp_id) == COMPONENT_TYPE_LOAD) {
		/* Fill in component location */
		location->addr = data.load_address;
		location->size = *count * bis->info->phy_block_size;
	} else {
		location->addr = 0;
		location->size = 0;
	}
	/* Try to compact list */
	*count = disk_compact_blocklist(*list, *count, bis->info);
write_segment_table:
	assert(*list != NULL);
	assert(*count != 0);

	rc = add_segment_table(bis->fd, *list, *count, &segment, bis->info,
			       program_table_id);
	if (rc == 0)
		create_component_entry(component, &segment,
				       component_type_by_id(comp_id),
				       data, bis->info, program_table_id);
	return rc;
}

static int add_component_buffer(struct install_set *bis, void *buffer,
				size_t size, component_data data,
				void *component, int comp_id, int menu_idx,
				int program_table_id)
{
	return add_component_buffer_align(bis, buffer, size, data, component,
					  bis->info->phy_block_size, NULL,
					  comp_id, menu_idx, program_table_id);
}

static int add_dummy_buffer(struct install_set *bis, size_t size,
			    address_t addr, void *component, int comp_id,
			    int menu_idx, int program_table_id)
{
	char *buffer;
	int rc = 0;

	buffer = misc_malloc(size);
	if (buffer == NULL)
		return -1;

	memset(buffer, 0, size);
	rc = add_component_buffer(bis, buffer, size,
				  (component_data)(uint64_t)addr,
				  component, comp_id, menu_idx,
				  program_table_id);
	free(buffer);
	return rc;
}


static void print_components(struct install_set *bis, int menu_idx)
{
	const char *padding = "................";
	int i;

	printf("  component address:\n");
	/* Process all available components */
	for (i = 0; i < NR_PROGRAM_COMPONENTS; i++) {
		struct program_component *pc = get_component(bis, i, menu_idx);

		if (pc->loc.size == 0)
			continue;
		printf("    %s%s: 0x%08llx-0x%08llx\n", component_desc_by_id(i),
		       &padding[strlen(component_desc_by_id(i))],
		       (unsigned long long)pc->loc.addr,
		       (unsigned long long)(pc->loc.addr + pc->loc.size - 1));
	}
}

static int
extract_signature(const char *filename, void **ret_signature,
		  struct signature_header *sig_head)
{
	struct file_signature *file_sig;
	size_t signature_size = 0;
	void *signature;
	char *buffer;
	size_t size;

	if (misc_read_file(filename, &buffer, &size, 0))
		return 0;

	file_sig = (void *) buffer + size - sizeof(*file_sig);
	if (memcmp(file_sig->magic, SIGNATURE_MAGIC, sizeof(file_sig->magic))
	    != 0)
		goto out;

	signature = misc_malloc(file_sig->sig_len);
	if (signature == NULL)
		goto out;
	signature_size = file_sig->sig_len;

	memcpy(signature, buffer + size - signature_size - sizeof(*file_sig),
	       signature_size);

	switch (file_sig->id_type) {
	case PKEY_ID_PKCS7:
		sig_head->format = PKCS7_FORMAT;
		break;
	default:
		error_text("Unsupported signature type %02x",
			   file_sig->id_type);
		signature_size = 0;
		free(signature);
		goto out;
	}

	sig_head->length = signature_size;
	*ret_signature = signature;
	/* return size of signature and corresponding header */
	signature_size += sizeof(*file_sig);
out:
	free(buffer);
	return signature_size;
}

static void
check_remaining_filesize(size_t filesize, size_t signature_size,
			 struct disk_info *info, char *filename)
{
	if ((filesize - signature_size) % info->phy_block_size) {
		fprintf(stderr,
			"Warning: Size of signed file %s is not a multiple of the disk block size\n",
			filename);
	}
}

static int is_last_table(struct install_set *bis, int table_id)
{
	assert(bis->nr_tables > 0 && bis->nr_tables <= NR_PROGRAM_TABLES);

	return table_id == bis->nr_tables - 1;
}

static int add_ipl_program(struct install_set *bis, char *filename,
		bool add_envblk, struct job_envblk_data *envblk,
		struct job_ipl_data *ipl, disk_blockptr_t *program,
		int verbose, int add_files, component_header_type type,
		struct job_target_data *target, int is_secure,
		int menu_idx, int program_table_id)
{
	int last_table = is_last_table(bis, program_table_id);
	struct signature_header sig_head;
	size_t ramdisk_size, image_size;
	size_t stage3_params_size;
	size_t signature_size;
	int offset;
	uint64_t flags = 0;
	void *stage3_params;
	struct stat stats;
	off_t envblk_off;
	void *signature;
	void *table;
	int rc;

	memset(&sig_head, 0, sizeof(sig_head));
	table = util_zalloc(bis->info->phy_block_size);
	if (table == NULL)
		return -1;
	/* Create component table */
	offset = 0;
	/* Fill in component table header */
	create_component_header(VOID_ADD(table, offset), type);
	offset += sizeof(struct component_header);
	/*
	 * Workaround for machine loader bug
	 * need to define the stage 3 loader at first position in the bootmap
	 * file
	 */
	/* initiate values for ramdisk */
	stats.st_size = 0;
	if (ipl->common.ramdisk != NULL) {
		/* Add ramdisk */
		if (verbose && last_table)
			printf("  initial ramdisk...: %s\n", ipl->common.ramdisk);
		/* Get ramdisk file size */
		if (stat(ipl->common.ramdisk, &stats)) {
			error_reason(strerror(errno));
			error_text("Could not get information for file '%s'",
				   ipl->common.ramdisk);
			free(table);
			return -1;
		}
	}
	ramdisk_size = stats.st_size;
	if (bis->info->type == disk_type_scsi) {
		flags |= STAGE3_FLAG_SCSI;
		/*
		 * Add dummy components for stage 3 heap and stack to block the
		 * associated memory areas against firmware use.
		 */
		rc = add_dummy_buffer(bis, STAGE3_HEAP_SIZE,
				      STAGE3_HEAP_ADDRESS,
				      VOID_ADD(table, offset),
				      COMPONENT_ID_HEAP_AREA,
				      menu_idx, program_table_id);
		if (rc) {
			error_text("Could not add stage3 HEAP dummy");
			free(table);
			return rc;
		}
		offset += sizeof(struct component_entry);
		rc = add_dummy_buffer(bis, STAGE3_STACK_SIZE,
				      STAGE3_STACK_ADDRESS,
				      VOID_ADD(table, offset),
				      COMPONENT_ID_STACK_AREA,
				      menu_idx, program_table_id);
		if (rc) {
			error_text("Could not add stage3 STACK dummy");
			free(table);
			return rc;
		}
		offset += sizeof(struct component_entry);
	}
	if (ipl->is_kdump)
		flags |= STAGE3_FLAG_KDUMP;

	/* Get kernel file size */
	if (stat(ipl->common.image, &stats)) {
		error_reason(strerror(errno));
		error_text("Could not get information for file '%s'",
			   ipl->common.image);
		free(table);
		return -1;
	}
	image_size = stats.st_size;
	signature_size = extract_signature(ZIPL_STAGE3_PATH, &signature,
					   &sig_head);
	if (signature_size &&
	    (is_secure == SECURE_BOOT_ENABLED ||
	     (is_secure == SECURE_BOOT_AUTO && secure_boot_supported))) {
		if (verbose && last_table)
			printf("  signature for.....: %s\n", ZIPL_STAGE3_PATH);

		rc = add_component_buffer(bis, signature, sig_head.length,
					  (component_data)sig_head,
					  VOID_ADD(table, offset),
					  COMPONENT_ID_LOADER_SIGNATURE,
					  menu_idx, program_table_id);
		if (rc) {
			error_text("Could not add stage3 signature");
			free(table);
			return rc;
		}
		offset += sizeof(struct component_entry);
		free(signature);
	} else if (is_secure == SECURE_BOOT_ENABLED) {
		/*
		 * If secure boot is forced and we have failed to extract a
		 * signature for the stage 3 loader zipl will abort with an
		 * error message
		 */
		error_text("Could not install Secure Boot IPL records");
		error_reason("Missing signature in internal loader file %s",
			     ZIPL_STAGE3_PATH);
		free(table);
		return -1;
	}

	/* Add stage 3 loader to bootmap */
	rc = add_component_file(bis, ZIPL_STAGE3_PATH, STAGE3_LOAD_ADDRESS,
				signature_size, VOID_ADD(table, offset), 1,
				target, COMPONENT_ID_LOADER, menu_idx,
				program_table_id);
	if (rc) {
		error_text("Could not add internal loader file '%s'",
			   ZIPL_STAGE3_PATH);
		free(table);
		return rc;
	}
	offset += sizeof(struct component_entry);

	/* Add stage 3 parameter to bootmap */
	rc = boot_get_stage3_parms(&stage3_params, &stage3_params_size,
				   ipl->common.parm_addr, ipl->common.ramdisk_addr,
				   ramdisk_size,
				   ipl->is_kdump ? IMAGE_ENTRY_KDUMP :
				   IMAGE_ENTRY,
				   (bis->info->type == disk_type_scsi) ? 0 : 1,
				   flags, ipl->common.image_addr, image_size,
				   ipl->envblk_addr,
				   add_envblk ? envblk->size : 0);
	if (rc) {
		free(table);
		return rc;
	}
	rc = add_component_buffer(bis, stage3_params, stage3_params_size,
				  (component_data) (uint64_t)
				  STAGE3_PARAMS_ADDRESS,
				  VOID_ADD(table, offset),
				  COMPONENT_ID_PARAMETERS,
				  menu_idx, program_table_id);
	free(stage3_params);
	if (rc) {
		error_text("Could not add parameters");
		free(table);
		return -1;
	}
	offset += sizeof(struct component_entry);

	/* Add kernel image */
	if (verbose && last_table)
		printf("  kernel image......: %s\n", ipl->common.image);

	signature_size = extract_signature(ipl->common.image, &signature, &sig_head);
	if (signature_size &&
	    (is_secure == SECURE_BOOT_ENABLED ||
	     (is_secure == SECURE_BOOT_AUTO && secure_boot_supported))) {
		if (verbose && last_table)
			printf("  signature for.....: %s\n", ipl->common.image);

		rc = add_component_buffer(bis, signature, sig_head.length,
					  (component_data)sig_head,
					  VOID_ADD(table, offset),
					  COMPONENT_ID_IMAGE_SIGNATURE,
					  menu_idx, program_table_id);
		if (rc) {
			error_text("Could not add image signature");
			free(table);
			return rc;
		}
		offset += sizeof(struct component_entry);
		free(signature);
		check_remaining_filesize(image_size, signature_size, bis->info,
					 ipl->common.image);
	} else if (is_secure == SECURE_BOOT_ENABLED) {
		/*
		 * If secure boot is forced and we have failed to extract a
		 * signature for the kernel image zipl will abort with an
		 * error message
		 */
		error_text("Could not install Secure Boot IPL records");
		error_reason("Missing signature in image file %s",
			     ipl->common.image);
		free(table);
		return -1;
	}

	rc = add_component_file(bis, ipl->common.image, ipl->common.image_addr,
				signature_size, VOID_ADD(table, offset),
				add_files, target, COMPONENT_ID_KERNEL_IMAGE,
				menu_idx, program_table_id);
	if (rc) {
		error_text("Could not add image file '%s'", ipl->common.image);
		free(table);
		return rc;
	}
	offset += sizeof(struct component_entry);

	/* Add kernel parmline */
	if (ipl->common.parmline != NULL) {
		if (verbose && last_table)
			printf("  kernel parmline...: '%s'\n", ipl->common.parmline);
		rc = add_component_buffer(bis, ipl->common.parmline,
					  strlen(ipl->common.parmline) + 1,
					  (component_data)ipl->common.parm_addr,
					  VOID_ADD(table, offset),
					  COMPONENT_ID_PARMLINE,
					  menu_idx, program_table_id);
		if (rc) {
			error_text("Could not add parmline '%s'",
				   ipl->common.parmline);
			free(table);
			return -1;
		}
		offset += sizeof(struct component_entry);
	}
	/* add ramdisk */
	if (ipl->common.ramdisk != NULL) {
		signature_size = extract_signature(ipl->common.ramdisk, &signature,
						   &sig_head);
		if (signature_size &&
		    (is_secure == SECURE_BOOT_ENABLED ||
		     (is_secure == SECURE_BOOT_AUTO &&
		      secure_boot_supported))) {
			if (verbose && last_table) {
				printf("  signature for.....: %s\n",
				       ipl->common.ramdisk);
			}
			rc = add_component_buffer(bis, signature,
						  sig_head.length,
						  (component_data)sig_head,
						  VOID_ADD(table, offset),
						 COMPONENT_ID_RAMDISK_SIGNATURE,
						  menu_idx, program_table_id);
			if (rc) {
				error_text("Could not add ramdisk signature");
				free(table);
				return rc;
			}
			offset += sizeof(struct component_entry);
			free(signature);
			check_remaining_filesize(ramdisk_size, signature_size,
						 bis->info,
						 ipl->common.ramdisk);
		}
		rc = add_component_file(bis, ipl->common.ramdisk,
					ipl->common.ramdisk_addr,
					signature_size,
					VOID_ADD(table, offset),
					add_files, target, COMPONENT_ID_RAMDISK,
					menu_idx, program_table_id);
		if (rc) {
			error_text("Could not add ramdisk '%s'",
				   ipl->common.ramdisk);
			free(table);
			return -1;
		}
		offset += sizeof(struct component_entry);
	}
	if (add_envblk == true) {
		/*
		 * finally add environment block
		 */
		rc = envblk_offset_get(bis->fd, &envblk_off);
		if (rc) {
			free(table);
			return rc;
		}
		if (envblk_off == 0) {
			/*
			 * write with fs_block_size alignment to make sure
			 * that the logical environment block will get to
			 * single file system block
			 */
			rc = add_component_buffer_align(bis,
					       envblk->buf, envblk->size,
					       (component_data)ipl->envblk_addr,
					       VOID_ADD(table, offset),
					       bis->info->fs_block_size,
					       &envblk_off, COMPONENT_ID_ENVBLK,
					       menu_idx, program_table_id);
			if (rc) {
				error_text("Could not add environment block");
				free(table);
				return rc;
			}
			assert(envblk_off % bis->info->fs_block_size == 0);
			/*
			 * store environment block location
			 * in the bootmap header
			 */
			rc = envblk_offset_set(bis->fd, envblk_off);
			if (rc) {
				error_text("Could not store environment block location");
				free(table);
				return rc;
			}
		} else {
			struct file_range reg;

			reg.offset = envblk_off;
			reg.len = envblk->size;
			rc = add_component_file_range(bis, filename, &reg,
						      ipl->envblk_addr, 0,
						      VOID_ADD(table, offset),
						      0, target,
						      COMPONENT_ID_ENVBLK,
						      menu_idx,
						      program_table_id);
			if (rc) {
				error_text("Could not add environment block");
				free(table);
				return rc;
			}
		}
		offset += sizeof(struct component_entry);
	}
	if (verbose && last_table)
		print_components(bis, menu_idx);
	/* Terminate component table */
	create_component_entry(VOID_ADD(table, offset), NULL,
			       COMPONENT_TYPE_EXECUTE,
			       (component_data) (uint64_t)
			       (STAGE3_ENTRY | PSW_LOAD),
			       bis->info, program_table_id);
	/* Write component table */
	rc = disk_write_block_aligned(bis->fd, table,
				      bis->info->phy_block_size,
				      program, bis->info);
	free(table);
	return rc;
}

static int add_segment_program(struct install_set *bis,
			       struct job_segment_data *segment,
			       disk_blockptr_t *program, int verbose,
			       int add_files, component_header_type type,
			       struct job_target_data *target,
			       int program_table_id)
{
	int last_table = is_last_table(bis, program_table_id);
	void *table;
	int offset;
	int rc;

	table = util_zalloc(bis->info->phy_block_size);
	if (table == NULL)
		return -1;
	/* Create component table */
	offset = 0;
	/* Fill in component table header */
	create_component_header(VOID_ADD(table, offset), type);
	offset += sizeof(struct component_header);
	/* Add segment file */
	if (verbose && last_table)
		printf("  segment file......: %s\n", segment->segment);

	rc = add_component_file(bis, segment->segment, segment->segment_addr, 0,
				VOID_ADD(table, offset), add_files, target,
				COMPONENT_ID_SEGMENT_FILE, 0 /* menu_idx */,
				program_table_id);
	if (rc) {
		error_text("Could not add segment file '%s'",
			   segment->segment);
		free(table);
		return rc;
	}
	offset += sizeof(struct component_entry);
	/* Print component addresses */
	if (verbose && last_table)
		print_components(bis, 0 /* menu_idx */);
	/* Terminate component table */
	create_component_entry(VOID_ADD(table, offset), NULL,
			       COMPONENT_TYPE_EXECUTE,
			       (component_data)(uint64_t)PSW_DISABLED_WAIT,
			       bis->info, program_table_id);
	/* Write component table */
	rc = disk_write_block_aligned(bis->fd, table,
				      bis->info->phy_block_size,
				      program, bis->info);
	free(table);
	return rc;
}


#define DUMP_PARAM_MAX_LEN	896

static int
check_dump_device_late(char *partition, struct disk_info *target_info,
		       struct job_target_data *target)
{
	struct disk_info* info;
	int rc;

	/* Get information about partition */
	rc = disk_get_info(partition, target, &info);
	if (rc) {
		error_text("Could not get information for dump partition '%s'",
			   partition);
		return rc;
	}
	if ((info->type != disk_type_scsi) || (info->partnum == 0)) {
		error_reason("Device '%s' is not a SCSI partition",
			     partition);
		disk_free_info(info);
		return -1;
	}
	if (info->device != target_info->device) {
		error_reason("Target directory is not on same device as "
			     "'%s'", partition);
		disk_free_info(info);
		return -1;
	}
	disk_free_info(info);
	return 0;
}

static int add_dump_program(struct install_set *bis, struct job_dump_data *dump,
			    disk_blockptr_t *program, int verbose,
			    component_header_type type,
			    struct job_target_data *target,
			    int program_table_id)
{
	struct job_ipl_data ipl;
	int rc;

	/* Convert fs dump job to IPL job */
	memset(&ipl, 0, sizeof(ipl));
	ipl.common = dump->common;

	/* Get file system dump parmline */
	rc = check_dump_device_late(dump->device, bis->info, target);
	if (rc)
		return rc;
	ipl.common.parmline = dump->common.parmline;
	ipl.common.parm_addr = dump->common.parm_addr;
	return add_ipl_program(bis, NULL, false, NULL, &ipl, program,
			       verbose, 1, type, target, SECURE_BOOT_DISABLED,
			       0 /* menu_idx */, program_table_id);
}


/**
 * Build a program table from job data and set pointer to program table
 * block upon success
 */
static int build_program_table(struct job_data *job,
			       struct install_set *bis, int program_table_id)
{
	int last_table = is_last_table(bis, program_table_id);
	int entries, component_header;
	disk_blockptr_t *table;
	int is_secure;
	int i;
	int rc;

	entries = get_program_table_size(bis->info);
	/* Get some memory for the program table */
	table = (disk_blockptr_t *) misc_malloc(sizeof(disk_blockptr_t) *
						entries);
	if (table == NULL)
		return -1;

	memset((void *) table, 0, sizeof(disk_blockptr_t) * entries);
	/* Add programs */
	switch (job->id) {
	case job_ipl:
		if (last_table) {
			if (job->command_line)
				printf("Adding IPL section\n");
			else
				printf("Adding IPL section '%s' (default)\n",
				       job->name);
		}
		if (job->data.ipl.is_kdump)
			component_header = COMPONENT_HEADER_DUMP;
		else
			component_header = COMPONENT_HEADER_IPL;
		rc = add_ipl_program(bis, bis->filename,
				     true, &job->envblk, &job->data.ipl,
				     &table[0], verbose || job->command_line,
				     job->add_files, component_header,
				     &job->target, job->is_secure, 0,
				     program_table_id);
		break;
	case job_segment:
		if (last_table) {
			if (job->command_line)
				printf("Adding segment load section\n");
			else
				printf("Adding segment load section '%s' (default)\n",
				       job->name);
		}
		rc = add_segment_program(bis, &job->data.segment, &table[0],
					 verbose || job->command_line,
					 job->add_files, COMPONENT_HEADER_IPL,
					 &job->target, program_table_id);
		break;
	case job_dump_partition:
		/* Only useful for a partition dump that uses a dump kernel*/
		if (last_table) {
			if (job->command_line)
				printf("Adding dump section\n");
			else
				printf("Adding dump section '%s' (default)\n",
				       job->name);
		}
		rc = add_dump_program(bis, &job->data.dump, &table[0],
				      verbose || job->command_line,
				      COMPONENT_HEADER_DUMP, &job->target,
				      program_table_id);
		break;
	case job_menu:
		if (last_table)
			printf("Building menu '%s'\n", job->name);
		rc = 0;
		for (i=0; i < job->data.menu.num; i++) {
			switch (job->data.menu.entry[i].id) {
			case job_ipl:
				if (last_table &&
				    job->data.menu.entry[i].data.ipl.common.ignore) {
					printf("Skipping #%d: IPL section '%s' (missing files)\n",
					       job->data.menu.entry[i].pos,
					       job->data.menu.entry[i].name);
					break;
				}
				if (last_table)
					printf("Adding #%d: IPL section '%s'%s",
					       job->data.menu.entry[i].pos,
					       job->data.menu.entry[i].name,
					       (job->data.menu.entry[i].pos ==
						job->data.menu.default_pos) ?
					       " (default)" : "");
				if (job->data.menu.entry[i].data.ipl.is_kdump) {
					component_header =
						COMPONENT_HEADER_DUMP;
					if (last_table)
						printf(" (kdump)\n");
				} else {
					component_header =
						COMPONENT_HEADER_IPL;
					if (last_table)
						printf("\n");
				}
				if (job->is_secure != SECURE_BOOT_UNDEFINED)
					is_secure = job->is_secure;
				else
					is_secure =
					      job->data.menu.entry[i].is_secure;
				rc = add_ipl_program(bis, bis->filename,
					true, &job->envblk,
					&job->data.menu.entry[i].data.ipl,
					&table[job->data.menu.entry[i].pos],
					verbose || job->command_line,
					job->add_files, component_header,
						     &job->target, is_secure, i,
						     program_table_id);
				break;
			case job_print_usage:
			case job_print_version:
			case job_segment:
			case job_dump_partition:
			case job_mvdump:
			case job_menu:
			case job_ipl_tape:
				rc = -1;
				/* Should not happen */
				break;
			}
			if (rc)
				break;
		}
		if (rc == 0) {
			/* Set default entry */
			table[0] = table[job->data.menu.default_pos];
		}
		break;
	case job_print_usage:
	case job_print_version:
	default:
		/* Should not happen */
		rc = -1;
		break;
	}
	if (job->envblk.buf && verbose && last_table)
		envblk_print(job->envblk.buf, job->envblk.size);

	if (rc == 0) {
		disk_blockptr_t *pointer;

		/* Add program table block */
		pointer = &bis->tables[program_table_id].table;
		rc = add_program_table(bis->fd, table, entries,
				       pointer, bis->info,
				       program_table_id);
	}
	free(table);
	return rc;
}


/* Write block of zeroes to the bootmap file FD and store the resulting
 * block pointer in BLOCK. Return zero on success, non-zero otherwise. */
static int
write_empty_block(int fd, disk_blockptr_t* block, struct disk_info* info)
{
	void* buffer;
	int rc;

	buffer = misc_malloc(info->phy_block_size);
	if (buffer == NULL)
		return -1;
	memset(buffer, 0, info->phy_block_size);
	rc = disk_write_block_aligned(fd, buffer, info->phy_block_size, block,
				      info);
	free(buffer);
	return rc;
}


static int install_stages_dasd_fba(int fd, char *filename,
				   struct job_data *job,
				   struct disk_info *info,
				   disk_blockptr_t **stage1b_list,
				   blocknum_t *stage1b_count,
				   int program_table_id)
{
	disk_blockptr_t *stage2_list;
	blocknum_t stage2_count;
	size_t stage2_size;
	void *stage2_data;

	switch (program_table_id) {
	case LEGACY_BLKPTR_FORMAT_ID:
		/*
		 * This program table is used for CCW-type IPL (see comments
		 * for install_bootloader()).
		 * Add stage2 loader
		 */
		if (boot_get_fba_stage2(&stage2_data, &stage2_size, job))
			return -1;
		stage2_count = disk_write_block_buffer(fd, 0, stage2_data,
						       stage2_size,
						       &stage2_list, info);
		free(stage2_data);
		if (stage2_count == 0) {
			error_text("Could not write to file '%s'", filename);
			return -1;
		}
		if (install_fba_stage1b(fd, stage1b_list, stage1b_count,
					stage2_list, stage2_count, info))
			return -1;
		free(stage2_list);
		break;
	case BLKPTR_FORMAT_ID:
		/*
		 * This program table is not used when booting from DASD FBA
		 * (see comments for install_bootloader()
		 */
		*stage1b_list = NULL;
		*stage1b_count = 0;
		break;
	default:
		assert(0);
	}
	return 0;
}

static int install_stages_eckd_dasd(int fd, char *filename,
				    struct job_data *job,
				    struct disk_info *info,
				    disk_blockptr_t *program_table,
				    disk_blockptr_t **stage1b_list,
				    blocknum_t *stage1b_count,
				    int program_table_id)
{
	disk_blockptr_t *stage2b_list;
	blocknum_t stage2b_count;
	size_t stage2b_size;
	void *stage2b_data;

	switch (program_table_id) {
	case LEGACY_BLKPTR_FORMAT_ID:
		/*
		 * This program table is used for CCW-type IPL.
		 * Add stage2 loader
		 */
		if (boot_get_eckd_stage2(&stage2b_data, &stage2b_size, job))
			return -1;
		stage2b_count = disk_write_block_buffer(fd, 0, stage2b_data,
							stage2b_size,
							&stage2b_list,
							info);
		free(stage2b_data);
		if (stage2b_count == 0) {
			error_text("Could not write to file '%s'", filename);
			return -1;
		}
		if (install_eckd_stage1b(fd, stage1b_list, stage1b_count,
					 stage2b_list, stage2b_count, info))
			return -1;
		free(stage2b_list);
		break;
	case BLKPTR_FORMAT_ID:
		/*
		 * This program table is used for List-Directed IPL,
		 * which doesn't invoke stage2 loader.
		 * Link the program table with the boot record, that
		 * will be installed later by install_bootloader()
		 */
		if (boot_get_eckd_ld_ipl_br(&stage2b_data, &stage2b_size,
					    program_table, info))
			return -1;
		stage2b_count = disk_write_block_buffer(fd, 0, stage2b_data,
							stage2b_size,
							stage1b_list,
							info);
		free(stage2b_data);
		if (stage2b_count == 0) {
			error_text("Could not write to file '%s'", filename);
			return -1;
		}
		*stage1b_count = stage2b_count;
		break;
	default:
		assert(0);
	}
	return 0;
}

static int bootmap_install_stages(struct job_data *job, struct install_set *bis,
				  int program_table_id)
{
	struct program_table *pt = &bis->tables[program_table_id];
	int rc = 0;

	switch (bis->info->type) {
	case disk_type_fba:
		rc = install_stages_dasd_fba(bis->fd, bis->filename, job,
					     bis->info,
					     &pt->stage1b_list,
					     &pt->stage1b_count,
					     program_table_id);
		break;
	case disk_type_eckd_ldl:
	case disk_type_eckd_cdl:
		rc = install_stages_eckd_dasd(bis->fd, bis->filename, job,
					      bis->info,
					      &pt->table,
					      &pt->stage1b_list,
					      &pt->stage1b_count,
					      program_table_id);
		break;
	case disk_type_scsi:
	case disk_type_diag:
		pt->stage1b_list = NULL;
		pt->stage1b_count = 0;
		break;
	}
	return rc;
}

static int
bootmap_write_scsi_superblock(int fd, struct disk_info *info,
			      disk_blockptr_t *scsi_dump_sb_blockptr,
			      ulong dump_size)
{
	struct scsi_dump_sb scsi_sb;

	memset(&scsi_sb, 0, sizeof(scsi_sb));
	scsi_sb.magic = SCSI_DUMP_SB_MAGIC;
	scsi_sb.version = 1;
	scsi_sb.part_start = info->geo.start * info->phy_block_size;
	scsi_sb.part_size = info->phy_blocks * info->phy_block_size;
	scsi_sb.dump_offset = 0;
	scsi_sb.dump_size = dump_size;
	scsi_sb.csum_offset = 0;
	scsi_sb.csum_size = SCSI_DUMP_SB_CSUM_SIZE;
	/* Set seed because otherwise csum over zero block is 0 */
	scsi_sb.csum = SCSI_DUMP_SB_SEED;
	return disk_write_block_aligned(fd, &scsi_sb,
					sizeof(scsi_sb),
					scsi_dump_sb_blockptr, info);
}


static int
estimate_scsi_dump_size(struct job_data *job, struct disk_info *info, ulong *dump_size)
{
	struct stat st;
	ulong size;

	/* Use approximated stage 3 size as starting point */
	size = IMAGE_LOAD_ADDRESS;

	/* Ramdisk */
	if (job->data.dump.common.ramdisk != NULL) {
		if (stat(job->data.dump.common.ramdisk, &st))
			return -1;
		size += DIV_ROUND_UP(st.st_size, info->phy_block_size);
		size += 1; /* For ramdisk section entry */
	}
	/* Kernel */
	if (stat(job->data.dump.common.image, &st))
		return -1;
	size += DIV_ROUND_UP(st.st_size - IMAGE_LOAD_ADDRESS,
			     info->phy_block_size);
	/* Parmfile */
	size += DIV_ROUND_UP(DUMP_PARAM_MAX_LEN, info->phy_block_size);
	size += 8;  /* 1x table + 1x script + 3x section + 1x empty
		       1x header + 1x scsi dump super block */
	if (size > info->phy_blocks) {
		error_text("Partition too small for dump tool");
		return -1;
	}
	*dump_size = (info->phy_blocks - size) * info->phy_block_size;
	return 0;
}

/**
 * Check that disk is appropriate for the JOB
 */
static int disk_is_appropriate(const struct job_data *job,
			       const struct disk_info *info)
{
	if (job->is_secure == SECURE_BOOT_ENABLED &&
	    info->type != disk_type_scsi &&
	    info->type != disk_type_eckd_cdl) {
		error_reason("Secure boot forced for improper disk type");
		return 0;
	}
	return 1;
}

static int
check_dump_device(const struct job_data *job, const struct disk_info *info,
		  const char *device)
{
	int rc, part_ext;

	/* Check for supported disk and driver types */
	if ((info->source == source_auto) && (info->type == disk_type_diag)) {
		error_reason("Unsupported disk type (%s)",
			     disk_get_type_name(info->type));
		return -1;
	}
	if (!disk_is_appropriate(job, info))
		return -1;

	rc = util_part_search(device, info->geo.start,
			      info->phy_blocks, info->phy_block_size, &part_ext);
	if (rc <= 0 || part_ext) {
		if (rc == 0)
			error_reason("No partition");
		else if (rc < 0)
			error_reason("Could not read partition table");
		else if (part_ext)
			error_reason("Extended partitions not allowed");
		error_text("Invalid dump device");
		return -1;
	}
	return 0;
}

/**
 * Set actual number of "similar" program tables to be installed
 */
static void set_nr_tables(struct job_data *job, struct install_set *bis)
{
	assert(bis->nr_tables == 0);

	if (bis->info->type == disk_type_eckd_cdl &&
	    (job->id == job_ipl || job->id == job_menu))
		bis->nr_tables = NR_PROGRAM_TABLES;
	else
		bis->nr_tables = 1;
}

/**
 * Prepare resources to build a program table
 */
static int prepare_build_program_table_device(struct job_data *job,
					      struct install_set *bis,
					      int program_table_id)
{
	ulong unused_size;

	if (program_table_id)
		/* skip the preparation work */
		return 0;
	/* Get full path of bootmap file */
	if (!dry_run) {
		bis->filename = misc_strdup(job->data.dump.device);
		if (!bis->filename)
			return -1;
		bis->fd = misc_open_exclusive(bis->filename);
		if (bis->fd == -1) {
			error_text("Could not open file '%s'", bis->filename);
			return -1;
		}
	} else {
		bis->filename = misc_make_path(job->target.bootmap_dir,
					       BOOTMAP_TEMPLATE_FILENAME);
		if (!bis->filename)
			return -1;
		/* Create temporary bootmap file */
		bis->fd = mkstemp(bis->filename);
		if (bis->fd == -1) {
			error_reason(strerror(errno));
			error_text("Could not create file '%s':",
				   bis->filename);
			return -1;
		}
	}
	/* Retrieve target device information */
	if (disk_get_info(bis->filename, &job->target, &bis->info))
		return -1;

	if (verbose) {
		printf("Target device information\n");
		disk_print_info(bis->info);
	}
	if (misc_temp_dev(bis->info->device, 1, &bis->device))
		return -1;
	if (check_dump_device(job, bis->info, bis->device))
		return -1;
	printf("Building bootmap directly on partition '%s'%s\n",
	       bis->filename,
	       job->add_files ? " (files will be added to partition)"
	       : "");
	/* For partition dump set raw partition offset
	   to expected size before end of disk */
	if (estimate_scsi_dump_size(job, bis->info, &unused_size))
		return -1;
	if (lseek(bis->fd, unused_size, SEEK_SET) < 0)
		return -1;

	/* Initialize bootmap header */
	if (bootmap_header_init(bis->fd)) {
		error_text("Could not init bootmap header at '%s'",
			   bis->filename);
		return -1;
	}
	/* Write empty block to be read in place of holes in files */
	if (write_empty_block(bis->fd, &empty_block, bis->info)) {
		error_text("Could not write to file '%s'",
			   bis->filename);
		return -1;
	}
	if (bootmap_write_scsi_superblock(bis->fd, bis->info,
					  &bis->scsi_dump_sb_blockptr,
					  unused_size)) {
		error_text("Could not write SCSI superblock to file '%s'",
			   bis->filename);
		return -1;
	}
	set_nr_tables(job, bis);
	return 0;
}

static int bootmap_create_device(struct job_data *job, struct install_set *bis,
				 int program_table_id)
{
	if (prepare_build_program_table_device(job, bis, program_table_id))
		return -1;
	if (build_program_table(job, bis, program_table_id))
		return -1;
	/* Install stage 2 loader to bootmap if necessary */
	if (bootmap_install_stages(job, bis, program_table_id)) {
		error_text("Could not install loader stages to bootmap");
		return -1;
	}
	return 0;
}

/**
 * Prepare resources to build a program table
 */
static int prepare_build_program_table_file(struct job_data *job,
					    char *bootmap_dir,
					    struct install_set *bis,
					    int program_table_id)
{
	if (program_table_id)
		/* skip the preparation work */
		return 0;
	/* Create temporary bootmap file */
	bis->filename = misc_make_path(bootmap_dir, BOOTMAP_TEMPLATE_FILENAME);
	if (!bis->filename)
		return -1;
	bis->fd = mkstemp(bis->filename);
	if (bis->fd == -1) {
		error_reason(strerror(errno));
		error_text("Could not create file '%s':", bis->filename);
		return -1;
	}
	/* Retrieve target device information. Note that we have to
	 * call disk_get_info_from_file() to also get the file system
	 * block size. */
	if (disk_get_info_from_file(bis->filename, &job->target, &bis->info))
		return -1;
	/* Check for supported disk and driver types */
	if (bis->info->source == source_auto &&
	    bis->info->type == disk_type_diag) {
		error_reason("Unsupported disk type (%s)",
			     disk_get_type_name(bis->info->type));
		return -1;
	}
	if (!disk_is_appropriate(job, bis->info))
		return -1;
	if (verbose) {
		printf("Target device information\n");
		disk_print_info(bis->info);
	}
	if (misc_temp_dev(bis->info->device, 1, &bis->device))
		return -1;
	/* Check configuration number limits */
	if (job->id == job_menu) {
		if (check_menu_positions(&job->data.menu, job->name,
					 bis->info))
			return -1;
	}
	printf("Building bootmap in '%s'%s\n", bootmap_dir,
	       job->add_files ? " (files will be added to bootmap file)"
	       : "");
	/* Initialize bootmap header */
	if (bootmap_header_init(bis->fd)) {
		error_text("Could not init bootmap header at '%s'",
			   bis->filename);
		return -1;
	}
	/* Write empty block to be read in place of holes in files */
	if (write_empty_block(bis->fd, &empty_block, bis->info)) {
		error_text("Could not write to file '%s'", bis->filename);
		return -1;
	}
	set_nr_tables(job, bis);
	return 0;
}

/**
 * Rename to final bootmap name
 */
static int finalize_create_file(char *bootmap_dir, struct install_set *bis)
{
	char *final_name;

	final_name = misc_make_path(bootmap_dir, BOOTMAP_FILENAME);
	if (!final_name)
		return -1;
	if (rename(bis->filename, final_name)) {
		error_reason(strerror(errno));
		error_text("Could not rename '%s' to '%s'",
			   bis->filename, final_name);
		free(final_name);
		return -1;
	}
	free(final_name);
	return 0;
}

static int bootmap_create_file(struct job_data *job, char *bootmap_dir,
			       struct install_set *bis, int program_table_id)
{
	if (prepare_build_program_table_file(job, bootmap_dir, bis,
					     program_table_id))
		return -1;
	if (build_program_table(job, bis, program_table_id))
		return -1;
	/* Install stage 2 loader to bootmap if necessary */
	if (bootmap_install_stages(job, bis, program_table_id)) {
		error_text("Could not install loader stages to file '%s'",
			   bis->filename);
		return -1;
	}
	if (!dry_run && is_last_table(bis, program_table_id))
		return finalize_create_file(bootmap_dir, bis);
	return 0;
}

static int
ngdump_create_meta(const char *path)
{
	char *filename = NULL;
	FILE *fp;
	int rc;

	util_asprintf(&filename, "%s/ngdump.meta", path);

	fp = fopen(filename, "w");
	if (!fp) {
		free(filename);
		error_reason(strerror(errno));
		error_text("Could not create file '%s'", filename);
		return -1;
	}
	free(filename);

	rc = fprintf(fp, "version=1\n");
	if (rc < 0)
		return -1;
	rc = fprintf(fp, "file=\n");
	if (rc < 0)
		return -1;
	rc = fprintf(fp, "sha256sum=\n");
	if (rc < 0)
		return -1;
	rc = fclose(fp);
	if (rc < 0)
		return -1;

	return 0;
}

static int bootmap_create_device_ngdump(struct job_data *job,
					struct install_set *bis,
					int program_table_id)
{
	struct disk_info *info;
	int rc;

	assert(program_table_id == 0);
	/* Retrieve target device information */
	if (disk_get_info(job->data.dump.device, &job->target, &info))
		return -1;
	if (misc_temp_dev(info->device, 1, &bis->device))
		return -1;
	if (check_dump_device(job, info, bis->device))
		return -1;

	bis->dump_mount_point = misc_make_path("/tmp",
					       DUMP_TEMP_MOUNT_POINT_NAME);
	if (!bis->dump_mount_point) {
		error_reason(strerror(errno));
		error_text("Could not make path for '%s'",
			   DUMP_TEMP_MOUNT_POINT_NAME);
		return -1;
	}
	/* Create a mount point directory */
	if (mkdtemp(bis->dump_mount_point) == NULL) {
		error_reason(strerror(errno));
		error_text("Could not create mount point '%s'",
			   bis->dump_mount_point);
		return -1;
	}
	bis->dump_tmp_dir_created = 1;
	if (!dry_run) {
		char *cmd = NULL;
		util_asprintf(&cmd, "mkfs.%s -qF %s >/dev/null",
			      NGDUMP_FSTYPE, job->data.dump.device);
		if (verbose)
			printf("Formatting partition '%s'\n",
				job->data.dump.device);
		rc = system(cmd);
		free(cmd);
		if (rc) {
			error_reason(strerror(errno));
			error_text("Could not format partition '%s':",
				   job->data.dump.device);
			return -1;
		}
	}
	/*
	 * Mount partition where bootmap file and also a dump file will
	 * be stored.
	 */
	if (mount(job->data.dump.device, bis->dump_mount_point,
		  NGDUMP_FSTYPE, 0, NULL)) {
		error_reason(strerror(errno));
		error_text("Could not mount partition '%s':",
			   job->data.dump.device);
		return -1;
	}
	bis->dump_mounted = 1;
	if (bootmap_create_file(job, bis->dump_mount_point,
				bis, program_table_id))
		return -1;
	if (ngdump_create_meta(bis->dump_mount_point))
		return -1;
	return 0;
}


static int
bootmap_create(struct job_data *job, struct install_set *bis,
	       int program_table_id)
{
	if (job->id == job_dump_partition) {
		if (is_ngdump_enabled(job->data.dump.device, &job->target))
			return bootmap_create_device_ngdump(job, bis,
							    program_table_id);
		else
			return bootmap_create_device(job, bis,
						     program_table_id);
	} else
		return bootmap_create_file(job, job->target.bootmap_dir,
					   bis, program_table_id);
}

/**
 * Initialize Bootloader Installation Set
 */
static int init_bis(struct job_data *job, struct install_set *bis)
{
	int i;

	memset(bis, 0, sizeof(*bis));
	bis->nr_menu_entries = 1;
	if (job->id == job_menu)
		bis->nr_menu_entries = job->data.menu.num;
	/*
	 * allocate "matrix" of program components
	 */
	for (i = 0; i < NR_PROGRAM_COMPONENTS; i++) {
		bis->components[i] =
			util_zalloc(sizeof(struct program_component) *
				    bis->nr_menu_entries);
		if (!bis->components[i])
			return -1;
	}
	return 0;
}

/**
 * Prapare a Bootloader Installation Set BIS based on one, or two
 * "similar" program tables, depinding on job ID and disk type (see
 * comments For install_bootloader())
 */
int prepare_bootloader(struct job_data *job, struct install_set *bis)
{
	int i;
	int rc;

	secure_boot_supported = check_secure_boot_support();

	rc = init_bis(job, bis);
	if (rc)
		return rc;
	for (i = 0;; i++) {
		rc = bootmap_create(job, bis, i);
		if (rc || is_last_table(bis, i))
			break;
	}
	return rc;
}

/**
 * Release all resources accumulated along the installation process
 */
void free_bootloader(struct install_set *bis)
{
	int i, j;

	for (i = 0; i < NR_PROGRAM_TABLES; i++)
		free(bis->tables[i].stage1b_list);
	for (i = 0; i < NR_PROGRAM_COMPONENTS; i++) {
		for (j = 0; j < bis->nr_menu_entries; j++)
			free(get_component(bis, i, j)->list);
		free(bis->components[i]);
	}
	if (bis->fd > 0)
		close(bis->fd);
	if (dry_run)
		misc_free_temp_file(bis->filename);
	free(bis->filename);
	misc_free_temp_dev(bis->device);
	disk_free_info(bis->info);
	if (bis->dump_mount_point) {
		if (bis->dump_mounted && umount(bis->dump_mount_point))
			warn("Could not umount dump device at %s",
			     bis->dump_mount_point);
		if (bis->dump_tmp_dir_created && rmdir(bis->dump_mount_point))
			warn("Could not remove directory %s",
			     bis->dump_mount_point);
		free(bis->dump_mount_point);
	}
}
