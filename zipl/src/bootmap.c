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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lib/zt_common.h"
#include "lib/util_part.h"
#include "lib/util_path.h"
#include "boot/s390.h"
#include "stage3.h"

#include "boot.h"
#include "bootmap.h"
#include "disk.h"
#include "error.h"
#include "install.h"
#include "misc.h"

/* Header text of the bootmap file */
static const char header_text[] = "zSeries bootmap file\n"
				  "created by zIPL\n";

/* Pointer to dedicated empty block in bootmap. */
disk_blockptr_t empty_block;


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
		return sizeof(struct eckd_blockptr);
	case disk_type_diag:
		break;
	}
	return 0;
}


void
bootmap_store_blockptr(void* buffer, disk_blockptr_t* ptr,
		       struct disk_info* info)
{
	struct linear_blockptr *lin;
	struct eckd_blockptr *eckd;

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
			eckd = (struct eckd_blockptr *) buffer;
			eckd->cyl = ptr->chs.cyl;
			eckd->head = ptr->chs.head |
				     ((ptr->chs.cyl >> 12) & 0xfff0);
			eckd->sec = ptr->chs.sec;
			eckd->size = ptr->chs.size;
			eckd->blockct = ptr->chs.blockct;
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

	fp = fopen(ZIPL_SIPL_PATH, "r");
	if (!fp)
		return false;

	if (fscanf(fp, "%d", &val) != 1) {
		fclose(fp);
		return false;
	}
	fclose(fp);

	return val ? true : false;
}


/* Write COUNT elements of the blocklist specified by LIST as a linked list
 * of segment table blocks to the file identified by file descriptor FD. Upon
 * success, return 0 and set SECTION_POINTER to point to the first block in
 * the resulting segment table. Return non-zero otherwise. */
int
add_segment_table(int fd, disk_blockptr_t* list, blocknum_t count,
		  disk_blockptr_t* segment_pointer,
		  struct disk_info* info)
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
					&empty_block, info);
		else
			bootmap_store_blockptr(
					VOID_ADD(buffer, offset * pointer_size),
					&list[count-1], info);
		if (offset > 0)
			continue;
		/* Finalize segment table */
		offset = max_offset;
		bootmap_store_blockptr(VOID_ADD(buffer, offset * pointer_size),
				       &next, info);
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


static int
add_program_table(int fd, disk_blockptr_t* table, int entries,
		  disk_blockptr_t* pointer, struct disk_info* info)
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
				       info);
		offset += get_blockptr_size(info);
	}
	/* Write program table */
	rc = disk_write_block_aligned(fd, block, PROGRAM_TABLE_BLOCK_SIZE,
				      pointer, info);
	free(block);
	return rc;
}

struct component_entry {
	uint8_t data[23];
	uint8_t type;
	component_data compdat;
} __packed;

typedef enum {
	component_execute = 0x01,
	component_load = 0x02,
	component_signature = 0x03
} component_type;

static void
create_component_entry(void* buffer, disk_blockptr_t* pointer,
		       component_type type, component_data data,
		       struct disk_info* info)
{
	struct component_entry* entry;

	entry = (struct component_entry*) buffer;
	memset(entry, 0, sizeof(struct component_entry));
	entry->type = (uint8_t) type;
	switch (type) {
		case component_load:
			bootmap_store_blockptr(&entry->data, pointer,
					       info);
			entry->compdat.load_address = data.load_address;
			break;
		case component_execute:
			entry->compdat.load_psw = data.load_psw;
			break;
		case component_signature:
			bootmap_store_blockptr(&entry->data, pointer,
					       info);
			entry->compdat.sig_head = data.sig_head;
			break;
	}
}


struct component_header {
	uint8_t magic[4];
	uint8_t type;
	uint8_t reserved[27];
}  __packed;

typedef enum {
	component_header_ipl = 0x00,
	component_header_dump = 0x01
} component_header_type;

static void
create_component_header(void* buffer, component_header_type type)
{
	struct component_header* header;

	header = (struct component_header*) buffer;
	memset(header, 0, sizeof(struct component_header));
	memcpy(&header->magic, ZIPL_MAGIC, ZIPL_MAGIC_SIZE);
	header->type = (uint8_t) type;
}


struct component_loc {
	address_t addr;
	size_t size;
};

static int
add_component_file(int fd, const char* filename, address_t load_address,
		   size_t trailer, void *component, int add_files,
		   struct disk_info* info, struct job_target_data* target,
		   struct component_loc *location)
{
	struct disk_info* file_info;
	struct component_loc loc;
	disk_blockptr_t segment;
	disk_blockptr_t* list;
	char* buffer;
	size_t size;
	blocknum_t count;
	int rc;

	if (add_files) {
		/* Read file to buffer */
		rc = misc_read_file(filename, &buffer, &size, 0);
		if (rc) {
			error_text("Could not read file '%s'", filename);
			return rc;
		}
		size -= trailer;
		/* Write buffer */
		count = disk_write_block_buffer(fd, 0, buffer,
						size, &list, info);
		free(buffer);
		if (count == 0) {
			error_text("Could not write to bootmap file");
			return -1;
		}
	} else {
		/* Make sure file is on correct device */
		rc = disk_get_info_from_file(filename, target, &file_info);
		if (rc)
			return -1;
		if (file_info->device != info->device) {
			disk_free_info(file_info);
			error_reason("File is not on target device");
			return -1;
		}
		/* Get block list from existing file */
		count = disk_get_blocklist_from_file(filename, &list,
						     file_info);
		disk_free_info(file_info);
		if (count == 0)
			return -1;
		count -= DIV_ROUND_UP(trailer, info->phy_block_size);
	}
	/* Fill in component location */
	loc.addr = load_address;
	loc.size = count * info->phy_block_size;
	/* Try to compact list */
	count = disk_compact_blocklist(list, count, info);
	/* Write segment table */
	rc = add_segment_table(fd, list, count, &segment, info);
	free(list);
	if (rc == 0) {
		create_component_entry(component, &segment, component_load,
				       (component_data) load_address, info);
		/* Return location if requested */
		if (location != NULL)
			*location = loc;
	}
	return rc;
}

static int
add_component_buffer(int fd, void* buffer, size_t size, component_data data,
		     void* component, struct disk_info* info,
		     struct component_loc *location, int type)
{
	struct component_loc loc;
	disk_blockptr_t segment;
	disk_blockptr_t* list;
	blocknum_t count;
	int rc;

	/* Write buffer */
	count = disk_write_block_buffer(fd, 0, buffer, size, &list, info);
	if (count == 0) {
		error_text("Could not write to bootmap file");
		return -1;
	}
	if (type == component_load) {
		/* Fill in component location */
		loc.addr = data.load_address;
		loc.size = count * info->phy_block_size;
	} else {
		loc.addr = 0;
		loc.size = 0;
	}
	/* Try to compact list */
	count = disk_compact_blocklist(list, count, info);
	/* Write segment table */
	rc = add_segment_table(fd, list, count, &segment, info);
	free(list);
	if (rc == 0) {
		create_component_entry(component, &segment, type, data, info);
		/* Return location if requested */
		if (location != NULL)
			*location = loc;
	}
	return rc;
}


static int
add_dummy_buffer(int fd, size_t size, address_t addr, void *component,
		 struct disk_info *info, struct component_loc *comp_loc)
{
	char *buffer;
	int rc;

	buffer = misc_malloc(size);
	if (buffer == NULL)
		return -1;

	memset(buffer, 0, size);
	rc = add_component_buffer(fd, buffer, size,
				  (component_data) (uint64_t) addr,
				  component, info, comp_loc, component_load);
	if (rc) {
		free(buffer);
		return rc;
	}
	free(buffer);
	return 0;
}


static void
print_components(const char *name[], struct component_loc *loc, int num)
{
	const char *padding = "................";
	int i;

	printf("  component address:\n");
	/* Process all available components */
	for (i = 0; i < num; i++) {
		if (loc[i].size == 0)
			continue;
		printf("    %s%s: 0x%08llx-0x%08llx\n", name[i],
		       &padding[strlen(name[i])],
		       (unsigned long long) loc[i].addr,
		       (unsigned long long) (loc[i].addr + loc[i].size - 1));
	}
}

static int
extract_signature(char *filename, void **ret_signature,
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

	*ret_signature = signature;
	sig_head->length = signature_size;

	switch (file_sig->id_type) {
	case PKEY_ID_PKCS7:
		sig_head->format = PKCS7_FORMAT;
		break;
	default:
		error_text("Unsupported signature type %02x",
			   file_sig->id_type);
		signature_size = 0;
		goto out;
	}
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

static int
add_ipl_program(int fd, struct job_ipl_data* ipl, disk_blockptr_t* program,
		int verbose, int add_files, component_header_type type,
		struct disk_info* info, struct job_target_data* target,
		int is_secure)
{
	struct component_loc comp_loc[10];
	struct signature_header sig_head;
	size_t ramdisk_size, image_size;
	bool secure_boot_supported;
	size_t stage3_params_size;
	const char *comp_name[10];
	size_t signature_size;
	int offset;
	uint64_t flags = 0;
	void *stage3_params;
	struct stat stats;
	void *signature;
	int comp_nr = 0;
	void *table;
	int rc;

	memset(comp_loc, 0, sizeof(comp_loc));
	memset(&sig_head, 0, sizeof(sig_head));
	table = misc_malloc(info->phy_block_size);
	if (table == NULL)
		return -1;
	memset(table, 0, info->phy_block_size);
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
	if (ipl->ramdisk != NULL) {
		/* Add ramdisk */
		if (verbose) {
			printf("  initial ramdisk...: %s\n", ipl->ramdisk);
		}
		/* Get ramdisk file size */
		if (stat(ipl->ramdisk, &stats)) {
			error_reason(strerror(errno));
			error_text("Could not get information for file '%s'",
				   ipl->ramdisk);
			free(table);
			return -1;
		}
	}
	ramdisk_size = stats.st_size;
	if (info->type == disk_type_scsi) {
		flags |= STAGE3_FLAG_SCSI;
		/*
		 * Add dummy components for stage 3 heap and stack to block the
		 * associated memory areas against firmware use.
		 */
		rc = add_dummy_buffer(fd, STAGE3_HEAP_SIZE, STAGE3_HEAP_ADDRESS,
				      VOID_ADD(table, offset), info,
				      &comp_loc[comp_nr]);
		if (rc) {
			error_text("Could not add stage3 HEAP dummy");
			free(table);
			return rc;
		}
		comp_name[comp_nr] = "heap area";
		offset += sizeof(struct component_entry);
		comp_nr++;
		rc = add_dummy_buffer(fd, STAGE3_STACK_SIZE,
				      STAGE3_STACK_ADDRESS,
				      VOID_ADD(table, offset), info,
				      &comp_loc[comp_nr]);
		if (rc) {
			error_text("Could not add stage3 STACK dummy");
			free(table);
			return rc;
		}
		comp_name[comp_nr] = "stack area";
		offset += sizeof(struct component_entry);
		comp_nr++;
	}
	if (ipl->is_kdump)
		flags |= STAGE3_FLAG_KDUMP;

	/* Get kernel file size */
	if (stat(ipl->image, &stats)) {
		error_reason(strerror(errno));
		error_text("Could not get information for file '%s'",
			   ipl->image);
		free(table);
		return -1;
	}
	image_size = stats.st_size;
	secure_boot_supported = check_secure_boot_support();
	signature_size = extract_signature(ZIPL_STAGE3_PATH, &signature,
					   &sig_head);
	if (signature_size &&
	    (is_secure == SECURE_BOOT_ENABLED ||
	     (is_secure == SECURE_BOOT_AUTO && secure_boot_supported))) {
		if (verbose)
			printf("  signature for.....: %s\n", ZIPL_STAGE3_PATH);

		rc = add_component_buffer(fd, signature, sig_head.length,
					  (component_data)sig_head,
					  VOID_ADD(table, offset), info,
					  &comp_loc[comp_nr],
					  component_signature);
		if (rc) {
			error_text("Could not add stage3 signature");
			free(table);
			return rc;
		}
		comp_name[comp_nr] = "loader signature";
		offset += sizeof(struct component_entry);
		comp_nr++;
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
	rc = add_component_file(fd, ZIPL_STAGE3_PATH, STAGE3_LOAD_ADDRESS,
				signature_size, VOID_ADD(table, offset), 1,
				info, target, &comp_loc[comp_nr]);
	if (rc) {
		error_text("Could not add internal loader file '%s'",
			   ZIPL_STAGE3_PATH);
		free(table);
		return rc;
	}
	offset += sizeof(struct component_entry);
	comp_name[comp_nr] = "internal loader";
	comp_nr++;

	/* Add stage 3 parameter to bootmap */
	rc = boot_get_stage3_parms(&stage3_params, &stage3_params_size,
				   ipl->parm_addr, ipl->ramdisk_addr,
				   ramdisk_size,
				   ipl->is_kdump ? IMAGE_ENTRY_KDUMP :
				   IMAGE_ENTRY,
				   (info->type == disk_type_scsi) ? 0 : 1,
				   flags, ipl->image_addr, image_size);
	if (rc) {
		free(table);
		return rc;
	}
	rc = add_component_buffer(fd, stage3_params, stage3_params_size,
				  (component_data) (uint64_t)
				  STAGE3_PARAMS_ADDRESS,
				  VOID_ADD(table, offset), info,
				  &comp_loc[comp_nr], component_load);
	free(stage3_params);
	if (rc) {
		error_text("Could not add parameters");
		free(table);
		return -1;
	}
	offset += sizeof(struct component_entry);
	comp_name[comp_nr] = "parameters";
	comp_nr++;

	/* Add kernel image */
	if (verbose) {
		printf("  kernel image......: %s\n", ipl->image);
	}
	signature_size = extract_signature(ipl->image, &signature, &sig_head);
	if (signature_size &&
	    (is_secure == SECURE_BOOT_ENABLED ||
	     (is_secure == SECURE_BOOT_AUTO && secure_boot_supported))) {
		if (verbose)
			printf("  signature for.....: %s\n", ipl->image);

		rc = add_component_buffer(fd, signature, sig_head.length,
					  (component_data)sig_head,
					  VOID_ADD(table, offset), info,
					  &comp_loc[comp_nr],
					  component_signature);
		if (rc) {
			error_text("Could not add image signature");
			free(table);
			return rc;
		}
		comp_name[comp_nr] = "image signature";
		offset += sizeof(struct component_entry);
		comp_nr++;
		free(signature);
		check_remaining_filesize(image_size, signature_size, info,
					 ipl->image);
	} else if (is_secure == SECURE_BOOT_ENABLED) {
		/*
		 * If secure boot is forced and we have failed to extract a
		 * signature for the kernel image zipl will abort with an
		 * error message
		 */
		error_text("Could not install Secure Boot IPL records");
		error_reason("Missing signature in image file %s",
			     ipl->image);
		free(table);
		return -1;
	}

	rc = add_component_file(fd, ipl->image, ipl->image_addr,
				signature_size, VOID_ADD(table, offset),
				add_files, info, target, &comp_loc[comp_nr]);
	if (rc) {
		error_text("Could not add image file '%s'", ipl->image);
		free(table);
		return rc;
	}
	offset += sizeof(struct component_entry);
	comp_name[comp_nr] = "kernel image";
	comp_nr++;

	/* Add kernel parmline */
	if (ipl->parmline != NULL) {
		if (verbose) {
			printf("  kernel parmline...: '%s'\n", ipl->parmline);
		}
		rc = add_component_buffer(fd, ipl->parmline,
					  strlen(ipl->parmline) + 1,
					  (component_data) ipl->parm_addr,
					  VOID_ADD(table, offset),
					  info, &comp_loc[comp_nr],
					  component_load);
		if (rc) {
			error_text("Could not add parmline '%s'",
				   ipl->parmline);
			free(table);
			return -1;
		}
		offset += sizeof(struct component_entry);
		comp_name[comp_nr] = "parmline";
		comp_nr++;
	}

	/* finally add ramdisk */
	if (ipl->ramdisk != NULL) {
		signature_size = extract_signature(ipl->ramdisk, &signature,
						   &sig_head);
		if (signature_size &&
		    (is_secure == SECURE_BOOT_ENABLED ||
		     (is_secure == SECURE_BOOT_AUTO &&
		      secure_boot_supported))) {
			if (verbose) {
				printf("  signature for.....: %s\n",
				       ipl->ramdisk);
			}
			rc = add_component_buffer(fd, signature,
						  sig_head.length,
						  (component_data)sig_head,
						  VOID_ADD(table, offset), info,
						  &comp_loc[comp_nr],
						  component_signature);
			if (rc) {
				error_text("Could not add ramdisk signature");
				free(table);
				return rc;
			}
			comp_name[comp_nr] = "ramdisk signature";
			offset += sizeof(struct component_entry);
			comp_nr++;
			free(signature);
			check_remaining_filesize(ramdisk_size, signature_size,
						 info, ipl->ramdisk);
		}
		rc = add_component_file(fd, ipl->ramdisk,
					ipl->ramdisk_addr, signature_size,
					VOID_ADD(table, offset),
					add_files, info, target,
					&comp_loc[comp_nr]);
		if (rc) {
			error_text("Could not add ramdisk '%s'",
				   ipl->ramdisk);
			free(table);
			return -1;
		}
		offset += sizeof(struct component_entry);
		comp_name[comp_nr] = "initial ramdisk";
		comp_nr++;
	}
	if (verbose)
		print_components(comp_name, comp_loc, comp_nr);
	/* Terminate component table */
	create_component_entry(VOID_ADD(table, offset), NULL,
			       component_execute,
			       (component_data) (uint64_t)
			       (STAGE3_ENTRY | PSW_LOAD),
			       info);
	/* Write component table */
	rc = disk_write_block_aligned(fd, table, info->phy_block_size,
				      program, info);
	free(table);
	return rc;
}


static int
add_segment_program(int fd, struct job_segment_data* segment,
		    disk_blockptr_t* program, int verbose, int add_files,
		    component_header_type type, struct disk_info* info,
		    struct job_target_data* target)
{
	const char *comp_name[1] = {"segment file"};
	struct component_loc comp_loc[1];
	void* table;
	int offset;
	int rc;

	memset(comp_loc, 0, sizeof(comp_loc));
	table = misc_malloc(info->phy_block_size);
	if (table == NULL)
		return -1;
	memset(table, 0, info->phy_block_size);
	/* Create component table */
	offset = 0;
	/* Fill in component table header */
	create_component_header(VOID_ADD(table, offset), type);
	offset += sizeof(struct component_header);
	/* Add segment file */
	if (verbose) {
		printf("  segment file......: %s\n", segment->segment);
	}
	rc = add_component_file(fd, segment->segment, segment->segment_addr, 0,
				VOID_ADD(table, offset), add_files, info,
				target, &comp_loc[0]);
if (rc) {
		error_text("Could not add segment file '%s'",
			   segment->segment);
		free(table);
		return rc;
	}
	offset += sizeof(struct component_entry);
	/* Print component addresses */
	if (verbose)
		print_components(comp_name, comp_loc, 1);
	/* Terminate component table */
	create_component_entry(VOID_ADD(table, offset), NULL,
			       component_execute, (component_data) (uint64_t)
			       PSW_DISABLED_WAIT, info);
	/* Write component table */
	rc = disk_write_block_aligned(fd, table, info->phy_block_size,
				      program, info);
	free(table);
	return rc;
}


#define DUMP_PARAM_MAX_LEN	896

static char *
create_dump_parmline(const char* parmline, const char* root_dev,
		     uint64_t mem, int max_cpus)
{
	char* result;

	result = misc_malloc(DUMP_PARAM_MAX_LEN);
	if (!result)
		return NULL;
	snprintf(result, DUMP_PARAM_MAX_LEN, "%s%sroot=%s dump_mem=%lld "
		 "possible_cpus=%d cgroup_disable=memory ",
		 parmline ? parmline : "", parmline ? " " : "", root_dev,
		 (unsigned long long) mem, max_cpus);
	result[DUMP_PARAM_MAX_LEN - 1] = 0;
	return result;
}


static int
get_dump_parmline(char *partition, char *parameters,
		  struct disk_info *target_info,
		  struct job_target_data *target, char **result)
{
	char* buffer;
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
	buffer = create_dump_parmline(parameters, "/dev/ram0",
				      info->partnum, 1);
	disk_free_info(info);
	if (buffer == NULL)
		return -1;
	*result = buffer;
	return 0;
}


static int
add_dump_program(int fd, struct job_dump_data* dump,
		    disk_blockptr_t* program, int verbose,
		    component_header_type type,
		    struct disk_info* info, struct job_target_data* target)
{
	struct job_ipl_data ipl;
	int rc;

	/* Convert fs dump job to IPL job */
	memset(&ipl, 0, sizeof(ipl));
	ipl.image = dump->image;
	ipl.image_addr = dump->image_addr;
	ipl.ramdisk = dump->ramdisk;
	ipl.ramdisk_addr = dump->ramdisk_addr;

	/* Get file system dump parmline */
	rc = get_dump_parmline(dump->device, dump->parmline,
			       info, target, &ipl.parmline);
	if (rc)
		return rc;
	ipl.parm_addr = dump->parm_addr;
	return add_ipl_program(fd, &ipl, program, verbose, 1,
			       type, info, target, SECURE_BOOT_DISABLED);
}


/* Build a program table from job data and set pointer to program table
 * block upon success. */
static int
build_program_table(int fd, struct job_data* job, disk_blockptr_t* pointer,
		    struct disk_info* info)
{
	disk_blockptr_t* table;
	int entries, component_header;
	int is_secure;
	int i;
	int rc;

	entries = get_program_table_size(info);
	/* Get some memory for the program table */
	table = (disk_blockptr_t *) misc_malloc(sizeof(disk_blockptr_t) *
						entries);
	if (table == NULL)
		return -1;
	memset((void *) table, 0, sizeof(disk_blockptr_t) * entries);
	/* Add programs */
	switch (job->id) {
	case job_ipl:
		if (job->command_line)
			printf("Adding IPL section\n");
		else
			printf("Adding IPL section '%s' (default)\n",
			       job->name);
		if (job->data.ipl.is_kdump)
			component_header = component_header_dump;
		else
			component_header = component_header_ipl;
		rc = add_ipl_program(fd, &job->data.ipl, &table[0],
				     verbose || job->command_line,
				     job->add_files, component_header,
				     info, &job->target, job->is_secure);
		break;
	case job_segment:
		if (job->command_line)
			printf("Adding segment load section\n");
		else
			printf("Adding segment load section '%s' (default)\n",
			       job->name);
		rc = add_segment_program(fd, &job->data.segment, &table[0],
					 verbose || job->command_line,
					 job->add_files, component_header_ipl,
					 info, &job->target);
		break;
	case job_dump_partition:
		/* Only useful for a partition dump that uses a dump kernel*/
		if (job->command_line)
			printf("Adding dump section\n");
		else
			printf("Adding dump section '%s' (default)\n",
			       job->name);
		rc = add_dump_program(fd, &job->data.dump, &table[0],
					 verbose || job->command_line,
					 component_header_dump,
					 info, &job->target);
		break;
	case job_menu:
		printf("Building menu '%s'\n", job->name);
		rc = 0;
		for (i=0; i < job->data.menu.num; i++) {
			switch (job->data.menu.entry[i].id) {
			case job_ipl:
				printf("Adding #%d: IPL section '%s'%s",
				       job->data.menu.entry[i].pos,
				       job->data.menu.entry[i].name,
				       (job->data.menu.entry[i].pos ==
				        job->data.menu.default_pos) ?
						" (default)": "");
				if (job->data.menu.entry[i].data.ipl.is_kdump) {
					component_header =
						component_header_dump;
					printf(" (kdump)\n");
				} else {
					component_header =
						component_header_ipl;
					printf("\n");
				}
				if (job->is_secure != SECURE_BOOT_UNDEFINED)
					is_secure = job->is_secure;
				else
					is_secure =
					      job->data.menu.entry[i].is_secure;
				rc = add_ipl_program(fd,
					&job->data.menu.entry[i].data.ipl,
					&table[job->data.menu.entry[i].pos],
					verbose || job->command_line,
					job->add_files,	component_header,
						     info, &job->target,
						     is_secure);
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
	if (rc == 0) {
		/* Add program table block */
		rc = add_program_table(fd, table, entries, pointer, info);
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


int
bootmap_create(struct job_data *job, disk_blockptr_t *program_table,
	       disk_blockptr_t *scsi_dump_sb_blockptr,
	       disk_blockptr_t **stage1b_list, blocknum_t *stage1b_count,
	       char **new_device, struct disk_info **new_info)
{
	struct scsi_dump_sb scsi_sb;
	char *device, *filename, *mapname;
	disk_blockptr_t *stage2_list;
	blocknum_t stage2_count;
	struct disk_info *info;
	size_t stage2_size;
	void *stage2_data;
	int fd, rc, part_ext;

	/* Get full path of bootmap file */
	if (job->id == job_dump_partition && !dry_run) {
		filename = misc_strdup(job->data.dump.device);
		if (filename == NULL)
			return -1;
		fd = misc_open_exclusive(filename);
		if (fd == -1) {
			error_text("Could not open file '%s'", filename);
			goto out_free_filename;
		}

	} else {
		filename = misc_make_path(job->target.bootmap_dir,
					  BOOTMAP_TEMPLATE_FILENAME);
		if (filename == NULL)
			return -1;
		/* Create temporary bootmap file */
		fd = mkstemp(filename);
		if (fd == -1) {
			error_reason(strerror(errno));
			error_text("Could not create file '%s':", filename);
			goto out_free_filename;
		}
	}
	/* Retrieve target device information. Note that we have to
	 * call disk_get_info_from_file() to also get the file system
	 * block size. */
	if (job->id == job_dump_partition) {
		if (disk_get_info(filename, &job->target, &info))
			goto out_close_fd;
	} else {
		if (disk_get_info_from_file(filename, &job->target, &info))
			goto out_close_fd;
	}
	/* Check for supported disk and driver types */
	if ((info->source == source_auto) && (info->type == disk_type_diag)) {
		error_reason("Unsupported disk type (%s)",
			     disk_get_type_name(info->type));
		goto out_disk_free_info;
	}
	/* Check if secure boot was enabled only for SCSI */
	if (job->is_secure == SECURE_BOOT_ENABLED &&
	    info->type != disk_type_scsi) {
		error_reason("Secure boot forced for non-SCSI disk type");
		goto out_disk_free_info;
	}
	if (verbose) {
		printf("Target device information\n");
		disk_print_info(info);
	}
	if (misc_temp_dev(info->device, 1, &device))
		goto out_disk_free_info;
	/* Check configuration number limits */
	if (job->id == job_menu) {
		if (check_menu_positions(&job->data.menu, job->name, info))
			goto out_misc_free_temp_dev;
	}
	if (job->id == job_dump_partition) {
		rc = util_part_search(device, info->geo.start, info->phy_blocks,
				      info->phy_block_size, &part_ext);
		if (rc <= 0 || part_ext) {
			if (rc == 0)
				error_reason("No partition");
			else if (rc < 0)
				error_reason("Could not read partition table");
			else if (part_ext)
				error_reason("Extended partitions not allowed");
			error_text("Invalid dump device");
			goto out_misc_free_temp_dev;
		}
		printf("Building bootmap directly on partition '%s'%s\n",
		       filename,
		       job->add_files ? " (files will be added to partition)"
		       : "");
	} else {
		printf("Building bootmap in '%s'%s\n", job->target.bootmap_dir,
		       job->add_files ? " (files will be added to bootmap file)"
		       : "");
	}
	/* For partition dump set raw partition offset
	   to expected size before end of disk */
	if (job->id == job_dump_partition) {
		struct stat st;
		ulong size;
		ulong unused_size;

		/* Use approximated stage 3 size as starting point */
		size = IMAGE_LOAD_ADDRESS;

		/* Ramdisk */
		if (job->data.dump.ramdisk != NULL) {
			if (stat(job->data.dump.ramdisk, &st))
				goto out_misc_free_temp_dev;
			size += DIV_ROUND_UP(st.st_size, info->phy_block_size);
			size += 1; /* For ramdisk section entry */
		}
		/* Kernel */
		if (stat(job->data.dump.image, &st))
			goto out_misc_free_temp_dev;
		size += DIV_ROUND_UP(st.st_size - IMAGE_LOAD_ADDRESS,
				     info->phy_block_size);
		/* Parmfile */
		size += DIV_ROUND_UP(DUMP_PARAM_MAX_LEN, info->phy_block_size);
		size += 8;  /* 1x table + 1x script + 3x section + 1x empty
			       1x header + 1x scsi dump super block */
		if (size > info->phy_blocks) {
			error_text("Partition too small for dump tool");
			goto out_misc_free_temp_dev;
		}
		unused_size = (info->phy_blocks - size) * info->phy_block_size;
		if (lseek(fd, unused_size, SEEK_SET) < 0)
			goto out_misc_free_temp_dev;
		scsi_sb.dump_size = unused_size;
	}

	/* Write bootmap header */
	if (misc_write(fd, header_text, sizeof(header_text))) {
		error_text("Could not write to file '%s'", filename);
		goto out_misc_free_temp_dev;
	}
	/* Write empty block to be read in place of holes in files */
	if (write_empty_block(fd, &empty_block, info)) {
		error_text("Could not write to file '%s'", filename);
		goto out_misc_free_temp_dev;
	}
	/* Build program table */
	if (build_program_table(fd, job, program_table, info))
		goto out_misc_free_temp_dev;
	if (job->id == job_dump_partition) {
		scsi_sb.magic = SCSI_DUMP_SB_MAGIC;
		scsi_sb.version = 1;
		scsi_sb.part_start = info->geo.start * info->phy_block_size;
		scsi_sb.part_size = info->phy_blocks * info->phy_block_size;
		scsi_sb.dump_offset = 0;
		scsi_sb.csum_offset = 0;
		scsi_sb.csum_size = SCSI_DUMP_SB_CSUM_SIZE;
		/* Set seed because otherwise csum over zero block is 0 */
		scsi_sb.csum = SCSI_DUMP_SB_SEED;
		disk_write_block_aligned(fd, &scsi_sb,
					 sizeof(scsi_sb),
					 scsi_dump_sb_blockptr, info);
	} else
		scsi_dump_sb_blockptr->linear.block = 0;

	/* Add stage 2 loader to bootmap if necessary */
	switch (info->type) {
	case disk_type_fba:
		if (boot_get_fba_stage2(&stage2_data, &stage2_size, job))
			goto out_misc_free_temp_dev;
		stage2_count = disk_write_block_buffer(fd, 0, stage2_data,
						stage2_size, &stage2_list,
						info);
		free(stage2_data);
		if (stage2_count == 0) {
			error_text("Could not write to file '%s'", filename);
			goto out_misc_free_temp_dev;
		}
		if (install_fba_stage1b(fd, stage1b_list, stage1b_count,
					stage2_list, stage2_count, info))
			goto out_misc_free_temp_dev;
		free(stage2_list);
		break;
	case disk_type_eckd_ldl:
	case disk_type_eckd_cdl:
		if (boot_get_eckd_stage2(&stage2_data, &stage2_size, job))
			goto out_misc_free_temp_dev;
		stage2_count = disk_write_block_buffer(fd, 0, stage2_data,
						stage2_size, &stage2_list,
						info);
		free(stage2_data);
		if (stage2_count == 0) {
			error_text("Could not write to file '%s'", filename);
			goto out_misc_free_temp_dev;
		}
		if (install_eckd_stage1b(fd, stage1b_list, stage1b_count,
					 stage2_list, stage2_count, info))
			goto out_misc_free_temp_dev;
		free(stage2_list);
		break;
	case disk_type_scsi:
	case disk_type_diag:
		*stage1b_list = NULL;
		*stage1b_count = 0;
		break;
	}
	if (dry_run) {
		misc_free_temp_file(filename);
	} else if (job->id != job_dump_partition) {
		/* Rename to final bootmap name */
		mapname = misc_make_path(job->target.bootmap_dir,
				BOOTMAP_FILENAME);
		if (mapname == NULL)
			goto out_misc_free_temp_dev;
		if (rename(filename, mapname)) {
			error_reason(strerror(errno));
			error_text("Could not overwrite file '%s':", mapname);
			free(mapname);
			goto out_misc_free_temp_dev;
		}
		free(mapname);
	}
	*new_device = device;
	*new_info = info;
	close(fd);
	free(filename);
	return 0;

out_misc_free_temp_dev:
	misc_free_temp_dev(device);
out_disk_free_info:
	disk_free_info(info);
out_close_fd:
	close(fd);
	if (job->id != job_dump_partition)
		misc_free_temp_file(filename);
out_free_filename:
	free(filename);
	return -1;
}
