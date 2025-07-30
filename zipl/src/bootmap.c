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
static disk_blockptr_t empty_blocks[MAX_TARGETS];

/* State of secure boot in the system */
static bool secure_boot_supported;

/* Get size of a bootmap block pointer for disk with given INFO. */
static int
get_blockptr_size(struct disk_info *info)
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
			    struct disk_info *info, int format_id)
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

/* Calculate the maximum number of entries in the program table. INFO
 * specifies the type of disk. */
static int
get_program_table_size(struct disk_info *info)
{
	return PROGRAM_TABLE_BLOCK_SIZE / get_blockptr_size(info) - 1;
}



static int
check_menu_positions(struct job_menu_data* menu, char* name,
		     struct disk_info *info)
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
static int add_segment_table(struct misc_fd *mfd, disk_blockptr_t *list,
			     blocknum_t count, disk_blockptr_t *segment_pointer,
			     int fs_block_size, struct disk_info *info,
			     int mirror_id, int program_table_id)
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
				       &empty_blocks[mirror_id], info,
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
		rc = disk_write_block_aligned(mfd, buffer, info->phy_block_size,
					      &next, fs_block_size, info);
		if (rc) {
			free(buffer);
			return rc;
		}
	}
	free(buffer);
	*segment_pointer = next;
	return 0;
}


static int add_program_table(struct misc_fd *mfd, disk_blockptr_t *table,
			     int entries, disk_blockptr_t *pointer,
			     int fs_block_size, struct disk_info *info,
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
	rc = disk_write_block_aligned(mfd, block, PROGRAM_TABLE_BLOCK_SIZE,
				      pointer, fs_block_size, info);
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

/*
 * Not precise check that the file FILENAME locates on the physical
 * disk specified by WHERE.
 *
 * Try to auto-detect parameters of the disk which the file locates on
 * and compare found device-ID with DISK.
 * Return 0, if auto-detection succeeded, and it is proven that the
 * file does NOT locate on DISK. Otherwise, return 1.
 */
static int file_is_on_device(const char *filename, struct device_info *where)
{
	/*
	 * Retrieve info of the underlying disk without any user hints
	 */
	struct job_target_data tmp = {.source = source_unknown};
	struct device_info *info;
	int rc;

	rc = device_get_info_from_file(filename, &tmp, &info);
	free_target_data(&tmp);
	if (rc) {
		/*
		 * In some cases it is impossible to auto-detect
		 * disk parameters (e.g. when the file is on a
		 * mounted qcow2 image).
		 * Skip the check with warnings.
		 */
		fprintf(stderr,
			"Warning: Could not auto-detect disk parameters for %s\n",
			filename);
		fprintf(stderr,
			"Warning: Preparing a logical device for boot might fail\n");
		return 1;
	}
	if (info->base[0].disk != where->base[0].disk) {
		device_free_info(info);
		return 0;
	}
	device_free_info(info);
	return 1;
}

static int add_component_file_range(struct install_set *bis,
				    const char *filename,
				    struct file_range *reg,
				    address_t load_address,
				    size_t trailer, void *component,
				    int add_files,
				    int comp_id, int menu_idx,
				    int mirror_id,
				    int program_table_id)
{
	struct program_component *pc = get_component(bis, mirror_id,
						     comp_id, menu_idx);
	struct disk_info *info = &bis->info->base[mirror_id];
	struct component_loc *location = &pc->loc;
	disk_blockptr_t **list = &pc->list;
	blocknum_t *count = &pc->count;
	disk_blockptr_t segment;
	char* buffer;
	size_t size;
	int rc;

	if (bis->skip_prepare_device &&
	    bis->mirrors[mirror_id].skip_prepare_blocklist)
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
		*count = disk_write_block_buffer_align(&bis->mfd,
						       0 /* not a base disk */,
						       buffer, size, list,
						       bis->info->fs_block_size,
						       info,
						       info->phy_block_size,
						       /*
							* save component offset
							*/
						       &bis->comp_reg
						       [comp_id].offset);
		free(buffer);
		if (*count == 0) {
			error_text("Could not write to bootmap file");
			return -1;
		}
		/* zero offset is occupied by bootmap header */
		assert(bis->comp_reg[comp_id].offset > 0);
		/* save component size */
		bis->comp_reg[comp_id].len = size;
	} else {
		if (!file_is_on_device(filename, bis->info)) {
			error_reason("File is not on target device");
			return -1;
		}
		/* Get block list from existing file */
		*count = disk_get_blocklist_from_file(filename, reg,
						      list,
						      bis->info->fs_block_size,
						      info);
		if (*count == 0)
			return -1;
		*count -= DIV_ROUND_UP(trailer, info->phy_block_size);
	}
	/* Fill in component location */
	location->addr = load_address;
	location->size = *count * info->phy_block_size;
	/* Try to compact list */
	*count = disk_compact_blocklist(*list, *count, info);
write_segment_table:
	assert(*list != NULL);
	assert(*count != 0);
	rc = add_segment_table(&bis->mfd, *list, *count, &segment,
			       bis->info->fs_block_size, info,
			       mirror_id, program_table_id);
	if (rc == 0)
		create_component_entry(component, &segment,
				       component_type_by_id(comp_id),
				       (component_data)load_address,
				       info, program_table_id);
	return rc;
}

static int add_component_file(struct install_set *bis, const char *filename,
			      address_t load_address, size_t trailer,
			      void *component, int add_files, int comp_id,
			      int menu_idx, int mirror_id, int program_table_id)
{
	struct file_range *reg = NULL;

	if (add_files &&
	    bis->comp_reg[comp_id].offset > 0) {
		/*
		 * The file has been already written to the bootmap.
		 * Use the respective region in the bootmap file to
		 * add the component
		 */
		filename = bis->filename;
		reg = &bis->comp_reg[comp_id];
		add_files = 0;
	}
	return add_component_file_range(bis, filename, reg, load_address,
					trailer, component, add_files,
					comp_id, menu_idx, mirror_id,
					program_table_id);
}

static int add_component_buffer_base(struct install_set *bis, void *buffer,
				     size_t size, component_data data,
				     void *component, int comp_id, int menu_idx,
				     int mirror_id, int program_table_id)
{
	struct program_component *pc = get_component(bis, mirror_id,
						     comp_id, menu_idx);
	struct disk_info *info = &bis->info->base[mirror_id];
	struct component_loc *location = &pc->loc;
	disk_blockptr_t **list = &pc->list;
	blocknum_t *count = &pc->count;
	disk_blockptr_t segment;
	loff_t offset;
	int align;
	int rc;

	align = fs_block_aligned_by_id(comp_id) ?
		bis->info->fs_block_size :
		info->phy_block_size;

	if (bis->skip_prepare_device &&
	    bis->mirrors[mirror_id].skip_prepare_blocklist)
		/* skip the preparation work */
		goto write_segment_table;
	/* Write buffer */
	*count = disk_write_block_buffer_align(&bis->mfd, 0, buffer, size, list,
					       bis->info->fs_block_size,
					       info, align, &offset);
	if (*count == 0) {
		error_text("Could not write to bootmap file");
		return -1;
	}
	if (!bis->comp_reg[comp_id].offset) {
		/*
		 * save component offset and size
		 */
		assert(offset > 0);
		bis->comp_reg[comp_id].offset = offset;
		bis->comp_reg[comp_id].len = size;
	}
	if (component_type_by_id(comp_id) == COMPONENT_TYPE_LOAD) {
		/* Fill in component location */
		location->addr = data.load_address;
		location->size = *count * info->phy_block_size;
	} else {
		location->addr = 0;
		location->size = 0;
	}
	/* Try to compact list */
	*count = disk_compact_blocklist(*list, *count, info);
write_segment_table:
	assert(*list != NULL);
	assert(*count != 0);

	rc = add_segment_table(&bis->mfd, *list, *count, &segment,
			       bis->info->fs_block_size, info,
			       mirror_id, program_table_id);
	if (rc == 0)
		create_component_entry(component, &segment,
				       component_type_by_id(comp_id),
				       data, info, program_table_id);
	return rc;
}

static int add_component_buffer(struct install_set *bis, void *buffer,
				size_t size, component_data data,
				void *component, int comp_id, int menu_idx,
				int mirror_id, int program_table_id)
{
	if (bis->comp_reg[comp_id].offset > 0) {
		/*
		 * The component data has been already written to the
		 * bootmap. Refer the respective region in the bootmap
		 * file.
		 */
		return add_component_file_range(bis,
						bis->filename /* bootmap */,
						&bis->comp_reg[comp_id],
						data.load_address,
						0 /*trailer */,
						component,
						0 /* do not add file data*/,
						comp_id, menu_idx, mirror_id,
						program_table_id);
	}
	return add_component_buffer_base(bis, buffer, size, data, component,
					 comp_id, menu_idx, mirror_id,
					 program_table_id);
}

static int add_dummy_buffer(struct install_set *bis, size_t size,
			    address_t addr, void *component, int comp_id,
			    int menu_idx, int mirror_id, int program_table_id)
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
				  mirror_id,
				  program_table_id);
	free(buffer);
	return rc;
}


static void print_components(struct install_set *bis,
			     int mirror_id, int menu_idx)
{
	const char *padding = "................";
	int i;

	printf("  component address:\n");
	/* Process all available components */
	for (i = 0; i < NR_PROGRAM_COMPONENTS; i++) {
		struct program_component *pc = get_component(bis, mirror_id,
							     i, menu_idx);

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

static int add_ipl_program(struct install_set *bis, bool add_envblk,
			   struct job_envblk_data *envblk,
			   struct job_ipl_data *ipl, disk_blockptr_t *program,
			   int verbose, int add_files,
			   component_header_type type, int is_secure,
			   int menu_idx, int mirror_id,
			   int program_table_id)
{
	struct disk_info *info = &bis->info->base[mirror_id];
	struct signature_header sig_head;
	size_t ramdisk_size, image_size;
	size_t stage3_params_size;
	size_t signature_size;
	int offset;
	uint64_t flags = 0;
	void *stage3_params;
	struct stat stats;
	void *signature;
	void *table;
	int rc;

	memset(&sig_head, 0, sizeof(sig_head));
	table = util_zalloc(info->phy_block_size);
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
		if (verbose && bis->mirrors[mirror_id].print_details)
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
	if (info->type == disk_type_scsi) {
		flags |= STAGE3_FLAG_SCSI;
		/*
		 * Add dummy components for stage 3 heap and stack to block the
		 * associated memory areas against firmware use.
		 */
		rc = add_dummy_buffer(bis, STAGE3_HEAP_SIZE,
				      STAGE3_HEAP_ADDRESS,
				      VOID_ADD(table, offset),
				      COMPONENT_ID_HEAP_AREA,
				      menu_idx, mirror_id, program_table_id);
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
				      menu_idx, mirror_id, program_table_id);
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
		if (verbose && bis->mirrors[mirror_id].print_details)
			printf("  signature for.....: %s\n", ZIPL_STAGE3_PATH);

		rc = add_component_buffer(bis, signature, sig_head.length,
					  (component_data)sig_head,
					  VOID_ADD(table, offset),
					  COMPONENT_ID_LOADER_SIGNATURE,
					  menu_idx, mirror_id,
					  program_table_id);
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
				COMPONENT_ID_LOADER, menu_idx, mirror_id,
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
				   (info->type == disk_type_scsi) ? 0 : 1,
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
				  menu_idx, mirror_id, program_table_id);
	free(stage3_params);
	if (rc) {
		error_text("Could not add parameters");
		free(table);
		return -1;
	}
	offset += sizeof(struct component_entry);

	/* Add kernel image */
	if (verbose && bis->mirrors[mirror_id].print_details)
		printf("  kernel image......: %s\n", ipl->common.image);

	signature_size = extract_signature(ipl->common.image, &signature, &sig_head);
	if (signature_size &&
	    (is_secure == SECURE_BOOT_ENABLED ||
	     (is_secure == SECURE_BOOT_AUTO && secure_boot_supported))) {
		if (verbose && bis->mirrors[mirror_id].print_details)
			printf("  signature for.....: %s\n", ipl->common.image);

		rc = add_component_buffer(bis, signature, sig_head.length,
					  (component_data)sig_head,
					  VOID_ADD(table, offset),
					  COMPONENT_ID_IMAGE_SIGNATURE,
					  menu_idx, mirror_id,
					  program_table_id);
		if (rc) {
			error_text("Could not add image signature");
			free(table);
			return rc;
		}
		offset += sizeof(struct component_entry);
		free(signature);
		check_remaining_filesize(image_size, signature_size, info,
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
				add_files, COMPONENT_ID_KERNEL_IMAGE,
				menu_idx, mirror_id, program_table_id);
	if (rc) {
		error_text("Could not add image file '%s'", ipl->common.image);
		free(table);
		return rc;
	}
	offset += sizeof(struct component_entry);

	/* Add kernel parmline */
	if (ipl->common.parmline != NULL) {
		if (verbose && bis->mirrors[mirror_id].print_details)
			printf("  kernel parmline...: '%s'\n", ipl->common.parmline);
		rc = add_component_buffer(bis, ipl->common.parmline,
					  strlen(ipl->common.parmline) + 1,
					  (component_data)ipl->common.parm_addr,
					  VOID_ADD(table, offset),
					  COMPONENT_ID_PARMLINE,
					  menu_idx, mirror_id,
					  program_table_id);
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
			if (verbose && bis->mirrors[mirror_id].print_details) {
				printf("  signature for.....: %s\n",
				       ipl->common.ramdisk);
			}
			rc = add_component_buffer(bis, signature,
						  sig_head.length,
						  (component_data)sig_head,
						  VOID_ADD(table, offset),
						 COMPONENT_ID_RAMDISK_SIGNATURE,
						  menu_idx, mirror_id,
						  program_table_id);
			if (rc) {
				error_text("Could not add ramdisk signature");
				free(table);
				return rc;
			}
			offset += sizeof(struct component_entry);
			free(signature);
			check_remaining_filesize(ramdisk_size, signature_size,
						 info, ipl->common.ramdisk);
		}
		rc = add_component_file(bis, ipl->common.ramdisk,
					ipl->common.ramdisk_addr,
					signature_size,
					VOID_ADD(table, offset),
					add_files, COMPONENT_ID_RAMDISK,
					menu_idx, mirror_id, program_table_id);
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
		int save_location = !bis->comp_reg[COMPONENT_ID_ENVBLK].offset;

		rc = add_component_buffer(bis,
					  envblk->buf, envblk->size,
					  (component_data)ipl->envblk_addr,
					  VOID_ADD(table, offset),
					  COMPONENT_ID_ENVBLK,
					  menu_idx, mirror_id,
					  program_table_id);
		if (rc) {
			error_text("Could not add environment block");
			free(table);
			return rc;
		}
		if (save_location) {
			/*
			 * store environment block location in the bootmap
			 * header for future operations performed by
			 * zipl-editenv(8) tool
			 */
			assert(bis->comp_reg[COMPONENT_ID_ENVBLK].offset > 0 &&
			       bis->comp_reg[COMPONENT_ID_ENVBLK].offset %
			       bis->info->fs_block_size == 0);
			rc = envblk_offset_set(&bis->mfd,
				bis->comp_reg[COMPONENT_ID_ENVBLK].offset);
			if (rc) {
				error_text("Could not store environment block location");
				free(table);
				return rc;
			}
		}
		offset += sizeof(struct component_entry);
	}
	if (verbose && bis->mirrors[mirror_id].print_details)
		print_components(bis, mirror_id, menu_idx);
	/* Terminate component table */
	create_component_entry(VOID_ADD(table, offset), NULL,
			       COMPONENT_TYPE_EXECUTE,
			       (component_data) (uint64_t)
			       (STAGE3_ENTRY | PSW_LOAD),
			       info, program_table_id);
	/* Write component table */
	rc = disk_write_block_aligned(&bis->mfd, table,
				      info->phy_block_size, program,
				      bis->info->fs_block_size, info);
	free(table);
	return rc;
}

static int add_segment_program(struct install_set *bis,
			       struct job_segment_data *segment,
			       disk_blockptr_t *program, int verbose,
			       int add_files, component_header_type type,
			       int mirror_id, int program_table_id)
{
	struct disk_info *info = &bis->info->base[mirror_id];
	void *table;
	int offset;
	int rc;

	table = util_zalloc(info->phy_block_size);
	if (table == NULL)
		return -1;
	/* Create component table */
	offset = 0;
	/* Fill in component table header */
	create_component_header(VOID_ADD(table, offset), type);
	offset += sizeof(struct component_header);
	/* Add segment file */
	if (verbose && bis->mirrors[mirror_id].print_details)
		printf("  segment file......: %s\n", segment->segment);

	rc = add_component_file(bis, segment->segment, segment->segment_addr, 0,
				VOID_ADD(table, offset), add_files,
				COMPONENT_ID_SEGMENT_FILE, 0 /* menu_idx */,
				mirror_id, program_table_id);
	if (rc) {
		error_text("Could not add segment file '%s'",
			   segment->segment);
		free(table);
		return rc;
	}
	offset += sizeof(struct component_entry);
	/* Print component addresses */
	if (verbose && bis->mirrors[mirror_id].print_details)
		print_components(bis, mirror_id, 0 /* menu_idx */);
	/* Terminate component table */
	create_component_entry(VOID_ADD(table, offset), NULL,
			       COMPONENT_TYPE_EXECUTE,
			       (component_data)(uint64_t)PSW_DISABLED_WAIT,
			       info, program_table_id);
	/* Write component table */
	rc = disk_write_block_aligned(&bis->mfd, table,
				      info->phy_block_size, program,
				      bis->info->fs_block_size, info);
	free(table);
	return rc;
}

#define DUMP_PARAM_MAX_LEN	896

static int add_dump_program(struct install_set *bis,
			    const struct job_dump_data *dump,
			    disk_blockptr_t *program, int verbose,
			    component_header_type type,
			    int program_table_id)
{
	struct job_ipl_data ipl;

	/* Convert fs dump job to IPL job */
	memset(&ipl, 0, sizeof(ipl));
	ipl.common = dump->common;

	return add_ipl_program(bis, false, NULL, &ipl, program,
			       verbose, 1, type, SECURE_BOOT_DISABLED,
			       0 /* menu_idx */, 0 /* mirror id */,
			       program_table_id);
}


/**
 * Build a program table from job data and set pointer to program table
 * block upon success
 * PROGRAM_TABLE_ID: offset of the program table in the array (@bis->tables)
 */
static int build_program_table(struct job_data *job, struct install_set *bis,
			       int mirror_id, int program_table_id)
{
	struct disk_info *info = &bis->info->base[mirror_id];
	int entries, component_header;
	disk_blockptr_t *table;
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
		if (bis->mirrors[mirror_id].print_details) {
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
		rc = add_ipl_program(bis,
				     true, &job->envblk, &job->data.ipl,
				     &table[0], verbose || job->command_line,
				     job->add_files, component_header,
				     job->is_secure, 0, mirror_id,
				     program_table_id);
		break;
	case job_segment:
		if (bis->mirrors[mirror_id].print_details) {
			if (job->command_line)
				printf("Adding segment load section\n");
			else
				printf("Adding segment load section '%s' (default)\n",
				       job->name);
		}
		rc = add_segment_program(bis, &job->data.segment, &table[0],
					 verbose || job->command_line,
					 job->add_files, COMPONENT_HEADER_IPL,
					 mirror_id, program_table_id);
		break;
	case job_dump_partition:
		/* Only useful for a partition dump that uses a dump kernel*/
		if (bis->mirrors[mirror_id].print_details) {
			if (job->command_line)
				printf("Adding dump section\n");
			else
				printf("Adding dump section '%s' (default)\n",
				       job->name);
		}
		rc = add_dump_program(bis, &job->data.dump, &table[0],
				      verbose || job->command_line,
				      COMPONENT_HEADER_DUMP,
				      program_table_id);
		break;
	case job_menu:
		if (bis->mirrors[mirror_id].print_details)
			printf("Building menu '%s'\n", job->name);
		rc = 0;
		for (i=0; i < job->data.menu.num; i++) {
			switch (job->data.menu.entry[i].id) {
			case job_ipl:
				if (bis->mirrors[mirror_id].print_details &&
				    job->data.menu.entry[i].data.ipl.common.ignore) {
					printf("Skipping #%d: IPL section '%s' (missing files)\n",
					       job->data.menu.entry[i].pos,
					       job->data.menu.entry[i].name);
					break;
				}
				if (bis->mirrors[mirror_id].print_details)
					printf("Adding #%d: IPL section '%s'%s",
					       job->data.menu.entry[i].pos,
					       job->data.menu.entry[i].name,
					       (job->data.menu.entry[i].pos ==
						job->data.menu.default_pos) ?
					       " (default)" : "");
				if (job->data.menu.entry[i].data.ipl.is_kdump) {
					component_header =
						COMPONENT_HEADER_DUMP;
					if (bis->mirrors[mirror_id].print_details)
						printf(" (kdump)\n");
				} else {
					component_header =
						COMPONENT_HEADER_IPL;
					if (bis->mirrors[mirror_id].print_details)
						printf("\n");
				}
				if (job->is_secure != SECURE_BOOT_UNDEFINED)
					is_secure = job->is_secure;
				else
					is_secure =
					      job->data.menu.entry[i].is_secure;
				rc = add_ipl_program(bis,
					true, &job->envblk,
					&job->data.menu.entry[i].data.ipl,
					&table[job->data.menu.entry[i].pos],
					verbose || job->command_line,
					job->add_files, component_header,
						     is_secure, i,
						     mirror_id,
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
	if (job->envblk.buf && verbose &&
	    bis->mirrors[mirror_id].print_details)
		envblk_print(job->envblk.buf, job->envblk.size);

	if (rc == 0) {
		disk_blockptr_t *pointer;

		/* Add program table block */
		pointer = &bis->mirrors[mirror_id].tables[program_table_id].table;
		rc = add_program_table(&bis->mfd, table, entries,
				       pointer, bis->info->fs_block_size, info,
				       program_table_id);
	}
	free(table);
	return rc;
}


/* Write block of zeroes to the bootmap file FD and store the resulting
 * block pointer in BLOCK. Return zero on success, non-zero otherwise. */
static int
write_empty_block(struct misc_fd *mfd, disk_blockptr_t *block,
		  int fs_block_size, struct disk_info *info)
{
	void* buffer;
	int rc;

	buffer = misc_malloc(info->phy_block_size);
	if (buffer == NULL)
		return -1;
	memset(buffer, 0, info->phy_block_size);
	rc = disk_write_block_aligned(mfd, buffer, info->phy_block_size, block,
				      fs_block_size, info);
	free(buffer);
	return rc;
}


static int install_stages_dasd_fba(struct misc_fd *mfd, char *filename,
				   struct job_data *job,
				   int fs_block_size,
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
		stage2_count = disk_write_block_buffer(mfd, 0, stage2_data,
						       stage2_size,
						       &stage2_list,
						       fs_block_size,
						       info);
		free(stage2_data);
		if (stage2_count == 0) {
			error_text("Could not write to file '%s'", filename);
			return -1;
		}
		if (install_fba_stage1b(mfd, stage1b_list, stage1b_count,
					stage2_list, stage2_count,
					fs_block_size, info))
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

static int install_stages_eckd_dasd(struct misc_fd *mfd, char *filename,
				    struct job_data *job,
				    int fs_block_size,
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
		stage2b_count = disk_write_block_buffer(mfd, 0, stage2b_data,
							stage2b_size,
							&stage2b_list,
							fs_block_size,
							info);
		free(stage2b_data);
		if (stage2b_count == 0) {
			error_text("Could not write to file '%s'", filename);
			return -1;
		}
		if (install_eckd_stage1b(mfd, stage1b_list, stage1b_count,
					 stage2b_list, stage2b_count,
					 fs_block_size, info))
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
		stage2b_count = disk_write_block_buffer(mfd, 0, stage2b_data,
							stage2b_size,
							stage1b_list,
							fs_block_size,
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
				  int mirror_id, int program_table_id)
{
	struct program_table *pt;
	struct disk_info *info;
	int rc = 0;

	pt = &bis->mirrors[mirror_id].tables[program_table_id];
	info = &bis->info->base[mirror_id];

	switch (info->type) {
	case disk_type_fba:
		rc = install_stages_dasd_fba(&bis->mfd, bis->filename, job,
					     bis->info->fs_block_size,
					     info,
					     &pt->stage1b_list,
					     &pt->stage1b_count,
					     program_table_id);
		break;
	case disk_type_eckd_ldl:
	case disk_type_eckd_cdl:
		rc = install_stages_eckd_dasd(&bis->mfd, bis->filename, job,
					      bis->info->fs_block_size,
					      info,
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
bootmap_write_scsi_superblock(struct misc_fd *mfd, int fs_block_size,
			      struct disk_info *info,
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
	return disk_write_block_aligned(mfd, &scsi_sb, sizeof(scsi_sb),
					scsi_dump_sb_blockptr, fs_block_size,
					info);
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
 * Check that disk with retrieved INFO is appropriate for the JOB
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
	/* common checks */
	if (job->target.source == source_auto &&
	    info->type == disk_type_diag) {
		error_reason("Unsupported disk type (%s)",
			     disk_get_type_name(info->type));
		return -1;
	}
	/* job-specific checks */
	if (job->id == job_dump_partition) {
		if (job->is_ldipl_dump && info->type != disk_type_eckd_cdl) {
			error_reason("Inappropriate dump device (not DASD-CDL)");
			return 0;
		}
		if (!job->is_ldipl_dump && info->type != disk_type_scsi) {
			error_reason("Inappropriate dump device (not SCSI)");
			return 0;
		}
		/* Check that data starts beyond the boot area on the base disk.
		 * In case of source_script the check is performed by the script
		 */
		if (job->target.source == source_auto && info->partnum == 0) {
			error_reason("Dump device %s is not a partition",
				     job->data.dump.device);
			return 0;
		}
	}
	return 1;
}

static int
check_dump_device(struct job_data *job, const struct disk_info *info,
		  const char *device)
{
	int rc, part_ext;

	if (!disk_is_appropriate(job, info))
		return -1;
	if (job_dump_is_ngdump(job))
		return 0;
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
 * Prepare resources to build a program table
 */
static int prepare_build_program_table_device(struct job_data *job,
					      struct install_set *bis)
{
	struct disk_info *info;
	ulong unused_size;

	if (bis->skip_prepare_device)
		/* skip the preparation work */
		return 0;
	/* Get full path of bootmap file */
	bis->filename = misc_strdup(job->data.dump.device);
	if (!bis->filename)
		return -1;
	if (misc_open_device(bis->filename, &bis->mfd, dry_run) == -1) {
		error_text("Could not open file '%s'", bis->filename);
		return -1;
	}
	/* Retrieve target device information */
	if (device_get_info(bis->filename, &job->target, &bis->info))
		return -1;

	if (verbose) {
		printf("Target device information\n");
		device_print_info(bis->info, &job->target);
	}
	/* Mirrored dump devices are not supported */
	info = &bis->info->base[FIRST_MIRROR_ID];
	if (misc_temp_dev(info->disk, 1,
			  &bis->mirrors[FIRST_MIRROR_ID].basetmp))
		return -1;
	if (check_dump_device(job, info,
			      bis->mirrors[FIRST_MIRROR_ID].basetmp))
		return -1;
	printf("Building bootmap directly on partition '%s'%s\n",
	       bis->filename,
	       job->add_files ? " (files will be added to partition)"
	       : "");
	/* For partition dump set raw partition offset
	   to expected size before end of disk */
	if (estimate_scsi_dump_size(job, info, &unused_size))
		return -1;
	if (lseek(bis->mfd.fd, unused_size, SEEK_SET) < 0)
		return -1;

	/* Initialize bootmap header */
	if (bootmap_header_init(&bis->mfd)) {
		error_text("Could not init bootmap header at '%s'",
			   bis->filename);
		return -1;
	}
	/* Write empty block to be read in place of holes in files */
	if (write_empty_block(&bis->mfd, &empty_blocks[FIRST_MIRROR_ID],
			      bis->info->fs_block_size, info)) {
		error_text("Could not write to file '%s'",
			   bis->filename);
		return -1;
	}
	if (bootmap_write_scsi_superblock(&bis->mfd,
					  bis->info->fs_block_size, info,
					  &bis->scsi_dump_sb_blockptr,
					  unused_size)) {
		error_text("Could not write SCSI superblock to file '%s'",
			   bis->filename);
		return -1;
	}
	return 0;
}

/**
 * Called when making a dump on a raw SCSI partition
 */
static int prepare_bootloader_device(struct job_data *job,
				     struct install_set *bis)
{
	if (prepare_build_program_table_device(job, bis))
		return -1;
	/*
	 * build a single program table at offset 1,
	 * see comment before install_bootloader() for details
	 */
	bis->mirrors[FIRST_MIRROR_ID].print_details = 1;
	if (build_program_table(job, bis,
				FIRST_MIRROR_ID, BLKPTR_FORMAT_ID))
		return -1;
	/* Install stage 2 loader to bootmap if necessary */
	if (bootmap_install_stages(job, bis,
				   FIRST_MIRROR_ID, BLKPTR_FORMAT_ID)) {
		error_text("Could not install loader stages to bootmap");
		return -1;
	}
	return 0;
}

/**
 * Prepare resources to build a program table
 */
static int prepare_build_program_table_file(struct job_data *job,
					    struct install_set *bis)
{
	int i;

	if (bis->skip_prepare_device)
		/* skip the preparation work */
		return 0;
	/* Create temporary bootmap file */
	bis->filename = misc_make_path(job->target.bootmap_dir,
				       BOOTMAP_TEMPLATE_FILENAME);
	if (!bis->filename)
		return -1;
	bis->mfd.fd = mkstemp(bis->filename);
	if (bis->mfd.fd == -1) {
		error_reason(strerror(errno));
		error_text("Could not create file '%s':", bis->filename);
		return -1;
	}
	bis->tmp_filename_created = 1;
	/*
	 * Retrieve target device information and
	 * complete the info with the file system block size
	 */
	if (job->id == job_dump_partition && dry_run) {
		/*
		 * ngdump job in dry-run mode.
		 *
		 * The dump device has read-only status.
		 * The bootmap and the meta-file to be created
		 * directly at the temporary mount point wthout
		 * mounting anything to it (thus, the mentioned
		 * files to be actually created in the "proxy"
		 * file system.
		 *
		 * Retrieve info from the dump device
		 * Retrieve file system block size from the proxy
		 * file system
		 */
		if (device_get_info(job->data.dump.device,
				    &job->target, &bis->info))
			return -1;
		if (device_info_set_fs_block(bis->filename, bis->info))
			return -1;
	} else {
		/*
		 * ngdump or ipl job.
		 */
		if (device_get_info_from_file(bis->filename,
					      &job->target,
					      &bis->info))
			return -1;
	}
	for (i = 0; i < job_get_nr_targets(job); i++) {
		if (!disk_is_appropriate(job, &bis->info->base[i]))
			return -1;
	}
	if (verbose) {
		printf("Target device information\n");
		device_print_info(bis->info, &job->target);
	}
	for (i = 0; i < job_get_nr_targets(job); i++) {
		if (misc_temp_dev(bis->info->base[i].disk,
				  1 /* block device */,
				  &bis->mirrors[i].basetmp))
			return -1;
	}
	/* Check configuration number limits */
	if (job->id == job_menu) {
		for (i = 0; i < job_get_nr_targets(job); i++) {
			if (check_menu_positions(&job->data.menu,
						 job->name,
						 &bis->info->base[i]))
				return -1;
		}
	}
	printf("Building bootmap in '%s'%s\n", job->target.bootmap_dir,
	       job->add_files ? " (files will be added to bootmap file)"
	       : "");
	/* Initialize bootmap header */
	if (bootmap_header_init(&bis->mfd)) {
		error_text("Could not init bootmap header at '%s'",
			   bis->filename);
		return -1;
	}
	/* Write empty block to be read in place of holes in files */
	for (i = 0; i < job_get_nr_targets(job); i++) {
		if (write_empty_block(&bis->mfd,
				      &empty_blocks[i],
				      bis->info->fs_block_size,
				      &bis->info->base[i])) {
			error_text("Could not write to file '%s'", bis->filename);
			return -1;
		}
	}
	return 0;
}

/**
 * Rename to final bootmap name
 */
static int finalize_create_file(struct job_data *job, struct install_set *bis)
{
	char *final_name;

	/*
	 * Sync the file before rename
	 */
	if (misc_fsync(&bis->mfd, bis->filename))
		return -1;
	final_name = misc_make_path(job->target.bootmap_dir, BOOTMAP_FILENAME);
	if (!final_name)
		return -1;
	if (rename(bis->filename, final_name)) {
		error_reason(strerror(errno));
		error_text("Could not rename '%s' to '%s'",
			   bis->filename, final_name);
		free(final_name);
		return -1;
	}
	/*
	 * The temporary object with @bis->filename has been removed
	 * from the semantic volume
	 */
	bis->tmp_filename_created = 0;
	/*
	 * Sync meta-data and the parent directory of the new object.
	 * For this, sync the whole file system, using the descriptor
	 * obtained for the file with the old name.
	 */
	if (syncfs(bis->mfd.fd)) {
		error_reason(strerror(errno));
		error_text("Could not sync fs containing '%s'",
			   final_name);
		free(final_name);
		return -1;
	}
	free(final_name);
	return 0;
}

/*
 * PROGRAM_TABLE_ID: offset of the program table in the array (@bis->tables)
 */
static int bootmap_create_file(struct job_data *job, struct install_set *bis,
			       int mirror_id, int program_table_id)
{
	if (prepare_build_program_table_file(job, bis))
		return -1;
	if (build_program_table(job, bis, mirror_id, program_table_id))
		return -1;
	/* Install stage 2 loader to bootmap if necessary */
	if (bootmap_install_stages(job, bis, mirror_id, program_table_id)) {
		error_text("Could not install loader stages to file '%s'",
			   bis->filename);
		return -1;
	}
	return 0;
}

void ngdump_delete_meta(const char *dir)
{
	char *filename = NULL;

	filename = misc_make_path(dir, DUMP_META_FILE_NAME);
	unlink(filename);
	free(filename);
}

/**
 * Create a file with the short name DUMP_META_FILE_NAME in the directory PATH.
 * This file is required for NGDump stand-alone dumper, it's read/written
 * by the dumper when it starts.
 */
static int ngdump_create_meta(const char *path)
{
	char *filename = NULL;
	FILE *fp;
	int rc;

	filename = misc_make_path(path, DUMP_META_FILE_NAME);

	fp = fopen(filename, "w");
	if (!fp) {
		error_reason(strerror(errno));
		error_text("Could not create file '%s'", filename);
		free(filename);
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
	/*
	 * In case of dry-run the meta-file will be removed.
	 * Otherwise it will be written to disk when unmounting
	 * the ngdump.
	 */
	return 0;
}

static int ngdump_mount_device(struct job_data *job)
{
	if (dry_run)
		/*
		 * the bootmap and the meta-file to be stored
		 * directly at the temporary mount point without
		 * mounting any partition
		 */
		return 0;
	/*
	 * the bootmap and the meta-file to be stored on the
	 * formatted and mounted dump partition
	 */
	if (mount(job->data.dump.device, job->target.bootmap_dir,
		  NGDUMP_FSTYPE, 0, NULL)) {
		error_reason(strerror(errno));
		error_text("Could not mount partition '%s':",
			   job->data.dump.device);
		return -1;
	}
	job->dump_mounted = 1;
	return 0;
}

static char *ngdump_dir(void)
{
	return getenv("TMPDIR") ? : DUMP_TEMP_MOUNT_POINT_DIR;
}

static char *build_mount_point_pathname(void)
{
	return misc_make_path(ngdump_dir(), DUMP_TEMP_MOUNT_POINT_NAME);
}

static int prepare_bootloader_ngdump(struct job_data *job,
				     struct install_set *bis)
{
	struct device_info *dev_info;
	struct disk_info *info;

	/* Retrieve target device information */
	if (device_get_info(job->data.dump.device, &job->target, &dev_info))
		return -1;
	info = &dev_info->base[FIRST_MIRROR_ID];

	if (misc_temp_dev(info->disk, 1,
			  &bis->mirrors[FIRST_MIRROR_ID].basetmp))
		return -1;
	if (check_dump_device(job, info,
			      bis->mirrors[FIRST_MIRROR_ID].basetmp))
		return -1;

	assert(!job->target.bootmap_dir);
	job->target.bootmap_dir = build_mount_point_pathname();
	if (!job->target.bootmap_dir) {
		error_reason(strerror(errno));
		error_text("Could not make path for '%s'",
			   DUMP_TEMP_MOUNT_POINT_NAME);
		return -1;
	}
	/* Create a mount point directory */
	if (!mkdtemp(job->target.bootmap_dir)) {
		error_reason(strerror(errno));
		error_text("Could not create mount point '%s'",
			   job->target.bootmap_dir);
		return -1;
	}
	job->bootmap_dir_created = 1;
	if (ngdump_mount_device(job))
		return -1;
	/*
	 * Build a single program table for List-Directed IPL
	 * See comments before install_bootloader() for details
	 */
	bis->mirrors[FIRST_MIRROR_ID].print_details = 1;
	if (bootmap_create_file(job, bis,
				FIRST_MIRROR_ID, BLKPTR_FORMAT_ID)) {
		if (dry_run && is_error(FS_MAP_ERROR))
			fprintf(stderr,
				"'%s' doesn't satisfy the requirements. Set TMPDIR properly\n",
				ngdump_dir());
		return -1;
	}
	return ngdump_create_meta(job->target.bootmap_dir);
}

/**
 * Build one or two program tables for CCW-type and(or) for List-Direceted IPL
 * at respective offsets in the array BIS->tables. See the comment before
 * install_bootloader() for details
 */
static int prepare_bootloader_ipl_mirror(struct job_data *job,
					 struct install_set *bis,
					 int mirror_id)
{
	struct disk_info *info;

	/*
	 * Build a program table for List-Directed IPL from
	 * SCSI or ECKD DASD
	 */
	bis->mirrors[mirror_id].print_details = 1;
	if (bootmap_create_file(job, bis, mirror_id, BLKPTR_FORMAT_ID))
		return -1;

	bis->skip_prepare_device = 1;
	bis->mirrors[mirror_id].skip_prepare_blocklist = 1;
	bis->mirrors[mirror_id].print_details = 0;

	info = &bis->info->base[mirror_id];
	if (info->type == disk_type_scsi)
		/* only one table to be installed per device */
		return 0;
	/*
	 * Build one more program table for CCW-type IPL from
	 * ECKD DASD
	 */
	if (bootmap_create_file(job, bis, mirror_id, LEGACY_BLKPTR_FORMAT_ID))
		return -1;
	return 0;
}

static int prepare_bootloader_ipl(struct job_data *job, struct install_set *bis)
{
	int i;

	if (prepare_bootloader_ipl_mirror(job, bis, FIRST_MIRROR_ID))
		return -1;
	/* also, prepare other mirrors, if any */
	for (i = FIRST_MIRROR_ID + 1; i < job_get_nr_targets(job); i++) {
		if (prepare_bootloader_ipl_mirror(job, bis, i))
			return -1;
	}
	return 0;
}

/**
 * Initialize Bootloader Installation Set
 */
static int init_bis(struct job_data *job, struct install_set *bis)
{
	int i, j;

	memset(bis, 0, sizeof(*bis));
	bis->nr_menu_entries = 1;
	if (job->id == job_menu)
		bis->nr_menu_entries = job->data.menu.num;
	/*
	 * allocate "matrix" of program components
	 */
	for (i = 0; i < MAX_TARGETS; i++) {
		for (j = 0; j < NR_PROGRAM_COMPONENTS; j++) {
			bis->mirrors[i].components[j] =
				util_zalloc(sizeof(struct program_component) *
					    bis->nr_menu_entries);
			if (!bis->mirrors[i].components[j])
				return -1;
		}
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
	secure_boot_supported = check_secure_boot_support();

	if (init_bis(job, bis))
		return -1;
	if (job->id == job_dump_partition) {
		if (job_dump_is_ngdump(job))
			return prepare_bootloader_ngdump(job, bis);
		else
			return prepare_bootloader_device(job, bis);
	} else {
		return prepare_bootloader_ipl(job, bis);
	}
}

/**
 * Do whatever needed after successful boot records installation
 * but before releasing all the captured resources
 */
int post_install_bootloader(struct job_data *job, struct install_set *bis)
{
	if (dry_run)
		return 0;
	if (job->id == job_dump_partition) {
		if (job_dump_is_ngdump(job))
			return finalize_create_file(job, bis);
		else
			return misc_fsync(&bis->mfd, bis->filename);
	} else {
		return finalize_create_file(job, bis);
	}
}

/**
 * Release all resources accumulated along the installation process
 */
void free_bootloader(struct install_set *bis, struct job_data *job)
{
	int i, j, k;

	for (k = 0; k < job_get_nr_targets(job); k++) {
		for (i = 0; i < NR_PROGRAM_TABLES; i++)
			free(bis->mirrors[k].tables[i].stage1b_list);
		for (i = 0; i < NR_PROGRAM_COMPONENTS; i++) {
			for (j = 0; j < bis->nr_menu_entries; j++)
				free(get_component(bis, k, i, j)->list);
			free(bis->mirrors[k].components[i]);
		}
		if (bis->mirrors[k].basetmp)
			misc_free_temp_dev(bis->mirrors[k].basetmp);
	}
	if (bis->mfd.fd > 0)
		close(bis->mfd.fd);
	if (bis->tmp_filename_created)
		misc_free_temp_file(bis->filename);
	free(bis->filename);
	device_free_info(bis->info);
}
