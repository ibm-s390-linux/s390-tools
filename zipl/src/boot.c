/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Functions to handle the boot loader data
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "stage3.h"

#include "../boot/data.h"
#include "boot.h"
#include "bootmap.h"
#include "error.h"
#include "misc.h"

#define DATA_SIZE(x)	((size_t) (&_binary_##x##_bin_end - &_binary_##x##_bin_start))
#define DATA_ADDR(x)	(&_binary_##x##_bin_start)

#define STAGE2_MAX_SIZE		0x3000
#define STAGE1B_LOAD_ADDR	0xe000
#define CCW_FLAG_CC		0x40
#define CCW_FLAG_SLI		0x20
#define FBA_BLK_SIZE		512

static struct boot_ccw0 tic_to_stage1b = {
	.cmd = 0x08, /* tic */
	.address_lo = STAGE1B_LOAD_ADDR,
};

/* Check sizes of internal objects. Return 0 if everything is correct,
 * non-zero otherwise. */
int
boot_check_data(void)
{
	if (DATA_SIZE(fba0) != sizeof(struct boot_fba_stage0)) {
		error_reason("Size mismatch of FBA stage 0 loader");
		return -1;
	}
	if (DATA_SIZE(fba1b) != sizeof(struct boot_fba_stage1b)) {
		error_reason("Size mismatch of FBA stage 1b loader");
		return -1;
	}
	if (DATA_SIZE(eckd0_ldl) !=
	    sizeof(struct boot_eckd_ldl_stage0)) {
		error_reason("Size mismatch of ECKD LDL stage 0 loader");
		return -1;
	}
	if (DATA_SIZE(eckd0_cdl) != sizeof(struct boot_eckd_cdl_stage0)) {
		error_reason("Size mismatch of ECKD CDL stage 0 loader");
		return -1;
	}
	if (DATA_SIZE(eckd1) != sizeof(struct boot_eckd_stage1)) {
		error_reason("Size mismatch of ECKD stage 1 loader");
		return -1;
	}
	if (DATA_SIZE(eckd1b) != sizeof(struct boot_eckd_stage1b)) {
		error_reason("Size mismatch of ECKD stage 1b loader");
		return -1;
	}
	return 0;
}

/*
 * Create a stage 3 parameter block in memory.
 * Upon success, return 0 and set BUFFER to point to the data buffer and set
 * BYTECOUNT to contain the parameter block size in bytes.
 * Return non-zero otherwise.
 */
int
boot_get_stage3_parms(void **buffer, size_t *bytecount, address_t parm_addr,
		      address_t initrd_addr, size_t initrd_len,
		      address_t entry, int extra_parm, uint64_t flags,
		      address_t image_addr, size_t image_len)
{
	struct stage3_parms params;
	void* data;

	if (entry != (entry & PSW32_ADDR_MASK)) {
		error_reason("Kernel image entry point to high (31 bit "
			     "addressing mode)");
		return -1;
	}
	/* Get memory */
	data = misc_malloc(sizeof(params));
	if (data == NULL)
		return -1;
	memset(data, 0, sizeof(params));
	/* Prepare params section */
	params.parm_addr = (uint64_t) parm_addr;
	params.initrd_addr = (uint64_t) initrd_addr;
	params.initrd_len = (uint64_t) initrd_len;
	params.load_psw = (uint64_t)(entry | PSW_LOAD);
	params.extra_parm = (uint64_t) extra_parm;
	params.flags = flags;
	params.image_len = (uint64_t) image_len;
	params.image_addr = (uint64_t) image_addr;
	/* Initialize buffer */
	memcpy(data, &params, sizeof(params));
	*buffer = data;
	*bytecount = sizeof(params);
	return 0;
}

int
boot_init_fba_stage0(struct boot_fba_stage0 *stage0,
		     disk_blockptr_t *stage1b_list, blocknum_t stage1b_count)
{
	blocknum_t i;

	/* Initialize stage 0 data */
	memcpy(stage0, DATA_ADDR(fba0), DATA_SIZE(fba0));
	/* Fill in blocklist for stage 2 loader */
	if (stage1b_count > STAGE1B_BLK_CNT_MAX) {
		error_reason("Not enough room for FBA stage 1b loader");
		return -1;
	}
	for (i = 0; i < stage1b_count; i++) {
		stage0->locdata[i].blocknr =
			(uint32_t) stage1b_list[i].linear.block;
		stage0->locread[i].read.address_lo =
			STAGE1B_LOAD_ADDR + i * FBA_BLK_SIZE;
	}
	/* Terminate CCW chain: Tic to stage 1b */
	memcpy(&stage0->locread[i], &tic_to_stage1b, sizeof(tic_to_stage1b));
	return 0;
}

void
boot_init_eckd_ldl_stage0(struct boot_eckd_ldl_stage0 *stage0)
{
	memcpy(stage0, DATA_ADDR(eckd0_ldl), DATA_SIZE(eckd0_ldl));
	/* Fill in size of stage 1 plus stage 0 loader */
	stage0->read_r1.count = sizeof(struct boot_eckd_stage1) +
		sizeof(struct boot_eckd_ldl_stage0);
}

void
boot_init_eckd_cdl_stage0(struct boot_eckd_cdl_stage0 *stage0)
{
	memcpy(stage0, DATA_ADDR(eckd0_cdl), DATA_SIZE(eckd0_cdl));
	/* Fill in size of stage 1 loader */
	stage0->read.count = sizeof(struct boot_eckd_stage1);
}

int
boot_init_eckd_stage1(struct boot_eckd_stage1 *stage1,
		      disk_blockptr_t *stage1b_list, blocknum_t stage1b_count)
{
	blocknum_t i;

	memcpy(stage1, DATA_ADDR(eckd1), DATA_SIZE(eckd1));
	/* Fill in blocklist for stage 1b  loader */
	if (stage1b_count > STAGE1B_BLK_CNT_MAX) {
		error_reason("Not enough room for ECKD stage 1b loader "
			     "(try larger block size)");
		return -1;
	}
	for (i = 0; i < stage1b_count; i++) {
		stage1->ssrt[i].read.count = stage1b_list[i].chs.size;
		stage1->seek[i].cyl = stage1b_list[i].chs.cyl;
		stage1->seek[i].head = stage1b_list[i].chs.head |
			((stage1b_list[i].chs.cyl >> 12) & 0xfff0);
		stage1->seek[i].sec = stage1b_list[i].chs.sec;
		stage1->ssrt[i].read.address_lo =
			STAGE1B_LOAD_ADDR + i * stage1b_list[i].chs.size;
		stage1->ssrt[i].read.flags = CCW_FLAG_CC | CCW_FLAG_SLI;
	}
	/* Terminate CCW chain: Tic to stage 1b */
	memcpy(&stage1->ssrt[i], &tic_to_stage1b, sizeof(tic_to_stage1b));
	return 0;
}

int
boot_init_fba_stage1b(struct boot_fba_stage1b *stage1b,
		      disk_blockptr_t *stage2_list, blocknum_t stage2_count)
{
	blocknum_t i;

	memcpy(stage1b, DATA_ADDR(fba1b), DATA_SIZE(fba1b));
	if (stage2_count > STAGE2_BLK_CNT_MAX) {
		error_reason("Not enough room for FBA stage 2 loader");
		return -1;
	}
	for (i = 0; i < stage2_count; i++) {
		stage1b->locdata[i].blocknr =
			(uint32_t) stage2_list[i].linear.block;
		stage1b->locread[i].read.address_lo =
			STAGE2_LOAD_ADDRESS + i * FBA_BLK_SIZE;
	}
	/* Terminate CCW chain */
	stage1b->locread[i - 1].read.flags &= ~CCW_FLAG_CC;
	return 0;
}

int
boot_init_eckd_stage1b(struct boot_eckd_stage1b *stage1b,
		       disk_blockptr_t *stage2_list, blocknum_t stage2_count)
{
	blocknum_t i;

	memcpy(stage1b, DATA_ADDR(eckd1b), DATA_SIZE(eckd1b));
	if (stage2_count > STAGE2_BLK_CNT_MAX) {
		error_reason("Not enough room for ECKD stage 2 loader "
			     "(try larger block size)");
		return -1;
	}
	for (i = 0; i < stage2_count; i++) {
		stage1b->ssrt[i].read.count = stage2_list[i].chs.size;
		stage1b->seek[i].cyl = stage2_list[i].chs.cyl;
		stage1b->seek[i].head = stage2_list[i].chs.head |
			((stage2_list[i].chs.cyl >> 12) & 0xfff0);
		stage1b->seek[i].sec = stage2_list[i].chs.sec;
		stage1b->ssrt[i].read.address_lo = STAGE2_LOAD_ADDRESS +
			i * stage2_list[i].chs.size;
		stage1b->ssrt[i].read.flags = CCW_FLAG_CC | CCW_FLAG_SLI;
	}
	/* Terminate CCW chain */
	stage1b->ssrt[i - 1].read.flags &= ~CCW_FLAG_CC;
	return 0;
}

int
boot_get_tape_ipl(void** data, size_t* size, address_t parm_addr,
		  address_t initrd_addr, address_t image_addr)
{
	struct boot_tape_ipl_params params;
	void* buffer;

	if (image_addr != (image_addr & PSW32_ADDR_MASK)) {
		error_reason("Kernel image load address to high (31 bit "
			     "addressing mode)");
		return -1;
	}
	buffer = misc_malloc(DATA_SIZE(tape0));
	if (buffer == NULL)
		return -1;
	/* Prepare params section */
	params.parm_addr = (uint64_t) parm_addr;
	params.initrd_addr = (uint64_t) initrd_addr;
	params.load_psw = (uint64_t) (image_addr | PSW_LOAD);
	/* Initialize buffer */
	memcpy(buffer, DATA_ADDR(tape0), DATA_SIZE(tape0));
	memcpy(VOID_ADD(buffer, BOOT_TAPE_IPL_PARAMS_OFFSET), &params,
	       sizeof(struct boot_tape_ipl_params));
	*data = buffer;
	*size = DATA_SIZE(tape0);
	return 0;
}

struct menu_buffer {
	void *start;
	size_t size;
	size_t off;
};

static void
mb_init(struct menu_buffer *buffer, void *data, size_t size)
{
	buffer-> start = data;
	buffer->size = size;
	buffer->off = 0;
	memset(data, 0, size);
}


static void *
mb_alloc(struct menu_buffer *buffer, size_t len)
{
	void *result;

	if (buffer->off + len > buffer->size)
		return NULL;
	result = VOID_ADD(buffer->start, buffer->off);
	buffer->off += len;

	return result;
}


static void*
mb_sprintf(struct menu_buffer *buffer, const char *fmt, ...)
{
	va_list args;
	int size;
	int len;
	char *str;

	str = VOID_ADD(buffer->start, buffer->off);
	size = buffer->size - buffer->off;
	va_start(args, fmt);
	len = vsnprintf(str, size, fmt, args);
	va_end(args);
	if (len < 0 || len >= size)
		return NULL;
	misc_ascii_to_ebcdic((unsigned char *) str,
			     (unsigned char *) str + len);
	mb_alloc(buffer, len + 1);

	return str;
}


static int
store_stage2_menu(void* data, size_t size, struct job_data* job)
{
	struct boot_stage2_params* params;
	char* name;
	int flag;
	int timeout;
	int i;
	struct menu_buffer mb;
	void *str;
	uint64_t config_kdump = 0;

	mb_init(&mb, data, size);
	if (job->id == job_menu) {
		name = "-";
		for (i = 0; i < job->data.menu.num; i++) {
			if (job->data.menu.entry[i].id == job_ipl &&
			    job->data.menu.entry[i].data.ipl.is_kdump)
				/* we start with 2nd bit */
				config_kdump |= (0x1 << (i + 1));
			if (job->data.menu.entry[i].pos ==
			    job->data.menu.default_pos) {
				if (job->data.menu.entry[i].id == job_ipl &&
				    job->data.menu.entry[i].data.ipl.is_kdump)
					/* default entry is first bit */
					config_kdump |= 0x1;
				name = job->data.menu.entry[i].name;
			}
		}
		flag = (job->data.menu.prompt != 0);
		timeout = job->data.menu.timeout;
		/* Be verbose */
		if (verbose) {
			printf("Preparing boot menu\n");
			printf("  Interactive prompt......: %s\n",
			       job->data.menu.prompt ? "enabled" : "disabled");
			if (job->data.menu.timeout == 0)
				printf("  Menu timeout............: "
				       "disabled\n");
			else
				printf("  Menu timeout............: %d "
				       "seconds\n", job->data.menu.timeout);
			printf("  Default configuration...: '%s'\n", name);
		}
	} else {
		if (job->id == job_ipl && job->data.ipl.is_kdump)
			config_kdump |= 0x1;
		name = job->name;
		flag = 0;
		timeout = 0;
	}
	/* Header */
	params = mb_alloc(&mb, sizeof(struct boot_stage2_params));
	if (!params)
		goto err_nospace;
	params->flag = flag;
	params->config_kdump = config_kdump;
	params->timeout = timeout;
	/* Banner text */
	str = mb_sprintf(&mb, "zIPL v%s interactive boot menu\n ",
			   RELEASE_STRING);
	if (!str)
		goto err_nospace;
	params->banner = (uint16_t) ((unsigned long) str -
				     (unsigned long) data);
	/* Default config text */
	if (name != NULL)
		str = mb_sprintf(&mb, " 0. default (%s)", name);
	else
		str = mb_sprintf(&mb, " 0. default");
	if (!str)
		goto err_nospace;
	params->config[0] = (uint16_t) ((unsigned long) str -
					(unsigned long) data);
	/* Skip rest if job is not an actual menu */
	if (job->id != job_menu)
		return 0;
	/* Config texts */
	for (i = 0; i < job->data.menu.num; i++) {
		const char *kdump_str = "";
		if (job->data.menu.entry[i].data.ipl.is_kdump)
			kdump_str = " (kdump)";
		str = mb_sprintf(&mb, "%2d. %s%s",
				 job->data.menu.entry[i].pos,
				 job->data.menu.entry[i].name,
				 kdump_str);
		if (!str)
			goto err_nospace_user;
		params->config[job->data.menu.entry[i].pos] = (uint16_t)
			((unsigned long) str - (unsigned long) data);
	}
	return 0;

err_nospace:
	error_reason("Not enough room for menu data");
	return -1;
err_nospace_user:
	error_reason("Not enough room for menu data (try fewer sections or "
		     "shorter names)");
	return -1;
}



int
boot_get_fba_stage2(void** data, size_t* size, struct job_data* job)
{
	void* buffer;
	int rc;

	buffer = misc_malloc(STAGE2_MAX_SIZE);
	if (buffer == NULL)
		return -1;
	memcpy(buffer, DATA_ADDR(fba2), DATA_SIZE(fba2));
	rc = store_stage2_menu(VOID_ADD(buffer, DATA_SIZE(fba2)),
			       STAGE2_MAX_SIZE - DATA_SIZE(fba2),
			       job);
	if (rc) {
		free(buffer);
		return rc;
	}
	*data = buffer;
	*size = STAGE2_MAX_SIZE;
	return 0;
}


int
boot_get_eckd_stage2(void** data, size_t* size, struct job_data* job)
{
	void* buffer;
	int rc;

	buffer = misc_malloc(STAGE2_MAX_SIZE);
	if (buffer == NULL)
		return -1;
	memcpy(buffer, DATA_ADDR(eckd2), DATA_SIZE(eckd2));
	rc = store_stage2_menu(VOID_ADD(buffer, DATA_SIZE(eckd2)),
			       STAGE2_MAX_SIZE - DATA_SIZE(eckd2),
			       job);
	if (rc) {
		free(buffer);
		return rc;
	}
	*data = buffer;
	*size = STAGE2_MAX_SIZE;
	return 0;
}


int
boot_get_tape_dump(void** data, size_t* size, uint64_t mem)
{
	void* buffer;

	buffer = misc_malloc(DATA_SIZE(tape2dump));
	if (buffer == NULL)
		return -1;
	memcpy(buffer, DATA_ADDR(tape2dump), DATA_SIZE(tape2dump));
	/* Write mem size to end of dump record */
	memcpy(VOID_ADD(buffer, DATA_SIZE(tape2dump) - sizeof(mem)), &mem,
	       sizeof(mem));
	*data = buffer;
	*size = DATA_SIZE(tape2dump);
	return 0;
}


int
boot_get_eckd_dump_stage2(void** data, size_t* size, uint64_t mem)
{
	void* buffer;

	buffer = misc_malloc(DATA_SIZE(eckd2dump_sv));
	if (buffer == NULL)
		return -1;
	memcpy(buffer, DATA_ADDR(eckd2dump_sv), DATA_SIZE(eckd2dump_sv));
	/* Write mem size to end of dump record */
	memcpy(VOID_ADD(buffer, DATA_SIZE(eckd2dump_sv) - sizeof(mem)),
	       &mem, sizeof(mem));
	*data = buffer;
	*size = DATA_SIZE(eckd2dump_sv);
	return 0;
}

int
boot_get_eckd_mvdump_stage2(void** data, size_t* size, uint64_t mem,
			    uint8_t force, struct mvdump_parm_table parm)
{
	void* buffer;

	buffer = misc_malloc(DATA_SIZE(eckd2dump_mv));
	if (buffer == NULL)
		return -1;
	memcpy(buffer, DATA_ADDR(eckd2dump_mv), DATA_SIZE(eckd2dump_mv));
	/* Write mem size and force indicator (as specified by zipl -M)
	 * to end of dump record, right before 512-byte parameter table */
	memcpy(VOID_ADD(buffer, DATA_SIZE(eckd2dump_mv) - sizeof(mem) -
			sizeof(struct mvdump_parm_table)), &mem, sizeof(mem));
	memcpy(VOID_ADD(buffer, DATA_SIZE(eckd2dump_mv) - sizeof(mem) -
			sizeof(force) - sizeof(struct mvdump_parm_table)),
	       &force, sizeof(force));
	memcpy(VOID_ADD(buffer, DATA_SIZE(eckd2dump_mv) -
			sizeof(struct mvdump_parm_table)), &parm,
	       sizeof(struct mvdump_parm_table));
	*data = buffer;
	*size = DATA_SIZE(eckd2dump_mv);
	return 0;
}


int
boot_get_fba_dump_stage2(void** data, size_t* size, uint64_t mem)
{
	void* buffer;

	buffer = misc_malloc(DATA_SIZE(fba2dump));
	if (buffer == NULL)
		return -1;
	memcpy(buffer, DATA_ADDR(fba2dump), DATA_SIZE(fba2dump));
	/* Write mem size to end of dump record */
	memcpy(VOID_ADD(buffer, DATA_SIZE(fba2dump) - sizeof(mem)),
	       &mem, sizeof(mem));
	*data = buffer;
	*size = DATA_SIZE(fba2dump);
	return 0;
}

void
boot_get_dump_info(struct boot_info *boot_info, uint8_t dev_type, void *param)
{
	memset(boot_info, 0, sizeof(*boot_info));
	memcpy(&boot_info->magic, BOOT_INFO_MAGIC, sizeof(boot_info->magic));
	boot_info->flags |= BOOT_INFO_FLAGS_ARCH;
	boot_info->dev_type = dev_type;
	boot_info->bp_type = BOOT_INFO_BP_TYPE_DUMP;
	boot_info->version = BOOT_INFO_VERSION;
	memcpy(&boot_info->bp.dump.param, param,
	       sizeof(boot_info->bp.dump.param));
}

void
boot_get_ipl_info(struct boot_info *boot_info, uint8_t dev_type,
		  disk_blockptr_t *bm_ptr, struct disk_info *info)
{
	memset(boot_info, 0, sizeof(*boot_info));
	memcpy(&boot_info->magic, BOOT_INFO_MAGIC, sizeof(boot_info->magic));
	boot_info->flags |= BOOT_INFO_FLAGS_ARCH;
	boot_info->dev_type = dev_type;
	boot_info->bp_type = BOOT_INFO_BP_TYPE_IPL;
	boot_info->version = BOOT_INFO_VERSION;
	bootmap_store_blockptr(&boot_info->bp, bm_ptr, info);
}

