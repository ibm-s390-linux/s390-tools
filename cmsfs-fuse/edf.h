/*
 * cmsfs-fuse - CMS EDF filesystem support for Linux
 *
 * EDF and label structures
 *
 * Copyright IBM Corp. 2010, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _EDF_H
#define _EDF_H

#include "helper.h"

/*
 * File status table entry
 */
struct fst_entry {
	char		name[8];
	char		type[8];
	char		res1[8];

	short int	mode;
	char		res2[4];

	char		record_format;
	char		flag;
	int		record_len;
	char		res3[4];

	unsigned int	fop;
	/* number of data blocks (not incl. pointer blocks) */
	int		nr_blocks;
	int		nr_records;
	char		levels;
	char		ptr_size;
	char		date[6];
	char		res4[4];
};

struct cms_label {
	char		id[6];
	char		user_id[6];

	unsigned int	blocksize;
	unsigned int	dop;
	unsigned int	f_cylinders;
	unsigned int	max_cylinders;

	unsigned int	total_blocks;
	unsigned int	used_blocks;

	unsigned int	fst_entry_size;
	unsigned int	fst_per_block;

	char		date[6];
	unsigned int	res1[3];
	char		res2[8];
};

#define RECORD_LEN_VARIABLE	0xe5
#define RECORD_LEN_FIXED	0xc6

/* TODO: correct for fixed? */
#define MAX_RECORD_LEN		0xffff

#define FST_ENTRY_SIZE		sizeof(struct fst_entry)
#define FST_ENTRY_DIR_NAME	0x0000000100000000ULL
#define FST_ENTRY_DIR_TYPE	0xc4c9d9c5c3e3d6d9ULL	/* 'DIRECTOR' */
#define FST_ENTRY_ALLOC_NAME	0x0000000200000000ULL
#define FST_ENTRY_ALLOC_TYPE	0xc1d3d3d6c3d4c1d7ULL	/* 'ALLOCMAP' */

#define FST_FLAG_CENTURY	0x0008
#define FST_FOP_OFFSET		0x28
#define FST_LEVEL_OFFSET	0x34

#define VAR_RECORD_HEADER_SIZE	0x2
#define VAR_RECORD_SPANNED	0xffffffff

#define PTR_SIZE		(sizeof(struct fixed_ptr))
#define VPTR_SIZE		(sizeof(struct var_ptr))

struct fixed_ptr {
	unsigned int next;
};

struct var_ptr {
	unsigned int next;
	int hi_record_nr;
	unsigned int disp;
};

static inline int is_directory(const char *name,
			       const char *type)
{
	if ((*(unsigned long long *) name) != FST_ENTRY_DIR_NAME)
		return 0;
	if ((*(unsigned long long *) type) != FST_ENTRY_DIR_TYPE)
		return 0;
	return 1;
}

static inline int is_allocmap(const char *name,
			      const char *type)
{
	if ((*(unsigned long long *) name) != FST_ENTRY_ALLOC_NAME)
		return 0;
	if ((*(unsigned long long *) type) != FST_ENTRY_ALLOC_TYPE)
		return 0;
	return 1;
}

static inline int is_file(void *name, void *type)
{
	if ((*(unsigned long long *) name) == 0ULL)
		return 0;
	/* Assumption: type = 0 is not legal */
	if ((*(unsigned long long *) type) == 0ULL)
		return 0;
	return 1;
}

#endif
