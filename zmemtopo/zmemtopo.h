/*
 * zmemtopo - Show CEC memory topology data on System z
 *
 * Copyright IBM Corp. 2025
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZMEMTOPO_H
#define ZMEMTOPO_H

#include <stdint.h>
#include <sys/ioctl.h>

#include "lib/zt_common.h"

/* IOCTL macros and structs */
struct diag310_memtop {
	uint64_t address;
	uint64_t nesting_lvl;
};

/* Diag IOCTL macros */
#define DIAG_PATH		"/dev/diag"
#define DIAG_MAGIC_STR		'D'
#define DIAG310_GET_STRIDE	_IOR(DIAG_MAGIC_STR, 0x79, size_t)
#define DIAG310_GET_MEMTOPLEN	_IOWR(DIAG_MAGIC_STR, 0x7a, size_t)
#define DIAG310_GET_MEMTOPBUF	_IOWR(DIAG_MAGIC_STR, 0x7b, struct diag310_memtop)
/* sorting fields */
#define SORT_NR			1
#define SORT_NAME		2
#define SORT_SIZE		3
/* topology nesting levels */
#define NESTING_LVL_MAX		6
#define NESTING_LVL_DEF		3
#define NESTING_LVL_MIN		1
/* formatting macros */
#define LPAR_NAME_LEN		8
#define LPAR_NO_LEN		3
#define ENTRY_DIGIT		3
#define SUM_PAD			4
#define LEVEL_LEN		12
#define CELL_LEN		32
/* formatting symbols */
#define UTF_V			"\342\224\202"	/* |   */
#define UTF_VR			"\342\224\234"	/* |-  */
#define UTF_UR			"\342\224\224"	/* '-  */
#define UTF_SP			"\342\200\200"	/* space */
#define ASCII_V			"|"
#define ASCII_VR		"|-"
#define ASCII_UR		"`-"
/* scaling macros */
#define SCALE_KB		(1024UL)
#define SCALE_MB		(SCALE_KB * 1024UL)
#define SCALE_GB		(SCALE_MB * 1024UL)
#define SCALE_TB		(SCALE_GB * 1024UL)
#define UNIT_LEN		2

/* IOCTL data parsing structures */
struct diag310_t_hdr {
	uint32_t		tod[3];		/* time of day */
	uint8_t			lpar_cnt;	/* lpar count in CEC */
	uint8_t			reserved;
	uint16_t		this_part;	/* lpar number of the current system */
} __packed;

struct diag310_p_hdr {
	char			pname[8];	/* partition name */
	uint8_t			pn;		/* partition number */
	uint8_t			tie;		/* count of entries following this header */
	uint16_t		reserved1;
	uint32_t		reserved2;
} __packed;

struct diag310_tle {
	uint8_t			cl;		/* container level for this entry */
	uint8_t			ice_nr;		/* number of increments for this entry */
	uint16_t		ices[];		/* memory increment values */
};

/* structures to represent and format the parsed data */
struct stride_unit {
	char			suffix[UNIT_LEN];
	unsigned long		scale;
	unsigned long		size;
};

struct view_data {
	unsigned int		cell_len;
	unsigned int		entry_len;
	struct stride_unit	unit;
	unsigned int		level_len[NESTING_LVL_MAX];
	unsigned int		end_flag[NESTING_LVL_MAX + 1];
};

struct topology_entry {
	unsigned int		count;
	unsigned short		*increments;
};

struct partition {
	struct util_list_node	node;
	unsigned int		part_nr;
	unsigned int		increment_total;
	char			part_name[LPAR_NAME_LEN + 1];
	struct topology_entry	entries[NESTING_LVL_MAX];
};

struct partitions {
	struct util_list	*list;
};

#endif /* ZMEMTOPO_H */

