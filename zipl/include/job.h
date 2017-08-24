/*
 * s390-tools/zipl/include/job.h
 *   Functions and data structures representing the actual 'job' that the
 *   user wants us to execute.
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef JOB_H
#define JOB_H

#include <stdbool.h>

#include "disk.h"
#include "zipl.h"


enum job_id {
	job_print_usage = 1,
	job_print_version = 2,
	job_ipl = 3,
	job_segment = 4,
	job_dump_partition = 5,
	job_menu = 6,
	job_ipl_tape = 7,
	job_mvdump = 8,
};

struct job_target_data {
	char* bootmap_dir;
	char* targetbase;
	disk_type_t targettype;
	int targetcylinders;
	int targetheads;
	int targetsectors;
	int targetblocksize;
	blocknum_t targetoffset;
};

struct job_ipl_data {
	char* image;
	char* parmline;
	char* ramdisk;
	address_t image_addr;
	address_t parm_addr;
	address_t ramdisk_addr;
	int is_kdump;
	bool optional;
	bool ignore;
};

struct job_segment_data {
	char* segment;
	address_t segment_addr;
};

struct job_dump_data {
	char* device;
	char* image;
	char* parmline;
	char* ramdisk;
	address_t image_addr;
	address_t parm_addr;
	address_t ramdisk_addr;
	uint64_t mem;
};

struct job_mvdump_data {
	char* device_list;
	int device_count;
	char* device[MAX_DUMP_VOLUMES];
	uint64_t mem;
	uint8_t force;
};

struct job_ipl_tape_data {
	char* device;
	char* image;
	char* parmline;
	char* ramdisk;
	address_t image_addr;
	address_t parm_addr;
	address_t ramdisk_addr;
};


union job_menu_entry_data {
	struct job_ipl_data ipl;
	struct job_dump_data dump;
};

struct job_menu_entry {
	int pos;
	char* name;
	enum job_id id;
	union job_menu_entry_data data;
	int is_secure;
};

struct job_menu_data {
	int num;
	int default_pos;
	int prompt;
	int timeout;
	struct job_menu_entry* entry;
};

struct job_data {
	enum job_id id;
	struct job_target_data target;
	char* name;
	union {
		struct job_ipl_data ipl;
		struct job_menu_data menu;
		struct job_segment_data segment;
		struct job_dump_data dump;
		struct job_ipl_tape_data ipl_tape;
		struct job_mvdump_data mvdump;
	} data;
	int noninteractive;
	int verbose;
	int add_files;
	int dry_run;
	int command_line;
	int is_secure;
};


int job_get(int argc, char* argv[], struct job_data** data);
void job_free(struct job_data* job);
int type_from_target(char *target, disk_type_t *type);
int check_job_dump_images(struct job_dump_data* dump, char* name);

#endif /* not JOB_H */
