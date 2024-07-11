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

/*
 * Set of parameters per physical disk, which are provided
 * either by user, or by helper script
 */
struct target {
	char *targetbase;
	disk_type_t targettype;
	int targetcylinders;
	int targetheads;
	int targetsectors;
	int targetblocksize;
	blocknum_t targetoffset;
	int check_params;
};

/* target information source */
typedef enum {
	source_unknown = 0,
	source_auto = 1,
	source_user = 2,
	source_script = 3
} source_t;

struct job_target_data {
	char *bootmap_dir;
	int nr_targets;
	struct target targets[MAX_TARGETS];
	source_t source;
};

enum target_params {
	TARGET_BASE,
	TARGET_TYPE,
	TARGET_GEOMETRY,
	TARGET_BLOCKSIZE,
	TARGET_OFFSET,
	LAST_TARGET_PARAM
};

struct job_common_ipl_data {
	char* image;
	char* parmline;
	char* ramdisk;
	address_t image_addr;
	address_t parm_addr;
	address_t ramdisk_addr;
	bool optional;
	bool ignore;
};

struct job_ipl_data {
	struct job_common_ipl_data common;
	address_t envblk_addr;
	int is_kdump;
};

struct job_envblk_data {
	int size;
	char *buf;
};

struct job_segment_data {
	char* segment;
	address_t segment_addr;
};

struct job_dump_data {
	struct job_common_ipl_data common;
	char* device;
	uint64_t mem;
	bool no_compress;
};

struct job_mvdump_data {
	char* device_list;
	int device_count;
	char* device[MAX_DUMP_VOLUMES];
	uint64_t mem;
	uint8_t force;
};

struct job_ipl_tape_data {
	struct job_common_ipl_data common;
	char* device;
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
	struct job_envblk_data envblk;
	char* name;
	union {
		struct job_ipl_data ipl;
		struct job_menu_data menu;
		struct job_segment_data segment;
		struct job_dump_data dump;
		struct job_ipl_tape_data ipl_tape;
		struct job_mvdump_data mvdump;
	} data;
	int dump_mounted;
	int bootmap_dir_created;
	int noninteractive;
	int verbose;
	int add_files;
	int dry_run;
	int command_line;
	int is_secure;
	int is_ldipl_dump;
};

static inline struct target *target_at(struct job_target_data *data,
				       int index)
{
	return index >= MAX_TARGETS ? NULL : &data->targets[index];
}

static inline char *get_targetbase(struct job_target_data *data, int index)
{
	return target_at(data, index)->targetbase;
}

static inline void set_targetbase(struct job_target_data *data, int index,
				  char *value)
{
	target_at(data, index)->targetbase = value;
}

static inline disk_type_t get_targettype(struct job_target_data *data,
					 int index)
{
	return target_at(data, index)->targettype;
}

int set_targettype(struct job_target_data *data, int index, char *value);

static inline char *job_get_targetbase(struct job_data *job)
{
	return get_targetbase(&job->target, 0);
}

static inline void job_set_targetbase(struct job_data *job, char *value)
{
	set_targetbase(&job->target, 0, value);
}

static inline int job_get_nr_targets(struct job_data *job)
{
	return job->target.nr_targets;
}

static inline void job_set_nr_targets(struct job_data *job, int value)
{
	job->target.nr_targets = value;
}

static inline disk_type_t job_get_targettype(struct job_data *job)
{
	return get_targettype(&job->target, 0);
}

int job_set_targettype(struct job_data *job, char *value);

#define define_target_param_ops(_TYPE_, _PARAM_)		        \
static inline _TYPE_ get_target##_PARAM_(struct job_target_data *data,  \
					 int index)			\
{									\
	return target_at(data, index)->target##_PARAM_;			\
}									\
									\
static inline void set_target##_PARAM_(struct job_target_data *data,	\
				       int index, _TYPE_ value)		\
{									\
	target_at(data, index)->target##_PARAM_ = value;		\
}									\
									\
static inline _TYPE_ job_get_target##_PARAM_(struct job_data *job)	\
{									\
	return get_target##_PARAM_(&job->target, 0);			\
}									\
									\
static inline void job_set_target##_PARAM_(struct job_data *job,        \
					   _TYPE_ value)		\
{									\
	set_target##_PARAM_(&job->target, 0, value);			\
}

define_target_param_ops(int, cylinders)
define_target_param_ops(int, heads)
define_target_param_ops(int, sectors)
define_target_param_ops(int, blocksize)
define_target_param_ops(blocknum_t, offset)

/**
 * Return true, if target parameters are set at least for one target base disk
 */
static inline int target_parameters_are_set(struct job_target_data *td)
{
	return get_targetbase(td, 0) != NULL;
}

int job_get(int argc, char* argv[], struct job_data** data);
void job_free(struct job_data* job);
void free_target_data(struct job_target_data *td);
int type_from_target(char *target, disk_type_t *type);
int check_job_dump_images(struct job_dump_data* dump, char* name);
int check_job_images_ngdump(struct job_dump_data* dump, char* name);
bool is_ngdump_enabled(struct job_data *job);

#endif /* not JOB_H */
