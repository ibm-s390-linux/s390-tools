/*
 * s390-tools/zipl/include/scan.h
 *   Scanner for zipl.conf configuration files
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#ifndef SCAN_H
#define SCAN_H

#include "zipl.h"


#define SCAN_SECTION_NUM		9
#define SCAN_KEYWORD_NUM		22
#define SCAN_KEYWORD_ONLY_NUM		1
#define SCAN_AUTOMENU_NAME		"zipl-automatic-menu"

enum scan_id {
	scan_id_empty = 0,
	scan_id_section_heading = 1,
	scan_id_menu_heading = 2,
	scan_id_keyword_assignment = 3,
	scan_id_number_assignment = 4,
	scan_id_keyword_only = 5,
};

enum scan_keyword_id {
	scan_keyword_default	= 0,
	scan_keyword_dumpto	= 1,
	scan_keyword_dumptofs	= 2,
	scan_keyword_image	= 3,
	scan_keyword_parameters	= 4,
	scan_keyword_parmfile	= 5,
	scan_keyword_ramdisk	= 6,
	scan_keyword_segment	= 7,
	scan_keyword_target	= 8,
	scan_keyword_prompt	= 9,
	scan_keyword_timeout	= 10,
	scan_keyword_defaultmenu = 11,
	scan_keyword_tape	= 12,
	scan_keyword_mvdump	= 13,
	scan_keyword_targetbase = 14,
	scan_keyword_targettype = 15,
	scan_keyword_targetgeometry = 16,
	scan_keyword_targetblocksize = 17,
	scan_keyword_targetoffset = 18,
	scan_keyword_defaultauto = 19,
	scan_keyword_kdump = 20,
	scan_keyword_secure = 21,
};

enum scan_section_type {
	section_invalid		= -1,
	section_default_auto	= 0,
	section_default_menu	= 1,
	section_default_section	= 2,
	section_ipl		= 3,
	section_segment		= 4,
	section_dump		= 5,
	section_dumpfs		= 6,
	section_ipl_tape	= 7,
	section_mvdump		= 8,
};

enum scan_target_type {
	target_type_invalid	= -1,
	target_type_scsi	= 0,
	target_type_fba		= 1,
	target_type_ldl		= 2,
	target_type_cdl		= 3,
};

enum scan_key_state {
	req, /* Keyword is required */
	opt, /* Keyword is optional */
	inv  /* Keyword is invalid */
};

struct scan_section_heading {
	char* name;
};

struct scan_menu_heading {
	char* name;
};

struct scan_keyword_assignment {
	enum scan_keyword_id keyword;
	char* value;
};

struct scan_number_assignment {
	int number;
	char* value;
};

struct scan_keyword_only {
	enum scan_keyword_id keyword;
};

struct scan_token {
	enum scan_id id;
	int line;
	union {
		struct scan_section_heading section;
		struct scan_menu_heading menu;
		struct scan_keyword_assignment keyword;
		struct scan_number_assignment number;
		struct scan_keyword_only keyword_only;
	} content;
};

/* Determines which keyword may be present in which section */
extern enum scan_key_state scan_key_table[SCAN_SECTION_NUM][SCAN_KEYWORD_NUM];


int scan_file(const char* filename, struct scan_token** array);
int scan_bls(const char* blsdir, struct scan_token** token, int scan_size);
void scan_free(struct scan_token* array);
char* scan_keyword_name(enum scan_keyword_id id);
int scan_check_defaultboot(struct scan_token* scan);
struct scan_token* scan_build_automenu(struct scan_token* scan);
int scan_check(struct scan_token* scan);
void scan_update_bls_path(struct scan_token *scan);
int scan_find_section(struct scan_token* scan, char* name, enum scan_id type,
		      int offset);
int scan_check_section_data(char* keyword[], int* line, char* name,
			    int section_line, enum scan_section_type* type);
int scan_check_target_data(char* keyword[], int* line);
enum scan_section_type scan_get_section_type(char* keyword[]);
enum scan_target_type scan_get_target_type(char *type);

#endif /* not SCAN_H */
