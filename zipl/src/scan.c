/*
 * zipl - zSeries Initial Program Loader tool
 *
 * Scanner for zipl.conf configuration files
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */


/* Need ISOC99 function isblank() in ctype.h */
#ifndef __USE_ISOC99
#define __USE_ISOC99
#endif

/* Need GNU function strverscmp() in dirent.h */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <sys/stat.h>

#include "lib/util_base.h"

#include "boot.h"
#include "error.h"
#include "misc.h"
#include "scan.h"


/* Determines which keyword may be present in which section */
enum scan_key_state scan_key_table[SCAN_SECTION_NUM][SCAN_KEYWORD_NUM] = {
/*	 defa dump dump imag para parm ramd segm targ prom time defa tape mv
 *	 ult  to   tofs e    mete file isk  ent  et   pt   out  ultm      dump
 *			     rs                                 enu
 *
 *       targ targ targ targ targ defa kdum secu
 *       etba etty etge etbl etof ulta p    re
 *       se   pe   omet ocks fset uto
 *                 ry   ize
 */
/* default auto */
	{opt, inv, inv, inv, inv, inv, inv, inv, req, opt, opt, inv, inv, inv,
	 opt, opt, opt, opt, opt, opt, inv, opt},
/* default menu */
	{inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, req, inv, inv,
	 inv, inv, inv, inv, inv, inv, inv, opt},
/* default section */
	{req, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv,
	 inv, inv, inv, inv, inv, inv, inv, opt},
/* ipl		*/
	{inv, inv, inv, req, opt, opt, opt, inv, req, inv, inv, inv, inv, inv,
	 opt, opt, opt, opt, opt, inv, opt, opt},
/* segment load */
	{inv, inv, inv, inv, inv, inv, inv, req, req, inv, inv, inv, inv, inv,
	 inv, inv, inv, inv, inv, inv, inv, inv},
/* part dump	*/
	{inv, req, inv, inv, inv, inv, inv, inv, opt, inv, inv, inv, inv, inv,
	 inv, inv, inv, inv, inv, inv, inv, inv},
/* fs dump	*/
	{inv, inv, req, inv, opt, opt, inv, inv, req, inv, inv, inv, inv, inv,
	 inv, inv, inv, inv, inv, inv, inv, inv},
/* ipl tape	*/
	{inv, inv, inv, req, opt, opt, opt, inv, inv, inv, inv, inv, req, inv,
	 inv, inv, inv, inv, inv, inv, inv, inv},
/* multi volume dump	*/
	{inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, inv, req,
	 inv, inv, inv, inv, inv, inv, inv, inv}
};

/* Determines which keyword may be present in a menu section */
enum scan_key_state scan_menu_key_table[SCAN_KEYWORD_NUM] = {
/* menu section */
	 opt, inv, inv, inv, inv, inv, inv, inv, req, opt, opt, inv, inv, inv,
	 opt, opt, opt, opt, opt, inv, inv, opt
};

/* Mapping of keyword IDs to strings */
static const struct {
	char* keyword;
	enum scan_keyword_id id;
} keyword_list[] = {
	{ "defaultmenu", scan_keyword_defaultmenu},
	{ "default", scan_keyword_default },
	{ "dumptofs", scan_keyword_dumptofs },
	{ "dumpto", scan_keyword_dumpto },
	{ "image", scan_keyword_image },
	{ "mvdump", scan_keyword_mvdump },
	{ "parameters", scan_keyword_parameters },
	{ "parmfile", scan_keyword_parmfile },
	{ "ramdisk", scan_keyword_ramdisk },
	{ "segment", scan_keyword_segment },
	{ "targetbase", scan_keyword_targetbase},
	{ "targettype", scan_keyword_targettype},
	{ "targetgeometry", scan_keyword_targetgeometry},
	{ "targetblocksize", scan_keyword_targetblocksize},
	{ "targetoffset", scan_keyword_targetoffset},
	{ "target", scan_keyword_target},
	{ "prompt", scan_keyword_prompt},
	{ "timeout", scan_keyword_timeout},
	{ "tape", scan_keyword_tape},
	{ "kdump", scan_keyword_kdump},
	{ "secure", scan_keyword_secure},
};

/* List of keywords that are used without an assignment */
static const struct {
	char* keyword;
	enum scan_keyword_id id;
} keyword_only_list[] = {
	{ "defaultauto", scan_keyword_defaultauto}
};

/* Retrieve name of keyword identified by ID. */
char *
scan_keyword_name(enum scan_keyword_id id)
{
	unsigned int i;

	for (i=0; i < ARRAY_SIZE(keyword_list); i++) {
		if (id == keyword_list[i].id)
			return keyword_list[i].keyword;
	}
	for (i=0; i < ARRAY_SIZE(keyword_only_list); i++) {
		if (id == keyword_only_list[i].id)
			return keyword_only_list[i].keyword;
	}
	return "<unknown>";
}


/* Advance the current file pointer of file buffer FILE until the current
 * character is no longer a blank. Return 0 if at least one blank
 * character was encountered, non-zero otherwise. */
static int
skip_blanks(struct misc_file_buffer* file)
{
	int rc;

	rc = -1;
	for (; isblank(misc_get_char(file, 0)); file->pos++)
		rc = 0;
	return rc;
}


/* Advance the current file position to beginning of next line in file buffer
 * FILE or to end of file. */
static void
skip_line(struct misc_file_buffer* file)
{
	for (;; file->pos++) {
		switch (misc_get_char(file, 0)) {
		case '\n':
			file->pos++;
			return;
		case EOF:
			return;
		}
	}
}


/* Skip trailing blanks of line. On success, return zero and set the file
 * buffer position to beginning of next line or EOF. Return non-zero if
 * non-blank characters were found before end of line. */
static int
skip_trailing_blanks(struct misc_file_buffer* file)
{
	int current;

	for (;; file->pos++) {
		current = misc_get_char(file, 0);
		if (current == '\n') {
			file->pos++;
			return 0;
		} else if (current == EOF)
			return 0;
		else if (!isblank(current))
			return -1;
	}
}


static int
scan_section_heading(struct misc_file_buffer* file, struct scan_token* token,
		     int line)
{
	int start_pos;
	int end_pos;
	int current;
	char* name;

	for (start_pos=file->pos; misc_get_char(file, 0) != ']'; file->pos++) {
		current = misc_get_char(file, 0);
		switch (current) {
		case EOF:
		case '\n':
			error_reason("Line %d: unterminated section heading",
				     line);
			return -1;
		default:
			if (!(isalnum(current) || ispunct(current))) {
				error_reason("Line %d: invalid character in "
					     "section name", line);
				return -1;
			}
		}
	}
	end_pos = file->pos;
	if (end_pos == start_pos) {
		error_reason("Line %d: empty section name", line);
		return -1;
	}
	file->pos++;
	if (skip_trailing_blanks(file)) {
		error_reason("Line %d: unexpected characters after section "
			     "name", line);
		return -1;
	}
	name = (char *) misc_malloc(end_pos - start_pos + 1);
	if (name == NULL)
		return -1;
	memcpy(name, &file->buffer[start_pos], end_pos - start_pos);
	name[end_pos - start_pos] = 0;
	token->id = scan_id_section_heading;
	token->line = line;
	token->content.section.name = name;
	return 0;
}


static int
scan_menu_heading(struct misc_file_buffer* file, struct scan_token* token,
		  int line)
{
	int start_pos;
	int end_pos;
	int current;
	char* name;

	for (start_pos=file->pos; ; file->pos++) {
		current = misc_get_char(file, 0);
		if ((current == EOF) || (current == '\n'))
			break;
		else if (isblank(current))
			break;
		else if (!isalnum(current)) {
			error_reason("Line %d: invalid character in menu name ",
				     line);
			return -1;
		}
	}
	end_pos = file->pos;
	if (skip_trailing_blanks(file)) {
		error_reason("Line %d: blanks not allowed in menu name",
			     line);
		return -1;
	}
	if (end_pos == start_pos) {
		error_reason("Line %d: empty menu name", line);
		return -1;
	}
	name = (char *) misc_malloc(end_pos - start_pos + 1);
	if (name == NULL)
		return -1;
	memcpy(name, &file->buffer[start_pos], end_pos - start_pos);
	name[end_pos - start_pos] = 0;
	token->id = scan_id_menu_heading;
	token->line = line;
	token->content.menu.name = name;
	return 0;
}


static int
scan_number(struct misc_file_buffer* file, int* number, int line)
{
	int start_pos;
	int old_number;
	int new_number;

	old_number = 0;
	new_number = 0;
	start_pos = file->pos;
	for (; isdigit(misc_get_char(file, 0)); file->pos++) {
		new_number = old_number*10 + misc_get_char(file, 0) - '0';
		if (new_number < old_number) {
			error_reason("Line %d: number too large", line);
			return -1;
		}
		old_number = new_number;
	}
	if (file->pos == start_pos) {
		error_reason("Line %d: number expected", line);
		return -1;
	}
	*number = new_number;
	return 0;
}


static int
scan_value_string(struct misc_file_buffer* file, char** value, int line)
{
	int quote;
	int start_pos;
	int end_pos;
	int last_nonspace;
	int current;
	char* string;

	current = misc_get_char(file, 0);
	if (current == '\"') {
		quote = '\"';
		file->pos++;
	} else if (current == '\'') {
		quote = '\'';
		file->pos++;
	} else quote = 0;
	last_nonspace = -1;
	for (start_pos=file->pos;; file->pos++) {
		current = misc_get_char(file, 0);
		if ((current == EOF) || (current == '\n')) {
			break;
		} else if (quote) {
			if (current == quote)
				break;
		} else if (!isblank(current))
			last_nonspace = file->pos;
	}
	end_pos = file->pos;
	if (quote) {
		if (current != quote) {
			error_reason("Line %d: unterminated quotes", line);
			return -1;
		}
	} else if (last_nonspace >= 0)
		end_pos = last_nonspace + 1;
	string = (char *) misc_malloc(end_pos - start_pos + 1);
	if (string == NULL)
		return -1;
	if (end_pos > start_pos)
		memcpy(string, &file->buffer[start_pos], end_pos - start_pos);
	string[end_pos - start_pos] = 0;
	*value = string;
	if (quote)
		file->pos++;
	return 0;
}


static int
scan_number_assignment(struct misc_file_buffer* file, struct scan_token* token,
		      int line)
{
	int rc;

	rc = scan_number(file, &token->content.number.number, line);
	if (rc)
		return rc;
	skip_blanks(file);
	if (misc_get_char(file, 0) != '=') {
		error_reason("Line %d: number expected as keyword", line);
		return -1;
	}
	file->pos++;
	skip_blanks(file);
	rc = scan_value_string(file, &token->content.number.value, line);
	if (rc)
		return rc;
	if (skip_trailing_blanks(file)) {
		error_reason("Line %d: unexpected characters at end of line",
			     line);
		return -1;
	}
	token->id = scan_id_number_assignment;
	token->line = line;
	return 0;
}

static int
match_keyword(struct misc_file_buffer* file, const char* keyword)
{
	unsigned int i;

	for (i=0; i<strlen(keyword); i++)
		if (misc_get_char(file, i) != keyword[i])
			return -1;
	return 0;
}


static int
scan_keyword(struct misc_file_buffer* file, enum scan_keyword_id* id, int line)
{
	unsigned int i;

	for (i=0; i < ARRAY_SIZE(keyword_list); i++)
		if (match_keyword(file, keyword_list[i].keyword) == 0) {
			file->pos += strlen(keyword_list[i].keyword);
			*id = keyword_list[i].id;
			return 0;
		}
	error_reason("Line %d: unknown keyword", line);
	return -1;
}


static int
scan_keyword_assignment(struct misc_file_buffer* file, struct scan_token* token,
		       int line)
{
	int rc;

	rc = scan_keyword(file, &token->content.keyword.keyword, line);
	if (rc)
		return rc;
	skip_blanks(file);
	if (misc_get_char(file, 0) != '=') {
		error_reason("Line %d: unexpected characters after keyword",
			     line);
		return -1;
	}
	file->pos++;
	skip_blanks(file);
	rc = scan_value_string(file, &token->content.keyword.value, line);
	if (rc)
		return rc;
	if (skip_trailing_blanks(file)) {
		error_reason("Line %d: unexpected characters at end of line",
			     line);
		return -1;
	}
	token->id = scan_id_keyword_assignment;
	token->line = line;
	return 0;
}


static int
scan_keyword_only(struct misc_file_buffer* file, enum scan_keyword_id* id,
		  int line)
{
	unsigned int i;

	for (i=0; i < ARRAY_SIZE(keyword_only_list); i++)
		if (match_keyword(file, keyword_only_list[i].keyword) == 0) {
			file->pos += strlen(keyword_only_list[i].keyword);
			*id = keyword_only_list[i].id;
			return 0;
		}
	error_reason("Line %d: unknown keyword", line);
	return -1;
}


static int
scan_keyword_only_statement(struct misc_file_buffer* file,
			    struct scan_token* token, int line)
{
	int rc;

	rc = scan_keyword_only(file, &token->content.keyword.keyword, line);
	if (rc)
		return rc;
	if (skip_trailing_blanks(file)) {
		error_reason("Line %d: unexpected characters at end of line",
			     line);
		return -1;
	}
	token->id = scan_id_keyword_only;
	token->line = line;
	return 0;
}


static int
search_line_for(struct misc_file_buffer* file, int search)
{
	int i;
	int current;

	for (i=0; ; i++) {
		current = misc_get_char(file, i);
		switch (current) {
		case EOF:
		case '\n':
			return 0;
		default:
			if (current == search)
				return 1;
		}
	}
}


void
scan_free(struct scan_token* array)
{
	int i;

	for (i=0; array[i].id != 0; i++) {
		switch (array[i].id) {
		case scan_id_section_heading:
			if (array[i].content.section.name != NULL) {
				free(array[i].content.section.name);
				array[i].content.section.name = NULL;
			}
			break;
		case scan_id_menu_heading:
			if (array[i].content.menu.name != NULL) {
				free(array[i].content.menu.name);
				array[i].content.menu.name = NULL;
			}
			break;
		case scan_id_keyword_assignment:
			if (array[i].content.keyword.value != NULL) {
				free(array[i].content.keyword.value);
				array[i].content.keyword.value = NULL;
			}
			break;
		case scan_id_number_assignment:
			if (array[i].content.number.value != NULL) {
				free(array[i].content.number.value);
				array[i].content.number.value = NULL;
			}
			break;
		default:
			break;
		}
	}
	free(array);
}


#define INITIAL_ARRAY_LENGTH 40

/* Scan file FILENAME for tokens. Upon success, return the number allocated
 * tokens and set TOKEN to point to a NULL-terminated array of scan_tokens,
 * i.e. the token id of the last token is 0. Return non-zero otherwise. */
int
scan_file(const char* filename, struct scan_token** token)
{
	struct misc_file_buffer file;
	struct scan_token* array;
	struct scan_token* buffer;
	int pos;
	int size;
	int current;
	int rc;
	int line;

	rc = misc_get_file_buffer(filename, &file);
	if (rc)
		return rc;
	size = INITIAL_ARRAY_LENGTH;
	pos = 0;
	array = (struct scan_token*) misc_malloc(size *
						 sizeof(struct scan_token));
	if (array == NULL) {
		misc_free_file_buffer(&file);
		return -1;
	}
	memset(array, 0, size * sizeof(struct scan_token));
	line = 1;
	while ((size_t) file.pos < file.length) {
		skip_blanks(&file);
		current = misc_get_char(&file, 0);
		switch (current) {
		case '[':
			file.pos++;
			rc = scan_section_heading(&file, &array[pos++], line);
			break;
		case ':':
			file.pos++;
			rc = scan_menu_heading(&file, &array[pos++], line);
			break;
		case '#':
			file.pos++;
			skip_line(&file);
			rc = 0;
			break;
		case '\n':
			file.pos++;
			rc = 0;
			break;
		case EOF:
			rc = 0;
			break;
		default:
			if (search_line_for(&file, '=')) {
				if (isdigit(current))
					rc = scan_number_assignment(
						&file, &array[pos++], line);
				else
					rc = scan_keyword_assignment(
						&file, &array[pos++], line);
			} else {
				rc = scan_keyword_only_statement(&file,
							&array[pos++], line);
			}
		}
		if (rc)
			break;
		line++;
		/* Enlarge array if there is only one position left */
		if (pos + 1 >= size) {
			size *= 2;
			buffer = (struct scan_token *)
					misc_malloc(size *
						    sizeof(struct scan_token));
			if (buffer == NULL) {
				rc = -1;
				break;
			}
			memset(buffer, 0, size * sizeof(struct scan_token));
			memcpy(buffer, array, pos*sizeof(struct scan_token));
			free(array);
			array = buffer;
		}
	}
	misc_free_file_buffer(&file);
	if (rc) {
		scan_free(array);
		return rc;
	}

	*token = array;
	return size;
}


static int
bls_filter(const struct dirent *ent)
{
	int offset = strlen(ent->d_name) - strlen(".conf");

	if (offset < 0)
		return 0;

	return strncmp(ent->d_name + offset, ".conf", strlen(".conf")) == 0;
}


static int
bls_sort(const struct dirent **ent_a, const struct dirent **ent_b)
{
	return strverscmp((*ent_a)->d_name, (*ent_b)->d_name);
}


static int
scan_append_section_heading(struct scan_token* scan, int* index, char* name);
static int
scan_append_keyword_assignment(struct scan_token* scan, int* index,
			       enum scan_keyword_id id, char* value);


static int
scan_bls_field(struct misc_file_buffer *file, struct scan_token* scan,
	       int* index)
{
	int current;
	int key_start, key_end;
	int val_start, val_end;
	char *val;

	for (key_start = file->pos; ; file->pos++) {
		current = misc_get_char(file, 0);

		if (isblank(current)) {
			key_end = file->pos;
			skip_blanks(file);
			val_start = file->pos;
			break;
		}

		if (!isalnum(current) && current != '_' && current != '-')
			return -1;
	}

	for (; ; file->pos++) {
		current = misc_get_char(file, 0);

		if (current == '\n' || current == EOF)
			break;
	}

	val_end = file->pos;

	while (val_end > val_start && isblank(file->buffer[val_end - 1]))
		val_end--;

	file->buffer[key_end] = '\0';
	file->buffer[val_end] = '\0';

	if (strncmp("title", &file->buffer[key_start], key_end - key_start) == 0) {
		scan_append_section_heading(scan, index, &file->buffer[val_start]);
	}

	if (strncmp("linux", &file->buffer[key_start], key_end - key_start) == 0) {
		misc_asprintf(&val, "%s", &file->buffer[val_start]);
		scan_append_keyword_assignment(scan, index, scan_keyword_image, val);
		free(val);
	}

	if (strncmp("options", &file->buffer[key_start], key_end - key_start) == 0) {
		scan_append_keyword_assignment(scan, index, scan_keyword_parameters,
					       &file->buffer[val_start]);
	}

	if (strncmp("initrd", &file->buffer[key_start], key_end - key_start) == 0) {
		misc_asprintf(&val, "%s", &file->buffer[val_start]);
		scan_append_keyword_assignment(scan, index, scan_keyword_ramdisk, val);
		free(val);
	}

	return 0;
}

/**
 * find a line with keyword "title" and move it to the top
 */
static int sort_bls_fields(struct misc_file_buffer *file, char *filename)
{
	bool is_title = false;
	size_t title_len = 0;
	int nr_titles = 0;
	size_t title_off;
	char *title;
	int current;
	size_t len;

	while (file->length - file->pos > 4 /* for "title" */) {
		if (strncmp("title", &file->buffer[file->pos], 5) == 0) {
			is_title = true;
			nr_titles++;
			title_off = file->pos;
		}
		for (len = 0;; file->pos++, len++) {
			current = misc_get_char(file, 0);
			if (current == '\n' || current == EOF)
				break;
		}
		if (is_title == true)
			title_len = len;
		if (current == EOF)
			break;
		file->pos++;
	}
	file->pos = 0;

	if (nr_titles == 0) {
		error_reason("no title in %s", filename);
		return -1;
	}
	if (nr_titles > 1) {
		error_reason("more than one title in %s", filename);
		return -1;
	}
	if (title_off == 0)
		return 0;

	title = misc_malloc(title_len);
	if (!title)
		return -1;
	/*
	 * copy the title field w/o trailing '\n' to the temporary buffer
	 */
	memcpy(title, &file->buffer[title_off], title_len);
	/*
	 * shift preceded memory region w/o trailing '\n' to the right
	 */
	assert(file->buffer[title_off - 1] == '\n');
	memmove(&file->buffer[title_len + 1], &file->buffer[0], title_off - 1);
	file->buffer[title_len] = '\n';
	memcpy(&file->buffer[0], title, title_len);

	free(title);
	return 0;
}

int
scan_bls(const char* blsdir, struct scan_token** token, int scan_size)
{
	int count = 0;
	int size, remaining = 0, n, current, rc = -1;
	struct scan_token* buffer;
	struct scan_token* array = *token;
	struct dirent** bls_entries;
	struct misc_file_buffer file;
	struct stat sb;
	char filename[PATH_MAX];

	if (!(stat(blsdir, &sb) == 0 && S_ISDIR(sb.st_mode)))
		return 0;

	n = scandir(blsdir, &bls_entries, bls_filter, bls_sort);
	if (n <= 0)
		return n;

	while (array[count].id != 0)
		count++;

	remaining = scan_size - count;

	/* The array of scanned tokens is allocated when the zipl config file is
	 * parsed. Its size is a multiple of INITIAL_ARRAY_LENGTH so it may have
	 * enough space to scan all the tokens that are defined in the BLS files.
	 * Calculate if is enough assuming that a BLS fragment can contain up to
	 * 4 tokens: a section heading and 3 keywords (image, ramdisk, parameter).
	 */
	if (remaining < n * 4) {
		size = scan_size - remaining + (n * 4);
		buffer = (struct scan_token *)misc_malloc(size * sizeof(struct scan_token));
		if (!buffer)
			goto err;
		memset(buffer, 0, size * sizeof(struct scan_token));
		memcpy(buffer, array, count * sizeof(struct scan_token));
	} else {
		buffer = array;
	}

	while (n--) {
		sprintf(filename, "%s/%s", blsdir, bls_entries[n]->d_name);
		printf("Using BLS config file '%s'\n", filename);

		rc = misc_get_file_buffer(filename, &file);
		if (rc)
			goto err;

		rc = sort_bls_fields(&file, filename);
		if (rc)
			goto err;

		while ((size_t)file.pos < file.length) {
			current = misc_get_char(&file, 0);
			switch (current) {
			case '#':
				file.pos++;
				skip_line(&file);
				break;
			case EOF:
				break;
			case '\t':
			case '\n':
			case '\0':
			case ' ':
				file.pos++;
				break;
			default:
				rc = scan_bls_field(&file, buffer, &count);
				if (rc) {
					error_reason("Incorrect BLS field in "
						"config file %s\n", filename);
					goto err;
				}
				break;
			}
		}

		misc_free_file_buffer(&file);
		free(bls_entries[n]);
	}

	*token = buffer;
	rc = 0;
err:
	if (n > 0) {
		do {
			free(bls_entries[n]);
		} while (n-- > 0);
	}

	free(bls_entries);
	return rc;
}


/* Search scanned tokens SCAN for a section/menu heading (according to
 * TYPE) of the given NAME, beginning at token OFFSET. Return the index of
 * the section/menu heading on success, a negative value on error. */
int
scan_find_section(struct scan_token* scan, char* name, enum scan_id type,
		  int offset)
{
	int i;

	for (i=offset; (int) scan[i].id != 0; i++) {
		if ((scan[i].id == scan_id_section_heading) &&
		    (type == scan_id_section_heading))
			if (strcmp(scan[i].content.section.name, name) == 0)
				return i;
		if ((scan[i].id == scan_id_menu_heading) &&
		    (type == scan_id_menu_heading))
			if (strcmp(scan[i].content.menu.name, name) == 0)
				return i;
	}
	return -1;
}


/* Check whether a string contains a load address as comma separated hex
 * value at end of string. */
static int
contains_address(char* string)
{
	unsigned long long result;

	/* Find trailing comma */
	string = strrchr(string, ',');
	if (string != NULL) {
		/* Try to scan a hexadecimal address */
		if (sscanf(string + 1, "%llx", &result) == 1) {
			return 1;
		}
	}
	return 0;
}


enum scan_section_type
scan_get_section_type(char* keyword[])
{
	if (keyword[(int) scan_keyword_tape] != NULL)
		return section_ipl_tape;
	else if (keyword[(int) scan_keyword_image] != NULL)
		return section_ipl;
	else if (keyword[(int) scan_keyword_segment] != NULL)
		return section_segment;
	else if (keyword[(int) scan_keyword_dumpto] != NULL)
		return section_dump;
	else if (keyword[(int) scan_keyword_dumptofs] != NULL)
		return section_dumpfs;
	else if (keyword[(int) scan_keyword_mvdump] != NULL)
		return section_mvdump;
	else
		return section_invalid;
}

enum scan_target_type
scan_get_target_type(char *type)
{
	if (strcasecmp(type, "SCSI") == 0)
		return target_type_scsi;
	else if (strcasecmp(type, "FBA") == 0)
		return target_type_fba;
	else if (strcasecmp(type, "LDL") == 0)
		return target_type_ldl;
	else if (strcasecmp(type, "CDL") == 0)
		return target_type_cdl;
	return target_type_invalid;
}

/* Check section data for correctness. KEYWORD[keyword_id] defines whether
 * a keyword is present, LINE[keyword_id] specifies in which line a keyword
 * was found or NULL when specified on command line, NAME specifies the
 * section name or NULL when specified on command line. */
int
scan_check_section_data(char* keyword[], int* line, char* name,
			int section_line, enum scan_section_type* type)
{
	char* main_keyword;
	int i;

	main_keyword = "";
	/* Find out what type this section is */
	if (*type == section_invalid) {
		if (keyword[(int) scan_keyword_tape]) {
			*type = section_ipl_tape;
			main_keyword = scan_keyword_name(scan_keyword_tape);
		} else if (keyword[(int) scan_keyword_image]) {
			*type = section_ipl;
			main_keyword = scan_keyword_name(scan_keyword_image);
		} else if (keyword[(int) scan_keyword_segment]) {
			*type = section_segment;
			main_keyword = scan_keyword_name(scan_keyword_segment);
		} else if (keyword[(int) scan_keyword_dumpto]) {
			*type = section_dump;
			main_keyword = scan_keyword_name(scan_keyword_dumpto);
		} else if (keyword[(int) scan_keyword_dumptofs]) {
			error_reason("Option dumptofs is deprecated, "
				     "use dumpto instead");
			return -1;
		} else if (keyword[(int) scan_keyword_mvdump]) {
			*type = section_mvdump;
			main_keyword = scan_keyword_name(scan_keyword_mvdump);
		} else {
			error_reason("Line %d: section '%s' must contain "
				     "either one of keywords 'image', "
				     "'segment', 'dumpto', 'dumptofs', "
				     "'mvdump' or 'tape'", section_line, name);
			return -1;
		}
	}
	/* Check keywords */
	for (i=0; i < SCAN_KEYWORD_NUM; i++) {
		switch (scan_key_table[(int) *type][i]) {
		case req:
			/* Check for missing data */
			if ((keyword[i] == 0) && (line != NULL)) {
				/* Missing keyword in config file section */
				error_reason("Line %d: missing keyword '%s' "
					     "in section '%s'", section_line,
					     scan_keyword_name(
						     (enum scan_keyword_id) i),
					     name);
				return -1;
			} else if ((keyword[i] == 0) && (line == NULL)) {
				/* Missing keyword on command line */
				error_reason("Option '%s' required when "
					     "specifying '%s'",
					     scan_keyword_name(
						     (enum scan_keyword_id) i),
					     main_keyword);

				return -1;
			}
			break;
		case inv:
			/* Check for invalid data */
			if ((keyword[i] != 0) && (line != NULL)) {
				/* Invalid keyword in config file section */
				error_reason("Line %d: keyword '%s' not "
					     "allowed in section '%s'",
					     line[i],
					     scan_keyword_name(
						     (enum scan_keyword_id) i),
					     name);
				return -1;
			} else if ((keyword[i] != 0) && (line == NULL)) {
				/* Invalid keyword on command line */
				error_reason("Only one of options '%s' and "
					     "'%s' allowed", main_keyword,
					     scan_keyword_name(
						     (enum scan_keyword_id) i));
				return -1;
			}
			break;
		case opt:
			break;
		}
	}
	/* Additional check needed for segment */
	i = (int) scan_keyword_segment;
	if (keyword[i] != NULL) {
		if (!contains_address(keyword[i])) {
			if (line != NULL) {
				error_reason("Line %d: keyword 'segment' "
					     "requires "
					     "load address", line[i]);
			} else {
				error_reason("Option 'segment' requires "
					     "load address");
			}
			return -1;
		}
	}
	return 0;
}


static int
check_blocksize(int size)
{
	switch (size) {
	case 512:
	case 1024:
	case 2048:
	case 4096:
		return 0;
	}
	return -1;
}

static int
scan_count_target_keywords(char* keyword[])
{
	int num = 0;

	if (keyword[(int) scan_keyword_target])
		num++;
	if (keyword[(int) scan_keyword_targetbase])
		num++;
	if (keyword[(int) scan_keyword_targettype])
		num++;
	if (keyword[(int) scan_keyword_targetgeometry])
		num++;
	if (keyword[(int) scan_keyword_targetblocksize])
		num++;
	if (keyword[(int) scan_keyword_targetoffset])
		num++;
	return num;
}

int
scan_check_target_data(char* keyword[], int* line)
{
	int cylinders, heads, sectors;
	char dummy;
	int number;
	enum scan_keyword_id errid;

	if (keyword[(int) scan_keyword_targetbase] == 0) {
		if (keyword[(int) scan_keyword_targettype] != 0)
			errid = scan_keyword_targettype;
		else if ((keyword[(int) scan_keyword_targetgeometry] != 0))
			errid = scan_keyword_targetgeometry;
		else if ((keyword[(int) scan_keyword_targetblocksize] != 0))
			errid = scan_keyword_targetblocksize;
		else if ((keyword[(int) scan_keyword_targetoffset] != 0))
			errid = scan_keyword_targetoffset;
		else
			return 0;
		if (line != NULL)
			error_reason("Line %d: keyword 'targetbase' required "
				"when specifying '%s'",
				line[(int) errid], scan_keyword_name(errid));
		else
			error_reason("Option 'targetbase' required when "
				"specifying '%s'",
				scan_keyword_name(errid));
		return -1;
	}
	if (keyword[(int) scan_keyword_targettype] == 0) {
		if (line != NULL)
			error_reason("Line %d: keyword 'targettype' "
				"required when specifying 'targetbase'",
				line[(int) scan_keyword_targetbase]);
		else
			error_reason("Option 'targettype' required "
				     "when specifying 'targetbase'");
		return -1;
	}
	switch (scan_get_target_type(keyword[(int) scan_keyword_targettype])) {
	case target_type_cdl:
	case target_type_ldl:
		if ((keyword[(int) scan_keyword_targetgeometry] != 0))
			break;
		if (line != NULL)
			error_reason("Line %d: keyword 'targetgeometry' "
				"required when specifying 'targettype' %s",
				line[(int) scan_keyword_targettype],
				keyword[(int) scan_keyword_targettype]);
		else
			error_reason("Option 'targetgeometry' required when "
				"specifying 'targettype' %s",
				keyword[(int) scan_keyword_targettype]);
		return -1;
	case target_type_scsi:
	case target_type_fba:
		if ((keyword[(int) scan_keyword_targetgeometry] == 0))
			break;
		if (line != NULL)
			error_reason("Line %d: keyword "
				"'targetgeometry' not allowed for "
				"'targettype' %s",
				line[(int) scan_keyword_targetgeometry],
				keyword[(int) scan_keyword_targettype]);
		else
			error_reason("Keyword 'targetgeometry' not "
				"allowed for 'targettype' %s",
				keyword[(int) scan_keyword_targettype]);
		return -1;
	case target_type_invalid:
		if (line != NULL)
			error_reason("Line %d: Unrecognized 'targettype' value "
				"'%s'",
				line[(int) scan_keyword_targettype],
				keyword[(int) scan_keyword_targettype]);
		else
			error_reason("Unrecognized 'targettype' value '%s'",
				keyword[(int) scan_keyword_targettype]);
		return -1;
	}
	if (keyword[(int) scan_keyword_targetgeometry] != 0) {
		if ((sscanf(keyword[(int) scan_keyword_targetgeometry],
		    "%d,%d,%d %c", &cylinders, &heads, &sectors, &dummy)
		    != 3) || (cylinders <= 0) || (heads <= 0) ||
		    (sectors <= 0)) {
			if (line != NULL)
				error_reason("Line %d: Invalid target geometry "
					"'%s'", line[
					(int) scan_keyword_targetgeometry],
					keyword[
					(int) scan_keyword_targetgeometry]);
			else
				error_reason("Invalid target geometry '%s'",
					keyword[
					(int) scan_keyword_targetgeometry]);
			return -1;
		}
	}
	if (keyword[(int) scan_keyword_targetblocksize] == 0) {
		if (line != NULL)
			error_reason("Line %d: Keyword 'targetblocksize' "
				"required when specifying 'targetbase'",
				line[(int) scan_keyword_targetbase]);
		else
			error_reason("Option 'targetblocksize' required when "
				"specifying 'targetbase'");
		return -1;
	}
	if ((sscanf(keyword[(int) scan_keyword_targetblocksize], "%d %c",
	    &number, &dummy) != 1) || check_blocksize(number)) {
		if (line != NULL)
			error_reason("Line %d: Invalid target blocksize '%s'",
				line[(int) scan_keyword_targetblocksize],
				keyword[(int) scan_keyword_targetblocksize]);
		else
			error_reason("Invalid target blocksize '%s'",
				keyword[(int) scan_keyword_targetblocksize]);
		return -1;
	}
	if (keyword[(int) scan_keyword_targetoffset] == 0) {
		if (line != NULL)
			error_reason("Line %d: Keyword 'targetoffset' "
				"required when specifying 'targetbase'",
				line[(int) scan_keyword_targetbase]);
		else
			error_reason("Option 'targetoffset' required when "
				"specifying 'targetbase'");
		return -1;
	}
	if (sscanf(keyword[(int) scan_keyword_targetoffset], "%d %c",
	    &number, &dummy) != 1) {
		if (line != NULL)
			error_reason("Line %d: Invalid target offset '%s'",
				line[(int) scan_keyword_targetoffset],
				keyword[(int) scan_keyword_targetoffset]);
		else
			error_reason("Invalid target offset '%s'",
				keyword[(int) scan_keyword_targetoffset]);
		return -1;
	}
	return 0;
}


static int
scan_is_delimiter(enum scan_id id)
{
	return id == scan_id_empty || id == scan_id_section_heading ||
	       id == scan_id_menu_heading;
}


/*
 * Copy data from scan array to keyword/number assignment array. Return 0
 * on success, non-zero otherwise.
 *
 * If keyword X is specified in the section, keyword[X] contains the value of
 * that keyword and keyword_line[x] the line in which the keyword was defined.
 * Otherwise keyword[X] contains NULL.
 * If number assignment X is specified in the section, num[X - 1] contains
 * the value of that assignment and num_line the line in which the assignment
 * was found. Otherwise num[X - 1] contains NULL. If num is NULL, an error
 * is reported if a number assignment is found.
 */
static int
scan_get_section_keywords(struct scan_token* scan, int* index, char* name,
			  char* keyword[], int keyword_line[], char** num,
			  int* num_line)
{
	int i;
	int id;
	int key;
	int line;
	int number;
	char* value;

	/* Initialize array data. */
	for (i = 0; i < SCAN_KEYWORD_NUM; i++) {
		keyword[i] = NULL;
		keyword_line[i] = 0;
	}
	if (num) {
		for (i = 0; i < BOOT_MENU_ENTRIES; i++) {
			num[i] = NULL;
			num_line[i] = 0;
		}
	}
	/* Extract data for keyword and number assignments. */
	for (i = *index + 1; !scan_is_delimiter(scan[i].id); i++) {
		id = (int) scan[i].id;
		line = scan[i].line;
		/* Handle number assignments first. */
		if (id == scan_id_number_assignment) {
			number = scan[i].content.number.number;
			/* Check if number assignments are expected. */
			if (!num) {
				error_reason("Line %d: number assignment not "
					     "allowed in section '%s'",
					     line, name);
				return -1;
			}
			/* Check for valid numbers. */
			if (number <= 0) {
				error_reason("Line %d: position must be "
					     "greater than zero",
					     line);
                                return -1;

			}
			if (number > BOOT_MENU_ENTRIES) {
				error_reason("Line %d: position must not "
					     "exceed %d", line,
					     BOOT_MENU_ENTRIES);
                                return -1;
			}
			/* Rule 10 */
			if (num[number - 1]) {
				error_reason("Line %d: position %d already "
					     "specified", line, number);
				return -1;
			}
			num[number - 1] = scan[i].content.number.value;
			num_line[number - 1] = line;
			continue;
		}
		/* Handle keyword assignments. */
		if (id == scan_id_keyword_assignment) {
			key = scan[i].content.keyword.keyword;
			value = scan[i].content.keyword.value;
		} else if (id == scan_id_keyword_only) {
			key = scan[i].content.keyword_only.keyword;
			/* Define a dummy value. */
			value = "";
		} else {
			continue;
		}
		if (keyword[key]) {
			/* Rule 5 */
			error_reason("Line %d: keyword '%s' already specified",
				     line, scan_keyword_name(key));
			return -1;
		}
		keyword[key] = value;
		keyword_line[key] = line;
	}
	*index = i;

	return 0;
}


/* Check section at INDEX for compliance with config file rules. Upon success,
 * return zero and advance INDEX to point to the end of the section. Return
 * non-zero otherwise. */
static int
check_section(struct scan_token* scan, int* index)
{
	char* name;
	char* keyword[SCAN_KEYWORD_NUM];
	int keyword_line[SCAN_KEYWORD_NUM];
	enum scan_section_type type;
	int line;
	int rc;
	
	name = scan[*index].content.section.name;
	/* Ensure unique section names */
	line = scan_find_section(scan, name, scan_id_section_heading, *index+1);
	if (line >= 0) {
		error_reason("Line %d: section name '%s' already specified",
			     scan[line].line, name);
		return -1;
	}
	line = scan[*index].line;
	/* Get keyword data and advance index to end of section */
	rc = scan_get_section_keywords(scan, index, name, keyword, keyword_line,
				       NULL, NULL);
	if (rc)
		return rc;
	/* Check already done in scan_check_defaultboot */
	if (strcmp(name, DEFAULTBOOT_SECTION) == 0)
		return 0;
	else
		type = section_invalid;
	/* Check section data */
	rc = scan_check_section_data(keyword, keyword_line, name, line, &type);
	if (rc)
		return rc;
	/* Check target data */
	rc = scan_check_target_data(keyword, keyword_line);
	if (rc)
		return rc;
	return 0;
}


static int
check_menu_keyword_data(char* keyword[], int* line, char* name,
			int section_line)
{
	int i;

	for (i = 0; i < SCAN_KEYWORD_NUM; i++) {
		switch (scan_menu_key_table[i]) {
		case inv:
			if (!keyword[i])
				break;
			error_reason("Line %d: keyword '%s' not allowed in "
				     "menu section '%s'", line[i],
				     scan_keyword_name(
					(enum scan_keyword_id) i), name);
				return -1;
			break;
		case req:
			if (keyword[i])
				break;
			error_reason("Line %d: missing keyword '%s' "
				     "in menu section '%s'", section_line,
				     scan_keyword_name(
					(enum scan_keyword_id) i), name);
			return -1;
		default:
			break;
		}
	}
	return 0;
}

/* Check menu section at INDEX for compliance with config file rules. Upon
 * success, return zero and advance INDEX to point to the end of the section.
 * Return non-zero otherwise. */
static int
check_menu(struct scan_token* scan, int* index)
{
	char* keyword[SCAN_KEYWORD_NUM];
	int keyword_line[SCAN_KEYWORD_NUM];
	char* num[BOOT_MENU_ENTRIES];
	int num_line[BOOT_MENU_ENTRIES];
	char* menu_name;
	int menu_line;
	char dummy;
	int i;
	int rc;
	int number;
	int num_configs;

	menu_name = scan[*index].content.menu.name;
	menu_line = scan[*index].line;
	/* Rule 15 */
	i = scan_find_section(scan, menu_name, scan_id_menu_heading,
			      *index + 1);
	if (i >= 0) {
		error_reason("Line %d: menu name '%s' already specified",
			     scan[i].line, menu_name);
		return -1;
	}
	/* Get keyword and number assignment data */
	rc = scan_get_section_keywords(scan, index, menu_name, keyword,
				       keyword_line, num, num_line);
	if (rc)
		return rc;
	/* Check for required and invalid keywords */
	rc = check_menu_keyword_data(keyword, keyword_line, menu_name,
				     menu_line);
	if (rc)
		return rc;
	/* Check default value */
	i = (int) scan_keyword_default;
	if (keyword[i]) {
		if (sscanf(keyword[i], "%d %c", &number, &dummy) != 1) {
			error_reason("Line %d: default position must be a "
				     "number", keyword_line[i]);
			return -1;
		}
		if (number < 1) {
			error_reason("Line %d: default position must be "
				     "greater than zero", keyword_line[i]);
			return -1;
		}
		if (number > BOOT_MENU_ENTRIES) {
			error_reason("Line %d: default position too large",
				     keyword_line[i]);
			return -1;
		}
		if (!num[number - 1]) {
			error_reason("Line %d: menu position %d not defined",
				     keyword_line[i], number);
			return -1;
		}
	}
	/* Check prompt value */
	i = (int) scan_keyword_prompt;
	if (keyword[i]) {
		if (sscanf(keyword[i], "%d %c", &number, &dummy) != 1) {
			error_reason("Line %d: prompt value must be a number",
				     keyword_line[i]);
			return -1;
		}
		if (number != 0 && number != 1) {
			error_reason("Line %d: prompt value is out of range "
				     "(must be 0 or 1)", keyword_line[i]);
			return -1;
		}
	}
	/* Check timeout value */
	i = (int) scan_keyword_timeout;
	if (keyword[i]) {
		if (sscanf(keyword[i], "%d %c", &number, &dummy) != 1) {
			error_reason("Line %d: timeout value must be a number",
				     keyword_line[i]);
			return -1;
		}
		if (number < 0) {
			error_reason("Line %d: timeout value is out of range",
				     keyword_line[i]);
			return -1;
		}
	}
	/* Check number assignments */
	num_configs = 0;
	for (i = 0; i < BOOT_MENU_ENTRIES; i++) {
		if (!num[i])
			continue;
		if (scan_find_section(scan, num[i], scan_id_section_heading,
				      0) < 0) {
			error_reason("Line %d: section '%s' not found",
				     num_line[i], num[i]);
			return -1;
		}
		num_configs++;
	}
	/* Check for boot configurations */
	if (num_configs == 0) {
		error_reason("Line %d: no boot configuration specified in "
			     "menu '%s'", menu_line, menu_name);
		return -1;
	}
	/* Check target data */
	rc = scan_check_target_data(keyword, keyword_line);
	if (rc)
		return rc;

	return 0;
}

static const struct {
	char* name;
	enum scan_id id;
} id_list[] = {
	{ "none", scan_id_empty },
	{ "section heading", scan_id_section_heading },
	{ "menu heading", scan_id_menu_heading },
	{ "keyword assignment",  scan_id_keyword_assignment },
	{ "number assignment", scan_id_number_assignment},
	{ "keyword", scan_id_keyword_only},
};

static const char *
scan_id_name(enum scan_id id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(id_list); i++) {
		if (id == id_list[i].id)
			return id_list[i].name;
	}
	return "<unknown>";
}


/* Check scanned tokens for compliance with config file rules. Return zero
 * if config file complies, non-zero otherwise. Rules are:
 *
 * Global:
 *  1 - no keywords are allowed outside of a section
 *
 * Configuration sections:
 *  2 - may not contain number assignments
 *  3 - must contain certain keywords according to type (see keyword_table)
 *  4 - may not contain certain keywords according to type (see keyword_table)
 *  5 - keywords may be specified at most once
 *  6 - must contain at least one keyword assignment
 *  7 - section name must be unique in the configuration file
 *  8 - defaultboot:default must point to a valid section
 *
 * Menu sections:
 *  9  - must contain at least one number assignment
 *  10 - numbers in number assignment have to be unique in the section
 *  11 - referenced sections must be present
 *  12 - must contain certain keywords according to type (see keyword_table)
 *  13 - may not contain certain keywords according to type (see keyword_table)
 *  14 - keywords may be specified at most once
 *  15 - menu name must be unique in the configuration file
 *  16 - optional default position must be a valid position
 * */
int
scan_check(struct scan_token* scan)
{
	int i;
	int rc;

	i = 0;
	while (scan[i].id != scan_id_empty) {
		switch (scan[i].id) {
		case scan_id_section_heading:
			rc = check_section(scan, &i);
			if (rc)
				return rc;
			break;
		case scan_id_menu_heading:
			rc = check_menu(scan, &i);
			if (rc)
				return rc;
			break;
		default:
			/* Rule 1 */
			error_reason("Line %d: %s not allowed outside of "
				     "section", scan[i].line,
				     scan_id_name(scan[i].id));
			return -1;
		}
	}
	return 0;
}

/*
 * Check if kernel and initrd image paths provided by BLS files are readable.
 * If not, add value of 'scan_keyword_target' into search path and silently
 * update scan list if the file exists.
 * In case neither path works the scan_check code will correctly handle missing
 * files
 */
void scan_update_bls_path(struct scan_token *scan)
{
	char *target_value = NULL;
	char *img_value = NULL;
	char *file = NULL;
	char *tmp, *value;
	int i;
	/*
	 * In the BLS case, each BLS section heading inherits a keyword
	 * assignment target= from zipl.conf, and they are all the same.
	 *
	 */
	for (i = 0 ; scan[i].id != scan_id_empty; i++) {
		if (scan[i].id == scan_id_keyword_assignment &&
		    scan[i].content.keyword.keyword == scan_keyword_target) {
			target_value = scan[i].content.keyword.value;
			break;
		}
	}
	if (!target_value)
		return;
	for (i = 0 ; scan[i].id != scan_id_empty; i++) {
		if (scan[i].id != scan_id_keyword_assignment)
			continue;
		if (scan[i].content.keyword.keyword == scan_keyword_image ||
		    scan[i].content.keyword.keyword == scan_keyword_ramdisk) {

			value = scan[i].content.keyword.value;
			/*
			 * put the filename only into the file var before
			 * checking its presence
			 */
			if (contains_address(value)) {
				tmp = strrchr(value, ',');
				file = strndup(value, tmp - value);
			} else {
				file = value;
			}
			if (misc_check_readable_file(file)) {
				misc_asprintf(&img_value, "%s%s",
					      target_value, file);
				if (misc_check_readable_file(img_value))
					continue;

				/*
				 * when file has stripped the load address part,
				 * do generate a prefixed value
				 */
				if (file != value) {
					free(file);
					free(img_value);
					misc_asprintf(&img_value, "%s%s",
						      target_value, value);
				}
				free(scan[i].content.keyword.value);
				scan[i].content.keyword.value = img_value;
			}
		}
	}
	return;
}

static int
scan_get_defaultboot_type(char* keyword[], int line[], int section_line,
			  enum scan_section_type* type)
{
	int key1;
	int key2;

	if (keyword[(int) scan_keyword_defaultauto]) {
		if (keyword[(int) scan_keyword_defaultmenu]) {
			key1 = (int) scan_keyword_defaultauto;
			key2 = (int) scan_keyword_defaultmenu;
			goto err_too_much;
		}
		if (!keyword[(int) scan_keyword_target]) {
			goto err_no_target;
		}
		*type = section_default_auto;
	} else if (keyword[(int) scan_keyword_target]) {
		if (keyword[(int) scan_keyword_defaultmenu]) {
			key1 = (int) scan_keyword_target;
			key2 = (int) scan_keyword_defaultmenu;
			goto err_too_much_target;
		}
		*type = section_default_auto;
	} else if (keyword[(int) scan_keyword_defaultmenu]) {
		if (keyword[(int) scan_keyword_default]) {
			key1 = (int) scan_keyword_defaultmenu;
			key2 = (int) scan_keyword_default;
			goto err_too_much;
		}
		*type = section_default_menu;
	} else if (keyword[(int) scan_keyword_default]) {
		*type = section_default_section;
	} else {
		error_reason("Line %d: Section '%s' requires one of keywords "
			     "'default', 'defaultmenu', 'defaultauto' or "
			     "'target'", section_line, DEFAULTBOOT_SECTION);
		return -1;
	}
	return 0;

err_no_target:
	error_reason("Line %d: Keyword 'target' required in section '%s' when "
		     "specifying 'defaultauto'", section_line,
		     DEFAULTBOOT_SECTION);
	return -1;

err_too_much:
	error_reason("Line %d: Only one of keywords 'default', 'defaultmenu' "
		     "and 'defaultauto' allowed in section '%s'",
		     MAX(line[key1], line[key2]), DEFAULTBOOT_SECTION);
	return -1;

err_too_much_target:
	error_reason("Line %d: Only one of keywords 'default', 'defaultmenu' "
		     "and 'target' allowed in section '%s'",
		     MAX(line[key1], line[key2]), DEFAULTBOOT_SECTION);
	return -1;
}


/* scan_check_defaultboot checks the defaultboot section of the configuration
 * file. It returns
 *    0   on successful check, NO automenu is to be built
 *    1   on successful check, the automenu must be built
 *   -1   on error
 */
int
scan_check_defaultboot(struct scan_token* scan)
{
	int i;
	int j;
	char* keyword[SCAN_KEYWORD_NUM];
	int keyword_line[SCAN_KEYWORD_NUM];
	enum scan_section_type type;
	int defaultboot_line;
	int rc;

	/* Check if defaultboot is defined */
	i = scan_find_section(scan, DEFAULTBOOT_SECTION,
			      scan_id_section_heading, 0);
	if (i < 0) {
		error_reason("No '%s' section found and no section specified "
			     "on command line", DEFAULTBOOT_SECTION);
		return -1;
	}
	/* Ensure unique section names */
	j = scan_find_section(scan, DEFAULTBOOT_SECTION,
			      scan_id_section_heading, i + 1);
	if (j >= 0) {
		error_reason("Line %d: section name '%s' already specified",
			     scan[j].line, DEFAULTBOOT_SECTION);
		return -1;
	}
	defaultboot_line = scan[i].line;
	/* Get keyword data */
	rc = scan_get_section_keywords(scan, &i, DEFAULTBOOT_SECTION, keyword,
				       keyword_line, NULL, NULL);
	if (rc)
		return rc;
	/* Check default keyword value */
	i = (int) scan_keyword_default;
	if (keyword[i] && scan_find_section(scan, keyword[i],
					    scan_id_section_heading, 0) < 0) {
		error_reason("Line %d: no such section '%s'", keyword_line[i],
			     keyword[i]);
		return -1;
	}
	/* Determine default boot type */
	rc = scan_get_defaultboot_type(keyword, keyword_line, defaultboot_line,
				       &type);
	if (rc)
		return rc;
	/* Check target keywords */
	if (type == section_default_auto &&
	    scan_count_target_keywords(keyword) > 0) {
		rc = scan_check_target_data(keyword, keyword_line);
		if (rc)
			return rc;
	}
	/* Check remaining section data */
	rc = scan_check_section_data(keyword, keyword_line, DEFAULTBOOT_SECTION,
				     defaultboot_line, &type);
	if (rc)
		return rc;
	if (type == section_default_auto)
		return 1;
	else
		return 0;
}


static void
scan_skip_section(struct scan_token* scan, int* index)
{
	do {
		(*index)++;
	} while (!scan_is_delimiter(scan[*index].id));
}


static int
scan_copy_section(struct scan_token* from, struct scan_token* to,
		  int* index_from, int* index_to)
{
	struct scan_token* token;

	do {
		token = &to[*index_to];
		*token = from[*index_from];
		switch (token->id) {
		case scan_id_section_heading:
			token->content.section.name =
				misc_strdup(token->content.section.name);
			if (!token->content.section.name)
				return -1;
			break;
		case scan_id_menu_heading:
			token->content.menu.name =
				misc_strdup(token->content.menu.name);
			if (!token->content.menu.name)
				return -1;
			break;
		case scan_id_keyword_assignment:
			token->content.keyword.value =
				misc_strdup(token->content.keyword.value);
			if (!token->content.keyword.value)
				return -1;
			break;
		case scan_id_number_assignment:
			token->content.number.value =
				misc_strdup(token->content.number.value);
			if (!token->content.number.value)
				return -1;
			break;
		default:
			break;
		}
		(*index_from)++;
		(*index_to)++;
	} while (!scan_is_delimiter(from[*index_from].id));

	return 0;
}


static int
scan_append_section_heading(struct scan_token* scan, int* index, char* name)
{
	scan[*index].id = scan_id_section_heading;
	scan[*index].line = 0;
	scan[*index].content.section.name = misc_strdup(name);
	if (!scan[*index].content.section.name)
		return -1;
	(*index)++;
	return 0;
}


static int
scan_append_menu_heading(struct scan_token* scan, int* index, char* name)
{
	scan[*index].id = scan_id_menu_heading;
	scan[*index].line = 0;
	scan[*index].content.menu.name = misc_strdup(name);
	if (!scan[*index].content.menu.name)
		return -1;
	(*index)++;
	return 0;
}


static int
scan_append_number_assignment(struct scan_token* scan, int* index, int num,
			      char* value)
{
	scan[*index].id = scan_id_number_assignment;
	scan[*index].line = 0;
	scan[*index].content.number.number = num;
	scan[*index].content.number.value = misc_strdup(value);
	if (!scan[*index].content.number.value)
		return -1;
	(*index)++;
	return 0;
}


static int
scan_append_keyword_assignment(struct scan_token* scan, int* index,
			       enum scan_keyword_id id, char* value)
{
	scan[*index].id = scan_id_keyword_assignment;
	scan[*index].line = 0;
	scan[*index].content.keyword.keyword = id;
	scan[*index].content.keyword.value = misc_strdup(value);
	if (!scan[*index].content.keyword.value)
		return -1;
	(*index)++;
	return 0;
}


static int
scan_append_target_keywords(struct scan_token* scan, int* index,
			    char* keyword[])
{
	enum scan_keyword_id id[] = {
		scan_keyword_target,
		scan_keyword_targetbase,
		scan_keyword_targettype,
		scan_keyword_targetgeometry,
		scan_keyword_targetblocksize,
		scan_keyword_targetoffset,
	};
	unsigned int i;
	int rc;

	for (i = 0; i < ARRAY_SIZE(id); i++) {
		if (!keyword[(int) id[i]])
			continue;
		rc = scan_append_keyword_assignment(scan, index, id[i],
						    keyword[(int) id[i]]);
		if (rc)
			return rc;
	}

	return 0;
}


struct scan_token *
scan_build_automenu(struct scan_token* scan)
{
	char* entry[BOOT_MENU_ENTRIES];
	int num_entries;
	int default_entry;
	char* db_keyword[SCAN_KEYWORD_NUM];
	int db_line[SCAN_KEYWORD_NUM];
	char* sec_keyword[SCAN_KEYWORD_NUM];
	int sec_line[SCAN_KEYWORD_NUM];
	int num_targets;
	int num_sections;
	size_t size;
	struct scan_token* new_scan;
	int i;
	int i_new;
	char* name;
	char* default_name;
	int pos;

	/* Find defaultboot */
	i = scan_find_section(scan, DEFAULTBOOT_SECTION,
			      scan_id_section_heading, 0);
	/* Get defaultboot data */
	if (scan_get_section_keywords(scan, &i, DEFAULTBOOT_SECTION, db_keyword,
				      db_line, NULL, NULL))
		return NULL;
	default_name = db_keyword[(int) scan_keyword_default];
	num_targets = scan_count_target_keywords(db_keyword);
	/* Get size of scan array and number of sections */
	num_sections = 0;
	for (i = 0; scan[i].id != scan_id_empty; i++) {
		if (scan[i].id == scan_id_section_heading)
			num_sections++;
	}
	size = /* old scan array + delimiter */     i + 1 +
	       /* defaultboot heading  */           1 +
	       /* defaultmenu */                    1 +
	       /* menu heading  */                  1 +
	       /* keyword default,prompt,timeout */ 3 +
	       /* keyword secure */                 1 +
	       /* target keywords*/                 num_targets +
	       /* missing target definitions */     num_sections * num_targets +
	       /* number assigment  */              num_sections;
	size *= sizeof(struct scan_token);
	new_scan = misc_malloc(size);
	if (!new_scan)
		return NULL;
	memset(new_scan, 0, size);
	/* Fill new array */
	i = 0;
	i_new = 0;
	num_entries = 0;
	default_entry = -1;
	memset(entry, 0, sizeof(entry));
	while (scan[i].id != scan_id_empty) {
		switch (scan[i].id) {
		case scan_id_menu_heading:
			name = scan[i].content.menu.name;
			/* Abort if automenu name is already in use */
			if (strcmp(name, SCAN_AUTOMENU_NAME) == 0) {
				error_reason("Cannot build automenu: menu name "
					     "'%s' already used",
					     SCAN_AUTOMENU_NAME);
				goto err;
			}
			/* Menu sections are copied without changes */
			if (scan_copy_section(scan, new_scan, &i, &i_new))
				goto err;
			break;
		case scan_id_section_heading:
			name = scan[i].content.section.name;
			/* Do not copy old defaultboot section */
			if (strcmp(name, DEFAULTBOOT_SECTION) == 0) {
				scan_skip_section(scan, &i);
				break;
			}
			/* Get section data but do not advance index */
			pos = i;
			if (scan_get_section_keywords(scan, &pos, name,
						      sec_keyword, sec_line,
						      NULL, NULL))
				goto err;
			/* Copy section contents and advance index */
			if (scan_copy_section(scan, new_scan, &i, &i_new))
				goto err;
			/* Stop here for non-IPL sections. */
			if (scan_get_section_type(sec_keyword) != section_ipl)
				break;
			/* Is there enough room for another section? */
			if (num_entries == BOOT_MENU_ENTRIES) {
				error_reason("Cannot build automenu: too many "
					     "IPL sections defined (max %d)",
					     BOOT_MENU_ENTRIES);
				goto err;
			}
			/* Determine if this is the default entry */
			if (default_name && strcmp(default_name, name) == 0)
				default_entry = num_entries;
			entry[num_entries++] = name;
			/* Add missing target parameters if necessary */
			if (scan_count_target_keywords(sec_keyword) > 0)
				break;
			if (scan_append_target_keywords(new_scan, &i_new,
							db_keyword))
				goto err;
			break;
		default:
			/* Rule 1 */
			error_reason("Line %d: %s not allowed outside of "
				     "section", scan[i].line,
				     scan_id_name(scan[i].id));
			goto err;
		}
	}
	if (num_entries == 0) {
		error_reason("Cannot build automenu: no IPL entries available");
		goto err;
	}

	/* Append new defaultboot and automenu sections */
	/* [defaultboot] */
	if (scan_append_section_heading(new_scan, &i_new, DEFAULTBOOT_SECTION))
		goto err;
	/* defaultmenu=zipl-automatic-menu */
	if (scan_append_keyword_assignment(new_scan, &i_new,
				scan_keyword_defaultmenu, SCAN_AUTOMENU_NAME))
		goto err;
	/* :zipl-automatic-menu */
	if (scan_append_menu_heading(new_scan, &i_new, SCAN_AUTOMENU_NAME))
		goto err;
	/* default= */
	if (default_entry >= 0) {
		char str[20];

		snprintf(str, sizeof(str), "%d", default_entry + 1);
		if (scan_append_keyword_assignment(new_scan, &i_new,
						   scan_keyword_default, str))
			goto err;
	}
	/* prompt= */
	i = (int) scan_keyword_prompt;
	if (db_keyword[i]) {
		if (scan_append_keyword_assignment(new_scan, &i_new,
						   scan_keyword_prompt,
						   db_keyword[i]))
			goto err;
	}
	/* timeout= */
	i = (int) scan_keyword_timeout;
	if (db_keyword[i]) {
		if (scan_append_keyword_assignment(new_scan, &i_new,
						   scan_keyword_timeout,
						   db_keyword[i]))
			goto err;
	}
	/* secure= */
	i = (int) scan_keyword_secure;
	if (db_keyword[i]) {
		if (scan_append_keyword_assignment(new_scan, &i_new,
						   scan_keyword_secure,
						   db_keyword[i]))
			goto err;
			}
	/* target= */
	/* targetbase= */
	/* targetgeometry= */
	/* targetblocksize= */
	/* targetoffset= */
	if (scan_append_target_keywords(new_scan, &i_new, db_keyword))
		goto err;
	/* <num>=<section name>*/
	for (i = 0; i < num_entries; i++) {
		if (scan_append_number_assignment(new_scan, &i_new, i + 1,
						  entry[i]))
			goto err;
	}

	return new_scan;

err:
	scan_free(new_scan);
	return NULL;
}
