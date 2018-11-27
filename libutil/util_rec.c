/**
 * util - Utility function library
 *
 * Print records in different output formats
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <argz.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_base.h"
#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_panic.h"
#include "lib/util_prg.h"
#include "lib/util_rec.h"

/*
 * Field structure containing the string value and secondary information
 */
struct util_rec_fld {
	char *key;                  /* Name of the filed */
	char *hdr;                  /* Content of the header */
	size_t len;                 /* Length of string argz array */
	char *val;                  /* The value of the field */
	enum util_rec_align align;  /* Alignment of the field */
	int width;                  /* Field width */
	struct util_list_node node; /* Pointers to previous and next field */
};

/*
 * Print formats
 */
struct rec_fmt {
	enum {
		REC_FMT_WIDE,
		REC_FMT_LONG,
		REC_FMT_CSV,
	} type;
	union {
		struct wide_p {
			char *hdr_sep;
			char *col_sep;
			int argz_sep;
		} wide_p;
		struct long_p {
			char *hdr_sep;
			char *col_sep;
			int argz_sep;
			char *key;
			int key_size;
			int val_size;
		} long_p;
		struct csv_p {
			char *col_sep;
			int argz_sep;
		} csv_p;
	} d;
	int indent;
};

/*
 * Record structure (internal representation)
 */
/// @cond
struct util_rec {
	struct util_list *list; /* List of the fields */
	struct rec_fmt fmt;     /* Output format */
};
/// @endcond

struct util_list *__util_rec_get_list(struct util_rec *rec)
{
	return rec->list;
}

/*
 * Get the field according to a distinct key
 */
static struct util_rec_fld *rec_get_fld(struct util_rec *rec, const char *key)
{
	struct util_rec_fld *fld;

	util_list_iterate(rec->list, fld) {
		if (!strcmp(fld->key, key))
			return fld;
	}
	return NULL;
}

/**
 * Return the key name of a field
 *
 * @param[in] fld  Field for query
 *
 * @returns   Pointer to key string
 */
const char *util_rec_fld_get_key(struct util_rec_fld *fld)
{
	return fld->key;
}

/**
 * Create a new record with "wide" output format
 *
 * @param[in] hdr_sep  Header separator
 *
 * @returns   Pointer to the created record
 */
struct util_rec *util_rec_new_wide(const char *hdr_sep)
{
	struct util_rec *rec = util_malloc(sizeof(struct util_rec));

	rec->list = util_list_new(struct util_rec_fld, node);
	rec->fmt.type = REC_FMT_WIDE;
	rec->fmt.d.wide_p.hdr_sep = util_strdup(hdr_sep);
	rec->fmt.d.wide_p.argz_sep = ',';
	rec->fmt.indent = 0;
	return rec;
}

/*
 * Print the indentation characters
 */
static inline void rec_print_indention(int indent)
{
	if (indent <= 0)
		return;

	printf("%*s", indent, "");
}

/*
 * Print record separator in "wide" output format
 */
static void rec_print_wide_separator(struct util_rec *rec)
{
	const char *hdr_sep = rec->fmt.d.wide_p.hdr_sep;
	int size = 0, field_count = 0;
	struct util_rec_fld *fld;
	char *buf;

	if (!hdr_sep)
		return;

	util_list_iterate(rec->list, fld) {
		if (fld->hdr) {
			size += fld->width;
			field_count++;
		}
	}

	size += field_count - 1;
	buf = util_malloc(size + 1);
	memset(buf, (int)hdr_sep[0], size);
	buf[size] = 0;
	rec_print_indention(rec->fmt.indent);
	printf("%s\n", buf);
	free(buf);
}

/*
 * Print record header in "wide" output format
 */
static void rec_print_wide_hdr(struct util_rec *rec)
{
	const char *hdr_sep = rec->fmt.d.wide_p.hdr_sep;
	int col_nr = 0, size = 0, field_count = 0;
	struct util_rec_fld *fld;
	char *buf;

	rec_print_indention(rec->fmt.indent);
	util_list_iterate(rec->list, fld) {
		if (col_nr)
			printf(" ");
		if (fld->hdr) {
			if (fld->align == UTIL_REC_ALIGN_LEFT)
				printf("%-*s", fld->width, fld->hdr);
			else
				printf("%*s", fld->width, fld->hdr);
			size += fld->width;
			field_count++;
		}
		col_nr++;
	}
	printf("\n");
	if (!hdr_sep)
		return;
	size += field_count - 1;
	if (hdr_sep) {
		buf = util_malloc(size + 1);
		memset(buf, (int)hdr_sep[0], size);
		buf[size] = 0;
		rec_print_indention(rec->fmt.indent);
		printf("%s\n", buf);
		free(buf);
	}
}

/*
 * Print record field values in "wide" output format
 */
void rec_print_wide(struct util_rec *rec)
{
	const char argz_sep = rec->fmt.d.wide_p.argz_sep;
	struct util_rec_fld *fld;
	char argz_str[PAGE_SIZE];
	int fld_count = 0;
	char *entry;

	rec_print_indention(rec->fmt.indent);
	util_list_iterate(rec->list, fld) {
		if (!fld->hdr)
			continue;
		if (fld_count)
			printf(" ");
		entry = fld->val;
		if (argz_count(fld->val, fld->len) > 1) {
			strcpy(argz_str, entry);
			while ((entry = argz_next(fld->val, fld->len, entry)))
				strcat(strncat(argz_str, &argz_sep, 1), entry);
			entry = argz_str;
		}
		if (fld->align == UTIL_REC_ALIGN_LEFT)
			printf("%-*s", fld->width, entry);
		else
			printf("%*s", fld->width, entry);
		fld_count++;
	}
	printf("\n");
}

/*
 * Free private memory of record
 */
static void rec_free_wide(struct util_rec *rec)
{
	free(rec->fmt.d.wide_p.hdr_sep);
}

/**
 * Create a new record with "long" output format
 *
 * @param[in] hdr_sep   Header separator
 * @param[in] col_sep   Column separator
 * @param[in] key       Primary key of record
 * @param[in] key_size  Width of left column i.e. keys
 * @param[in] val_size  Width of right column i.e. values
 *
 * @returns   Pointer to the created record
 */
struct util_rec *util_rec_new_long(const char *hdr_sep, const char *col_sep,
				   const char *key, int key_size, int val_size)
{
	struct util_rec *rec = util_malloc(sizeof(struct util_rec));

	rec->list = util_list_new(struct util_rec_fld, node);
	rec->fmt.type = REC_FMT_LONG;
	rec->fmt.d.long_p.hdr_sep = util_strdup(hdr_sep);
	rec->fmt.d.long_p.col_sep = util_strdup(col_sep);
	rec->fmt.d.long_p.key = util_strdup(key);
	rec->fmt.d.long_p.key_size = key_size;
	rec->fmt.d.long_p.val_size = val_size;
	rec->fmt.d.long_p.argz_sep = ' ';
	rec->fmt.indent = 0;
	return rec;
}

/*
 * Print field header in "long" output format
 */
static void rec_print_long_hdr(struct util_rec *rec)
{
	struct long_p *p = &rec->fmt.d.long_p;
	struct util_rec_fld *fld;
	int len = 0;
	char *buf;

	fld = rec_get_fld(rec, p->key);
	util_assert(fld != NULL, "Record not found\n");
	util_assert(fld->hdr != NULL, "Header for field not found\n");
	rec_print_indention(rec->fmt.indent);
	if (p->col_sep) {
		printf("%-*s %s %-*s\n", p->key_size, fld->hdr,
		       p->col_sep, fld->width, fld->val);
		len = p->key_size + p->val_size + 3;
	} else {
		printf("%-*s %-*s\n", p->key_size, fld->hdr, fld->width,
		       fld->val);
		len = p->key_size + p->val_size + 1;
	}
	if (!p->hdr_sep)
		return;
	buf = util_malloc(len + 1);
	memset(buf, p->hdr_sep[0], len);
	buf[len] = 0;
	rec_print_indention(rec->fmt.indent);
	printf("%s\n", buf);
	free(buf);
}

/*
 * Print record field values in "long" output format
 */
static void rec_print_long(struct util_rec *rec)
{
	struct long_p *p = &rec->fmt.d.long_p;
	struct util_rec_fld *fld;
	char *item = NULL;

	rec_print_long_hdr(rec);

	util_list_iterate(rec->list, fld) {
		if (!fld->hdr)
			continue;
		if (!strcmp(p->key, fld->key))
			continue;
		if (!fld->val)
			continue;
		rec_print_indention(rec->fmt.indent);
		item = argz_next(fld->val, fld->len, item);
		if (p->col_sep) {
			printf("        %-*s %s %s\n",
			       p->key_size - 8, fld->hdr, p->col_sep, item);
			while ((item = argz_next(fld->val, fld->len, item))) {
				rec_print_indention(rec->fmt.indent);
				printf("        %-*s %c %s\n",
				       p->key_size - 8, "", p->argz_sep, item);
			}
		} else {
			printf("        %-*s %s\n",
			       p->key_size - 8, fld->hdr, fld->val);
			while ((item = argz_next(fld->val, fld->len, item))) {
				rec_print_indention(rec->fmt.indent);
				printf("        %-*s %s\n",
				       p->key_size - 8, "", item);
			}
		}
	}
	printf("\n");
}

/*
 * Free private memory of record
 */
static void rec_free_long(struct util_rec *rec)
{
	free(rec->fmt.d.long_p.hdr_sep);
	free(rec->fmt.d.long_p.col_sep);
	free(rec->fmt.d.long_p.key);
}

/**
 * Create a new record with "csv" output format
 *
 * @param[in] col_sep  Column separator
 *
 * @returns   Pointer to the created record
 */
struct util_rec *util_rec_new_csv(const char *col_sep)
{
	struct util_rec *rec = util_malloc(sizeof(struct util_rec));

	rec->list = util_list_new(struct util_rec_fld, node);
	rec->fmt.type = REC_FMT_CSV;
	rec->fmt.d.csv_p.col_sep = util_strdup(col_sep);
	rec->fmt.d.csv_p.argz_sep = ' ';
	rec->fmt.indent = 0;
	return rec;
}

/*
 * Print record header in "csv" output format
 */
void rec_print_csv_hdr(struct util_rec *rec)
{
	const char *col_sep = rec->fmt.d.csv_p.col_sep;
	struct util_rec_fld *fld;
	int fld_count = 0;

	rec_print_indention(rec->fmt.indent);
	util_list_iterate(rec->list, fld) {
		if (fld_count)
			printf("%c", *col_sep);
		if (fld->hdr) {
			printf("%s", fld->hdr);
			fld_count++;
		}
	}
	printf("\n");
}

/*
 * Print record field values in "csv" output format
 */
void rec_print_csv(struct util_rec *rec)
{
	const char argz_sep = rec->fmt.d.csv_p.argz_sep;
	const char *col_sep = rec->fmt.d.csv_p.col_sep;
	struct util_rec_fld *fld;
	int fld_count = 0;
	char *item = NULL;

	rec_print_indention(rec->fmt.indent);
	util_list_iterate(rec->list, fld) {
		item = argz_next(fld->val, fld->len, item);
		if (fld_count)
			printf("%c", *col_sep);
		if (fld->hdr) {
			printf("%s", item);
			while ((item = argz_next(fld->val, fld->len, item)))
				printf("%c%s", argz_sep, item);
			fld_count++;
		}
	}
	printf("\n");
}

/*
 * Free private memory of record
 */
static void rec_free_csv(struct util_rec *rec)
{
	free(rec->fmt.d.csv_p.col_sep);
}

/**
 * Define a new field for the record
 *
 * @param[in] rec    Pointer of the record
 * @param[in] key    Key of the filed is to be created. It should be unique
 *                   within the record.
 * @param[in] align  Alignment of field
 * @param[in] width  Width of field
 * @param[in] hdr    This information is printed in record headers. If it is
 *                   NULL, the field is prohibited form printing completely.
 */
void util_rec_def(struct util_rec *rec, const char *key,
		  enum util_rec_align align, int width, const char *hdr)
{
	struct util_rec_fld *fld = util_malloc(sizeof(struct util_rec_fld));

	fld->key = util_strdup(key);
	fld->hdr = util_strdup(hdr);
	fld->val = NULL;
	fld->align = align;
	fld->width = width;
	util_list_add_tail(rec->list, fld);
}

/**
 * Free record and associated fields
 *
 * @param[in] rec  Record pointer
 */
void util_rec_free(struct util_rec *rec)
{
	struct util_rec_fld *fld, *tmp;

	util_list_iterate_safe(rec->list, fld, tmp) {
		util_list_remove(rec->list, fld);
		free(fld->key);
		free(fld->hdr);
		free(fld->val);
		free(fld);
	}
	util_list_free(rec->list);
	switch (rec->fmt.type) {
	case REC_FMT_WIDE:
		rec_free_wide(rec);
		break;
	case REC_FMT_LONG:
		rec_free_long(rec);
		break;
	case REC_FMT_CSV:
		rec_free_csv(rec);
		break;
	}
	free(rec);
}

/**
 * Print record field values according to output format
 *
 * @param[in] rec  Record pointer
 */
void util_rec_print(struct util_rec *rec)
{
	switch (rec->fmt.type) {
	case REC_FMT_WIDE:
		rec_print_wide(rec);
		break;
	case REC_FMT_LONG:
		rec_print_long(rec);
		break;
	case REC_FMT_CSV:
		rec_print_csv(rec);
		break;
	}
}

/**
 * Print record header according to output format
 *
 * @param[in] rec  Record pointer
 */
void util_rec_print_hdr(struct util_rec *rec)
{
	switch (rec->fmt.type) {
	case REC_FMT_WIDE:
		rec_print_wide_hdr(rec);
		break;
	case REC_FMT_LONG:
		break;
	case REC_FMT_CSV:
		rec_print_csv_hdr(rec);
		break;
	}
}

/**
 * Print record separator according to output format
 *
 * @param[in] rec  Record pointer
 */
void util_rec_print_separator(struct util_rec *rec)
{
	switch (rec->fmt.type) {
	case REC_FMT_WIDE:
		rec_print_wide_separator(rec);
		break;
	case REC_FMT_LONG:
		break;
	case REC_FMT_CSV:
		break;
	}
}

/**
 * Set a field value to an argz vector
 *
 * @param[in]	rec	Record pointer
 * @param[in]	key	Key of the desired field
 * @param[in]	argz	Pointer to the series of strings
 * @param[in]	len	Length of the argz buffer
 */
void util_rec_set_argz(struct util_rec *rec, const char *key, const char *argz,
		       size_t len)
{
	struct util_rec_fld *fld;
	char *val;

	fld = rec_get_fld(rec, key);
	if (!fld)
		return;
	val = util_malloc(len);
	val = memcpy(val, argz, len);
	free(fld->val);
	fld->val = val;
	fld->len = len;
}

/**
 * Set a field value to a formatted string
 *
 * @param[in] rec  Record pointer
 * @param[in] key  Key of the desired field
 * @param[in] fmt  Format string for generation of value string
 * @param[in] ...  Parameters for format string
 *
 * @returns   Pointer to the field which was modified or NULL in the case of
 *            any error.
 */
void util_rec_set(struct util_rec *rec, const char *key, const char *fmt, ...)
{
	struct util_rec_fld *fld;
	va_list ap;
	char *str;

	util_assert(fmt != NULL, "Parameter 'fmt' pointer must not be NULL\n");
	fld = rec_get_fld(rec, key);
	if (!fld)
		return;
	UTIL_VASPRINTF(&str, fmt, ap);
	free(fld->val);
	fld->val = str;
	fld->len = strlen(str) + 1;
}

/**
 * Return the string value of a desired field. If the field value stored in argz
 * format, pointer to the first argz element is returned.
 *
 * @param[in] rec  Record pointer
 * @param[in] key  Key of the field
 *
 * @returns   If the desired field was found, the pointer to its value.
 *            NULL in the case of any error or if the field is empty.
 */
const char *util_rec_get(struct util_rec *rec, const char *key)
{
	struct util_rec_fld *fld = rec_get_fld(rec, key);

	return (fld != NULL) ? fld->val : NULL;
}

/**
 * Sets the indentation of the record
 *
 * @param[in] rec    Record pointer
 * @param[in] indent Number of characters to indent
 */
void util_rec_set_indent(struct util_rec *rec, int indent)
{
	rec->fmt.indent = indent;
}
