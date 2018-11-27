/**
 * @defgroup util_rec_h util_rec: Record interface
 * @{
 * @brief Print records in different output formats
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_REC_H
#define LIB_UTIL_REC_H

#include "lib/util_list.h"

#define PAGE_SIZE	4096

/**
 * Opaque handle for a record
 *
 * The util_rec structure describes:
 *
 * - A set of fields
 * - An output format with the required formatting attributes (e.g. character
 *   for header separator)
 */
struct util_rec;
/**
 * Opaque handle for a record field (used for util_rec_iterate)
 *
 * The util_rec_fld structure describes:
 *
 * - Field value
 * - Field key name
 * - A set of attributes (e.g. width, alignment etc.)
 */
struct util_rec_fld;

/**
 * Alignment in util_rec tables
 */
enum util_rec_align {
	/** Align field left */
	UTIL_REC_ALIGN_LEFT,
	/** Align field right */
	UTIL_REC_ALIGN_RIGHT,
};

struct util_list *__util_rec_get_list(struct util_rec *rec);
const char *util_rec_fld_get_key(struct util_rec_fld *fld);
#define util_rec_iterate(rec, fld) \
	util_list_iterate(__util_rec_get_list(rec), fld)

struct util_rec *util_rec_new_wide(const char *hdr_sep);
struct util_rec *util_rec_new_csv(const char *col_sep);
struct util_rec *util_rec_new_long(const char *hdr_sep, const char *col_sep,
				   const char *key, int key_size, int val_size);
void util_rec_free(struct util_rec *rec);

void util_rec_def(struct util_rec *rec, const char *key,
		  enum util_rec_align align, int width, const char *hdr);
void util_rec_set(struct util_rec *rec, const char *key, const char *fmt, ...);
void util_rec_set_argz(struct util_rec *rec, const char *key, const char *argz,
		       size_t len);

const char *util_rec_get(struct util_rec *rec, const char *key);

void util_rec_print_hdr(struct util_rec *rec);
void util_rec_print(struct util_rec *rec);
void util_rec_print_separator(struct util_rec *rec);

void util_rec_set_indent(struct util_rec *rec, int indent);

#endif /** LIB_UTIL_REC_H @} */
