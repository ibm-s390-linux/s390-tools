/**
 * util_rec_example - Example program for util_rec
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

//! [code]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_rec.h"

/*
 * Print three records in specified format
 */
static void print_records(const char *format, struct util_rec *rec)
{
	static const char * const size_vec[] = {"small", "medium", "large"};
	static const char * const name_vec[] = {"zero", "one", "two"};
	int i;

	printf("###########################################################\n");
	printf("# %s\n\n", format);

	/* Define fields of record */
	util_rec_def(rec, "number", UTIL_REC_ALIGN_LEFT, 6, "Number");
	util_rec_def(rec, "name", UTIL_REC_ALIGN_LEFT, 10, "Name");
	util_rec_def(rec, "size", UTIL_REC_ALIGN_RIGHT, 15, "Size");

	/* Print record header (is a nop for long format) */
	util_rec_print_hdr(rec);

	for (i = 0; i < 3; i++) {
		/* Fill fields of record with values */
		util_rec_set(rec, "number", "%d", i);
		util_rec_set(rec, "name", name_vec[i]);
		util_rec_set(rec, "size", size_vec[i]);
		/* Print the record */
		util_rec_print(rec);
	}
	/* Print a separator line (is a nop for long and csv format) */
	util_rec_print_separator(rec);
	printf("\n");
}

/*
 * Print keys for record fields
 */
static void print_fields(struct util_rec *rec)
{
	struct util_rec_fld *fld;
	int i = 1;

	printf("###########################################################\n");
	printf("# Keys of record fields\n");

	util_rec_iterate(rec, fld) {
		printf("Field %d : %s\n", i++, util_rec_fld_get_key(fld));
	}
}

/*
 * Print records in "wide", "long", and "csv" format
 */
int main(void)
{
	struct util_rec *rec;

	rec = util_rec_new_wide("-");
	print_records("Wide format", rec);
	util_rec_free(rec);

	rec = util_rec_new_wide("-");
	util_rec_set_indent(rec, 4);
	print_records("Wide format with indentation", rec);
	util_rec_free(rec);

	rec = util_rec_new_long("-", ":", "number", 30, 20);
	print_records("Long format", rec);
	util_rec_free(rec);

	rec = util_rec_new_csv(",");
	print_records("CSV format", rec);
	print_fields(rec);
	util_rec_free(rec);

	return EXIT_SUCCESS;
}
//! [code]
