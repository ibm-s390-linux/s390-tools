/*
 * lsscm - Show information about Storage Class Memory Increments
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_opt.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_rec.h"
#include "lib/util_scandir.h"
#include "lib/zt_common.h"

/*
 * Program configuration
 */
const struct util_prg prg = {
	.desc = "List information about available Storage Class Memory Increments.",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2016,
			.pub_last = 2017,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Configuration of command line options
 */
static struct util_opt opt_vec[] = {
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

/**
 * Print all attributes of one device
 *
 * @param[in]  name   Block device name, or NULL if scm_block.ko is not loaed
 * @param[in]  data   Address of scm device
 * @param[in]  rec    Container for tabular output
 */
static void print_scm_attrs(const char *name, const char *addr,
			    struct util_rec *rec)
{
	long value;
	char *path;

	path = util_path_sysfs("bus/scm/devices/%s", addr);

	util_rec_set(rec, "addr", addr);
	if (name) {
		util_rec_set(rec, "name", name);
		if (util_file_read_l(&value, 10, "%s/block/%s/size", path, name))
			goto out_free_path;
		util_rec_set(rec, "size", "%ldMB", value * 512 / (1024 * 1024));
	} else {
		util_rec_set(rec, "name", "N/A");
		util_rec_set(rec, "size", "%ldMB", 0);
	}

	if (util_file_read_l(&value, 10, "%s/rank", path))
		goto out_free_path;
	util_rec_set(rec, "rank", "%ld", value);

	if (util_file_read_l(&value, 10, "%s/data_state", path))
		goto out_free_path;
	util_rec_set(rec, "dstate", "%ld", value);

	if (util_file_read_l(&value, 10, "%s/oper_state", path))
		goto out_free_path;
	util_rec_set(rec, "ostate", "%ld", value);

	if (util_file_read_l(&value, 10, "%s/persistence", path))
		goto out_free_path;
	util_rec_set(rec, "pers", "%ld", value);

	if (util_file_read_l(&value, 10, "%s/res_id", path))
		goto out_free_path;
	util_rec_set(rec, "resid", "%ld", value);

	util_rec_print(rec);
out_free_path:
	free(path);
}

/**
 * Print one scm block device
 *
 * @param[in]  addr    Address
 * @param[in]  rec     Container for tabular output
 */
void print_scm(const char *addr, struct util_rec *rec)
{
	struct dirent **de_vec;
	char *path;
	int count;

	path = util_path_sysfs("bus/scm/devices/%s/block", addr);
	/* Match scma..scmzz */
	count = util_scandir(&de_vec, NULL, path, "^scm[[:lower:]]{1,2}$");
	if (count < 0) {
		/* If scm_block not loaded */
		print_scm_attrs(NULL, addr, rec);
	} else {
		util_assert(count == 1, "We expect only one block device\n");
		print_scm_attrs(de_vec[0]->d_name, addr, rec);
		util_scandir_free(de_vec, count);
	}
	free(path);
}

/*
 * Look for used scm increments
 */
static void cmd_lsscm(void)
{
	struct dirent **de_vec;
	struct util_rec *rec;
	int i, count;
	char *path;

	rec = util_rec_new_wide("-");
	util_rec_def(rec, "addr",   UTIL_REC_ALIGN_LEFT, 16, "SCM Increment");
	util_rec_def(rec, "size",   UTIL_REC_ALIGN_LEFT,  7, "Size");
	util_rec_def(rec, "name",   UTIL_REC_ALIGN_LEFT,  5, "Name");
	util_rec_def(rec, "rank",   UTIL_REC_ALIGN_RIGHT, 4, "Rank");
	util_rec_def(rec, "dstate", UTIL_REC_ALIGN_RIGHT, 7, "D_state");
	util_rec_def(rec, "ostate", UTIL_REC_ALIGN_RIGHT, 7, "O_state");
	util_rec_def(rec, "pers",   UTIL_REC_ALIGN_RIGHT, 4, "Pers");
	util_rec_def(rec, "resid",  UTIL_REC_ALIGN_RIGHT, 5, "ResID");

	util_rec_print_hdr(rec);
	/* Call print_scm() for each "/sys/bus/scm/devices/[%16x]" softlink */
	path = util_path_sysfs("bus/scm/devices");
	count = util_scandir(&de_vec, util_scandir_hexsort,
			     path, "^[[:xdigit:]]{16}$");
	if (count < 0)
		errx(EXIT_FAILURE, "Could not read directory: %s", path);
	for (i = 0; i < count; i++) {
		if (de_vec[i]->d_type != DT_LNK)
			continue;
		print_scm(de_vec[i]->d_name, rec);
	}
	util_ptr_vec_free((void **) de_vec, count);
	util_rec_free(rec);
	free(path);
}

/*
 * Entry point
 */
int main(int argc, char **argv)
{
	int c;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);
	while (1) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}
	if (argc > optind) {
		util_prg_print_arg_error(argv[optind]);
		return EXIT_FAILURE;
	}
	cmd_lsscm();
	return EXIT_SUCCESS;
}
