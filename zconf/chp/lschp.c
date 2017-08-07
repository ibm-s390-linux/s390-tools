/*
 * lschp - List information about available channel-paths
 *
 * Provide main function and command line parsing.
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <stdbool.h>
#include <stdlib.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_rec.h"
#include "lib/util_scandir.h"
#include "lib/zt_common.h"

/*
 * Program configuration
 */
static const struct util_prg prg = {
	.desc	= "List information about available channel-paths.",
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
 * Read all attributes of a desired directory
 *
 * Which attributes are to be investigated is defined in the
 * fallowing function body.
 *
 * @param[in] dir     Path of the desired directory
 * @param[in] css_id  ID for device identification
 * @param[in] rec     The buffer structure, where results are written to
 */
static void print_chpid(const char *chp_dir, unsigned int css_id,
			struct util_rec *rec)
{
	unsigned int css_id_tmp, chp_id;
	bool chid_external;
	char *path, buf[8];

	/* Get CHPID ID */
	if (sscanf(chp_dir, "chp%x.%x", &css_id_tmp, &chp_id) != 2)
		err(EXIT_FAILURE, "Invalid directory: %s", chp_dir);
	if (css_id != css_id_tmp)
		errx(EXIT_FAILURE, "Inconsistent css ids");
	path = util_path_sysfs("devices/css%x/%s", css_id, chp_dir);

	/* chpid  */
	util_rec_set(rec, "chpid", "%x.%02x", css_id, chp_id);

	/* vary */
	util_file_read_line(buf, sizeof(buf), "%s/status", path);
	if (strcmp(buf, "online") == 0)
		util_rec_set(rec, "vary", "1");
	else if (strcmp(buf, "offline") == 0)
		util_rec_set(rec, "vary", "0");
	else
		util_rec_set(rec, "vary", "-");

	/* configure */
	if (util_file_read_line(buf, sizeof(buf), "%s/configure", path))
		util_rec_set(rec, "cfg", "-");
	else
		util_rec_set(rec, "cfg", buf);

	/* type */
	if (util_file_read_line(buf, sizeof(buf), "%s/type", path))
		util_rec_set(rec, "type", "%s", "-");
	else
		util_rec_set(rec, "type", "%02lx", strtoul(buf, NULL, 16));

	/* cmg */
	util_file_read_line(buf, sizeof(buf), "%s/cmg", path);
	if ((strcmp(buf, "unknown") == 0) || (strlen(buf) == 0))
		util_rec_set(rec, "cmg", "%-3s", "-");
	else
		util_rec_set(rec, "cmg", "%-3lx", strtoul(buf, NULL, 0));

	/* shared */
	util_file_read_line(buf, sizeof(buf), "%s/shared", path);
	if ((strcmp(buf, "unknown") == 0) || (strlen(buf) == 0))
		util_rec_set(rec, "shared", "%s", "-");
	else
		util_rec_set(rec, "shared", "%-6lx", strtoul(buf, NULL, 0));

	/* chid */
	util_file_read_line(buf, sizeof(buf), "%s/chid_external", path);
	if (strcmp(buf, "1") == 0)
		chid_external = true;
	else
		chid_external = false;
	util_file_read_line(buf, sizeof(buf), "%s/chid", path);
	if (strlen(buf) != 0) {
		if (chid_external)
			util_rec_set(rec, "pchid", " %4s ", buf);
		else
			util_rec_set(rec, "pchid", "(%4s)", buf);
	} else {
		util_rec_set(rec, "pchid", "%s", "-");
	}
	util_rec_print(rec);
	free(path);
}

/**
 * Compare two dirents numerically (chp0.ff <-> chp0.fe)
 *
 * @param[in] de1   First directory entry
 * @param[in] de2   Second directory entry
 * @retval    -1    de1 is lower
 *             0    de1 equals de2
 *             1    de2 is lower
 */
static int chpsort(const struct dirent **de1, const struct dirent **de2)
{
	unsigned long val1 = strtoul(&(*de1)->d_name[5], NULL, 16);
	unsigned long val2 = strtoul(&(*de2)->d_name[5], NULL, 16);

	if (val1 < val2)
		return -1;
	if (val1 == val2)
		return 0;
	return 1;
}

/**
 * Show all channel paths for a given directory in sysfs
 *
 * @param[in] css_dir The desired directory
 * @param[in] rec     The buffer structure, where results are written to
 */
static void print_css(const char *css_dir, struct util_rec *rec)
{
	struct dirent **de_vec;
	unsigned int css_id;
	int i, count;
	char *path;

	if (sscanf(css_dir, "css%x", &css_id) != 1)
		err(EXIT_FAILURE, "Invalid directory: %s", css_dir);

	path = util_path_sysfs("devices/css%d", css_id);
	count = util_scandir(&de_vec, chpsort, path, "chp%x.*", css_id);
	for (i = 0; i < count; i++)
		print_chpid(de_vec[i]->d_name, css_id, rec);
	util_scandir_free(de_vec, count);
	free(path);
}

/*
 * Print chpid table
 */
static void cmd_lschp(void)
{
	struct dirent **de_vec;
	struct util_rec *rec;
	int i, count;
	char *path;

	rec = util_rec_new_wide("=");
	util_rec_def(rec, "chpid",  UTIL_REC_ALIGN_LEFT, 6, "CHPID");
	util_rec_def(rec, "vary",   UTIL_REC_ALIGN_LEFT, 5, "Vary");
	util_rec_def(rec, "cfg",    UTIL_REC_ALIGN_LEFT, 5, "Cfg.");
	util_rec_def(rec, "type",   UTIL_REC_ALIGN_LEFT, 5, "Type");
	util_rec_def(rec, "cmg",    UTIL_REC_ALIGN_LEFT, 4, "Cmg");
	util_rec_def(rec, "shared", UTIL_REC_ALIGN_LEFT, 6, "Shared");
	util_rec_def(rec, "pchid",  UTIL_REC_ALIGN_LEFT, 6, " PCHID");

	util_rec_print_hdr(rec);
	/*
	 * Iterate over each "/sys/devices/css.*"
	 */
	path = util_path_sysfs("devices");
	count = util_scandir(&de_vec, alphasort, path, "^css[[:xdigit:]]{1,2}$");
	for (i = 0; i < count; i++)
		print_css(de_vec[i]->d_name, rec);
	util_ptr_vec_free((void **) de_vec, count);
	free(path);
	util_rec_free(rec);
}

/*
 * Parse options and execute the command
 */
int main(int argc, char *argv[])
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
	cmd_lschp();
	return EXIT_SUCCESS;
}
