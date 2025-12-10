/*
 * lschp - List information about available channel-paths
 *
 * Provide main function and command line parsing.
 *
 * Copyright IBM Corp. 2016, 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_fmt.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_rec.h"
#include "lib/util_scandir.h"
#include "lib/zt_common.h"

#define CHP_SHARED  "shared"
#define CHP_STATE   "vary"
#define CHP_PCHID   "pchid"
#define CHP_TYPE    "type"
#define CHP_CFG     "cfg"
#define CHP_CMG     "cmg"
#define CHP_ID      "chpid"

static enum util_fmt_t fmt;
static bool fmt_specified;

#define OPT_FORMAT 262	/* --format */

/*
 * Program configuration
 */
static const struct util_prg prg = {
	.desc	= "List information about available channel-paths.",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2016,
			.pub_last = 2019,
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
	{
		.option = { "format", required_argument, NULL, OPT_FORMAT},
		.argument = "FORMAT",
		.desc = "Output format (" FMT_TYPE_NAMES ")",
		.flags = UTIL_OPT_FLAG_NOSHORT,
	},
	UTIL_OPT_END
};

/**
 * Set the "--format" option
 *
 * @param[in] str	Format for structured output
 */
static void fmt_set(const char *str)
{
	if (!util_fmt_name_to_type(str, &fmt)) {
		errx(EXIT_FAILURE, "Unknown format '%s', supported formats: %s\n", str,
		     FMT_TYPE_NAMES);
	}
}

/**
 * Print buffer structure as formatted
 *
 * @param[in] rec     The buffer structure, where results are written to
 */
static void fmt_rec_print_formatted(struct util_rec *rec)
{
	const char *str_val, *key;
	struct util_rec_fld *fld;
	bool is_chid_external;
	int ival = -1;

	util_fmt_obj_start(FMT_ROW, "entry");
	util_list_iterate(__util_rec_get_list(rec), fld) {
		key = util_rec_fld_get_key(fld);
		str_val = util_rec_get(rec, key);
		if (!strcmp(str_val, "-")) {
			util_fmt_pair(FMT_QUOTE | FMT_INVAL, key, "");
		} else if (!strcmp(key, CHP_PCHID)) {
			is_chid_external = (str_val[0] != '(');
			sscanf(str_val, is_chid_external ? "%x" : "(%x)", &ival);
			util_fmt_pair(FMT_DEFAULT, "chid", "%d", ival);
			util_fmt_pair(FMT_DEFAULT, "chid_external", "%s", is_chid_external ?
							"true" : "false");
		} else if (!strcmp(key, CHP_ID)) {
			util_fmt_pair(FMT_DEFAULT | FMT_QUOTE, key, "%s", str_val);
		} else if (!strcmp(key, CHP_TYPE)) {
			sscanf(str_val, "%x", &ival);
			util_fmt_pair(FMT_DEFAULT, key, "%d", ival);
		} else {
			ival = atoi(str_val);
			util_fmt_pair(FMT_DEFAULT, key, "%d", ival);
		}
	}
	util_fmt_obj_end(); /* entry */
}

static void fmt_init(void)
{
	unsigned int flags = FMT_HANDLEINT | FMT_KEEPINVAL;

	if (!fmt_specified)
		return;
	if (fmt == FMT_CSV)
		flags |= FMT_NOMETA | FMT_QUOTEALL;
	else
		flags |= FMT_DEFAULT;
	util_fmt_init(stdout, fmt, flags, 1);
}

static void fmt_end(void)
{
	if (!fmt_specified)
		return;
	util_fmt_exit();
}

/**
 * Read all attributes of a desired directory
 *
 * Which attributes are to be investigated is defined in the
 * fallowing function body.
 *
 * @param[in] dir     Path of the desired directory
 * @param[in] css_id  ID for device identification
 * @param[in] rec     The buffer structure, where results are written to
 * @param[in] chp     If set: CHPID to filter by
 */
static void print_chpid(const char *chp_dir, unsigned int css_id,
			struct util_rec *rec, char *chp)
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
	util_rec_set(rec, CHP_ID, "%x.%02x", css_id, chp_id);

	/* vary */
	util_file_read_line(buf, sizeof(buf), "%s/status", path);
	if (strcmp(buf, "online") == 0)
		util_rec_set(rec, CHP_STATE, "1");
	else if (strcmp(buf, "offline") == 0)
		util_rec_set(rec, CHP_STATE, "0");
	else
		util_rec_set(rec, CHP_STATE, "-");

	/* configure */
	if (util_file_read_line(buf, sizeof(buf), "%s/configure", path))
		util_rec_set(rec, CHP_CFG, "-");
	else
		util_rec_set(rec, CHP_CFG, buf);

	/* type */
	if (util_file_read_line(buf, sizeof(buf), "%s/type", path))
		util_rec_set(rec, CHP_TYPE, "%s", "-");
	else
		util_rec_set(rec, CHP_TYPE, "%02lx", strtoul(buf, NULL, 16));

	/* cmg */
	util_file_read_line(buf, sizeof(buf), "%s/cmg", path);
	if ((strcmp(buf, "unknown") == 0) || (strlen(buf) == 0))
		util_rec_set(rec, CHP_CMG, "%s", "-");
	else
		util_rec_set(rec, CHP_CMG, "%-3lx", strtoul(buf, NULL, 0));

	/* shared */
	util_file_read_line(buf, sizeof(buf), "%s/shared", path);
	if ((strcmp(buf, "unknown") == 0) || (strlen(buf) == 0))
		util_rec_set(rec, CHP_SHARED, "%s", "-");
	else
		util_rec_set(rec, CHP_SHARED, "%-6lx", strtoul(buf, NULL, 0));

	/* chid */
	util_file_read_line(buf, sizeof(buf), "%s/chid_external", path);
	if (strcmp(buf, "1") == 0)
		chid_external = true;
	else
		chid_external = false;
	util_file_read_line(buf, sizeof(buf), "%s/chid", path);
	if (strlen(buf) != 0) {
		if (chid_external)
			util_rec_set(rec, CHP_PCHID, " %4s ", buf);
		else
			util_rec_set(rec, CHP_PCHID, "(%4s)", buf);
	} else {
		util_rec_set(rec, CHP_PCHID, "%s", "-");
	}
	if (!strlen(chp) || strcmp(util_rec_get(rec, CHP_ID), chp) == 0) {
		if (fmt_specified)
			fmt_rec_print_formatted(rec);
		else
			util_rec_print(rec);
	}
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
 * @param[in] chp     If set: CHPID to filter by
 */
static void print_css(const char *css_dir, struct util_rec *rec, char *chp)
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
		print_chpid(de_vec[i]->d_name, css_id, rec, chp);
	util_scandir_free(de_vec, count);
	free(path);
}

/*
 * Print chpid table
 *
 * @param[in] chp              If set: CHPID to filter by
 */
static void cmd_lschp(char *chp)
{
	struct dirent **de_vec;
	struct util_rec *rec;
	int i, count;
	char *path;

	fmt_init();
	rec = util_rec_new_wide("=");
	util_rec_def(rec, CHP_ID,	UTIL_REC_ALIGN_LEFT, 6, "CHPID");
	util_rec_def(rec, CHP_STATE,	UTIL_REC_ALIGN_LEFT, 5, "Vary");
	util_rec_def(rec, CHP_CFG,	UTIL_REC_ALIGN_LEFT, 5, "Cfg.");
	util_rec_def(rec, CHP_TYPE,	UTIL_REC_ALIGN_LEFT, 5, "Type");
	util_rec_def(rec, CHP_CMG,	UTIL_REC_ALIGN_LEFT, 4, "Cmg");
	util_rec_def(rec, CHP_SHARED,	UTIL_REC_ALIGN_LEFT, 6, "Shared");
	util_rec_def(rec, CHP_PCHID,	UTIL_REC_ALIGN_LEFT, 6, " PCHID");

	if (!fmt_specified)
		util_rec_print_hdr(rec);
	/*
	 * Iterate over each "/sys/devices/css.*"
	 */
	path = util_path_sysfs("devices");
	count = util_scandir(&de_vec, alphasort, path, "^css[[:xdigit:]]{1,2}$");
	if (fmt_specified)
		util_fmt_obj_start(FMT_LIST, "channel_paths");
	for (i = 0; i < count; i++)
		print_css(de_vec[i]->d_name, rec, chp);
	if (fmt_specified)
		util_fmt_obj_end(); /* channel_paths */
	util_ptr_vec_free((void **) de_vec, count);
	free(path);
	util_rec_free(rec);
	fmt_end();
}

#define CHP_LEN		4
/*
 * Parse options and execute the command
 */
int main(int argc, char *argv[])
{
	char chp[CHP_LEN + 1] = "";
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
		case OPT_FORMAT:
			fmt_specified = true;
			fmt_set(argv[optind - 1]);
			break;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}
	if (argc > optind + 1)
		errx(EXIT_FAILURE, "Too many arguments specified");
	if (argc == optind + 1) {
		/* we take a single argument only */
		switch (strlen(argv[optind])) {
		case 1:
			sprintf(chp, "0.0%s", argv[optind]);
			break;
		case 2:
			sprintf(chp, "0.%s", argv[optind]);
			break;
		case CHP_LEN:
			strcpy(chp, argv[optind]);
			break;
		default:
			errx(EXIT_FAILURE, "%s is not a valid channel-path ID",
			     argv[optind]);
		}
		if (!isdigit(chp[0]) || chp[1] != '.' || !isxdigit(chp[2]) ||
		    !isxdigit(chp[3]))
			errx(EXIT_FAILURE, "%s is not a valid channel-path ID",
			     chp);
	}
	cmd_lschp(chp);

	return EXIT_SUCCESS;
}
