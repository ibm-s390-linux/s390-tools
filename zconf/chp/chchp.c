/*
 * chchp - Tool to modify channel-path state
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
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/zt_common.h"

#define CIO_SETTLE "/proc/cio_settle"
#define MAX_CHPID_CSS 255
#define MAX_CHPID_ID 255

/*
 * Private data
 */
struct chchp_l {
	struct {
		enum cmd_code {
			CMD_NONE,
			CMD_ATTRIBUTE,
			CMD_VARY,
			CMD_CONFIGURE,
		} code;
		const char *value;
	} cmd;
} l;

struct chchp_l *chchp_l = &l;

/*
 * Program configuration
 */
const struct util_prg prg = {
	.desc	=
"Modify the state of channel-path CHPID. CHPID can be a single, hexadecimal\n"
"channel-path identifier, a comma-separated list or a range of identifiers.",
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
	{
		.option = { "vary", required_argument, NULL, 'v'},
		.argument = "VALUE",
		.desc = "Logically vary channel-path to VALUE (1=on, 0=off)",
	},
	{
		.option = { "configure", required_argument, NULL, 'c'},
		.argument = "VALUE",
		.desc = "Configure channel-path to VALUE (1=on, 0=standby)",
	},
	{
		.option = { "attribute", required_argument, NULL, 'a'},
		.argument = "KEY=VALUE",
		.desc = "Set channel-path attribute KEY to VALUE",
	},
	UTIL_OPT_HELP,
	{
		.option = { "version", 0, NULL, 'V'},
		.desc = "Print version information, then exit",
	},
	UTIL_OPT_END
};

/*
 * Write and check attribute value
 */
static void write_value(const char *dir, const char *key, const char *val)
{
	char val2[256];

	if (!util_path_is_reg_file("%s/%s", dir, key)) {
		printf("failed - no such attribute\n");
		exit(EXIT_FAILURE);
	}
	if (!util_path_is_writable("%s/%s", dir, key)) {
		printf("failed - attribute not writable\n");
		exit(EXIT_FAILURE);
	}
	if (util_file_write_s(val, "%s/%s", dir, key)) {
		printf("failed - write failed\n");
		exit(EXIT_FAILURE);
	}
	if (util_file_read_line(val2, sizeof(val2), "%s/%s", dir, key)) {
		printf("failed - could not determine new attribute value\n");
		exit(EXIT_FAILURE);
	}
	/*
	 * Skip value comparison for 'status' attribute because input
	 * can be specified in different ways.
	 */
	if (strcmp(key, "status") != 0) {
		if (strcmp(val, val2) != 0) {
			printf("failed - attribute value not as expected\n");
			exit(EXIT_FAILURE);
		}
	}
	printf("done.\n");
}

/*
 * Configure channel-path
 */
static void configure(int css, int num, const char *dir, const char *val)
{
	const char *op;

	if (strcmp(val, "0") == 0)
		op = "standby";
	else
		op = "online";

	printf("Configure %s %x.%02x... ", op, css, num);
	write_value(dir, "configure", val);
}

/*
 * Vary channel-path
 */
static void vary(int css, int num, const char *dir, const char *val)
{
	const char *op;

	if (strcmp(val, "0") == 0)
		op = "offline";
	else
		op = "online";

	printf("Vary %s %x.%02x... ", op, css, num);
	write_value(dir, "status", val);
}

/*
 * Get key and value from "KEY=VALUE"
 */
static int get_key_value(char **key, char **val, const char *key_val)
{
	char *ptr;

	if (!strchr(key_val, '='))
		return -1;
	*key = util_strdup(key_val);
	ptr = strchr(*key, '=');
	*ptr = '\0';
	ptr += 1;
	*val = util_strdup(ptr);
	return 0;
}

/*
 * Modify channel-path attribute
 */
static void attribute(int css, int num, const char *dir, const char *key_val)
{
	char *key, *val;

	if (get_key_value(&key, &val, key_val))
		return;
	printf("Attribute %s=%s %x.%02x... ", key, val, css, num);
	write_value(dir, key, val);
	free(key);
	free(val);
}

/*
 * Make sure only one command is specified and argument was specified correctly
 */
static void check_and_set_command(enum cmd_code code, const char *value)
{
	char *key, *val;
	int rc;

	if (l.cmd.code != CMD_NONE) {
		errx(EXIT_FAILURE, "Only one of --vary, --configure or "
		     "--attribute allowed");
	}
	switch (code) {
	case CMD_ATTRIBUTE:
		rc = get_key_value(&key, &val, value);
		if (rc || strlen(key) == 0 || strlen(val) == 0)
			errx(EXIT_FAILURE, "--attribute requires an argument");
		free(key);
		free(val);
		break;
	case CMD_VARY:
		if (strcmp(value, "0") == 0 || strcmp(value, "1") == 0)
			break;
		errx(EXIT_FAILURE, "Invalid value for --vary (only 0 or 1 "
		     "allowed)");
	case CMD_CONFIGURE:
		if (strcmp(value, "0") == 0 || strcmp(value, "1") == 0)
			break;
		errx(EXIT_FAILURE, "Invalid value for --configure (only 0 or 1 "
		     "allowed)");
	default:
		break;
	}
	l.cmd.code = code;
	l.cmd.value = value;
}

/*
 * Get channel-path directory
 */
static char *get_chp_dir(int css, int id)
{
	struct stat sb;
	char *path;

	path = util_path_sysfs("devices/css%x/chp%x.%x", css, css, id);
	if ((stat(path, &sb) == 0) && (sb.st_mode == S_IFDIR))
		return path;
	free(path);
	return util_path_sysfs("devices/css%x/chp%x.%02x", css, css, id);
}

/*
 * Extract css id from channel-path id string
 */
static int get_chpid_css(const char *chpid)
{
	int id, css_id;

	if (strchr(chpid, '.') == NULL) {
		css_id = 0;
	} else {
		if (sscanf(chpid, "%x.%x", &css_id, &id) != 2) {
			errx(EXIT_FAILURE, "Invalid channel-path identifier "
			     "'%s'", chpid);
		}
		if (css_id < 0 || css_id > MAX_CHPID_CSS) {
			errx(EXIT_FAILURE, "Invalid channel-path identifier "
			     "'%s'", chpid);
		}
	}
	return css_id;
}

/*
 * Extract id from channel-path id string
 */
static int get_chpid_id(const char *chpid)
{
	int id, css_id;

	if (strchr(chpid, '.') == NULL) {
		if (sscanf(chpid, "%x", &id) != 1) {
			errx(EXIT_FAILURE, "Invalid channel-path identifier "
			     "'%s'", chpid);
		}
	} else if (sscanf(chpid, "%x.%x", &css_id, &id) != 2) {
		errx(EXIT_FAILURE, "Invalid channel-path identifier '%s'",
		     chpid);
	}
	if (id < 0 || id > MAX_CHPID_ID) {
		errx(EXIT_FAILURE, "Invalid channel-path identifier '%s'",
		     chpid);
	}
	return id;
}

/*
 * Perform command specified by COMMAND and VALUE
 */
static void perform_command(int css, int id)
{
	struct stat sb;
	char *path;

	path = get_chp_dir(css, id);
	if ((stat(path, &sb) != 0) || ((sb.st_mode & S_IFMT) != S_IFDIR)) {
		printf("Skipping unknown channel-path %x.%02x\n", css, id);
		goto out_free_path;
	}
	switch (l.cmd.code) {
	case CMD_VARY:
		vary(css, id, path, l.cmd.value);
		break;
	case CMD_CONFIGURE:
		configure(css, id, path, l.cmd.value);
		break;
	case CMD_ATTRIBUTE:
		attribute(css, id, path, l.cmd.value);
		break;
	default:
		util_panic("Invalid cmd: %d\n", l.cmd.code);
	}
out_free_path:
	free(path);
}

/*
 * Calculate iterator steps for chpid loop
 */
static int get_iterator_step(int css1, int id1, int css2, int id2)
{
	if (css1 == css2) {
		if (id1 < id2)
			return 1;
		else
			return -1;
	} else if (css1 < css2) {
		return 1;
	} else {
		return -1;
	}
}

/*
 * Execute command on all chpids: from - to
 */
static void loop_chpids(int css1, int id1, int css2, int id2)
{
	int step = get_iterator_step(css1, id1, css2, id2);

	while (1) {
		/* Perform function */
		perform_command(css1, id1);
		/* Check for loop end */
		if ((css1 == css2) && (id1 == id2))
			break;
		/* Advance iterator */
		id1 = id1 + step;
		if (id1 < 0) {
			css1 -= 1;
			id1 = 255;
		} else if (id2 > 255) {
			css1 += 1;
			id1 = 0;
		}
	}
}

/*
 * Parse options and execute the command
 */
int main(int argc, char *argv[])
{
	char *chpid_from, *chpid_to, *chpid_list = NULL;
	int from_css, from_id, to_css, to_id;
	struct stat sb;
	int c, i;

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
		case 'V':
			util_prg_print_version();
			return EXIT_SUCCESS;
		case 'v':
			check_and_set_command(CMD_VARY, optarg);
			break;
		case 'c':
			check_and_set_command(CMD_CONFIGURE, optarg);
			break;
		case 'a':
			check_and_set_command(CMD_ATTRIBUTE, optarg);
			break;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}
	if (l.cmd.code == CMD_NONE) {
		errx(EXIT_FAILURE, "One of --vary, --configure or --attribute "
		     "required");
	}
	if (optind == argc) {
		errx(EXIT_FAILURE, "Need to specify at least one channel-path "
		     "ID");
	}

	/* Append each argument with comma to distinguish blank-separators */
	for (i = optind; i < argc; i++) {
		if (i > optind)
			chpid_list = util_strcat_realloc(chpid_list, ",");
		chpid_list = util_strcat_realloc(chpid_list, argv[i]);
	}

	/* Loop over comma-separated list */
	chpid_from = strtok(chpid_list, ",");

	while (chpid_from != NULL) {
		chpid_to = strchr(chpid_from, '-');
		if (chpid_to == NULL)
			chpid_to = chpid_from;
		else
			*chpid_to++ = '\0';
		if (*chpid_to == '\0') {
			errx(EXIT_FAILURE, "Invalid channel-path identifier "
			     "range %s", chpid_from);
		}
		from_css = get_chpid_css(chpid_from);
		from_id = get_chpid_id(chpid_from);
		to_css = get_chpid_css(chpid_to);
		to_id = get_chpid_id(chpid_to);
		loop_chpids(from_css, from_id, to_css, to_id);
		chpid_from = strtok(NULL, ",");
	}

	/* Do CIO settle */
	if (stat(CIO_SETTLE, &sb) != 0)
		util_file_write_s("1", CIO_SETTLE);
	free(chpid_list);
	return EXIT_SUCCESS;
}
