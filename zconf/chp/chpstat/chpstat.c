/*
 * chpstat - Tool to display channel-path statistics
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "cmg.h"
#include "column.h"
#include "key.h"
#include "misc.h"

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_fmt.h"
#include "lib/util_libc.h"
#include "lib/util_opt.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_rec.h"
#include "lib/zt_common.h"

/* Output format API level. */
#define API_LEVEL		1

/* Default interval in seconds between output. */
#define DEFAULT_INTERVAL	5

/* Maximum interval in seconds after which timestamps wrap twice (approx.). */
#define MAX_INTERVAL		2140

/* Maximum number of CHPIDS. */
#define NUM_CHPIDS		256

/* Highest valid CHPID number. */
#define MAX_CHPID		255

/* Sysfs paths. */
#define SYS_CSS0	"devices/css0"
#define SYS_CM_ENABLE	SYS_CSS0 "/cm_enable"

/* ANSI X3.64 terminal control codes. */
#define ANSI_CLS		"\e[2J"
#define ANSI_LOCATE(x, y)	"\e[" STRINGIFY(x) ";" STRINGIFY(y) "H"
#define ANSI_BOLD		"\e[1m"
#define ANSI_REVERSE		"\e[7m"
#define ANSI_RESET		"\e[0m"

#define UNIT_DEC	1000UL
#define UNIT_BIN	1024UL
#define UNIT_AUTO	0

#define strlen_i(a)	((int)strlen(a))
#define strlen_u(a)	((unsigned int)strlen(a))

/* Channel-path measurement facility status values. */
enum cm_status_t {
	CM_UNSUPPORTED,
	CM_DISABLED,
	CM_ENABLED,
};

/* Program information. */
static const struct util_prg prg = {
	.desc = "Use chpstat to view channel-path statistics such as "
		"utilization and throughput, and to query and control the "
		"status of the channel-path statistics function.\n"
		"\n"
		"When run without further options, data for all channel-paths "
		"is displayed repeatedly with a " STRINGIFY(DEFAULT_INTERVAL)
		" second delay in table format. You can limit output to "
		"specific channel-paths by listing the associated CHPIDs on "
		"the command line.",
	.copyright_vec = {
		{
			.owner     = "IBM Corp.",
			.pub_first = 2024,
			.pub_last  = 2024,
		},
		UTIL_PRG_COPYRIGHT_END
	},
	.args = "[CHPIDS] [ACTIONS]",
};

enum {
	OPT_STATUS       = 's',
	OPT_ENABLE       = 'e',
	OPT_DISABLE      = 'd',
	OPT_LIST_COLUMNS = 'l',
	OPT_LIST_KEYS    = 'L',
	OPT_ITERATIONS   = 'n',
	OPT_INTERVAL     = 'i',
	OPT_COLUMNS      = 'c',
	OPT_KEYS         = 'k',
	OPT_ALL          = 'a',
	/* Options without short version below. */
	OPT_FORMAT       = 0x80, /* First non-printable character. */
	OPT_CHARS,
	OPT_UTIL,
	OPT_METRICS,
	OPT_CMG,
	OPT_SCALE,
	OPT_NO_ANSI,
	OPT_NO_PREFIX,
	OPT_DEBUG,
};

enum command_t {
	CMD_ENABLE       = OPT_ENABLE,
	CMD_DISABLE      = OPT_DISABLE,
	CMD_STATUS       = OPT_STATUS,
	CMD_LIST_COLUMNS = OPT_LIST_COLUMNS,
	CMD_LIST_KEYS    = OPT_LIST_KEYS,
	CMD_TABLE,
	CMD_LIST,
};

/*
 * Configuration of command line options
 */
static struct util_opt opt_vec[] = {
	{
		.desc = "ACTIONS",
		.flags = UTIL_OPT_FLAG_SECTION,
	},
	{
		.option = { "status", no_argument, NULL, OPT_STATUS },
		.desc = "Show channel-path statistics status",
	},
	{
		.option = { "enable", no_argument, NULL, OPT_ENABLE },
		.desc = "Enable channel-path statistics",
	},
	{
		.option = { "disable", no_argument, NULL, OPT_DISABLE },
		.desc = "Disable channel-path statistics",
	},
	{
		.option = { "list-columns", no_argument, NULL,
			    OPT_LIST_COLUMNS},
		.desc = "List available table columns",
	},
	{
		.option = { "list-keys", no_argument, NULL, OPT_LIST_KEYS},
		.desc = "List available data keys",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	{
		.desc = "OPTIONS",
		.flags = UTIL_OPT_FLAG_SECTION,
	},
	{
		.option = { "iterations", required_argument, NULL,
			    OPT_ITERATIONS },
		.argument = "NUM",
		.desc = "Display NUM reports before ending (0 for no end)",
	},
	{
		.option = { "interval", required_argument, NULL,
			    OPT_INTERVAL },
		.argument = "NUM",
		.desc = "Pause NUM seconds between display",
	},
	{
		.option = { "columns", required_argument, NULL, OPT_COLUMNS },
		.argument = "COL,..",
		.desc = "Show only specified columns in table output",
	},
	{
		.option = { "keys", required_argument, NULL, OPT_KEYS },
		.argument = "KEY,..",
		.desc = "Show only data for specified keys in list output",
	},
	{
		.option = { "all", no_argument, NULL, OPT_ALL },
		.desc = "Show all table columns and key data",
	},
	{
		.option = { "scale", required_argument, NULL, OPT_SCALE },
		.argument = "UNIT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Scale BPS values by UNIT (number, suffix or auto)",
	},
	{
		.option = { "cmg", required_argument, NULL, OPT_CMG },
		.argument = "CMG,..",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Show data for specified CMGs only",
	},
	{
		.option = { "format", required_argument, NULL, OPT_FORMAT },
		.argument = "FORMAT",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List data in specified FORMAT (" FMT_TYPE_NAMES ")",
	},
	{
		.option = { "chars", no_argument, NULL, OPT_CHARS },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List channel-path measurement characteristics",
	},
	{
		.option = { "util", no_argument, NULL, OPT_UTIL },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List unprocessed utilization data",
	},
	{
		.option = { "metrics", no_argument, NULL, OPT_METRICS },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "List performance metrics",
	},
	{
		.option = { "no-ansi", no_argument, NULL, OPT_NO_ANSI },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Do not use ANSI terminal codes in output",
	},
	{
		.option = { "no-prefix", no_argument, NULL, OPT_NO_PREFIX },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Hide key prefix in pairs output format",
	},
	{
		.option = { "debug", no_argument, NULL, OPT_DEBUG },
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Print debugging information",
	},
	UTIL_OPT_END
};

/* Settings from command line options. */
static struct {
	bool cmd_specified;
	enum command_t cmd;
	int iterations;
	bool forever;
	int interval;
	int groups;
	bool groups_specified;
	bool all;
	bool use_ansi;
	bool use_prefix;
	bool debug;
	enum util_fmt_t fmt;
	bool fmt_specified;
	bool cmgs_specified;
	bool columns_specified;
	bool keys_specified;
	unsigned long unit;
	char unit_suffix;
	bool unit_specified;
} opts;

/* Per CHPID run-time data. */
static struct chpid_data_t {
	int id;
	bool selected;
	struct cmg_t *cmg;
	int type;
	int shared;
	char *speed;
	struct cmg_data_t data;
} chpid_data[NUM_CHPIDS];

#define chpid_for_each(c) \
	for (int __i = 0; __i < NUM_CHPIDS && ((c) = &chpid_data[__i]); __i++)

/*
 * Buffer should be large enough to contain a full table of output columns for
 * up to 256 CHPIDs.
 */
#define OUTPUT_BUFFER_SIZE	131072

/*
 * Make stdout fully buffered to enable writing a full table to terminal in a
 * single flush write. This helps reduce visual flicker on output terminals.
 */
static void buffer_stdout(bool on)
{
	static void *buffer;

	if (on) {
		free(buffer);
		buffer = util_zalloc(OUTPUT_BUFFER_SIZE);
		setvbuf(stdout, buffer, _IOFBF, OUTPUT_BUFFER_SIZE);
	} else {
		setlinebuf(stdout);
		free(buffer);
		buffer = NULL;
	}
}

/*
 * Emit ANSI terminal control @codes depending on the global use_ansi option.
 */
static void ansi(const char *codes)
{
	if (opts.use_ansi)
		printf("%s", codes);
}

/*
 * Initialize default settings.
 */
static void init_opts(void)
{
	opts.cmd            = CMD_TABLE;
	opts.cmd_specified  = false;
	opts.iterations     = -1;
	opts.forever        = true;
	opts.interval       = DEFAULT_INTERVAL;
	opts.groups         = 0;
	opts.groups_specified = false;
	opts.all            = false;
	opts.use_ansi       = isatty(STDOUT_FILENO);
	opts.use_prefix     = true;
	opts.fmt            = FMT_JSON;
	opts.fmt_specified  = false;
	opts.cmgs_specified = false;
	opts.unit           = UNIT_AUTO;
	opts.unit_suffix    = 0;
	opts.unit_specified = false;
}

/*
 * Initialize chpid data array.
 */
static void init_chpid_data(void)
{
	int chpid;

	for (chpid = 0; chpid < NUM_CHPIDS; chpid++) {
		memset(&chpid_data[chpid], 0, sizeof(chpid_data[chpid]));
		chpid_data[chpid].id = chpid;
	}
}

/*
 * Release memory used by chpid data array.
 */
static void free_chpid_data(void)
{
	int chpid;

	for (chpid = 0; chpid < NUM_CHPIDS; chpid++)
		free(chpid_data[chpid].speed);
}

/*
 * Parse a command line argument @arg that was specified for command line
 * option @name as an integer and check if the result is between @min and @max.
 *
 * Return the resulting integer on success. On failure, exit with an
 * appropriate error message.
 */
static int parse_int(const char *name, const char *arg, long min, long max)
{
	char *endptr;
	long v;

	v = strtol(arg, &endptr, 10);
	if (*endptr || !*arg) {
		errx(EXIT_USAGE, "Value for option --%s is invalid: %s",
		     name, arg);
	}
	if (v < min) {
		errx(EXIT_USAGE, "Value %s for option --%s is too small "
		     "(min %ld)", arg, name, min);
	}
	if (v > max) {
		errx(EXIT_USAGE, "Value %s for option --%s is too large "
		     "(max %ld)", arg, name, max);
	}
	return (int)v;
}

/*
 * Parse a command line argument @arg as CHPID. Return the CHPID on success.
 * On failure, exit with an error message.
 */
static int parse_chpid(const char *arg)
{
	int id;
	char c;

	if ((sscanf(arg, "%x %c", &id, &c) == 1 ||
	     sscanf(arg, "0.%x %c", &id, &c) == 1) && id <= MAX_CHPID)
		return id;

	errx(EXIT_USAGE, "Invalid CHPID '%s'", arg);
}

/*
 * Parse the comma-separated list of column names in @arg and select the
 * associated columns.
 */
static void parse_columns(char *arg)
{
	struct column_t *col;
	char *name;

	while ((name = strsep(&arg, ","))) {
		col = column_get_by_name(name);
		if (!col)
			errx(EXIT_USAGE, "Unknown column name '%s'", name);
		column_select(col);
	}
}

/*
 * Parse the comma-separated list of key names in @arg and add it to the
 * list of specified keys.
 */
static void parse_keys(char *arg)
{
	struct key_t *key;
	char *name;

	while ((name = strsep(&arg, ","))) {
		key = key_get_by_name(name);
		if (!key)
			errx(EXIT_USAGE, "Unknown key '%s'", name);
		key_select(key);
	}
}

/*
 * Parse the comma-separated list of CMG values in @arg and select the
 * associated CMG.
 */
static void parse_cmgs(char *arg)
{
	struct cmg_t *cmg_t;
	char *name;
	int cmg;

	while ((name = strsep(&arg, ","))) {
		cmg = parse_int("cmg", name, 1, 255);
		cmg_t = cmg_get(cmg);
		if (!cmg_t)
			errx(EXIT_USAGE, "Unsupported CMG '%s'", name);
		cmg_t->selected = true;
	}
}

/*
 * Parse a scale unit value in @arg and return the resulting scaling factor.
 */
static unsigned long parse_unit(char *arg)
{
	unsigned long unit;
	char *endptr;

	if (strlen(arg) == 1) {
		opts.unit_suffix = (char)toupper(*arg);
		switch (opts.unit_suffix) {
		case 'K':
			return UNIT_BIN;
		case 'M':
			return UNIT_BIN * UNIT_BIN;
		case 'G':
			return UNIT_BIN * UNIT_BIN * UNIT_BIN;
		case 'T':
			return UNIT_BIN * UNIT_BIN * UNIT_BIN * UNIT_BIN;
		default:
			break;
		}
	}
	opts.unit_suffix = 0;
	if (strcmp(arg, "auto") == 0)
		return UNIT_AUTO;
	/* Parse as number. */
	unit = strtoul(arg, &endptr, 10);
	if (!*endptr && *arg && unit > 0 &&
	    !(unit == ULONG_MAX && errno == ERANGE)) {
		return unit;
	}

	errx(EXIT_USAGE, "Unsupported scaling unit '%s'", optarg);
}

/*
 * Determine the current status of the channel-path measurement facility.
 */
static enum cm_status_t get_cm_status(void)
{
	enum cm_status_t result;
	char *path;
	int i;

	path = util_path_sysfs(SYS_CM_ENABLE);
	if (!util_path_exists(path)) {
		result = CM_UNSUPPORTED;
		goto out;
	}
	if (util_file_read_i(&i, 10, path))
		errx(EXIT_RUNTIME, "Unable to read file '%s'", path);
	if (i == 0)
		result = CM_DISABLED;
	else
		result = CM_ENABLED;
out:
	free(path);

	return result;
}

/*
 * Change the channel-path facility status to the value represented by @on.
 */
static void set_cm_enable(long on)
{
	char *path;

	if (on)
		printf("Enabling channel-path statistics\n");
	else
		printf("Disabling channel-path statistics\n");

	path = util_path_sysfs(SYS_CM_ENABLE);
	if (util_file_write_l(on, 10, "%s", path) == 0) {
		free(path);
		return;
	}

	switch (errno) {
	case EIO:
		errx(EXIT_RUNTIME, "Unable to enable channel-path statistics\n"
		     "Check if your system is authorized (see section "
		     "AUTHORIZATION in 'man %s')",
		     program_invocation_short_name);
		break;
	default:
		err(EXIT_RUNTIME, "Unable to write to file '%s'", path);
	}
}

/*
 * Get sysfs path for attribute @filename of CHPID @chpid. If @filename is
 * not specified, return path to CHPID sysfs directory.
 */
static char *get_chpid_path(int chpid, const char *filename)
{
	return util_path_sysfs(SYS_CSS0 "/chp0.%02x%s%s", chpid,
			       filename ? "/" : "", filename ? filename : "");
}

/*
 * Check if CHPID @chpid exists.
 */
static bool chpid_exists(int chpid)
{
	char *path;
	bool rc;

	path = get_chpid_path(chpid, NULL);
	rc = util_path_exists("%s", path);
	free(path);

	return rc;
}

/*
 * Print debugging information related to reading file @path.
 */
static void debug_text(const char *path, const char *txt)
{
	if (!opts.debug)
		return;
	if (txt)
		printf("DEBUG: read(%s)='%s'\n", path, txt);
	else
		printf("DEBUG: read(%s)=- errno=%d\n", path, errno);
}

/*
 * Print debugging information related to reading file @path.
 */
static void debug_bin(const char *path, void *buffer, size_t expect, ssize_t rc)
{
	if (!opts.debug)
		return;
	printf("DEBUG: read(%s)=%d/%d\n", path, (int)rc, (int)expect);
	util_hexdump_grp(stdout, "DEBUG", buffer, 4, (int)rc, 0);
}

static char *read_chpid_attr_as_text(int chpid, const char *name, bool try)
{
	char *path, *value = NULL;

	path = get_chpid_path(chpid, name);
	if (try && !util_path_exists(path))
		goto out;
	value = util_file_read_text_file(path, true);
	debug_text(path, value);
	if (!value && !try)
		err(EXIT_RUNTIME, "Unable to read file '%s'", path);
out:
	free(path);

	return value;
}

/*
 * Read and return the value of the cmg sysfs attribute for CHPID @chpid.
 * Return %-1 if the CMG value is "unknown".
 */
static int read_cmg(int chpid)
{
	char *value;
	int cmg;

	value = read_chpid_attr_as_text(chpid, "cmg", false);
	if (strcmp(value, "unknown") == 0)
		cmg =  -1;
	else
		cmg = atoi(value);
	free(value);

	return cmg;
}

/*
 * Read and return the integer value of sysfs attribute @name for CHPID @chpid.
 * The integer is interpreted using base @base.
 */
static int read_chpid_attr_as_int(int chpid, const char *name, int base)
{
	char *value;
	long i;

	value = read_chpid_attr_as_text(chpid, name, false);
	i = strtol(value, NULL, base);
	free(value);

	return (int)i;
}

/*
 * Read and return the value of sysfs attribute speed_bps for CHPID @chpid.
 * Return "-" if the attribute cannot be read, or if the value is unavailable.
 */
static char *read_speed(int chpid)
{
	char *value;

	value = read_chpid_attr_as_text(chpid, "speed_bps", true);
	/* Unavailable speed value is reported as "0". */
	if (value && strcmp(value, "0") == 0) {
		free(value);
		value = NULL;
	}

	return value;
}

/* Read @count bytes of binary data from file @path to @buffer. On success,
 * return %true. If @allow_eof is %true, return %false if not all data could
 * be read. Otherwise exit with an error message.
 */
static bool read_bin(const char *path, void *buffer, size_t count,
		     bool allow_eof)
{
	int fd;
	ssize_t rc = -1;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		goto err;
	rc = read(fd, buffer, count);
	debug_bin(path, buffer, count, rc);
	if (rc < 0)
		goto err;
	if ((size_t)rc < count && !allow_eof)
		goto err_eof;
	close(fd);

	return (size_t)rc == count;

err_eof:
	errx(EXIT_RUNTIME, "Unable to read file '%s': Unexpected end of file",
	     path);
err:
	err(EXIT_RUNTIME, "Unable to read file '%s'", path);
}

/*
 * Read the channel-measurements characteristics block for CHPID @chpid to
 * @cmcb.
 */
static void read_cmcb(int chpid, cmcb_t *cmcb)
{
	char *path;

	memset(cmcb, 0, sizeof(*cmcb));
	path = get_chpid_path(chpid, "measurement_chars");
	read_bin(path, cmcb, sizeof(*cmcb), false);
	free(path);
}

/*
 * Read the channel-utilization entry for CHPID @chpid to @cue.
 */
static void read_cue(int chpid, int cmg, cue_t *cue)
{
	char *path;

	memset(cue, 0, sizeof(*cue));
	path = get_chpid_path(chpid, "measurement");
	read_bin(path, cue, sizeof(*cue), false);
	free(path);

	/* Some firmware levels incorrectly report a CUIV of 0xfe for CMG 3 -
	 * fix this here to enable access to the full CUE data. */
	if (cmg == 3 && cue->common.cuiv == 0xfe) {
		if (opts.debug)
			printf("DEBUG: Fixing CMG 3 CUIV (0xfe => 0xff)\n");
		cue->common.cuiv = 0xff;
	}
}

/*
 * Read the extended channel-utilization entry for CHPID @chpid to @ext_cue.
 */
static bool read_ext_cue(int chpid, ext_cue_t *ext_cue)
{
	static bool once;
	bool e = false;
	char *path;

	memset(ext_cue, 0, sizeof(*ext_cue));
	path = get_chpid_path(chpid, "ext_measurement");
	/* Older kernels might not have extended measurement support. */
	if (util_path_exists(path)) {
		e = read_bin(path, ext_cue, sizeof(*ext_cue), true);
	} else if (!once) {
		warnx("Missing kernel support for extended channel-path "
		      "measurement data");
		once = true;
	}
	free(path);

	return e;
}

static bool cue_modified(cue_t *a, cue_t *b)
{
	return a->common.timestamp != b->common.timestamp;
}

/*
 * Read utilization data @util for @chpid with CMG @cmg.
 */
static void read_util(int chpid, int cmg, struct util_t *util)
{
	bool repeat = false, *e = &util->extended;
	ext_cue_t *ext_cue = &util->ext_cue;
	cue_t cue2, *cue = &util->cue;

	/* Loop to ensure that basic and extended CUEs are in sync. */
	do {
		read_cue(chpid, cmg, cue);
		*e = read_ext_cue(chpid, ext_cue);
		if (*e) {
			/* Re-read CUE to make sure it hasn't changed. */
			read_cue(chpid, cmg, &cue2);
			repeat = cue_modified(cue, &cue2);
		}
	} while (repeat);
}

/*
 * Select @chpid and read initial CHPID data from sysfs. If @try is %true,
 * return %true if CHPID is available, %false otherwise. If @try is %false,
 * exit with an error message if CHPID is unavailable.
 */
static bool select_chpid(int chpid, bool try)
{
	struct chpid_data_t *c = &chpid_data[chpid];
	struct cmg_t *cmg_t;
	int cmg;

	if (!chpid_exists(chpid)) {
		if (try)
			return false;
		errx(EXIT_RUNTIME, "CHPID 0.%02x does not exist", chpid);
	}
	cmg = read_cmg(chpid);
	if (cmg == -1) {
		if (try)
			return false;
		errx(EXIT_RUNTIME, "No statistics available for CHPID 0.%02x",
		     chpid);
	}
	cmg_t = cmg_get(cmg);
	if (!cmg_t) {
		if (try)
			return false;
		errx(EXIT_RUNTIME, "CHPID 0.%02x uses unsupported CMG %d",
		     chpid, cmg);
	}
	if (opts.cmgs_specified && !cmg_t->selected) {
		if (try)
			return false;
		errx(EXIT_RUNTIME, "CHPID 0.%02x excluded by --cmg option",
		     chpid);
	}

	cmg_t->found++;
	c->cmg        = cmg_t;
	c->type       = read_chpid_attr_as_int(chpid, "type", 16);
	c->shared     = read_chpid_attr_as_int(chpid, "shared", 10);
	c->speed      = read_speed(chpid);
	if (cmg_t->has_cmcb)
		read_cmcb(chpid, &c->data.cmcb);
	read_util(chpid, cmg, &c->data.util_a);
	c->data.util_b = c->data.util_a;
	c->selected   = true;

	return true;
}

/*
 * Select all available CHPIDs.
 */
static int select_all_chpids(void)
{
	int chpid, num_selected = 0;

	for (chpid = 0; chpid < NUM_CHPIDS; chpid++) {
		if (select_chpid(chpid, true))
			num_selected++;
	}

	return num_selected;
}

/*
 * Parse all positional parameters in @argv starting with @first up to @argc
 * and select all specified CHPIDs.
 */
static int parse_chpids(int first, int argc, char *argv[])
{
	int i, chpid, num_selected = 0;

	/* Parse optional CHPID selection. */
	for (i = first; i < argc; i++) {
		chpid = parse_chpid(argv[i]);
		if (chpid_data[chpid].selected)
			continue;
		select_chpid(chpid, false);
		num_selected++;
	}

	return num_selected;
}

/*
 * Enable channel-path statistics.
 */
static void cmd_enable(enum cm_status_t status)
{
	if (status == CM_ENABLED)
		printf("Channel-path statistics already enabled\n");
	else
		set_cm_enable(1);
}

/*
 * Disable channel-path statistics.
 */
static void cmd_disable(enum cm_status_t status)
{
	if (status == CM_DISABLED)
		printf("Channel-path statistics already disabled\n");
	else
		set_cm_enable(0);
}

/* pr_pair(key, fmt) */
#define pr_pair(k, fmt, ...) \
	util_fmt_pair(FMT_PERSIST, (k), (fmt), ##__VA_ARGS__)
/* pr_pair_quoted(key, fmt) */
#define pr_pair_quoted(k, fmt, ...) \
	util_fmt_pair(FMT_PERSIST | FMT_QUOTE, (k), (fmt), ##__VA_ARGS__)

/*
 * Show status of the channel-path statistics function in human-readable form.
 */
static void cmd_status_default(enum cm_status_t status)
{
	printf("Channel-path statistics are ");
	switch (status) {
	case CM_UNSUPPORTED:
		printf("not supported on this system\n");
		break;
	case CM_DISABLED:
		printf("disabled\n");
		break;
	case CM_ENABLED:
		printf("enabled\n");
		break;
	}
}

/*
 * Show status of the channel-path statistics function in machine-readable
 * format.
 */
static void cmd_status_fmt(enum cm_status_t status)
{
	const char *str = "";

	switch (status) {
	case CM_UNSUPPORTED:
		str = "unsupported";
		break;
	case CM_DISABLED:
		str = "disabled";
		break;
	case CM_ENABLED:
		str = "enabled";
		break;
	}

	util_fmt_add_key("status");
	util_fmt_obj_start(FMT_ROW, "chpstat_status");
	pr_pair_quoted("status", "%s", str);
	util_fmt_obj_end();
}

/*
 * Show status of the channel-path statistics function.
 */
static void cmd_status(enum cm_status_t status)
{
	if (opts.fmt_specified)
		cmd_status_fmt(status);
	else
		cmd_status_default(status);
}

/*
 * Update channel-utilization data for CHPID @c. Return %true if new data was
 * found, %false otherwise.
 */
static bool _update_util(struct chpid_data_t *c)
{
	struct util_t util;

	read_util(c->id, c->cmg->cmg, &util);
	if (!cue_modified(&util.cue, &c->data.util_b.cue))
		return false;

	c->data.util_a = c->data.util_b;
	c->data.util_b = util;

	return true;
}

/*
 * Update channel-utilization data for CHPID @c. If @wait is %true, repeat
 * update attempts every second until new data is available.
 */
static void update_util(struct chpid_data_t *c, bool wait)
{
	while (!_update_util(c) && wait)
		sleep(1);
}

/*
 * Update channel-path utilization data for all CHPIDs. If @wait is %true,
 * repeat the process until all CHPIDs have new data.
 */
static void update_util_all(bool wait)
{
	struct chpid_data_t *c;

	chpid_for_each(c) {
		if (c->selected)
			update_util(c, wait);
	}
}

/*
 * Return hostname of local host.
 */
static char *get_host_name(void)
{
	char host[HOST_NAME_MAX + 1] = { 0 }, *d;

	gethostname(host, sizeof(host) - 1);
	d = strchr(host, '.');
	if (d)
		*d = 0;
	if (!host[0])
		strncpy(host, "-", sizeof(host) - 1);

	return util_strdup(host);
}

/*
 * Print a header with iteration-specific information for iteration @iteration.
 */
static void pr_iteration_header(int iteration)
{
	unsigned int quoted = FMT_PERSIST | FMT_QUOTE, unquoted = FMT_PERSIST;
	char str[30], *host, *b = "", *r = "";
	struct timeval tv;
	struct tm *tm;

	if (opts.use_ansi) {
		b = ANSI_BOLD;
		r = ANSI_RESET;
	}

	gettimeofday(&tv, NULL);
	tm = localtime(&tv.tv_sec);
	host = get_host_name();

	if (opts.cmd == CMD_TABLE) {
		printf("%sIteration:%s %d  ", b, r, iteration);

		if (tm) {
			strftime(str, sizeof(str), "%F", tm);
			printf("%sDate:%s %s  ", b, r, str);
			strftime(str, sizeof(str), "%T%z", tm);
			printf("%sTime:%s %s  ", b, r, str);
		}
		printf("%sHost:%s %s\n", b, r, host);
	} else {
		util_fmt_pair(unquoted, KEY_ITERATION, "%d", iteration);
		util_fmt_pair(unquoted, KEY_TIME_EPOCH, "%llu", tv.tv_sec);
		if (tm) {
			strftime(str, sizeof(str), "%F %T%z", tm);
			util_fmt_pair(quoted, KEY_TIME, "%s", str);
		} else {
			util_fmt_pair(quoted | FMT_INVAL, KEY_TIME, "", str);
		}
	}

	free(host);
}

/*
 * Print generic, non-cmg specific data for CHPID @c.
 */
static void pr_chpid(struct chpid_data_t *c)
{
	pr_pair_quoted(KEY_CHPID, "0.%02x", c->id);
	pr_pair(KEY_TYPE, "%d", c->type);
	pr_pair(KEY_CMG, "%d", c->cmg->cmg);
	pr_pair(KEY_SHARED, "%d", c->shared);
	if (c->speed) {
		pr_pair_quoted(KEY_SPEED, "%s", c->speed);
	} else {
		util_fmt_pair(FMT_PERSIST | FMT_QUOTE | FMT_INVAL, KEY_SPEED,
			      "");
	}
}

static void pr_cmg_inval_pair(struct cmg_pair_t *p)
{
	if (p->type == CMG_FLOAT)
		util_fmt_pair(FMT_INVAL, p->key, "-1.0");
	else
		util_fmt_pair(FMT_INVAL, p->key, "-1");
}

static void pr_cmg_pair(struct cmg_pair_t *p)
{
	if (!p->valid) {
		pr_cmg_inval_pair(p);
		return;
	}

	switch (p->type) {
	case CMG_U32:
		util_fmt_pair(FMT_DEFAULT, p->key, "%u", p->value_u32);
		break;
	case CMG_U64:
		util_fmt_pair(FMT_DEFAULT, p->key, "%llu", p->value_u64);
		break;
	case CMG_FLOAT:
		util_fmt_pair(FMT_DEFAULT, p->key, "%.1f", p->value_double);
		break;
	}
}

static void pr_cmg_pairs(struct cmg_pair_t *pairs)
{
	int i;

	for (i = 0; pairs[i].key; i++)
		pr_cmg_pair(&pairs[i]);
}

static void pr_group(struct chpid_data_t *c, struct cmg_t *cmg,
		     enum key_group_t group)
{
	struct cmg_pair_t *pairs = NULL;

	pairs = cmg->get_values(&c->data, group);
	util_fmt_obj_start(FMT_DEFAULT, key_group_to_str(group));
	pr_cmg_pairs(pairs);
	util_fmt_obj_end();
	cmg_free_pairs(pairs);
}

/*
 * Show list of channel-path statistics once.
 */
static void cmd_list_once(void)
{
	struct chpid_data_t *c;
	struct cmg_t *cmg;

	util_fmt_obj_start(FMT_LIST, "channel_paths");
	chpid_for_each(c) {
		if (!c->selected)
			continue;
		cmg = c->cmg;
		if (opts.groups & (KEY_GRP_UTIL | KEY_GRP_METRICS))
			update_util(c, false);
		if (opts.groups & KEY_GRP_METRICS)
			cmg->update_metrics(&c->data);

		util_fmt_obj_start(FMT_ROW, NULL);
		if (opts.groups & KEY_GRP_CHP)
			pr_chpid(c);
		util_fmt_obj_start(FMT_DEFAULT, "cmg%d", cmg->cmg);
		if (opts.groups & KEY_GRP_CHARS)
			pr_group(c, cmg, KEY_GRP_CHARS);
		if (opts.groups & KEY_GRP_UTIL)
			pr_group(c, cmg, KEY_GRP_UTIL);
		if (opts.groups & KEY_GRP_METRICS)
			pr_group(c, cmg, KEY_GRP_METRICS);
		util_fmt_obj_end();
		util_fmt_obj_end();
	}
	util_fmt_obj_end();
}

/* Register the keys of all key-value pairs that will be printed. */
static void register_selected_keys(void)
{
	struct key_t *key;

	key_for_each_selected(key)
		util_fmt_add_key("%s", key->name);
}

/* Report an error if a key specified on the command line is not reported by
 * any available CHPID. */
static void check_key_availability(void)
{
	struct key_t *key;

	key_for_each_selected(key) {
		if (key->found)
			continue;
		errx(EXIT_RUNTIME, "No available CHPID provides key '%s' "
		     "(needs CMG %s)", key->name, key->cmg_str);
	}
}

static void apply_key_selection(void)
{
	bool do_filter = (opts.cmd == CMD_LIST);
	struct cmg_t *cmg_t;

	if (opts.all) {
		key_select_all();
	} else if (opts.groups_specified || opts.cmgs_specified ||
		 opts.keys_specified) {
		/* Apply selection options. */
		if (opts.groups_specified)
			key_select_by_groups(opts.groups, do_filter);
		if (opts.cmgs_specified) {
			cmg_for_each(cmg_t) {
				if (!cmg_t->selected)
					continue;
				key_select_by_cmg(cmg_t->cmg);
			}
		}
	} else {
		/* Select default keys suitable for command. */
		if (opts.cmd == CMD_LIST_KEYS)
			key_select_all();
		else
			key_select_by_groups(opts.groups, do_filter);
	}

	if (opts.cmd == CMD_LIST_KEYS)
		key_sort_selected();
}

/*
 * Show channel-path statistics in list format.
 */
static void cmd_list(void)
{
	int i;

	if (!opts.groups_specified && !opts.keys_specified)
		opts.groups = KEY_GRP_METRICS;
	opts.groups |= KEY_GRP_META | KEY_GRP_ITERATION | KEY_GRP_CHP;

	/* Re-initialize keys to get current key->found values. */
	key_init(opts.all);
	if (opts.keys_specified)
		check_key_availability();
	apply_key_selection();
	register_selected_keys();
	/* Select CMG key groups needed for selected keys. */
	opts.groups |= key_get_selected_groups();

	if (opts.groups & KEY_GRP_METRICS)
		update_util_all(true);

	if (opts.fmt != FMT_JSONSEQ)
		util_fmt_obj_start(FMT_LIST, NULL);
	for (i = 0; opts.forever || i < opts.iterations; i++) {
		if (i > 0)
			sleep((unsigned int)opts.interval);

		util_fmt_obj_start(0, NULL);
		if (opts.groups & KEY_GRP_ITERATION)
			pr_iteration_header(i);
		cmd_list_once();
		util_fmt_obj_end();

		/* Flush here to allow immediate consumption of full reports
		 * via pipes (e.g. for use with grep). */
		fflush(stdout);
	}
	if (opts.fmt != FMT_JSONSEQ)
		util_fmt_obj_end();
}

/*
 * Allocate a table using the names and widths of all selected columns.
 */
static struct util_rec *define_table(void)
{
	struct util_rec *rec;
	struct column_t *col;

	rec = util_rec_new_wide(NULL);
	column_for_each_selected(col) {
		util_rec_def(rec, col->name, UTIL_REC_ALIGN_RIGHT,
			     (int)col->width, "");
	}

	return rec;
}

/*
 * Scale value @v by @unit and return the suffix of the applied
 * unit-multiplier.
 */
static char scale_auto(struct cmg_pair_t *p, int unit)
{
	char suffixes[] = "\0KMGTPE";
	int i;

	for (i = 0; suffixes[i + 1]; i++) {
		switch (p->type) {
		case CMG_U32:
			if (p->value_u32 < (u32)unit)
				goto out;
			p->value_u32 /= (u32)unit;
			break;
		case CMG_U64:
			if (p->value_u64 < (u64)unit)
				goto out;
			p->value_u64 /= (u64)unit;
			break;
		case CMG_FLOAT:
			if (p->value_double < (double)unit)
				goto out;
			p->value_double /= (double)unit;
			break;
		default:
			break;
		}
	}

out:
	return suffixes[i];
}

static void scale_fixed(struct cmg_pair_t *p, unsigned long unit)
{
	switch (p->type) {
	case CMG_U32:
		p->value_u32 /= (u32)unit;
		break;
	case CMG_U64:
		p->value_u64 /= (u64)unit;
		break;
	case CMG_FLOAT:
		p->value_double /= (double)unit;
		break;
	default:
		break;
	}
}

/*
 * Add @value in formatted form to @column of @table. Scale value if defined
 * for @column.
 */
static void add_pair_value(struct util_rec *table, struct column_t *col,
			   struct cmg_pair_t *pair)
{
	char suffix = 0, str[16];
	int p;

	if (!pair->valid) {
		util_rec_set(table, col->name, "-");
		return;
	}

	if (pair->unit == CMG_NUMBER) {
		suffix = scale_auto(pair, UNIT_DEC);
	} else if (pair->unit == CMG_BPS) {
		if (opts.unit == UNIT_AUTO)
			suffix = scale_auto(pair, UNIT_BIN);
		else
			scale_fixed(pair, opts.unit);
	}

	switch (pair->type) {
	case CMG_U32:
		snprintf(str, sizeof(str), "%u%c", pair->value_u32, suffix);
		break;
	case CMG_U64:
		snprintf(str, sizeof(str), "%llu%c", pair->value_u64, suffix);
		break;
	case CMG_FLOAT:
		/* Find highest precision that fits into @width characters. */
		for (p = 2; p >= 0; p--) {
			snprintf(str, sizeof(str), "%.*f%c", p,
				 pair->value_double, suffix);
			if (strlen(str) <= col->width)
				break;
		}
		break;
	}
	util_rec_set(table, col->name, "%s", str);
}

/*
 * Add generic, non-cmg specific data for column @col and CHPID @c to @table.
 * Return %true if requested column was handled, %false otherwise.
 */
static bool add_column_generic(struct util_rec *table, struct column_t *col,
			       struct chpid_data_t *c)
{
	const char *name = col->name;

	switch (col->id) {
	case COL_CHPID:
		util_rec_set(table, name, "%02x", c->id);
		break;
	case COL_TYPE:
		util_rec_set(table, name, "%02x", c->type);
		break;
	case COL_CMG:
		util_rec_set(table, name, "%d", c->cmg->cmg);
		break;
	case COL_SHARED:
		util_rec_set(table, name, "%d", c->shared);
		break;
	case COL_SPEED:
		if (!c->speed)
			return false;
		util_rec_set(table, name, "%s", c->speed);
		break;
	default:
		return false;
	}

	return true;
}

static bool add_column_cmg(struct util_rec *table, struct column_t *col,
			   struct cmg_pair_t *pairs)
{
	int i;

	for (i = 0; pairs[i].key; i++) {
		if (pairs[i].col != col->id)
			continue;
		add_pair_value(table, col, &pairs[i]);
		return true;
	}

	return false;
}

/*
 * Add row data for CHPID @c to @table.
 */
static void add_table_row(struct util_rec *table, struct chpid_data_t *c,
			  struct cmg_pair_t *pairs)
{
	struct column_t *col;

	column_for_each_selected(col) {
		if (add_column_generic(table, col, c))
			continue;
		if (add_column_cmg(table, col, pairs))
			continue;
		/* Default text for unavailable column values. */
		util_rec_set(table, col->name, "-");
	}
}

/*
 * Find the longest number of consecutive columns that use the same non-empty
 * group header. Start with selected column @start. Update @num_ptr to contain
 * the number of consecutive columns, and @width_ptr to contain the total
 * width of these columns, including separating spaces.
 */
static void get_hdr_group_size(unsigned int start, unsigned int *num_ptr,
			       unsigned int *width_ptr)
{
	struct column_t *col;
	const char *last_hdr = "";
	unsigned int i, num, width;

	num = 0;
	width = 0;
	for (i = start; (col = column_get_by_index(i, true)); i++) {
		if (i > start) {
			if (!*last_hdr ||
			    strcmp(col->hdr1_group, last_hdr) != 0)
				break;
			/* Account for space between columns. */
			width++;
		}
		num++;
		width += col->width;
		last_hdr = col->hdr1_group;
	}
	*num_ptr = num;
	*width_ptr = width;
}

/*
 * Print @str centered in a space of @width characters.
 */
static void pr_centered(const char *str, unsigned int width)
{
	unsigned int a, b, l;

	l = strlen_u(str);
	width = MAX(width, l);
	a = (width - l) / 2;
	b = width - l - a;
	printf("%*s%s%*s", b, "", str, a, "");
}

/*
 * Distribute @extra characters evenly to column widths for @num selected
 * columns starting with @start.
 */
static void enlarge_columns(unsigned int start, unsigned int num,
			    unsigned int extra)
{
	struct column_t *col;
	unsigned int i, end, delta;

	end = start + num;
	for (i = start; i < end; i++) {
		col = column_get_by_index(i, true);
		delta = extra / (end - i);
		col->width += delta;
		extra -= delta;
	}
}

/*
 * Make sure that group header is centered over the non-spacing portions of
 * line 2 headers: |     HDR1      | => |       HDR1    |
 *                 |   HDR2    HDR2|    |   HDR2    HDR2|
 */
static void pr_hdr1_spacing(struct column_t *col, unsigned int *width_ptr)
{
	unsigned int w1, w2, spacing;

	w1 = strlen_u(col->hdr1_group);
	w2 = strlen_u(col->hdr2);
	if (col->width <= w2)
		return;
	spacing = col->width - w2;
	if (*width_ptr - spacing >= w1) {
		printf("%*s", spacing, "");
		*width_ptr -= spacing;
	}
}

/*
 * Print multi-line table header and update column widths based on header
 * lengths.
 */
static void print_table_header(void)
{
	struct column_t *col;
	unsigned int i, next_i, num, width, hdr_width;

	/* Print first header line and update column width based on heading. */
	for (i = 0; (col = column_get_by_index(i, true)); i = next_i) {
		if (i > 0)
			printf(" ");
		get_hdr_group_size(i, &num, &width);
		if (num == 1) {
			/* Update column width in case heading is wider. */
			width = MAX(width, strlen_u(col->hdr1_single));
			width = MAX(width, strlen_u(col->hdr2));
			col->width = width;
			printf("%*s", col->width, col->hdr1_single);
			next_i = i + 1;
			continue;
		}
		hdr_width = strlen_u(col->hdr1_group);
		if (hdr_width > width) {
			/* Header text is longer than sum of column widths,
			 * increase column widths accordingly.*/
			enlarge_columns(i, num, hdr_width - width);
			width = hdr_width;
		}
		pr_hdr1_spacing(col, &width);
		pr_centered(col->hdr1_group, width);
		next_i = i + num;
	}
	printf("\n");

	/* Print second header line. */
	i = 0;
	column_for_each_selected(col) {
		if (i++ > 0)
			printf(" ");
		printf("%*s", col->width, col->hdr2);
	}
	printf("\n");
}

/*
 * Show table of channel-path statistics once.
 */
static void cmd_table_once(void)
{
	struct cmg_pair_t *pairs;
	struct util_rec *table;
	struct chpid_data_t *c;
	struct cmg_t *cmg;

	ansi(ANSI_BOLD ANSI_REVERSE);
	print_table_header();
	ansi(ANSI_RESET);
	table = define_table();

	chpid_for_each(c) {
		if (!c->selected)
			continue;
		cmg = c->cmg;

		/* Update data. */
		update_util(c, false);
		cmg->update_metrics(&c->data);

		/* Add data to table. */
		pairs = cmg->get_values(&c->data, KEY_GRP_ALL);
		add_table_row(table, c, pairs);
		cmg_free_pairs(pairs);
		util_rec_print(table);
	}

	util_rec_free(table);

	if (opts.unit != UNIT_AUTO && !opts.unit_suffix)
		printf("\n* = %lu B/s\n", opts.unit);
}

static void apply_column_selection(void)
{
	struct cmg_t *cmg_t;

	if (opts.all) {
		column_select_all();
	} else if (opts.cmgs_specified) {
		/* Choose columns appropriate for CMGs specified via --cmg. */
		cmg_for_each(cmg_t) {
			if (!cmg_t->selected)
				continue;
			column_select_id_list(cmg_t->default_column_ids);
		}
	} else if (!opts.columns_specified) {
		/* Select default columns suitable for command. */
		if (opts.cmd == CMD_LIST_COLUMNS)
			column_select_all();
		else
			column_select_default();
	}
}

/* Artificial upper limit for BPS needed to determine maximum column widths. */
#define MAX_BPS		(1024.0 * /* MiB/s per GFC */ 100 * (/* MiB */ 1048576))

/*
 * Make sure each column fits expected values.
 */
static void calc_column_widths(void)
{
	struct column_t *col;
	const char *last_hdr1 = NULL;
	char str[32];
	unsigned int width;
	double v;

	column_for_each_selected(col) {
		/* Make sure column fits at least a single header. */
		col->width = MAX(col->width, strlen_u(col->hdr2));
		/* Make sure column fits maximum value. */
		width = col->width;
		switch (col->unit) {
		case COL_PERCENT:
			width = 4; /* "99.9" */
			break;
		case COL_NUMBER:
			width = 4; /* "999k" */
			break;
		case COL_BPS:
			if (!opts.unit_specified || opts.unit == UNIT_AUTO) {
				width = 4; /* "999K" */
			} else {
				v = MAX_BPS / (double)opts.unit;
				snprintf(str, sizeof(str) - 1, "%.0f%c", v,
					 opts.unit_suffix);
				width = strlen_u(str);
			}
			break;
		default:
			break;
		}
		col->width = MAX(col->width, width);
		/* Double space between groups. */
		if (last_hdr1 && strcmp(last_hdr1, col->hdr1_group) != 0)
			col->width++;
		last_hdr1 = col->hdr1_group;
	}
}

/*
 * Show table of channel-path statistics continuously as specified by
 * command line options.
 */
static void cmd_table(void)
{
	int i;

	apply_column_selection();
	calc_column_widths();
	column_update_bps_suffix(opts.unit == UNIT_AUTO, opts.unit_suffix);

	printf("Collecting initial utilization data\n");
	update_util_all(true);

	buffer_stdout(true);
	for (i = 0; opts.forever || i < opts.iterations; i++) {
		if (i > 0) {
			sleep((unsigned int)opts.interval);
			printf("\n");
		}

		/* Clear screen + move cursor to top-left of terminal (1,1). */
		ansi(ANSI_CLS ANSI_LOCATE(1, 1));

		pr_iteration_header(i);
		printf("\n");
		cmd_table_once();

		/* Make table visible in one go to avoid screen flicker. */
		fflush(stdout);
	}
	buffer_stdout(false);
}

#define HDR_COLUMN	"column"
#define HDR_HEADING	"heading"
#define HDR_DESC	"description"

/*
 * List available table columns in table format.
 */
static void cmd_list_columns_table(void)
{
	struct util_rec *table;
	struct column_t *col;
	int w, w1, w2, w3;

	/* Determine column widths. */
	w1 = strlen_i(HDR_COLUMN);
	w2 = strlen_i(HDR_HEADING);
	w3 = strlen_i(HDR_DESC);
	column_for_each_selected(col) {
		w1 = MAX(w1, strlen_i(col->name));
		w = strlen_i(col->hdr1_single) + strlen_i(col->hdr2) + 1;
		w2 = MAX(w2, w);
		w3 = MAX(w3, strlen_i(col->desc));
	}
	w1++;
	w2++;

	/* Print table heading. */
	table = util_rec_new_wide(NULL);
	util_rec_def(table, HDR_COLUMN, UTIL_REC_ALIGN_LEFT, w1, "COLUMN");
	util_rec_def(table, HDR_HEADING, UTIL_REC_ALIGN_LEFT, w2, "HEADING");
	util_rec_def(table, HDR_DESC, UTIL_REC_ALIGN_LEFT, w3, "DESCRIPTION");
	util_rec_print_hdr(table);

	/* Print rows of column data. */
	column_for_each_selected(col) {
		util_rec_set(table, HDR_COLUMN, col->name);
		if (*col->hdr1_single) {
			util_rec_set(table, HDR_HEADING, "%s %s",
				     col->hdr1_single, col->hdr2);
		} else {
			util_rec_set(table, HDR_HEADING, "%s", col->hdr2);
		}
		util_rec_set(table, HDR_DESC, "%s", col->desc);
		util_rec_print(table);
	}

	util_rec_free(table);
}

#define HDR_NAME	"name"
#define HDR_HEAD	"heading"

/*
 * List available table columns in machine-readable format.
 */
static void cmd_list_columns_fmt(void)
{
	struct column_t *col;

	util_fmt_add_key(HDR_NAME);
	util_fmt_add_key(HDR_HEAD);
	util_fmt_add_key(HDR_DESC);

	util_fmt_obj_start(FMT_LIST, "chpstat_list_columns");
	column_for_each_selected(col) {
		util_fmt_obj_start(FMT_ROW, NULL);
		pr_pair_quoted(HDR_NAME, "%s", col->name);
		if (*col->hdr1_single) {
			pr_pair_quoted(HDR_HEAD, "%s %s",
				       col->hdr1_single, col->hdr2);
		} else {
			pr_pair_quoted(HDR_HEAD, "%s", col->hdr2);
		}
		pr_pair_quoted(HDR_DESC, "%s", col->desc);
		util_fmt_obj_end();
	}
	util_fmt_obj_end();
}

/*
 * List available table columns.
 */
static void cmd_list_columns(void)
{
	apply_column_selection();
	if (opts.fmt_specified)
		cmd_list_columns_fmt();
	else
		cmd_list_columns_table();
}

#define HDR_KEY		"key"
#define HDR_GROUP	"group"
#define HDR_CMGS	"cmgs"

/*
 * List available table columns in table format.
 */
static void cmd_list_key_table(void)
{
	struct util_rec *table;
	struct key_t *key;
	int w1, w2, w3;

	/* Determine column width. */
	w1 = strlen_i(HDR_KEY);
	w2 = strlen_i(HDR_GROUP);
	w3 = strlen_i(HDR_CMGS);
	key_for_each_selected(key) {
		w1 = MAX(w1, strlen_i(key->name));
		w2 = MAX(w2, strlen_i(key_group_to_str(key->group)));
		w3 = MAX(w3, strlen_i(key->cmg_str));
	}
	/* Increase spacing between columns to improve readability. */
	w1++;
	w2++;
	/* Print table heading. */
	table = util_rec_new_wide(NULL);
	util_rec_def(table, HDR_KEY, UTIL_REC_ALIGN_LEFT, w1, "KEY");
	util_rec_def(table, HDR_GROUP, UTIL_REC_ALIGN_LEFT, w2, "GROUP");
	util_rec_def(table, HDR_CMGS, UTIL_REC_ALIGN_LEFT, w3, "CMGS");
	util_rec_print_hdr(table);
	/* Print rows of column data. */
	key_for_each_selected(key) {
		util_rec_set(table, HDR_KEY, "%s", key->name);
		util_rec_set(table, HDR_GROUP, "%s",
			     key_group_to_str(key->group));
		util_rec_set(table, HDR_CMGS, "%s", key->cmg_str);
		util_rec_print(table);
	}

	util_rec_free(table);
}

/*
 * List available keys in machine-readable format.
 */
static void cmd_list_key_fmt(void)
{
	struct key_t *key;

	util_fmt_add_key(HDR_KEY);
	util_fmt_add_key(HDR_GROUP);
	util_fmt_add_key(HDR_CMGS);

	util_fmt_obj_start(FMT_LIST, "chpstat_list_keys");
	key_for_each_selected(key) {
		util_fmt_obj_start(FMT_ROW, NULL);
		util_fmt_pair(FMT_QUOTE, HDR_KEY, "%s", key->name);
		util_fmt_pair(FMT_QUOTE, HDR_GROUP, "%s",
			      key_group_to_str(key->group));
		util_fmt_pair(FMT_QUOTE, HDR_CMGS, "%s", key->cmg_str);
		util_fmt_obj_end();
	}
	util_fmt_obj_end();
}

/*
 * List available keys.
 */
static void cmd_list_keys(void)
{
	apply_key_selection();
	if (opts.fmt_specified)
		cmd_list_key_fmt();
	else
		cmd_list_key_table();
}

/*
 * Return long command line name for specified @cmd option.
 */
static const char *cmd_to_optstr(enum command_t cmd)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(opt_vec); i++) {
		if (opt_vec[i].option.val == (int)cmd)
			return opt_vec[i].option.name;
	}
	return "";
}

/*
 * Set tool command @cmd and check for conflicting options.
 */
static void set_cmd(enum command_t cmd)
{
	if (!opts.cmd_specified || opts.cmd == cmd) {
		opts.cmd = cmd;
		opts.cmd_specified = true;
		return;
	}
	errx(EXIT_USAGE, "Options --%s and --%s cannot be specified together",
	     cmd_to_optstr(opts.cmd), cmd_to_optstr(cmd));
}

/*
 * Set output format to the format specified by @name.
 */
static void set_fmt(const char *name)
{
	enum util_fmt_t fmt;

	if (!util_fmt_name_to_type(name, &fmt)) {
		errx(EXIT_USAGE, "Unknown format '%s' - supported formats: "
		     FMT_TYPE_NAMES, name);
	}
	if (opts.fmt_specified && fmt != opts.fmt) {
		errx(EXIT_USAGE, "Option --format cannot be specified multiple "
		     "times");
	}
	opts.fmt = fmt;
	opts.fmt_specified = true;
}

static void init_fmt(void)
{
	unsigned int flags = 0;

	if (opts.keys_specified)
		flags |= FMT_FILTER;
	if (!opts.use_prefix)
		flags |= FMT_NOPREFIX;
	if (opts.fmt == FMT_JSON || opts.fmt == FMT_JSONSEQ) {
		/* Ensure correct JSON even if interrupted. */
		flags |= FMT_HANDLEINT;
	}
	if (opts.fmt == FMT_CSV) {
		/* Quote all values to ensure compatibility with a multitude
		 * of CSV consumers. */
		flags |= FMT_QUOTEALL;
	}
	if (opts.keys_specified || opts.all) {
		/* Always show data for keys with no valid value if the key
		 * was specifically requested by the user. */
		flags |= FMT_KEEPINVAL;
	}
	if (opts.debug)
		flags |= FMT_WARN;
	util_fmt_init(stdout, opts.fmt, flags, API_LEVEL);
	util_fmt_set_indent(0, 2, ' ');
}

/*
 * Parse options and execute the command
 */
int main(int argc, char *argv[])
{
	enum cm_status_t status;
	int c, num_selected;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);
	init_opts();
	init_chpid_data();
	key_init(opts.all);

	/* Parse command-line parameters. */
	while (1) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			/* --help */
			util_prg_print_help();
			util_opt_print_help();
			goto out;
		case 'v':
			/* --version */
			util_prg_print_version();
			goto out;
		case OPT_ENABLE:
			/* --enable */
			set_cmd(CMD_ENABLE);
			break;
		case OPT_DISABLE:
			/* --disable */
			set_cmd(CMD_DISABLE);
			break;
		case OPT_STATUS:
			/* --status */
			set_cmd(CMD_STATUS);
			break;
		case OPT_LIST_COLUMNS:
			/* --list-columns */
			set_cmd(CMD_LIST_COLUMNS);
			break;
		case OPT_COLUMNS:
			/* --columns */
			opts.columns_specified = true;
			parse_columns(optarg);
			break;
		case OPT_LIST_KEYS:
			/* --list-keys */
			set_cmd(CMD_LIST_KEYS);
			break;
		case OPT_KEYS:
			/* --keys KEY1,.. */
			opts.keys_specified = true;
			parse_keys(optarg);
			break;
		case OPT_CMG:
			/* --cmg NUM,.. */
			opts.cmgs_specified = true;
			parse_cmgs(optarg);
			break;
		case OPT_SCALE:
			/* --scale UNIT */
			opts.unit_specified = true;
			opts.unit = parse_unit(optarg);
			break;
		case OPT_ITERATIONS:
			/* --iterations NUM */
			opts.iterations = parse_int("iterations", optarg, 0,
						    INT_MAX);
			opts.forever = (opts.iterations < 1);
			break;
		case OPT_INTERVAL:
			/* --interval NUM */
			opts.interval = parse_int("interval", optarg, 1,
						  MAX_INTERVAL);
			break;
		case OPT_CHARS:
			/* --chars */
			opts.groups_specified = true;
			opts.groups |= KEY_GRP_CHARS;
			break;
		case OPT_UTIL:
			/* --util */
			opts.groups_specified = true;
			opts.groups |= KEY_GRP_UTIL;
			break;
		case OPT_METRICS:
			/* --metrics */
			opts.groups_specified = true;
			opts.groups |= KEY_GRP_METRICS;
			break;
		case OPT_ALL:
			/* --all */
			opts.all = true;
			break;
		case OPT_NO_ANSI:
			/* --no-ansi */
			opts.use_ansi = false;
			break;
		case OPT_NO_PREFIX:
			/* --no-prefix */
			opts.use_prefix = false;
			break;
		case OPT_DEBUG:
			/* --debug */
			opts.debug = true;
			break;
		case OPT_FORMAT:
			/* --format FORMAT */
			set_fmt(optarg);
			break;
		default:
			util_opt_print_parse_error((char)c, argv);
			return EXIT_USAGE;
		}
	}

	if (!opts.cmd_specified) {
		/* List output is implied by --chars, --util, --metrics, --keys
		 * and --format. */
		if (opts.groups_specified || opts.keys_specified ||
		    opts.fmt_specified)
			opts.cmd = CMD_LIST;
	}

	if (optind != argc && opts.cmd != CMD_LIST && opts.cmd != CMD_TABLE) {
		errx(EXIT_USAGE, "Unexpected parameter specified: %s",
		     argv[optind]);
	}

	/* Initialize output formatter. */
	init_fmt();

	/* Handle functions that work without CM support. */
	status = get_cm_status();
	switch (opts.cmd) {
	case CMD_STATUS:
		cmd_status(status);
		goto out;
	case CMD_LIST_COLUMNS:
		cmd_list_columns();
		goto out;
	case CMD_LIST_KEYS:
		cmd_list_keys();
		goto out;
	default:
		break;
	}

	/* Ensure measurements are available beyond this point. */
	if (status == CM_UNSUPPORTED) {
		errx(EXIT_RUNTIME, "This system does not support channel-path "
		     "statistics");
	}

	/* Handle supplemental functions. */
	switch (opts.cmd) {
	case CMD_ENABLE:
		cmd_enable(status);
		goto out;
	case CMD_DISABLE:
		cmd_disable(status);
		goto out;
	default:
		break;
	}

	/* Ensure measurements are enabled beyond this point. */
	if (status == CM_DISABLED) {
		errx(EXIT_RUNTIME, "Channel-path statistics are disabled\n"
		     "Use '%s --enable' to enable statistics",
		     program_invocation_short_name);
	}

	/* Determine CHPID list. */
	if (optind != argc)
		num_selected = parse_chpids(optind, argc, argv);
	else
		num_selected = select_all_chpids();
	if (num_selected == 0)
		errx(EXIT_RUNTIME, "No available CHPIDs found");

	switch (opts.cmd) {
	case CMD_LIST:
		cmd_list();
		break;
	default:
		cmd_table();
		break;
	}

out:
	util_fmt_exit();
	free_chpid_data();
	key_exit();
	cmg_exit();
	column_exit();

	return EXIT_OK;
}
