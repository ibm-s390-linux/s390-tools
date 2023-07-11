/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * lszdev: Display configuration of z Systems specific devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <getopt.h>
#include <string.h>
#include <unistd.h>

#include "lib/zt_common.h"

#include "blkinfo.h"
#include "ccw.h"
#include "ctc.h"
#include "device.h"
#include "devtype.h"
#include "inuse.h"
#include "misc.h"
#include "module.h"
#include "namespace.h"
#include "opts.h"
#include "path.h"
#include "scsi.h"
#include "select.h"
#include "subtype.h"
#include "table.h"
#include "table_types.h"

/* current site-id in action. By default, operations are always on fallback
 * site; We need the current site-id as global variable to avoid excessive
 * diff of simple function parameter modifications to pass this value.
 */
int global_site_id = SITE_FALLBACK;

/* Main program action. */
typedef enum {
	ACT_LIST,
	ACT_INFO,
	ACT_LIST_COLUMNS,
	ACT_LIST_TYPES,
	ACT_HELP,
	ACT_VERSION,
} action_t;

/* Representation of command line options. */
struct options {
	/* Selection. */
	struct select_opts *select;
	unsigned int type:1;

	/* Actions */
	unsigned int info;
	unsigned int list_columns:1;
	unsigned int list_types:1;
	unsigned int help:1;
	unsigned int version:1;

	/* Options */
	config_t config;
	unsigned int active:1;
	unsigned int persistent:1;
	unsigned int auto_conf:1;
	struct util_list *columns;	/* List of struct strlist_node */
	unsigned int no_headings:1;
	struct util_list *base;		/* List of struct strlist_node */
	unsigned int pairs:1;
	unsigned int shell:1;
	unsigned int verbose:1;
	unsigned int quiet:1;
	unsigned int site_id;
};

/* Makefile converts lszdev_usage.txt into C file which we include here. */
static const char *usage_text =
#include "lszdev_usage.c"
	;

#define OPT_ANONYMOUS_BASE	0x80
enum {
	OPT_ALL			= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_CONFIGURED		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_EXISTING		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_ONLINE		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_OFFLINE		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_FAILED		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_BY_PATH		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_BY_NODE		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_BY_INTERFACE	= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_BY_ATTRIB		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_TYPE		= 't',
	OPT_INFO		= 'i',
	OPT_LIST_COLUMNS	= 'l',
	OPT_LIST_TYPES		= 'L',
	OPT_HELP		= 'h',
	OPT_VERSION		= 'v',
	OPT_ACTIVE		= 'a',
	OPT_PERSISTENT		= 'p',
	OPT_COLUMNS		= 'c',
	OPT_NO_HEADINGS		= 'n',
	OPT_BASE		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_VERBOSE		= 'V',
	OPT_QUIET		= 'q',
	OPT_PAIRS		= 'P',
	OPT_SHELL		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_AUTO_CONF		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_SITE		= 's',
};

static struct opts_conflict conflict_list[] = {
	OPTS_CONFLICT(OPT_INFO,
		      OPT_LIST_COLUMNS, OPT_LIST_TYPES, OPT_HELP, OPT_VERSION,
		      OPT_COLUMNS, OPT_NO_HEADINGS,
		      0),
	OPTS_CONFLICT(OPT_LIST_COLUMNS,
		      OPT_LIST_TYPES, OPT_HELP, OPT_VERSION,
		      0),
	OPTS_CONFLICT(OPT_LIST_TYPES,
		      OPT_HELP, OPT_VERSION,
		      0),
	OPTS_CONFLICT(OPT_HELP,
		      OPT_VERSION,
		      0),
	OPTS_CONFLICT(OPT_TYPE,
		      OPT_CONFIGURED, OPT_EXISTING, OPT_ONLINE, OPT_OFFLINE,
		      OPT_BY_PATH, OPT_BY_NODE, OPT_BY_INTERFACE, OPT_FAILED,
		      0),
	OPTS_CONFLICT(OPT_SITE,
		      OPT_TYPE),
	OPTS_CONFLICT(OPT_ONLINE,
		      OPT_OFFLINE),
	OPTS_CONFLICT(OPT_QUIET,
		      OPT_VERBOSE),
	OPTS_CONFLICT(0, 0),
};

/* Command line options. */
static const struct option opt_list[] = {
	/* Selection. */
	{ "all",		no_argument,	NULL, OPT_ALL },
	{ "configured",		no_argument,	NULL, OPT_CONFIGURED },
	{ "existing",		no_argument,	NULL, OPT_EXISTING },
	{ "online",		no_argument,	NULL, OPT_ONLINE },
	{ "offline",		no_argument,	NULL, OPT_OFFLINE },
	{ "failed",		no_argument,	NULL, OPT_FAILED },
	{ "by-path",		required_argument, NULL, OPT_BY_PATH },
	{ "by-node",		required_argument, NULL, OPT_BY_NODE },
	{ "by-interface",	required_argument, NULL, OPT_BY_INTERFACE },
	{ "by-attrib",		required_argument, NULL, OPT_BY_ATTRIB },
	{ "type",		no_argument,	NULL, OPT_TYPE },

	/* Actions. */
	{ "info",		no_argument,	NULL, OPT_INFO },
	{ "list-columns",	no_argument,	NULL, OPT_LIST_COLUMNS },
	{ "list-types",		no_argument,	NULL, OPT_LIST_TYPES },
	{ "help",		no_argument,	NULL, OPT_HELP },
	{ "version",		no_argument,	NULL, OPT_VERSION },

	/* Options. */
	{ "active",		no_argument,	NULL, OPT_ACTIVE },
	{ "persistent",		no_argument,	NULL, OPT_PERSISTENT },
	{ "auto-conf",		no_argument,	NULL, OPT_AUTO_CONF },
	{ "columns",		required_argument, NULL, OPT_COLUMNS },
	{ "no-headings",	no_argument,	NULL, OPT_NO_HEADINGS },
	{ "base",		required_argument, NULL, OPT_BASE },
	{ "pairs",		no_argument,	NULL, OPT_PAIRS },
	{ "shell",              no_argument,    NULL, OPT_SHELL },
	{ "verbose",		no_argument,	NULL, OPT_VERBOSE },
	{ "quiet",		no_argument,	NULL, OPT_QUIET },
	{ "site",		required_argument, NULL, OPT_SITE },
	{ NULL,			no_argument,	NULL, 0 },
};

/* Command line abbreviations. */
static const char opt_str[] = ":tilLhvapPc:nVqs:";

/* Initialize options data structure. */
static void init_options(struct options *opts)
{
	memset(opts, 0, sizeof(struct options));
	opts->select = select_opts_new();
	opts->columns = strlist_new();
	opts->base = strlist_new();
	/* Default operations are on fallback site*/
	opts->site_id = SITE_FALLBACK;
}

/* Release memory used in options data structure. */
static void free_options(struct options *opts)
{
	if (!opts)
		return;
	select_opts_free(opts->select);
	strlist_free(opts->columns);
	strlist_free(opts->base);
}

/* Print usage information. */
static void print_usage(void)
{
	printf("%s", usage_text);
}

/* Print version information. */
static void print_version(void)
{
	printf("%s version %s\n", toolname, RELEASE_STRING);
}

/* Determine main program action from parse command line options. */
static action_t get_action(struct options *opts)
{
	if (opts->help)
		return ACT_HELP;
	if (opts->version)
		return ACT_VERSION;
	if (opts->info)
		return ACT_INFO;
	if (opts->list_columns)
		return ACT_LIST_COLUMNS;
	if (opts->list_types)
		return ACT_LIST_TYPES;
	return ACT_LIST;
}

/* Determine the site information from the device */
static char *get_site_from_pers(struct device *dev)
{
	int site = 0, i, num = 0;

	for (i = 0; i < NUM_SITES; i++) {
		if (dev->site_specific[i].exists) {
			site = i;
			num++;
			if (site == global_site_id && site != SITE_FALLBACK)
				return misc_asprintf("s%d", site);
		}
	}

	/* Incase of devices which do not have --site support, all the
	 * read configurations will be in the dev->persistent and not
	 * in dev->site_specific.
	 */
	if (num == 0 && dev->persistent.exists == 1 &&
	    global_site_id == SITE_FALLBACK)
		return misc_asprintf("yes");

	/* Found more site-specific information ? return s+ */
	if (num > 1)
		return misc_asprintf("s+");

	if (num == 1)
		if (site == SITE_FALLBACK)
			return misc_asprintf("yes");
		else
			return misc_asprintf("s%d", site);
	else
		return misc_asprintf("no");
}

/* Check options data structure for syntax errors. */
static exit_code_t check_options(struct options *opts,
				 int specified[OPTS_MAX + 1], int op)
{
	if (opts_check_conflict(op, specified, conflict_list, opt_list))
		return EXIT_USAGE_ERROR;

	return EXIT_OK;
}

/* Determine if STR is a valid device specification. */
static bool is_devspec(struct devtype *dt, struct subtype *st, char *str)
{
	char *copy, *curr, *next;
	bool rc;

	/* ID,ID-ID,... */
	copy = misc_strdup(str);
	next = copy;

	/* Separate by comma. */
	rc = true;
	if (st) {
		/* Is this a valid ID or range for this subtype? */
		while ((curr = strsep(&next, ","))) {
			if (!ns_is_id_valid(st->namespace, curr) &&
			    !ns_is_id_range_valid(st->namespace, curr)) {
				rc = false;
				break;
			}
		}
	} else if (dt) {
		/* Is this a valid ID or range for any subtype of this
		 * devtype? */
		while ((curr = strsep(&next, ","))) {
			if (!devtype_is_id_valid(dt, curr) &&
			    !devtype_is_id_range_valid(dt, curr)) {
				rc = false;
				break;
			}
		}
	} else {
		/* Is this a valid ID or range for any subtype? */
		while ((curr = strsep(&next, ","))) {
			if (!namespaces_is_id_valid(curr) &&
			    !namespaces_is_id_range_valid(curr)) {
				rc = false;
				break;
			}
		}
	}

	free(copy);

	return rc;
}

static exit_code_t check_devid(struct devtype *only_dt, struct subtype *only_st,
			       const char *id)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	struct namespace *ns;

	for (i = 0; (dt = devtypes[i]); i++) {
		if (only_dt && dt != only_dt)
			continue;
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (only_st && st != only_st)
				continue;
			if (ns_is_id_valid(st->namespace, id))
				return EXIT_OK;
		}
	}

	/* ID not valid - generate corresponding error message and exit code. */
	ns = NULL;
	if (only_st)
		ns = only_st->namespace;
	else if (only_dt && devtype_count_namespaces(only_dt) == 1)
		ns = only_dt->subtypes[0]->namespace;
	else
		ns = devtype_most_similar_namespace(only_dt, NULL, id);

	if (ns)
		return ns->is_id_valid(id, err_print);

	if (only_dt) {
		error("Unrecognized %s ID format: %s\n",
		      only_dt->devname, id);
		return EXIT_INVALID_ID;
	}

	syntax("Unknown device type or device ID format: %s\n", id);

	return EXIT_USAGE_ERROR;

}

static exit_code_t check_range(struct devtype *only_dt, struct subtype *only_st,
			       const char *range)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;
	struct namespace *ns;

	for (i = 0; (dt = devtypes[i]); i++) {
		if (only_dt && dt != only_dt)
			continue;
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (only_st && st != only_st)
				continue;
			if (ns_is_id_range_valid(st->namespace, range))
				return EXIT_OK;
		}
	}

	/* Range not valid - generate corresponding error message and exit
	 * code. */
	ns = NULL;
	if (only_st)
		ns = only_st->namespace;
	else if (only_dt && devtype_count_namespaces(only_dt) == 1)
		ns = only_dt->subtypes[0]->namespace;

	if (ns)
		return ns->is_id_range_valid(range, err_print);

	if (only_dt) {
		error("Unrecognized %s device ID range format: %s\n",
		      only_dt->devname, range);
		return EXIT_INVALID_ID;
	}

	syntax("Unknown device type or device ID range format: %s\n", range);

	return EXIT_USAGE_ERROR;
}

/* Get corresponding exit code and error message for invalid devspec. */
static exit_code_t check_devspec(struct devtype *dt, struct subtype *st,
				 const char *devspec)
{
	char *copy, *curr, *next;
	exit_code_t rc = EXIT_OK;

	/* ID,ID-ID,... */
	copy = misc_strdup(devspec);
	next = copy;

	/* Separate by comma. */
	while ((curr = strsep(&next, ","))) {
		if (strchr(curr, '-'))
			rc = check_range(dt, st, curr);
		else
			rc = check_devid(dt, st, curr);
		if (rc)
			break;
	}
	free(copy);

	return rc;
}

static exit_code_t check_devspecs(struct options *opts)
{
	struct strlist_node *str;
	exit_code_t rc = EXIT_OK;

	util_list_iterate(&opts->select->devids, str) {
		rc = check_devspec(opts->select->devtype, opts->select->subtype,
				   str->str);
		if (rc)
			break;
	}

	return rc;
}

/* Parse positional parameters. */
static exit_code_t parse_positional(struct options *opts, int argc,
				    char *argv[], int start)
{
	action_t action = get_action(opts);
	struct subtype *st;
	struct devtype *dt;
	int i;
	bool got_devspec;
	enum {
		invalid,
		required,
		optional,
	} ex_dev, ex_dt;

	/* Determine valid parameter combinations for each action. */
	switch (action) {
	case ACT_LIST:
	case ACT_INFO:
		if (opts->type) {
			ex_dev = invalid;
			ex_dt = required;
		} else {
			ex_dev = optional;
			ex_dt = optional;
		}
		break;
	case ACT_LIST_TYPES:
		ex_dev = invalid;
		ex_dt = optional;
		break;
	default:
		ex_dev = invalid;
		ex_dt = invalid;
		break;
	}

	/* Collect parameters. */
	for (i = start; i < argc; i++) {
		dt = devtype_find(argv[i]);
		st = subtype_find(argv[i]);

		if (ex_dt != invalid && st && !opts->select->devtype) {
			/* Got expected subtype. */
			opts->select->subtype = st;
			opts->select->devtype = st->devtype;
			continue;
		}
		if (ex_dt != invalid && dt && !opts->select->devtype) {
			/* Got expected devtype. */
			opts->select->devtype = dt;
			continue;
		}
		if (ex_dev != invalid && is_devspec(opts->select->devtype,
						    opts->select->subtype,
						    argv[i])) {
			/* Got expected device ID. */
			strlist_add_multi(&opts->select->devids, argv[i],
					  ",", 0);
			continue;
		}

		/* Handle error cases. */
		if (ex_dt != invalid && ex_dev == invalid) {
			if (opts->select->devtype)
				goto err_extra;
			else
				goto err_unknown_devtype;
		}
		if (ex_dt == invalid && ex_dev != invalid)
			goto err_unknown_dev;
		if (ex_dt != invalid && ex_dev != invalid) {
			if (opts->select->devtype)
				goto err_unknown_dev;
			goto err_unknown_dev_or_devtype;
		}

		goto err_extra;
	}

	/* Check for missing parameters. */
	got_devspec = select_opts_dev_specified(opts->select);

	if (ex_dt == required && !opts->select->devtype)
		goto err_no_devtype;
	if (ex_dev == required && !got_devspec)
		goto err_no_dev;
	if (ex_dev != invalid)
		goto check_devspec;

	return EXIT_OK;

check_devspec:
	return check_devspecs(opts);

err_unknown_dev_or_devtype:
	syntax("Unknown device type or device ID specification: %s\n", argv[i]);
	return EXIT_USAGE_ERROR;

err_unknown_dev:
	return check_devspec(opts->select->devtype, opts->select->subtype,
			     argv[i]);

err_unknown_devtype:
	error("Unrecognized device type: %s\n", argv[i]);
	return EXIT_UNKNOWN_DEVTYPE;

err_extra:
	syntax("Unexpected parameter found: %s\n", argv[i]);
	return EXIT_USAGE_ERROR;

err_no_devtype:
	error("Please specify a device type\n"
	      "Use '%s --list-types' to get a list of device types\n",
	      toolname);
	return EXIT_USAGE_ERROR;

err_no_dev:
	syntax("Please specify a device\n");
	return EXIT_USAGE_ERROR;
}

/* Parse command line options. Filter out invalid combinations. */
static exit_code_t parse_options(struct options *opts, int argc, char *argv[])
{
	exit_code_t rc;
	int opt;
	int specified[OPTS_MAX + 1];

	/* Suppress getopt error messages. */
	memset(specified, 0, sizeof(specified));
	rc = EXIT_OK;
	opterr = 0;
	while ((opt = getopt_long(argc, argv, opt_str, opt_list, NULL)) != -1) {
		switch (opt) {
		case OPT_ALL:
			/* --all */
			opts->select->all = 1;
			break;

		case OPT_CONFIGURED:
			/* --configured */
			opts->select->configured = 1;
			break;

		case OPT_EXISTING:
			/* --existing */
			opts->select->existing = 1;
			break;

		case OPT_ONLINE:
			/* --online */
			opts->select->online = 1;
			break;

		case OPT_OFFLINE:
			/* --offline */
			opts->select->offline = 1;
			break;

		case OPT_FAILED:
			/* --failed */
			opts->select->failed = 1;
			break;

		case OPT_BY_PATH:
			/* --by-path MOUNTPOINT */
			strlist_add(&opts->select->by_path, "%s", optarg);
			break;

		case OPT_BY_NODE:
			/* --by-node NODE */
			strlist_add(&opts->select->by_node, "%s", optarg);
			break;

		case OPT_BY_INTERFACE:
			/* --by-interface NAME */
			strlist_add(&opts->select->by_if, "%s", optarg);
			break;

		case OPT_BY_ATTRIB:
			/* --by-attrib NAME */
			if (!strchr(optarg, '=')) {
				syntax("--by-attrib requires argument in "
				       "ATTRIB=VALUE or ATTRIB!=VALUE "
				       "format\n");
				return EXIT_USAGE_ERROR;
			}
			strlist_add(&opts->select->by_attr, "%s", optarg);
			break;

		case OPT_TYPE:
			/* --type */
			opts->type = 1;
			break;

		case OPT_INFO:
			/* --info */
			opts->info++;
			break;

		case OPT_LIST_COLUMNS:
			/* --list-columns */
			opts->list_columns = 1;
			break;

		case OPT_LIST_TYPES:
			/* --list-types */
			opts->list_types = 1;
			break;

		case OPT_HELP:
			/* --help */
			opts->help = 1;
			/* --help has precedence - exit early */
			return EXIT_OK;

		case OPT_VERSION:
			/* --version */
			opts->version = 1;
			/* --version has precedence - exit early */
			return EXIT_OK;

		case OPT_ACTIVE:
			/* --active */
			opts->active = 1;
			break;

		case OPT_PERSISTENT:
			/* --persistent */
			opts->persistent = 1;
			break;

		case OPT_AUTO_CONF:
			/* --auto-conf */
			opts->auto_conf = 1;
			break;

		case OPT_COLUMNS:
			/* --columns COLUMN */
			strlist_add_multi(opts->columns, optarg, ",", 0);
			break;

		case OPT_NO_HEADINGS:
			/* --no-headings */
			opts->no_headings = 1;
			break;

		case OPT_BASE:
			/* --base PATH */
			strlist_add(opts->base, "%s", optarg);
			break;

		case OPT_PAIRS:
			/* --pairs */
			opts->pairs = 1;
			break;

		case OPT_SHELL:
			/* --shell */
			opts->shell = 1;
			break;

		case OPT_VERBOSE:
			/* --verbose */
			opts->verbose = 1;
			break;

		case OPT_QUIET:
			/* --quiet */
			opts->quiet = 1;
			break;

		case OPT_SITE:
			/* --site */
			/* User can specify only site-ids from 0 to 9 */
			if (!is_valid_site(optarg)) {
				syntax("Unsupported site ID\n");
				return EXIT_USAGE_ERROR;
			}

			if (opts->site_id != SITE_FALLBACK) {
				syntax("Cannot specify '--site' multiple "
				       "times\n");
				return EXIT_USAGE_ERROR;
			}

			/* site information is a persistent configuration.
			 * set opts->persistent here.
			 */
			opts->persistent = 1;
			opts->site_id = atoi(optarg);
			break;

		case ':':
			/* Missing option argument. */
			syntax("Option '%s' requires an argument\n",
			       argv[optind - 1]);
			return EXIT_USAGE_ERROR;

		case '?':
			/* Unknown option character. */
			if (optopt)
				syntax("Unrecognized option '-%c'\n", optopt);
			else {
				syntax("Unrecognized option '%s'\n",
				       argv[optind - 1]);
			}
			return EXIT_USAGE_ERROR;

		default:
			break;
		}
		if (opt >= 0 && opt <= OPTS_MAX)
			specified[opt] = 1;
		/* Check after each option to report errors in order of
		 * specification. */
		rc = check_options(opts, specified, opt);
		if (rc)
			break;
	}

	if (rc)
		goto out;

	/* check whether --pairs and --columns is used */
	if (opts->shell == 1 && (opts->pairs != 1 || util_list_is_empty(opts->columns))) {
		syntax("'--shell' must be used together with "
		       "'--pairs' and '--columns'\n");
		return EXIT_USAGE_ERROR;
	}

	/* Determine configuration set. */
	if (!opts->active && !opts->persistent && !opts->auto_conf) {
		/* Default display targets are active + persistent - note that
		 * autoconf data is still shown when available to make users
		 * aware of this type of data. */
		opts->config = config_active | config_persistent;
	} else {
		opts->config = get_config(opts->active, opts->persistent,
					  opts->auto_conf);
	}

	/* Handle positional parameters. */
	rc = parse_positional(opts, argc, argv, optind);

	/* Set implicit settings. */
	if (!select_opts_dev_specified(opts->select)) {
		switch (get_action(opts)) {
		case ACT_LIST:
		case ACT_INFO:
			/* List(--info without --type or device spec selects all
			 * devices. */
			if (!opts->type) {
				if (opts->config == config_all)
					opts->select->all = 1;
				else if (opts->config == config_active)
					opts->select->existing = 1;
				else if (opts->config == config_persistent ||
					 opts->site_id != SITE_FALLBACK)
					opts->select->configured = 1;
			}
			break;
		default:
			break;
		}
	}

out:
	return rc;
}

/* Column IDs for the devices table. */
enum dev_table_id {
	dev_type,
	dev_devid,
	dev_names,
	dev_blockdevs,
	dev_chardevs,
	dev_netdevs,
	dev_exists,
	dev_pers,
	dev_auto,
	dev_online,
	dev_failed,
	dev_modules,
	dev_attr,
	dev_attrpath,
};

/* Definition of output table for device list. */
static struct column *dev_table = COLUMN_ARRAY(
	COLUMN("TYPE",		align_left, dev_type, 1,
	       "Device type"),
	COLUMN("ID",		align_left, dev_devid, 1,
	       "Device identifier"),
	COLUMN("ON",		align_left, dev_online, 1,
	       "Device is online in the active configuration"),
	COLUMN("EXISTS",	align_left, dev_exists, 0,
	       "Device exists in the active configuration"),
	COLUMN("PERS",		align_left, dev_pers, 1,
	       "Device is configured persistently"),
	COLUMN("AUTO",		align_left, dev_auto, 0,
	       "Auto-configuration exists for device"),
	COLUMN("FAILED",	align_left, dev_failed, 0,
	       "Device is in error"),
	COLUMN("NAMES",		align_left, dev_names, 1,
	       "Associated Linux device names"),
	COLUMN("BLOCKDEVS",	align_left, dev_blockdevs, 0,
	       "Associated block devices including partitions"),
	COLUMN("CHARDEVS",	align_left, dev_chardevs, 0,
	       "Associated character devices"),
	COLUMN("NETDEVS",	align_left, dev_netdevs, 0,
	       "Associated network interfaces"),
	COLUMN("MODULES",	align_left, dev_modules, 0,
	       "Required kernel modules"),
	COLUMN("ATTR:",		align_left, dev_attr, 0,
	       "Value of specific attribute, e.g. ATTR:online"),
	COLUMN("ATTRPATH:",	align_left, dev_attrpath, 0,
	       "Path to specific attribute in active configuration")
);

static char *merge_str(const char *act, const char *pers, const char *ac,
		       config_t config, char **site, int max_sites)
{
	char *str;
	int i;
	struct util_list *str_list;

	str_list = strlist_new();

	act	= act  ? act  : "-";
	pers	= pers ? pers : "-";
	ac	= ac   ? ac   : "-";

	if (strcmp(act, pers) == 0 && strcmp(act, ac) == 0 &&
	    max_sites == 1)
		return misc_strdup(act);

	if (SCOPE_ACTIVE(config))
		strlist_add(str_list, act);
	if (SCOPE_PERSISTENT(config)) {
		if (global_site_id == SITE_FALLBACK) {
			strlist_add(str_list, pers);
		} else {
			strlist_add(str_list, site[global_site_id]);
			goto out;
		}
	}
	if (SCOPE_AUTOCONF(config)) {
		strlist_add(str_list, ac);
	}

	/* Do not show site-specific information when user specifically
	 * asked for persistent configuration setting.
	 */
	if (SCOPE_PERSISTENT(config) && config != config_persistent) {
		for (i = 0; i <= max_sites; i++) {
			if (site[i])
				strlist_add(str_list, site[i]);
			else
				if (str_list)
					strlist_add(str_list, "-");
		}
	}

out:
	str = strlist_flatten(str_list, "/");
	strlist_free(str_list);

	return str;
}

/* Return string representing online status of device @dev. */
static char *dev_table_get_online(struct device *dev, config_t config)
{
	int online;

	online = subtype_online_get(dev->subtype, dev, config_active);

	return misc_strdup(YESNO(online == 1));
}

/* Return string representing failed status of device @dev. */
static char *dev_table_get_failed(struct device *dev)
{
	struct util_list *errors;

	errors = subtype_get_errors(dev->subtype, dev->id);
	strlist_free(errors);

	return misc_strdup(YESNO(errors != NULL));
}

/* Return string for list of modules required by device @dev. */
static char *dev_table_get_modules(struct device *dev)
{
	struct util_list *names;
	char *str;

	names = strlist_new();
	device_add_modules(names, dev);
	str = strlist_flatten(names, " ");
	strlist_free(names);

	return str;
}

static char *get_attr(struct device *dev, const char *name, config_t config,
		      int site_id)
{
	struct setting_list *list;
	struct setting *s;

	list = device_get_setting_list(dev, config, site_id);
	if (!list)
		return NULL;
	s = setting_list_find(list, name);
	if (!s) {
		if (config == config_active) {
			/* Try reading active attribute directly. */
			return device_read_active_attrib(dev, name);
		}
		return NULL;
	}

	return misc_strdup(s->value);
}

/* When lszdev --info, make sure that the output contains only the
 * valid site information. Check if the site is valid and then add
 * the new SITEn column. For SITE_FALLBACK, the PERSISTENT column will
 * be used.
 */
static bool is_site_show(int site_id, int current_site)
{
	if (site_id == SITE_FALLBACK || site_id == current_site)
		return true;
	return false;
}

/* Return string for attribute with specified @name for device @dev. */
static char *dev_table_get_attr(struct device *dev, const char *attr,
				config_t config)
{
	char *act = NULL, *pers = NULL, *ac = NULL, *str;
	const char *name;
	char *site[NUM_USER_SITES];
	int i;
	static int max_sites;

	name = strchr(attr, ':');
	if (!name)
		return NULL;
	name++;

	/* To get the default settings on any configuration, make sure that
	 * the site_id is specified as SITE_FALLBACK. Any value of site_id
	 * less than SITE_FALLBACK will endup providing site-specific attribute
	 * settings.
	 */
	if (SCOPE_ACTIVE(config))
		act = get_attr(dev, name, config_active, SITE_FALLBACK);
	if (SCOPE_PERSISTENT(config)) {
		pers = get_attr(dev, name, config_persistent, SITE_FALLBACK);
		for (i = 0; i < NUM_USER_SITES; i++)
			site[i] = get_attr(dev, name, config, i);
	}
	if (SCOPE_AUTOCONF(config))
		ac = get_attr(dev, name, config_autoconf, SITE_FALLBACK);

	for (i = 0; i < NUM_USER_SITES; i++)
		if (dev->site_specific[i].exists)
			max_sites = (max_sites < i) ? i : max_sites;

	str = merge_str(act, pers, ac, config, site, max_sites);
	free(act);
	free(pers);
	free(ac);

	if (SCOPE_PERSISTENT(config))
		for (i = 0; i < NUM_USER_SITES; i++)
			free(site[i]);

	return str;
}

/* Return string for path to attribute with specified @name for device @dev
 * in the active configuration. */
static char *dev_table_get_attrpath(struct device *dev, const char *attr)
{
	const char *name;

	name = strchr(attr, ':');
	if (!name)
		return NULL;
	name++;

	return subtype_get_active_attrib_path(dev->subtype, dev, name);
}

/* Retrieve value of a cell for struct device @item in column @id in the
 * devices table. */
static char *dev_table_get_value(void *item, int id, const char *heading,
				 void *data)
{
	struct device *dev = item;
	struct options *opts = data;

	switch (id) {
	case dev_type:
		return misc_strdup(dev->subtype->name);
	case dev_devid:
		return misc_strdup(dev->id);
	case dev_names:
		return subtype_get_devnodes_str(dev->subtype, dev->id, 1, 0, 1,
						1);
	case dev_blockdevs:
		return subtype_get_devnodes_str(dev->subtype, dev->id, 1, 1, 0,
						0);
	case dev_chardevs:
		return subtype_get_devnodes_str(dev->subtype, dev->id, 0, 0, 1,
						0);
	case dev_netdevs:
		return subtype_get_devnodes_str(dev->subtype, dev->id, 0, 0, 0,
						1);
	case dev_exists:
		return misc_strdup(YESNO(dev->active.exists ||
					 dev->active.definable));
	case dev_pers:
		if (!is_dev_pers(dev) && dev->autoconf.exists)
			return misc_strdup("auto");
		return get_site_from_pers(dev);
	case dev_auto:
		return misc_strdup(YESNO(dev->autoconf.exists));
	case dev_online:
		return dev_table_get_online(dev, config_active);
	case dev_failed:
		return dev_table_get_failed(dev);
	case dev_modules:
		return dev_table_get_modules(dev);
	case dev_attr:
		return dev_table_get_attr(dev, heading, opts->config);
	case dev_attrpath:
		return dev_table_get_attrpath(dev, heading);
	default:
		break;
	}

	return NULL;
}

/* Determine if we need to read all device information based on command line
 * parameters. */
static read_scope_t get_scope(struct options *opts)
{
	struct strlist_node *s;
	struct column *col;

	util_list_iterate(opts->columns, s) {
		col = table_get_column(dev_table, s->str);
		if (!col)
			return scope_known;
		switch (col->id) {
		case dev_type:
		case dev_devid:
		case dev_names:
		case dev_blockdevs:
		case dev_chardevs:
		case dev_netdevs:
		case dev_exists:
		case dev_pers:
		case dev_auto:
		case dev_online:
		case dev_modules:
			continue;
		default:
			return scope_known;
		}
	}

	return scope_mandatory;
}

/* Build list of items in table from list of selected struct devices. */
static struct util_list *dev_table_build(struct options *opts,
					 exit_code_t *rc_ptr)
{
	struct util_list *selected, *devices = NULL;
	struct selected_dev_node *sel;
	struct device *dev;
	int active, persistent, autoconf;
	read_scope_t scope;
	exit_code_t rc;
	config_t config = opts->config;

	scope = get_scope(opts);
	selected = selected_dev_list_new();

	/* Read auto-config data when no configuration set was specified to
	 * make user aware of auto-config data. */
	if (!opts->active && !opts->persistent && !opts->auto_conf)
		config |= config_autoconf;

	rc = select_devices(opts->select, selected, 1, 0, opts->pairs,
			    config, scope, err_print);
	if (rc)
		goto out;
	devices = ptrlist_new();

	/* Process selected devices. */
	util_list_iterate(selected, sel) {
		if (sel->rc)
			continue;
		if (subtype_read_device(sel->st, sel->id, opts->config, scope,
					&dev))
			continue;

		if (dev->processed)
			continue;
		dev->processed = 1;

		/* Only process existing devices. */
		active = dev->active.exists || dev->active.definable;
		persistent = (int)is_dev_pers(dev);
		autoconf = dev->autoconf.exists;
		if (!active && !persistent && !autoconf)
			continue;

		/* with --site option, we consider only the persistent
		 * configurations available on the specified site-id.
		 * ignore active and autoconf here
		 */
		if (!persistent && global_site_id != SITE_FALLBACK)
			continue;
		ptrlist_add(devices, dev);
	}

	if (util_list_is_empty(devices)) {
		error("No device was selected!\n");
		ptrlist_free(devices, 0);
		devices = NULL;
		rc = EXIT_EMPTY_SELECTION;
	}

out:
	selected_dev_list_free(selected);
	if (rc_ptr)
		*rc_ptr = rc;

	return devices;
}

/* Perform device list. */
static exit_code_t do_list_devices(struct options *opts)
{
	struct util_list *items;
	exit_code_t rc;

	rc = table_check_columns(dev_table, opts->columns);
	if (rc)
		return rc;

	/* Create table from selection options. */
	items = dev_table_build(opts, &rc);
	if (rc)
		return rc;
	if (!items)
		return EXIT_EMPTY_SELECTION;

	/* Adjust columns visible depending on selected config set. */
	table_set_default(dev_table, dev_online, SCOPE_ACTIVE(opts->config));
	table_set_default(dev_table, dev_pers, SCOPE_PERSISTENT(opts->config));
	table_set_default(dev_table, dev_auto, SCOPE_AUTOCONF(opts->config) &&
					       !SCOPE_PERSISTENT(opts->config));
	table_set_default(dev_table, dev_names, SCOPE_ACTIVE(opts->config));

	/* Display table. */
	rc = table_print(dev_table, dev_table_get_value, opts, items,
			 opts->columns, !opts->no_headings, opts->pairs, 0,
			 util_list_is_empty(opts->columns), opts->shell);
	ptrlist_free(items, 0);

	return rc;
}

static char *devtype_get_modules_str(struct devtype *dt)
{
	struct util_list *modules;
	char *str;

	modules = strlist_new();
	devtype_add_modules(modules, dt, 1);
	str = strlist_flatten(modules, " ");
	strlist_free(modules);

	return str;
}

enum settings_table_id {
	settings_attribute,
	settings_readonly,
	settings_active,
	settings_persistent,
	settings_autoconf,
	settings_site0,
	settings_site1,
	settings_site2,
	settings_site3,
	settings_site4,
	settings_site5,
	settings_site6,
	settings_site7,
	settings_site8,
	settings_site9,
};

static struct column *settings_table = COLUMN_ARRAY(
	COLUMN("ATTRIBUTE", align_left, settings_attribute, 1, ""),
	COLUMN("READONLY", align_left, settings_readonly, 1, ""),
	COLUMN("ACTIVE", align_left, settings_active, 1, ""),
	COLUMN("PERSISTENT", align_left, settings_persistent, 1, ""),
	COLUMN("AUTOCONF", align_left, settings_autoconf, 0, ""),
	COLUMN("SITE0", align_left, settings_site0, 0, ""),
	COLUMN("SITE1", align_left, settings_site1, 0, ""),
	COLUMN("SITE2", align_left, settings_site2, 0, ""),
	COLUMN("SITE3", align_left, settings_site3, 0, ""),
	COLUMN("SITE4", align_left, settings_site4, 0, ""),
	COLUMN("SITE5", align_left, settings_site5, 0, ""),
	COLUMN("SITE6", align_left, settings_site6, 0, ""),
	COLUMN("SITE7", align_left, settings_site7, 0, ""),
	COLUMN("SITE8", align_left, settings_site8, 0, ""),
	COLUMN("SITE9", align_left, settings_site9, 0, "")
);

static struct util_list *settings_table_build(struct setting_list *active,
					      struct setting_list *persistent,
					      struct setting_list *autoconf,
					      struct device *dev,
					      bool readonly)
{
	struct util_list *names, *items;
	struct setting *s;
	struct strlist_node *str;
	int i;

	/* Get a list of all configured attributes. */
	names = strlist_new();
	if (active) {
		util_list_iterate(&active->list, s) {
			if ((readonly && !s->readonly) ||
			    (!readonly && s->readonly))
				continue;
			strlist_add(names, s->name);
		}
	}
	if (persistent && !readonly) {
		util_list_iterate(&persistent->list, s)
			strlist_add(names, s->name);
		if (dev) {
			for (i = 0; i < NUM_SITES; i++)
				util_list_iterate(&dev->site_specific[i].settings->list, s)
					strlist_add(names, s->name);
		}
	}
	if (autoconf && !readonly) {
		util_list_iterate(&autoconf->list, s)
			strlist_add(names, s->name);
	}
	strlist_sort_unique(names, str_cmp);

	/* Convert strlist to ptrlist. */
	items = ptrlist_new();
	util_list_iterate(names, str)
		ptrlist_add(items, misc_strdup(str->str));
	strlist_free(names);

	return items;
}

struct settings_table_data {
	struct setting_list *active;
	struct setting_list *persistent;
	struct setting_list *autoconf;
	struct setting_list *sites[NUM_SITES];
	int pairs;
	bool readonly;
};

static char *settings_table_get_value(void *item, int id, const char *heading,
				      void *data)
{
	char *name = item;
	struct settings_table_data *stdata = data;
	struct setting_list *list = NULL;
	struct setting *s;

	switch (id) {
	case settings_attribute:
	case settings_readonly:
		return misc_strdup(name);
	case settings_active:
		list = stdata->active;
		break;
	case settings_persistent:
		list = stdata->persistent;
		break;
	case settings_autoconf:
		list = stdata->autoconf;
		break;
	case settings_site0:
		list = stdata->sites[0];
		break;
	case settings_site1:
		list = stdata->sites[1];
		break;
	case settings_site2:
		list = stdata->sites[2];
		break;
	case settings_site3:
		list = stdata->sites[3];
		break;
	case settings_site4:
		list = stdata->sites[4];
		break;
	case settings_site5:
		list = stdata->sites[5];
		break;
	case settings_site6:
		list = stdata->sites[6];
		break;
	case settings_site7:
		list = stdata->sites[7];
		break;
	case settings_site8:
		list = stdata->sites[8];
		break;
	case settings_site9:
		list = stdata->sites[9];
		break;

	default:
		break;
	}
	if (list) {
		s = setting_list_find(list, name);
		if (s &&
		    !((id == settings_persistent || id == settings_autoconf) &&
		      s->derived)) {
			if (stdata->pairs)
				return misc_strdup(s->value);
			else
				return quote_str(s->value, 1);
		}
	}

	return misc_strdup(stdata->pairs ? "" : "-");
}

#define	INFO_INDENT	2
#define	INFO_WIDTH	19

static void settings_table_print(struct setting_list *active,
				 struct setting_list *persistent,
				 struct setting_list *autoconf,
				 struct device *dev,
				 struct options *opts, int ind, bool readonly,
				 bool neednl)
{
	struct util_list *items;
	struct settings_table_data data;
	int i;

	items = settings_table_build(
			SCOPE_ACTIVE(opts->config) ? active : NULL,
			SCOPE_PERSISTENT(opts->config) ? persistent : NULL,
			autoconf, dev, readonly);
	if (util_list_is_empty(items)) {
		if (!opts->pairs && !readonly)
			indent(ind, "%sNo settings found\n",
			       neednl ? "\n" : "");
		goto out;
	}
	if (neednl)
		printf("\n");

	table_set_default(settings_table, settings_attribute, readonly ? 0 : 1);
	table_set_default(settings_table, settings_readonly, readonly ? 1 : 0);
	table_set_default(settings_table, settings_active,
			  SCOPE_ACTIVE(opts->config));
	table_set_default(settings_table, settings_persistent,
			  is_site_show(opts->site_id, SITE_FALLBACK) &&
			  SCOPE_PERSISTENT(opts->config) && !readonly ? 1 : 0);
	table_set_default(settings_table, settings_autoconf,
			  (SCOPE_AUTOCONF(opts->config) || autoconf) &&
				!readonly ? 1 : 0);
	if (dev) {
		for (i = 0; i < NUM_USER_SITES; i++)
			table_set_default(settings_table, settings_site0 + i,
					  SCOPE_PERSISTENT(opts->config) &&
					  is_site_show(opts->site_id, i)  &&
					  dev->site_specific[i].exists &&
					  !readonly ? 1 : 0);

		for (i = 0; i < NUM_SITES; i++)
			data.sites[i] = dev->site_specific[i].settings;
	}

	data.active = active;
	data.persistent = persistent;
	data.autoconf = autoconf;
	data.pairs = opts->pairs;

	table_print(settings_table, settings_table_get_value, &data, items,
		    NULL, 1, opts->pairs, ind, 0, opts->shell);

out:
	ptrlist_free(items, 1);
}

static void print_info(const char *key, const char *value)
{
	if (!*value)
		value = "-";
	printf("%*s%*s%c %s\n", INFO_INDENT, "", -INFO_WIDTH, key,
	       *key ? ':' : ' ', value);
}

static void print_pair(const char *key, const char *value)
{
	char *quoted;

	quoted = quote_str(value, 1);
	printf("%s=%s\n", key, quoted);
	free(quoted);
}

static void print_pair_nonl(const char *key, const char *value)
{
	char *quoted;

	quoted = quote_str(value, 1);
	printf("%s=%s", key, quoted);
	free(quoted);
}

/* Perform device type list/info action. */
static exit_code_t do_info_type(struct options *opts)
{
	struct devtype *dt = opts->select->devtype;
	exit_code_t rc;
	char *modules;
	const char *name, *desc, *active, *persistent;

	/* Get devtype settings. */
	rc = dt->read_settings(dt, opts->config);
	if (rc)
		return rc;

	/* Ensure that settings which are not set are shown as such. */
	if (dt->persistent_settings)
		setting_list_remove_derived(dt->persistent_settings);

	/* Determine values for printing. */
	name		= dt->name;
	desc		= *dt->title ? dt->title : dt->subtypes[0]->title;
	modules		= devtype_get_modules_str(dt);
	active		= YESNO(dt->active_exists);
	persistent	= YESNO(dt->persistent_exists);

	/* Print information. */
	if (opts->pairs) {
		print_pair("TYPE", name);
		print_pair("DESCRIPTION", desc);
		print_pair("MODULES", modules);
		print_pair("ACTV", active);
		print_pair("PERS", persistent);
	} else {
		printf("DEVICE TYPE %s\n", name);
		print_info("Description", desc);
		print_info("Modules", modules);
		print_info("Active", active);
		print_info("Persistent", persistent);
		printf("\n");
	}

	if (!dt->type_attribs[0]) {
		if (!opts->pairs) {
			indent(INFO_INDENT, "Device type does not provide "
			       "type attributes\n");
		}
	} else {
		settings_table_print(dt->active_settings,
				     dt->persistent_settings, NULL, NULL, opts,
				     INFO_INDENT, false, false);
	}

	free(modules);

	return rc;
}

/* Perform --list-types. */
static exit_code_t do_list_type(struct options *opts)
{
	return table_types_show(opts->columns, !opts->no_headings, opts->pairs);
}

/* Perform --list-columns. */
static void do_list_columns(struct options *opts)
{
	table_print_columns(dev_table, opts->columns, !opts->no_headings,
			    opts->pairs);
}

/* Perform --info on one device. */
static void do_info_one_device(struct device *dev, struct options *opts)
{
	struct subtype *st = dev->subtype;
	char *names, *bdevs, *cdevs, *ndevs, *modules, *online, *path, *key, *sites;
	const char *id, *type, *exists, *persist, *ac, *prefix;
	struct util_list *resources, *errors;
	struct strlist_node *s;
	bool first;
	int i;

	/* Determine values for printing. */
	id	= dev->id;
	type	= st->name;
	names	= subtype_get_devnodes_str(st, dev->id, 1, 0, 1, 1);
	bdevs	= subtype_get_devnodes_str(st, dev->id, 1, 1, 0, 0);
	cdevs	= subtype_get_devnodes_str(st, dev->id, 0, 0, 1, 0);
	ndevs	= subtype_get_devnodes_str(st, dev->id, 0, 0, 0, 1);
	resources = inuse_get_resources(dev);
	modules	= dev_table_get_modules(dev);
	online	= dev_table_get_online(dev, config_active);
	errors	= subtype_get_errors(dev->subtype, dev->id);
	exists	= YESNO(dev->active.exists || dev->active.definable);
	persist	= YESNO(dev->persistent.exists);
	ac	= YESNO(dev->autoconf.exists);
	sites	= device_get_sites(dev);

	/* Print information. */
	if (opts->pairs) {
		print_pair("ID", id);
		print_pair("TYPE", type);
		print_pair("NAMES", names);
		print_pair("BLOCKDEVS", bdevs);
		print_pair("CHARDEVS", cdevs);
		print_pair("NETDEVS", ndevs);
		if (resources) {
			util_list_iterate(resources, s)
				print_pair("RESOURCE", s->str);
		}
		print_pair("MODULES", modules);
		print_pair("ONLINE", online);
		print_pair("EXISTS", exists);
		print_pair("PERSISTENT", persist);
		if (*sites)
			print_pair("SITES", sites);

		if (SCOPE_AUTOCONF(opts->config) || dev->autoconf.exists)
			print_pair("AUTOCONF", ac);
		if (errors) {
			util_list_iterate(errors, s)
				print_pair("ERROR", s->str);
		}
	} else {
		printf("DEVICE %s %s\n", type, id);
		print_info("Names", names);
		if (bdevs && *bdevs)
			print_info("Block devices", bdevs);
		if (cdevs && *cdevs)
			print_info("Character devices", cdevs);
		if (ndevs && *ndevs)
			print_info("Network interfaces", ndevs);
		if (resources) {
			first = true;
			util_list_iterate(resources, s) {
				print_info(first ? "Resources provided" : "",
					   s->str);
				first = false;
			}
		}
		print_info("Modules", modules);
		print_info("Online", online);
		print_info("Exists", exists);
		print_info("Persistent", persist);
		if (SCOPE_AUTOCONF(opts->config) || dev->autoconf.exists)
			print_info("Auto-configured", ac);
		if (*sites)
			print_info("Sites", sites);

		if (errors) {
			first = true;
			util_list_iterate(errors, s) {
				print_info(first ? "Errors" : "",
					   s->str);
				first = false;
			}
		}
	}

	if (opts->info > 1) {
		/* Print device path. */
		path = subtype_get_active_attrib_path(st, dev, "");
		if (path) {
			if (opts->pairs)
				print_pair("DEVPATH", path);
			else
				print_info("Device path", path);
			free(path);
		}

		/* Print prefix paths. */
		for (i = 0; st->prefixes && (prefix = st->prefixes[i]); i++) {
			path = subtype_get_active_attrib_path(st, dev, prefix);
			if (!path)
				continue;
			if (opts->pairs) {
				print_pair_nonl("PREFIX", prefix);
				printf(" ");
				print_pair("PATH", path);
			} else {
				key = misc_asprintf("%s path", prefix);
				print_info(key, path);
				free(key);
			}
			free(path);
		}
	}

	settings_table_print(dev->active.exists ? dev->active.settings : NULL,
			     is_dev_pers(dev) ? dev->persistent.settings :
			     NULL,
			     dev->autoconf.exists ? dev->autoconf.settings :
			     NULL, dev,
			     opts, INFO_INDENT, false, !opts->pairs);

	settings_table_print(dev->active.exists ? dev->active.settings : NULL,
			     is_dev_pers(dev) ? dev->persistent.settings :
			     NULL,
			     dev->autoconf.exists ? dev->autoconf.settings :
			     NULL, dev,
			     opts, INFO_INDENT, true, !opts->pairs);

	strlist_free(errors);
	free(online);
	free(modules);
	strlist_free(resources);
	free(ndevs);
	free(cdevs);
	free(bdevs);
	free(names);
	free(sites);
}

/* Perform --info on devices. */
static exit_code_t do_info_devices(struct options *opts)
{
	struct util_list *selected;
	struct selected_dev_node *sel;
	struct device *dev;
	int found, active, persistent, autoconf;
	exit_code_t rc, drc = EXIT_OK;
	read_scope_t scope;
	config_t config = opts->config;

	if (opts->info > 1)
		scope = scope_all;
	else
		scope = scope_known;

	/* Get list of selected devices. */
	selected = selected_dev_list_new();

	/* Read auto-config data when no configuration set was specified to
	 * make user aware of auto-config data. */
	if (!opts->active && !opts->persistent && !opts->auto_conf)
		config |= config_autoconf;

	select_devices(opts->select, selected, 1, 0, opts->pairs, config,
		       scope, err_print);

	/* Process selected devices. */
	found = 0;
	util_list_iterate(selected, sel) {
		if (sel->rc)
			continue;
		rc = subtype_read_device(sel->st, sel->id, opts->config,
					 scope, &dev);
		if (rc) {
			if (!drc)
				drc = rc;
			continue;
		}

		/* Only process existing devices. */
		active = dev->active.exists || dev->active.definable;
		persistent = (int)is_dev_pers(dev);
		autoconf = dev->autoconf.exists;
		if (!active && !persistent && !autoconf)
			continue;

		/* with --site option, we consider only the persistent
		 * configurations available on the specified site-id.
		 * ignore active and autoconf here
		 */
		if (!persistent && global_site_id != SITE_FALLBACK)
			continue;

		if (found > 0)
			printf("\n");
		do_info_one_device(dev, opts);
		found++;
	}
	selected_dev_list_free(selected);

	if (found == 0) {
		error("No device was selected!\n");
		drc = EXIT_EMPTY_SELECTION;
	}

	return drc;
}

int main(int argc, char *argv[])
{
	exit_code_t rc, drc = EXIT_OK;
	struct options opts;

	debug_init(argc, argv);

	/* Handle command line. */
	toolname = argv[0];
	init_options(&opts);
	devtypes_init();
	rc = parse_options(&opts, argc, argv);
	if (rc) {
		if (!drc)
			drc = rc;
		goto out;
	}

	/* Set globals. */
	verbose		= opts.verbose;
	quiet		= opts.quiet;
	global_site_id	= opts.site_id;
	path_set_base(opts.base);
	if (opts.pairs)
		set_stdout_data();

	/* Do not load modules when listing devices. Modules for existing
	 * devices should have been already loaded via udev modalias matching.
	 * Also users don't expect changes to their system when running a
	 * list tool. */
	module_load_suppress(1);

	/* Perform main action. */
	switch (get_action(&opts)) {
	case ACT_LIST:
		if (opts.type)
			rc = do_info_type(&opts);
		else
			rc = do_list_devices(&opts);
		break;
	case ACT_INFO:
		if (opts.type)
			rc = do_info_type(&opts);
		else
			rc = do_info_devices(&opts);
		break;
	case ACT_LIST_COLUMNS:
		do_list_columns(&opts);
		break;
	case ACT_LIST_TYPES:
		rc = do_list_type(&opts);
		break;
	case ACT_HELP:
		print_usage();
		break;
	case ACT_VERSION:
		print_version();
		break;
	}
	if (rc && !drc)
		drc = rc;

out:
	/* Write out any remaining messages. */
	delayed_print(0);

	/* Clean-up. */
	free_options(&opts);

	blkinfo_exit();
	ccw_exit();
	ctc_exit();
	devtypes_exit();
	inuse_exit();
	misc_exit();
	module_exit();
	rc = namespace_exit();
	if (rc && !drc)
		drc = rc;
	path_exit();
	scsi_exit();

	return drc ? drc : rc;
}
