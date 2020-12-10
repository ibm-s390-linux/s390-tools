/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * chzdev: Configure z Systems specific devices
 *
 * Copyright IBM Corp. 2016, 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/util_path.h"
#include "lib/zt_common.h"

#include "attrib.h"
#include "blkinfo.h"
#include "ccw.h"
#include "ctc.h"
#include "device.h"
#include "devnode.h"
#include "devtype.h"
#include "export.h"
#include "firmware.h"
#include "inuse.h"
#include "misc.h"
#include "module.h"
#include "namespace.h"
#include "opts.h"
#include "path.h"
#include "root.h"
#include "scsi.h"
#include "select.h"
#include "setting.h"
#include "subtype.h"
#include "table_attribs.h"
#include "table_types.h"
#include "udev.h"
#include "zfcp_lun.h"

/* Main program action. */
typedef enum {
	ACT_CONFIGURE,
	ACT_DECONFIGURE,
	ACT_LIST_ATTRIBS,
	ACT_LIST_TYPES,
	ACT_HELP_ATTRIBS,
	ACT_EXPORT,
	ACT_IMPORT,
	ACT_APPLY,
	ACT_HELP,
	ACT_VERSION,
} action_t;

/* Representation of command line options. */
struct options {
	/* Unparsed positional parameters. */
	struct util_list *positional;	/* List of struct strlist_node */

	/* Selection. */
	struct select_opts *select;
	unsigned int type:1;

	/* Settings */
	struct util_list *settings;	/* List of struct strlist_node */

	/* Actions */
	unsigned int enable:1;
	unsigned int deconfigure:1;
	unsigned int list_attribs:1;
	unsigned int list_types:1;
	unsigned int help_attribs:1;
	char *export;
	char *import;
	unsigned int apply:1;
	unsigned int help:1;
	unsigned int version:1;

	/* Options */
	config_t config;
	unsigned int active:1;
	unsigned int persistent:1;
	unsigned int auto_conf:1;
	struct util_list *remove;	/* List of struct strlist_node */
	unsigned int remove_all:1;
	unsigned int force:1;
	unsigned int yes:1;
	unsigned int no_root_check:1;
	unsigned int dryrun:1;
	struct util_list *base;		/* List of struct strlist_node */
	unsigned int verbose:1;
	unsigned int quiet:1;
	unsigned int no_settle:1;
};

/* Makefile converts chzdev_usage.txt into C file which we include here. */
static const char *usage_text =
#include "chzdev_usage.c"
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
	OPT_ENABLE		= 'e',
	OPT_DECONFIGURE		= 'd',
	OPT_LIST_ATTRIBS	= 'l',
	OPT_HELP_ATTRIBS	= 'H',
	OPT_LIST_TYPES		= 'L',
	OPT_EXPORT		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_IMPORT		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_APPLY		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_ACTIVE		= 'a',
	OPT_PERSISTENT		= 'p',
	OPT_REMOVE		= 'r',
	OPT_REMOVE_ALL		= 'R',
	OPT_FORCE		= 'f',
	OPT_YES			= 'y',
	OPT_NO_ROOT_UPDATE	= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_DRY_RUN		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_BASE		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_HELP		= 'h',
	OPT_VERSION		= 'v',
	OPT_VERBOSE		= 'V',
	OPT_QUIET		= 'q',
	OPT_NO_SETTLE		= (OPT_ANONYMOUS_BASE+__COUNTER__),
	OPT_AUTO_CONF		= (OPT_ANONYMOUS_BASE+__COUNTER__),
};

static struct opts_conflict conflict_list[] = {
	OPTS_CONFLICT(OPT_ENABLE,
		      OPT_DECONFIGURE, OPT_LIST_ATTRIBS, OPT_LIST_TYPES,
		      OPT_EXPORT, OPT_IMPORT, OPT_APPLY, OPT_TYPE, 0),
	OPTS_CONFLICT(OPT_DECONFIGURE,
		      OPT_LIST_ATTRIBS, OPT_HELP_ATTRIBS, OPT_LIST_TYPES,
		      OPT_EXPORT, OPT_IMPORT, OPT_APPLY, OPT_REMOVE,
		      OPT_REMOVE_ALL, OPT_TYPE, 0),
	OPTS_CONFLICT(OPT_LIST_ATTRIBS,
		      OPT_DECONFIGURE, OPT_HELP_ATTRIBS, OPT_LIST_TYPES,
		      OPT_EXPORT, OPT_IMPORT, OPT_APPLY, OPT_REMOVE,
		      OPT_REMOVE_ALL, OPT_CONFIGURED, OPT_EXISTING, OPT_ONLINE,
		      OPT_OFFLINE, OPT_BY_PATH, OPT_BY_NODE, OPT_BY_INTERFACE,
		      OPT_BY_ATTRIB, OPT_ACTIVE, OPT_PERSISTENT, OPT_FAILED, 0),
	OPTS_CONFLICT(OPT_LIST_TYPES,
		      OPT_DECONFIGURE, OPT_LIST_ATTRIBS, OPT_HELP_ATTRIBS,
		      OPT_EXPORT, OPT_IMPORT, OPT_APPLY, OPT_REMOVE,
		      OPT_REMOVE_ALL, OPT_CONFIGURED, OPT_EXISTING, OPT_ONLINE,
		      OPT_OFFLINE, OPT_BY_PATH, OPT_BY_NODE, OPT_BY_INTERFACE,
		      OPT_BY_ATTRIB, OPT_ACTIVE, OPT_PERSISTENT, OPT_FAILED, 0),
	OPTS_CONFLICT(OPT_EXPORT,
		      OPT_DECONFIGURE, OPT_LIST_ATTRIBS, OPT_HELP_ATTRIBS,
		      OPT_LIST_TYPES, OPT_IMPORT, OPT_APPLY, OPT_REMOVE,
		      OPT_REMOVE_ALL, 0),
	OPTS_CONFLICT(OPT_IMPORT,
		      OPT_DECONFIGURE, OPT_LIST_ATTRIBS, OPT_HELP_ATTRIBS,
		      OPT_LIST_TYPES, OPT_EXPORT, OPT_APPLY, OPT_REMOVE,
		      OPT_REMOVE_ALL, OPT_CONFIGURED, OPT_EXISTING, OPT_BY_PATH,
		      OPT_BY_ATTRIB, OPT_BY_NODE, OPT_BY_INTERFACE, 0),
	OPTS_CONFLICT(OPT_APPLY,
		      OPT_DECONFIGURE, OPT_LIST_ATTRIBS, OPT_HELP_ATTRIBS,
		      OPT_LIST_TYPES, OPT_EXPORT, OPT_IMPORT, OPT_REMOVE,
		      OPT_REMOVE_ALL, OPT_ACTIVE, 0),
	OPTS_CONFLICT(OPT_ONLINE,
		      OPT_OFFLINE),
	OPTS_CONFLICT(OPT_QUIET,
		      OPT_VERBOSE),
	OPTS_CONFLICT(OPT_AUTO_CONF,
		      OPT_TYPE, OPT_LIST_ATTRIBS, OPT_LIST_TYPES),
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
	{ "enable",		no_argument,	NULL, OPT_ENABLE },
	{ "disable",		no_argument,	NULL, OPT_DECONFIGURE },
	{ "list-attributes",	no_argument,	NULL, OPT_LIST_ATTRIBS },
	{ "help-attribute",	no_argument,	NULL, OPT_HELP_ATTRIBS },
	{ "list-types",		no_argument,	NULL, OPT_LIST_TYPES },
	{ "export",		required_argument, NULL, OPT_EXPORT },
	{ "import",		required_argument, NULL, OPT_IMPORT },
	{ "apply",		no_argument,	NULL, OPT_APPLY },
	{ "help",		no_argument,	NULL, OPT_HELP },
	{ "version",		no_argument,	NULL, OPT_VERSION },

	/* Options. */
	{ "active",		no_argument,	NULL, OPT_ACTIVE },
	{ "persistent",		no_argument,	NULL, OPT_PERSISTENT },
	{ "auto-conf",		no_argument,	NULL, OPT_AUTO_CONF },
	{ "remove",		required_argument, NULL, OPT_REMOVE },
	{ "remove-all",		no_argument,	NULL, OPT_REMOVE_ALL },
	{ "force",		no_argument,	NULL, OPT_FORCE },
	{ "yes",		no_argument,	NULL, OPT_YES },
	{ "no-root-update",	no_argument,	NULL, OPT_NO_ROOT_UPDATE },
	{ "dry-run",		no_argument,	NULL, OPT_DRY_RUN },
	{ "base",		required_argument, NULL, OPT_BASE },
	{ "verbose",		no_argument,	NULL, OPT_VERBOSE },
	{ "quiet",		no_argument,	NULL, OPT_QUIET },
	{ "no-settle",		no_argument,	NULL, OPT_NO_SETTLE },
	{ NULL,			no_argument,	NULL, 0 },
};

/* Command line abbreviations. */
static const char opt_str[] = ":edlHLapr:RfyhvVqt";

/* Count of persistently modified devices. */
static int pers_mod_devs;

/* Count of persistently modified device types. */
static int pers_mod_devtypes;

/* Initialize options data structure. */
static void init_options(struct options *opts)
{
	memset(opts, 0, sizeof(struct options));
	opts->select = select_opts_new();
	opts->positional = strlist_new();
	opts->settings = strlist_new();
	opts->remove = strlist_new();
	opts->base = strlist_new();
}

/* Release memory used in options data structure. */
static void free_options(struct options *opts)
{
	if (!opts)
		return;
	free(opts->export);
	free(opts->import);
	select_opts_free(opts->select);
	strlist_free(opts->positional);
	strlist_free(opts->settings);
	strlist_free(opts->remove);
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
	if (opts->enable)
		return ACT_CONFIGURE;
	if (opts->deconfigure)
		return ACT_DECONFIGURE;
	if (opts->list_attribs)
		return ACT_LIST_ATTRIBS;
	if (opts->help_attribs)
		return ACT_HELP_ATTRIBS;
	if (opts->list_types)
		return ACT_LIST_TYPES;
	if (opts->export)
		return ACT_EXPORT;
	if (opts->import)
		return ACT_IMPORT;
	if (opts->apply)
		return ACT_APPLY;
	return ACT_CONFIGURE;
}

/* Return option corresponding to action. */
static const char *get_action_option(action_t action)
{
	switch (action) {
	case ACT_DECONFIGURE:
		return "--disable";
	case ACT_LIST_ATTRIBS:
		return "--list-attributes";
	case ACT_HELP_ATTRIBS:
		return "--help-attributes";
	case ACT_LIST_TYPES:
		return "--list-types";
	case ACT_EXPORT:
		return "--export";
	case ACT_IMPORT:
		return "--import";
	case ACT_APPLY:
		return "--apply";
	case ACT_HELP:
		return "--help";
	case ACT_VERSION:
		return "--version";
	default:
		return "";
	}
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
		error("Unrecognized %s ID range format: %s\n",
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

	/* Collect parameters. */
	for (i = start; i < argc; i++) {
		dt = devtype_find(argv[i]);
		st = subtype_find(argv[i]);

		switch (action) {
		case ACT_CONFIGURE:
			if (opts->type) {
				/* DEVTYPE: Required
				 * DEVICE:  Invalid
				 * SETTING: Required */
				if (st && !opts->select->devtype) {
					opts->select->subtype = st;
					opts->select->devtype = st->devtype;
				} else if (dt && !opts->select->devtype) {
					opts->select->devtype = dt;
				} else if (strchr(argv[i], '=')) {
					strlist_add(opts->settings, "%s",
						    argv[i]);
				} else
					goto err_extra;
			} else {
				/* DEVTYPE: Optional
				 * DEVICE:  Optional
				 * SETTING: Optional */
				if (st && !opts->select->devtype) {
					opts->select->subtype = st;
					opts->select->devtype = st->devtype;
				} else if (dt && !opts->select->devtype)
					opts->select->devtype = dt;
				else if (strchr(argv[i], '=')) {
					strlist_add(opts->settings, "%s",
						    argv[i]);
				} else if (is_devspec(opts->select->devtype,
						      opts->select->subtype,
						      argv[i])) {
					strlist_add_multi(&opts->select->devids,
							  argv[i], ",", 0);
				} else
					goto err_inv_dev;
			}
			break;

		case ACT_DECONFIGURE:
		case ACT_EXPORT:
		case ACT_IMPORT:
		case ACT_APPLY:
			/* DEVTYPE: Optional
			 * DEVICE:  Required/optional */
			if (st && !opts->select->devtype) {
				opts->select->subtype = st;
				opts->select->devtype = st->devtype;
			} else if (dt && !opts->select->devtype)
				opts->select->devtype = dt;
			else if (strchr(argv[i], '='))
				goto err_inv_setting;
			else if (is_devspec(opts->select->devtype,
					    opts->select->subtype, argv[i])) {
				strlist_add_multi(&opts->select->devids,
						  argv[i], ",", 0);
			} else
				goto err_inv_dev;
			break;

		case ACT_LIST_ATTRIBS:
		case ACT_HELP_ATTRIBS:
			/* DEVTYPE: Mandatory
			 * OTHER:   Optional */
			if (st && !opts->select->devtype) {
				opts->select->subtype = st;
				opts->select->devtype = st->devtype;
			} else if (dt && !opts->select->devtype)
				opts->select->devtype = dt;
			else if (!st && !opts->select->devtype)
				goto err_unknown_devtype;
			else
				strlist_add(opts->positional, "%s", argv[i]);
			break;

		case ACT_LIST_TYPES:
			/* DEVTYPE: Optional */
			if (st || dt) {
				if (opts->select->devtype)
					goto err_extra;
				if (dt)
					opts->select->devtype = dt;
				else {
					opts->select->subtype = st;
					opts->select->devtype = st->devtype;
				}
			} else {
				if (!opts->select->devtype)
					goto err_unknown_devtype;
				else
					goto err_extra;
			}
			break;

		default:
			/* No positional parameters expected. */
			goto err_extra;
		};
	}

	got_devspec = select_opts_dev_specified(opts->select);

	/* Check for required parameters. */
	switch (action) {
	case ACT_CONFIGURE:
		if (opts->type) {
			/* DEVTYPE: Required
			 * DEVICE:  Invalid
			 * SETTING: Required */
			if (got_devspec)
				goto err_inv_type_dev;
			if (!opts->select->devtype)
				goto err_no_devtype;
			if (util_list_is_empty(opts->settings) &&
			    util_list_is_empty(opts->remove) &&
			    !opts->remove_all)
				goto err_no_devtype_setting;
		} else {
			if (!opts->enable &&
			    util_list_is_empty(opts->settings) &&
			    util_list_is_empty(opts->remove) &&
			    !opts->remove_all)
				goto err_no_enable;
			if (!got_devspec) {
				if (opts->enable)
					goto err_no_dev_conf;
				if (!opts->select->devtype)
					goto err_no_dev_or_type;
				if (util_list_is_empty(opts->settings) &&
				    util_list_is_empty(opts->remove) &&
				    !opts->remove_all)
					goto err_no_devtype_or_setting;
				goto err_no_dev_or_type_opt;
			}
			goto check_devspec;
		}
		break;

	case ACT_DECONFIGURE:
		if (!got_devspec)
			goto err_no_dev_deconf;
		goto check_devspec;

	case ACT_LIST_ATTRIBS:
	case ACT_HELP_ATTRIBS:
		if (!opts->select->devtype)
			goto err_no_devtype;
		break;

	case ACT_EXPORT:
		if (!got_devspec && !opts->type)
			goto err_no_dev_or_type_opt;
		goto check_devspec;

	case ACT_APPLY:
		if (!got_devspec && !opts->type)
			goto err_no_dev_or_type_opt;
		goto check_devspec;

	default:
		/* All ok. */
		break;
	};

	return EXIT_OK;

check_devspec:
	return check_devspecs(opts);

err_unknown_devtype:
	error("Unknown device type: %s\n", argv[i]);
	return EXIT_UNKNOWN_DEVTYPE;

err_extra:
	syntax("Extra parameter found: %s\n", argv[i]);
	return EXIT_USAGE_ERROR;

err_inv_dev:
	return check_devspec(opts->select->devtype, opts->select->subtype,
			     argv[i]);

err_inv_setting:
	syntax("Cannot specify '%s' together with setting '%s'\n",
	       get_action_option(action), argv[i]);
	return EXIT_USAGE_ERROR;

err_no_dev_or_type:
	syntax("Please specify a device or device type to configure\n");
	return EXIT_USAGE_ERROR;

err_no_dev_conf:
	syntax("Please specify a device to configure\n");
	return EXIT_USAGE_ERROR;

err_no_dev_deconf:
	syntax("Please specify a device to deconfigure\n");
	return EXIT_USAGE_ERROR;

err_no_devtype:
	error("Please specify a device type\n"
	      "Use '%s --list-types' to get a list of device types\n",
	      toolname);
	return EXIT_USAGE_ERROR;

err_no_devtype_setting:
	if (opts->select->devtype->type_attribs[0]) {
		error("Please specify a device type setting to configure\n"
		      "Use '%s %s --type --list-attributes' to get a list of "
		      "attributes\n", toolname, opts->select->devtype->name);
		return EXIT_USAGE_ERROR;
	}
	error("Device type %s does not provide type attributes\n",
	      opts->select->devtype->name);
	return EXIT_ATTRIB_NOT_FOUND;

err_no_devtype_or_setting:
	syntax("Please specify a device or setting to configure\n");
	return EXIT_USAGE_ERROR;

err_inv_type_dev:
	error("Cannot specify '--type' and select a device when configuring\n");
	return EXIT_USAGE_ERROR;

err_no_dev_or_type_opt:
	syntax("Please specify a device or --type to select device type\n");
	return EXIT_USAGE_ERROR;

err_no_enable:
	syntax("Please specify an action\n");
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

		case OPT_ENABLE:
			/* --enable */
			opts->enable = 1;
			break;

		case OPT_DECONFIGURE:
			/* --disable */
			opts->deconfigure = 1;
			break;

		case OPT_LIST_ATTRIBS:
			/* --list-attributes */
			opts->list_attribs = 1;
			break;

		case OPT_LIST_TYPES:
			/* --list-types */
			opts->list_types = 1;
			break;

		case OPT_HELP_ATTRIBS:
			/* --help-attributes */
			opts->help_attribs = 1;
			break;

		case OPT_EXPORT:
			/* --export */
			if (opts->export) {
				error("Cannot specify '--export' multiple "
				      "times\n");
				return EXIT_USAGE_ERROR;
			}
			opts->export = misc_strdup(optarg);
			break;

		case OPT_IMPORT:
			/* --import */
			if (opts->import) {
				error("Cannot specify '--import' multiple "
				      "times\n");
				return EXIT_USAGE_ERROR;
			}
			opts->import = misc_strdup(optarg);
			break;

		case OPT_APPLY:
			/* --apply */
			opts->apply = 1;
			break;

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

		case OPT_REMOVE:
			/* --remove ATTRIB */
			strlist_add(opts->remove, "%s", optarg);
			break;

		case OPT_REMOVE_ALL:
			/* --remove-all */
			opts->remove_all = 1;
			break;

		case OPT_FORCE:
			/* --force */
			opts->force = 1;
			break;

		case OPT_YES:
			/* --yes */
			opts->yes = 1;
			break;

		case OPT_NO_ROOT_UPDATE:
			/* --no-root-update */
			opts->no_root_check = 1;
			break;

		case OPT_DRY_RUN:
			/* --dry-run */
			opts->dryrun = 1;
			break;

		case OPT_BASE:
			/* --base PATH */
			strlist_add(opts->base, "%s", optarg);
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

		case OPT_VERBOSE:
			/* --verbose */
			opts->verbose = 1;
			break;

		case OPT_QUIET:
			/* --quiet */
			opts->quiet = 1;
			break;

		case OPT_NO_SETTLE:
			/* --no-settle */
			opts->no_settle = 1;
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

	/* Determine configuration set. */
	if (!opts->active && !opts->persistent && !opts->auto_conf) {
		/* Default configuration targets are active + persistent */
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
		case ACT_IMPORT:
			/* --import without --type or device spec
			 * selects both type and all devices. */
			if (!opts->type) {
				opts->select->all = 1;
				opts->type = 1;
			}
			break;
		default:
			break;
		}
	}

out:
	return rc;
}

static bool setting_is_removable(struct setting *s, int active)
{
	if (active) {
		if (!s->attrib || !s->attrib->activerem)
			return false;
	}
	if (s->derived)
		return false;
	if (s->attrib && s->attrib->mandatory)
		return false;

	return true;
}

static int count_removable(struct setting_list *list, int active)
{
	struct setting *s;
	int removable = 0;

	util_list_iterate(&list->list, s) {
		if (setting_is_removable(s, active))
			removable++;
	}

	return removable;
}

/* Remove all settings. */
static void remove_all_settings(struct setting_list *settings, int active)
{
	struct setting *s;
	int modified = 0;

	util_list_iterate(&settings->list, s) {
		if (!setting_is_removable(s, active))
			continue;
		s->removed = 1;
		s->modified = 1;
		modified = 1;
	}
	if (modified)
		settings->modified = 1;
}

/* Perform --remove-all operation for specified config on device. */
static exit_code_t device_remove_all(struct device *dev, config_t config)
{
	int active, persistent, autoconf;

	active = SCOPE_ACTIVE(config) ?
			count_removable(dev->active.settings, 1) : 0;
	persistent = SCOPE_PERSISTENT(config) ?
			count_removable(dev->persistent.settings, 0) : 0;
	autoconf = SCOPE_AUTOCONF(config) ?
			count_removable(dev->autoconf.settings, 0) : 0;
	if (active == 0 && persistent == 0 && autoconf == 0) {
		delayed_err("No removable settings found\n");
		return EXIT_SETTING_NOT_FOUND;
	}
	if (active)
		remove_all_settings(dev->active.settings, 1);
	if (persistent)
		remove_all_settings(dev->persistent.settings, 0);
	if (autoconf)
		remove_all_settings(dev->autoconf.settings, 0);

	return EXIT_OK;
}

/* Remove settings specified by NAMES from a list of SETTINGS.  */
static exit_code_t remove_settings(struct setting_list *settings,
				   struct util_list *names,
				   struct util_list *found,
				   struct util_list *notfound,
				   int check_activerem)
{
	struct strlist_node *s;
	struct setting *set;

	util_list_iterate(names, s) {
		set = setting_list_find(settings, s->str);
		if (set && !set->derived) {
			if (set->attrib && set->attrib->mandatory)
				goto err_mandatory;
			if (check_activerem && set->attrib &&
			    !set->attrib->activerem)
				goto err_activerem;
			strlist_add_unique(found, "%s", s->str);
			set->removed = 1;
			set->modified = 1;
			continue;
		}
		strlist_add_unique(notfound, "%s", s->str);
	}

	return EXIT_OK;

err_mandatory:
	delayed_err("Cannot remove setting for mandatory attribute '%s'\n",
		    s->str);
	return EXIT_USAGE_ERROR;

err_activerem:
	delayed_err("Cannot remove setting '%s' from the active "
		    "configuration\n", s->str);
	return EXIT_USAGE_ERROR;
}

/* Perform --remove operation on specified device. */
static exit_code_t device_remove_settings(struct device *dev,
					  struct util_list *names,
					  config_t config)
{
	struct util_list *found, *notfound;
	char *flat;
	exit_code_t rc = EXIT_OK;

	found = strlist_new();
	notfound = strlist_new();

	if (SCOPE_ACTIVE(config)) {
		rc = remove_settings(dev->active.settings, names, found,
				     notfound, 1);
		if (rc)
			goto out;
	}

	if (SCOPE_PERSISTENT(config)) {
		rc = remove_settings(dev->persistent.settings, names, found,
				     notfound, 0);
		if (rc)
			goto out;
	}

	if (SCOPE_AUTOCONF(config)) {
		rc = remove_settings(dev->autoconf.settings, names, found,
				     notfound, 0);
		if (rc)
			goto out;
	}

	if (!util_list_is_empty(notfound)) {
		flat = strlist_flatten(notfound, " ");
		delayed_err("Setting not found: %s\n", flat);
		free(flat);
		rc = EXIT_SETTING_NOT_FOUND;
	}

out:
	strlist_free(found);
	strlist_free(notfound);

	return rc;
}

static void ensure_online(struct device *dev, config_t config)
{
	struct subtype *st = dev->subtype;

	if (subtype_online_specified(st, dev, config))
		return;
	if (subtype_online_get(st, dev, config) == 1)
		return;
	subtype_online_set(st, dev, 1, config);
}

static void print_devs(struct util_list *list, devnode_t type)
{
	struct ptrlist_node *p;
	struct devnode *d;
	int first;

	first = 1;
	util_list_iterate(list, p) {
		d = p->ptr;
		if (d->type != type)
			continue;
		if (first) {
			switch (type) {
			case BLOCKDEV:
				info("    Block devices: ");
				break;
			case CHARDEV:
				info("    Character devices: ");
				break;
			case NETDEV:
				info("    Network interface: ");
				break;
			default:
				break;
			}
			first = 0;
		} else
			info(" ");
		info("%s%s", type != NETDEV ? "/dev/" : "", d->name);
	}
	if (!first)
		info("\n");
}

static void print_dev_config_info(struct device *dev, config_t config)
{
	struct subtype *st = dev->subtype;
	char *changes;
	struct util_list *devnodes;

	changes = setting_get_changes(
		  SCOPE_ACTIVE(config) ? dev->active.settings : NULL,
		  SCOPE_PERSISTENT(config) ? dev->persistent.settings : NULL,
		  SCOPE_AUTOCONF(config) ? dev->autoconf.settings : NULL);
	if (changes)
		info("    Changes: %s\n", changes);
	free(changes);

	/* Wait for potential renaming udev rules to finish. */
	udev_settle();

	devnodes = subtype_get_devnodes(st, dev->id);
	if (devnodes) {
		print_devs(devnodes, BLOCKDEV);
		print_devs(devnodes, CHARDEV);
		print_devs(devnodes, NETDEV);
		ptrlist_free(devnodes, 1);
	}
}

static exit_code_t cfg_read(struct subtype *st, const char *id,
			    config_t config, read_scope_t scope, int reread,
			    struct device **dev_ptr)
{
	exit_code_t rc;
	struct device *dev;
	struct namespace *ns = st->namespace;

	/* Handle blacklist. */
	if (ns->is_id_blacklisted && ns->unblacklist_id &&
	    ns->is_id_blacklisted(id))
		ns->unblacklist_id(id);

	/* Read configuration. */
	if (reread)
		rc = subtype_reread_device(st, id, config, scope, &dev);
	else
		rc = subtype_read_device(st, id, config, scope, &dev);

	if (rc == EXIT_OK && dev_ptr)
		*dev_ptr = dev;

	return rc;
}

static exit_code_t cfg_mod_existence(struct device *dev, config_t config)
{
	/* Create active config if necessary. */
	if (SCOPE_ACTIVE(config) && !dev->active.exists) {
		if (!dev->active.definable)
			return EXIT_DEVICE_NOT_FOUND;
		dev->active.exists = 1;
		dev->active.modified = 1;
	}

	/* Create persistent config if necessary. */
	if (SCOPE_PERSISTENT(config) && !dev->persistent.exists) {
		dev->persistent.exists = 1;
		dev->persistent.modified = 1;
	}

	/* Create autoconf config if necessary. */
	if (SCOPE_AUTOCONF(config) && !dev->autoconf.exists) {
		dev->autoconf.exists = 1;
		dev->autoconf.modified = 1;
	}

	return EXIT_OK;
}

static exit_code_t cfg_mod_settings(struct device *dev, struct options *opts,
				    int prereq)
{
	exit_code_t rc;

	if (prereq)
		goto online;

	/* Remove all settings. */
	if (opts->remove_all) {
		rc = device_remove_all(dev, opts->config);
		if (rc)
			return rc;
	}

	/* Remove a list of settings. */
	if (!util_list_is_empty(opts->remove)) {
		rc = device_remove_settings(dev, opts->remove, opts->config);
		if (rc)
			return rc;
	}

	/* Apply settings. */
	if (!util_list_is_empty(opts->settings)) {
		rc = device_apply_strlist(dev, opts->config, opts->settings);
		if (rc)
			return rc;
	}

	if (!opts->enable)
		goto mand;

online:
	/* Make sure there's an online attribute. */
	ensure_online(dev, config_active);
	ensure_online(dev, config_persistent);
	ensure_online(dev, config_autoconf);

mand:
	/* Ensure default values for mandatory attributes. */
	setting_list_apply_defaults(dev->persistent.settings,
				    dev->subtype->dev_attribs, true);
	setting_list_apply_defaults(dev->autoconf.settings,
				    dev->subtype->dev_attribs, true);

	return EXIT_OK;
}

static exit_code_t handle_nonexistent(struct device *dev)
{
	struct subtype *st = dev->subtype, *other_st;
	struct namespace *ns = st->namespace;

	if (namespaces_device_exists(ns, dev->id, config_active, &other_st) &&
	    dev->subtype != other_st) {
		if (force) {
			delayed_warn("Configuring %s %s as %s\n",
				     other_st->devname, dev->id, st->devname);
			return EXIT_OK;
		}
		delayed_forceable("Trying to configure %s %s as %s\n",
				  other_st->devname, dev->id, st->devname);
		return EXIT_INVALID_DEVTYPE;
	}

	delayed_warn("%s %s does not exist in active configuration\n",
		     st->devname, dev->id);
	return EXIT_OK;
}

static exit_code_t cfg_write(struct device *dev, int prereq, config_t config,
			     int check_active)
{
	struct subtype *st = dev->subtype;
	exit_code_t rc = EXIT_OK;

	if (!device_needs_writing(dev, config) && !force)
		goto out;

	if (check_active && !SCOPE_ACTIVE(config) &&
	    (SCOPE_PERSISTENT(config) || SCOPE_AUTOCONF(config)) &&
	    (!dev->active.exists && !dev->active.definable)) {
		rc = handle_nonexistent(dev);
		if (rc)
			return rc;
	}

	/* Pre-write check. */
	rc = subtype_check_pre_configure(st, dev, prereq, config);
	if (rc && !force)
		goto out;

	/* Write configuration. */
	if (SCOPE_PERSISTENT(config))
		pers_mod_devs++;
	rc = subtype_write_device(st, dev, config);
	if (rc)
		goto out;

	/* Post-write check. */
	rc = subtype_check_post_configure(st, dev, prereq, config);
	if (rc && !force)
		goto out;

out:
	return rc;
}

/* Apply changes in @opts to the device defined by @st and @id. */
static exit_code_t cfg_configure(struct subtype *st, const char *id,
				 struct options *opts, int try, int prereq,
				 struct device **dev_ptr, int *proc_ptr)
{
	config_t config = opts->config;
	exit_code_t rc;
	struct device *dev;

	/* Reset processed flag. */
	if (proc_ptr)
		*proc_ptr = 0;

	/* Read current device data. Note that we read data from all
	 * configurations to enable QETH autodetection and subtype
	 * detection (e.g. dasd -> dasd_fba).*/
	dev = NULL;
	rc = cfg_read(st, id, config_all, scope_known, 0, &dev);
	if (dev_ptr)
		*dev_ptr = dev;
	if (rc)
		return rc;

	/* Skip if already processed. */
	if (dev->processed)
		return EXIT_OK;

	/* Mark device as processed. */
	if (proc_ptr)
		*proc_ptr = 1;
	dev->processed = 1;

	/* Exit here if we're only trying and device cannot be configured. */
	if (try && !(dev->active.exists || dev->active.definable ||
		     dev->persistent.exists || dev->autoconf.exists)) {
		return EXIT_DEVICE_NOT_FOUND;
	}

	/* Create device if needed by action. */
	if (opts->enable || !util_list_is_empty(opts->settings)) {
		rc = cfg_mod_existence(dev, config);
		if (rc)
			return rc;
	}

	/* Apply changes to device settings. */
	rc = cfg_mod_settings(dev, opts, prereq);
	if (rc)
		return rc;

	/* Write resulting device data. */
	return cfg_write(dev, prereq, config, 1);
}

/* Apply persistent configuration to active configuration. */
static exit_code_t cfg_apply(struct subtype *st, const char *id, int prereq,
			     struct device **dev_ptr, int *proc_ptr,
			     bool autoconf)
{
	exit_code_t rc;
	struct device *dev;
	struct device_state *state;

	/* Reset processed flag. */
	if (proc_ptr)
		*proc_ptr = 0;

	/* Read current device data. */
	dev = NULL;
	rc = cfg_read(st, id, config_all, scope_known, 1, &dev);
	if (dev_ptr)
		*dev_ptr = dev;
	if (rc)
		return rc;

	/* Skip if already processed. */
	if (dev->processed)
		return EXIT_OK;

	/* Mark device as processed. */
	if (proc_ptr)
		*proc_ptr = 1;
	dev->processed = 1;

	state = autoconf ? &dev->autoconf : &dev->persistent;
	/* Exit here if there is no persistent configuration. */
	if (!state->exists)
		return EXIT_NO_DATA;

	/* Apply changes to device existence. */
	rc = cfg_mod_existence(dev, config_active);
	if (rc)
		return rc;

	/* Copy persistent settings to active configuration. */
	rc = device_apply_settings(dev, config_active, &state->settings->list);
	if (rc)
		return rc;

	/* Write resulting device data. */
	return cfg_write(dev, prereq, config_active, 1);
}

/* Apply imported configuration. */
static exit_code_t cfg_import(struct subtype *st, const char *id,
			      config_t config, int prereq,
			      struct device **dev_ptr, int *proc_ptr)
{
	exit_code_t rc;
	struct setting_list *active = NULL, *persistent = NULL,
			    *autoconf = NULL;
	struct device *dev;

	/* Reset processed flag. */
	if (proc_ptr)
		*proc_ptr = 0;

	/* Get imported data. */
	dev = device_list_find(st->devices, id, NULL);

	if (dev_ptr)
		*dev_ptr = dev;
	if (dev) {
		/* Only import each device once. */
		if (dev->processed)
			return EXIT_OK;
		active = setting_list_copy(dev->active.settings);
		persistent = setting_list_copy(dev->persistent.settings);
		autoconf = setting_list_copy(dev->autoconf.settings);
	} else if (!prereq) {
		/* Should not happen. */
		return EXIT_OK;
	}

	/* Read current device data. */
	rc = cfg_read(st, id, config, scope_known, 1, &dev);
	if (rc)
		goto out;

	/* Mark device as processed. */
	if (proc_ptr)
		*proc_ptr = 1;
	dev->processed = 1;

	/* Apply changes to device existence. */
	rc = cfg_mod_existence(dev, config);
	if (rc)
		goto out;

	if (!prereq) {
		/* Copy target settings to device configuration. */
		rc = device_apply_settings(dev, config_active, &active->list);
		if (rc)
			goto out;
		rc = device_apply_settings(dev, config_persistent,
					   &persistent->list);
		if (rc)
			goto out;
		rc = device_apply_settings(dev, config_autoconf,
					   &autoconf->list);
		if (rc)
			goto out;
	}
	ensure_online(dev, config_active);
	ensure_online(dev, config_persistent);
	ensure_online(dev, config_autoconf);

	/* Write resulting device data. */
	rc = cfg_write(dev, prereq, config, 0);

out:
	setting_list_free(autoconf);
	setting_list_free(persistent);
	setting_list_free(active);

	return rc;
}

static exit_code_t print_generic_err(struct selected_dev_node *sel,
				     struct device *dev, exit_code_t rc)
{
	struct subtype *other_st;
	struct subtype *st;
	int print = 1;
	exit_code_t rc2;

	if (rc != EXIT_DEVICE_NOT_FOUND || !sel)
		goto out;

	st = sel->st;

	/* Check if there is a subtype mismatch. */
	if (st && dev && !(dev->active.exists || dev->active.definable) &&
	    namespaces_device_exists(st->namespace, sel->id, config_active,
				     &other_st) && st != other_st) {
		delayed_err("Trying to configure %s %s as %s\n",
			    other_st->devname, sel->id, st->devname);
		rc = EXIT_INVALID_DEVTYPE;
		print = 0;
		goto out;
	}

	if (!sel->dt || devtype_count_namespaces(sel->dt) != 1)
		goto out;

	if (namespaces_device_exists(sel->dt->subtypes[0]->namespace,
				     sel->id, config_active, &other_st) &&
	    other_st->devtype != sel->dt) {
		delayed_err("Trying to configure %s %s as %s\n",
			    other_st->devname, sel->id, sel->dt->devname);
		rc = EXIT_INVALID_DEVTYPE;
		print = 0;
		goto out;
	}

	/* Try to get more information in case of a problem with definable
	 * devices. */
	if (st && st->support_definable && delayed_errors == 0) {
		rc2 = subtype_device_is_definable(st, sel->id,
						  err_delayed_print);
		if (rc2) {
			rc = rc2;
			print = 0;
		}
	}

out:
	if (print)
		delayed_err("%s\n", exit_code_to_str(rc));

	return rc;
}

static exit_code_t print_config_result(struct selected_dev_node *sel,
				       struct device *dev, struct options *opts,
				       config_t config, exit_code_t rc,
				       int prereq, int proc)
{
	const char *devname, *devid, *op, *verb;
	int already;

	/* Exit here if a message for this device has already been printed. */
	if (!proc)
		return rc;

	already = 0;
	if (opts->deconfigure) {
		op = "deconfigure";
		verb = "deconfigured";
		if (dev) {
			already = !dev->active.modified &&
				  !dev->persistent.modified &&
				  !dev->autoconf.modified;
		} else if (rc == EXIT_DEVICE_NOT_FOUND &&
			 (!SCOPE_ACTIVE(config) && (SCOPE_PERSISTENT(config) ||
			  SCOPE_AUTOCONF(config)))) {
			rc = EXIT_OK;
			already = 1;
		}
	} else {
		op = "configure";
		verb = "configured";
		if (dev)
			already = device_needs_writing(dev, config) ? 0 : 1;
	}

	/* Re-do actions if run with --force */
	if (force)
		already = 0;

	if (dev) {
		devname = dev->subtype->devname;
		devid = dev->id;
	} else if (sel && sel->st) {
		devname = sel->st->devname;
		devid = sel->id ? sel->id : sel->param;
	} else if (sel && sel->dt) {
		devname = sel->dt->devname;
		devid = sel->id ? sel->id : sel->param;
	} else {
		devname = "Device";
		if (sel)
			devid = sel->id ? sel->id : sel->param;
		else
			devid = "";
	}

	if (rc) {
		/* Error message. */
		warn("%s %s %s failed%s\n", devname, devid, op,
		     prereq ? " (prerequisite)" : "");

		/* Add the overall error message in case no other error message
		 * has been queued. */
		if (delayed_errors == 0)
			rc = print_generic_err(sel, dev, rc);
	} else if (already) {
		if (!prereq || delayed_messages_available()) {
			/* Already done message. */
			printf("%s %s already %s\n", devname, devid, verb);
		}
	} else {
		/* Success message. */
		printf("%s %s %s%s\n", devname, devid, verb,
		       prereq ? " (prerequisite)" : "");
		if (verbose && dev)
			print_dev_config_info(dev, config);
	}

	/* Show all delayed messages. */
	delayed_print(DELAY_INDENT);

	return rc;
}

static exit_code_t cfg_prereqs(struct subtype *st, const char *id,
			       struct options *opts, config_t config, int try)
{
	struct util_list *prereqs;
	struct selected_dev_node *sel;
	exit_code_t rc = EXIT_OK;
	struct device *dev;
	int proc;

	prereqs = selected_dev_list_new();
	subtype_add_prereqs(st, id, prereqs);
	util_list_iterate(prereqs, sel) {
		if (opts->apply) {
			rc = cfg_apply(sel->st, sel->id, 1, &dev, &proc,
				       opts->auto_conf);
		} else if (opts->import) {
			rc = cfg_import(sel->st, sel->id, config, 1, &dev,
					&proc);
		} else {
			rc = cfg_configure(sel->st, sel->id, opts, try, 1,
					   &dev, &proc);
		}
		rc = print_config_result(sel, dev, opts, config, rc, 1, proc);
		if (rc) {
			if (st == &zfcp_lun_subtype &&
			    rc == EXIT_DEVICE_NOT_FOUND) {
				/* Use special exit code for FCP. */
				rc = EXIT_ZFCP_FCP_NOT_FOUND;
			}

			if (try)
				break;
			warn("%s %s configure failed\n", st->devname, id);
			delayed_err("Could not configure prerequisite %s %s\n",
				    sel->st->devname, sel->id);
			delayed_print(DELAY_INDENT);
			break;
		}
	}
	selected_dev_list_free(prereqs);

	return rc;
}

static void handle_blacklist_range(struct namespace *ns, const char *range)
{
	if (!ns->is_id_range_blacklisted || !ns->unblacklist_id_range)
		return;
	if (!ns_is_id_range_valid(ns, range))
		return;
	if (ns->is_id_range_blacklisted(range))
		ns->unblacklist_id_range(range);
}

/* Try to perform unblacklisting in ranges while minimizing calls to
 * handle_blacklist_range (that is, only call when namespace or param
 * changed). */
static void unblacklist_ranges(struct selected_dev_node *sel,
			       struct namespace **ns_ptr,
			       const char **param_ptr)
{
	struct namespace *ns = *ns_ptr;
	const char *param = *param_ptr;

	if (ns == sel->st->namespace)
		return;
	if (!sel->param)
		return;
	if (param && strcmp(param, sel->param) == 0)
		return;
	ns = sel->st->namespace;
	param = sel->param;
	handle_blacklist_range(ns, param);
	*ns_ptr = ns;
	*param_ptr = param;
}

/* Handle device configuration. */
static exit_code_t configure_devices(struct options *opts, int specified,
				     int *found_ptr)
{
	struct util_list *selected;
	struct selected_dev_node *sel;
	exit_code_t rc, drc = EXIT_OK;
	int existing, proc;
	struct namespace *ns;
	const char *param;
	struct device *dev;
	config_t config = opts->config;

	/* Determine list of selected devices. */
	if ((!SCOPE_ACTIVE(config) &&
	    (SCOPE_PERSISTENT(config) || SCOPE_AUTOCONF(config))) ||
	    (opts->select->subtype && opts->select->subtype->support_definable))
		existing = 0;
	else
		existing = 1;
	selected = selected_dev_list_new();
	rc = select_devices(opts->select, selected, existing, 1, 0,
			    opts->config, scope_known, err_print);
	if (rc)
		goto out;
	if (util_list_is_empty(selected)) {
		if (!specified) {
			rc = EXIT_OK;
			goto out;
		}
		error("No device was selected!\n");
		rc = EXIT_EMPTY_SELECTION;
		goto out;
	}

	/* Work on selected devices. */
	ns = NULL;
	param = NULL;
	util_list_iterate(selected, sel) {
		dev = NULL;
		proc = 0;
		rc = sel->rc;
		if (rc) {
			proc = 1;
			/* If select_devices didn't find the device with any
			 * type in the active config, it does not exist. */
			if (rc == EXIT_INCOMPLETE_TYPE &&
			    SCOPE_ACTIVE(opts->config))
				rc = EXIT_DEVICE_NOT_FOUND;
			goto next;
		}

		/* Attempt to perform efficient unblacklisting in ranges. */
		unblacklist_ranges(sel, &ns, &param);

		/* Configure potential prerequisite devices. */
		rc = cfg_prereqs(sel->st, sel->id, opts, opts->config, 0);
		if (rc)
			goto next;

		/* Configure actual target device. */
		if (opts->apply) {
			rc = cfg_apply(sel->st, sel->id, 0, &dev, &proc,
				       opts->auto_conf);
		} else {
			rc = cfg_configure(sel->st, sel->id, opts, 0,
					   0, &dev, &proc);
		}

next:
		/* Print results. */
		rc = print_config_result(sel, dev, opts, opts->config, rc, 0,
					 proc);

		/* Remember first non-zero exit code. */
		if (rc && !drc)
			drc = rc;

		/* Skip device IDs which are combined in this one. */
		if (rc == EXIT_OK && dev) {
			if (found_ptr)
				(*found_ptr)++;
			/* Note: selected is modified but since we're not
			 *       using util_list_iterate_safe, the next
			 *       element will be correctly taken from the
			 *       modified list. */
			subtype_rem_combined(sel->st, dev, sel, selected);
		}
	}

out:
	selected_dev_list_free(selected);

	return drc ? drc : rc;
}

static exit_code_t check_in_use(struct device *dev)
{
	struct util_list *res;
	struct strlist_node *s;

	if (force)
		return EXIT_OK;
	res = inuse_get_resources(dev);
	if (!res)
		return EXIT_OK;

	warn("Warning: %s %s is in use!\n", dev->subtype->devname, dev->id);
	warn("         The following resources may be affected:\n");

	util_list_iterate(res, s)
		warn("          - %s\n", s->str);

	if (!confirm("Continue with operation?"))
		return EXIT_ABORTED;

	return EXIT_OK;
}

/* Deconfigure specified device. */
static exit_code_t deconfigure_one_device(struct subtype *st, const char *id,
					  struct options *opts, int try,
					  struct device **dev_ptr,
					  int *proc_ptr)
{
	exit_code_t rc;
	struct device *dev;
	config_t config, read_config;

	/* Reset processed flag. */
	if (proc_ptr)
		*proc_ptr = 0;

	config = opts->config;
	/* For trial configuration runs, we need information about the active
	 * configuration. */
	if (try && !SCOPE_ACTIVE(config))
		read_config = config_all;
	else
		read_config = opts->config;

	/* Read configuration. */
	dev = NULL;
	rc = subtype_read_device(st, id, read_config, scope_mandatory, &dev);
	if (dev_ptr)
		*dev_ptr = dev;
	if (rc)
		return rc;

	/* Selection can queue a device ID multiple times - filter out
	 * double selections here. */
	if (dev->processed)
		return EXIT_OK;

	/* Mark device as processed. */
	if (proc_ptr)
		*proc_ptr = 1;
	dev->processed = 1;

	if (try && !(dev->active.exists || dev->active.definable ||
		     dev->persistent.exists || dev->autoconf.exists)) {
		/* Attempt to deconfigure this device will fail. */
		return EXIT_DEVICE_NOT_FOUND;
	}

	/* Check if device exists in active config - we allow deconfigure if
	 * device doesn't exist in active when there may be a persistent
	 * dev. */
	if (SCOPE_ACTIVE(config) &&
	    !(dev->active.exists || dev->active.definable)) {
		if (!((SCOPE_PERSISTENT(config) && dev->persistent.exists) ||
		      (SCOPE_AUTOCONF(config) && dev->autoconf.exists)))
			return EXIT_DEVICE_NOT_FOUND;
	}

	/* Sanity check before deconfiguring devices that are in use. */
	rc = check_in_use(dev);
	if (rc)
		return rc;

	/* Deconfigure. */
	if (SCOPE_ACTIVE(config)) {
		dev->active.deconfigured = 1;
		if (st->support_definable) {
			/* Deconfigure for configurable devices means
			 * undefine. */
			if (dev->active.exists)
				dev->active.modified = 1;
		} else if (subtype_online_get(st, dev, config_active) == 1)
			dev->active.modified = 1;
	}
	if (SCOPE_PERSISTENT(config) && dev->persistent.exists) {
		dev->persistent.deconfigured = 1;
		dev->persistent.modified = 1;
	}
	if (SCOPE_AUTOCONF(config) && dev->autoconf.exists) {
		dev->autoconf.deconfigured = 1;
		dev->autoconf.modified = 1;
	}
	if (!dev->active.modified && !dev->persistent.modified &&
	    !dev->autoconf.modified)
		return EXIT_OK;

	/* Pre-write check. */
	rc = subtype_check_pre_configure(st, dev, 0, config);
	if (rc && !force)
		return rc;

	/* Write configuration. */
	if (SCOPE_PERSISTENT(config))
		pers_mod_devs++;
	rc = subtype_write_device(st, dev, config);
	if (rc)
		return rc;

	/* Post-write check. */
	rc = subtype_check_post_configure(st, dev, 0, config);
	if (rc && !force)
		return rc;

	return EXIT_OK;
}

/* Handle device deconfiguration. */
static exit_code_t deconfigure_devices(struct options *opts)
{
	struct util_list *selected;
	struct selected_dev_node *sel;
	exit_code_t rc, drc = EXIT_OK;
	int proc;
	struct device *dev;

	/* Determine list of selected devices. */
	selected = selected_dev_list_new();
	rc = select_devices(opts->select, selected, 1, 0, 0, opts->config,
			    scope_mandatory, err_print);
	if (rc)
		goto out;
	if (util_list_is_empty(selected)) {
		error("No device was selected!\n");
		rc = EXIT_EMPTY_SELECTION;
		goto out;
	}

	/* Work on selected devices. */
	util_list_iterate(selected, sel) {
		dev = NULL;
		proc = 0;

		if (sel->rc) {
			rc = EXIT_DEVICE_NOT_FOUND;
			proc = 1;
			goto next;
		}

		/* Deconfigure device. */
		rc = deconfigure_one_device(sel->st, sel->id, opts, 0,
					    &dev, &proc);

next:
		/* Print results. */
		rc = print_config_result(sel, dev, opts, opts->config, rc, 0,
					 proc);

		if (rc && !drc)
			drc = rc;

		/* Skip devices which are combined in this one. */
		if (rc == EXIT_OK && dev) {
			/* Note: selected is modified but since we're not
			 *       using util_list_iterate_safe, the next
			 *       element will be correctly taken from the
			 *       modified list. */
			subtype_rem_combined(sel->st, dev, sel, selected);
		}
	}

out:
	selected_dev_list_free(selected);

	return drc ? drc : rc;
}

/* Perform --remove operation for specified config on devtype. */
static exit_code_t devtype_remove_settings(struct devtype *dt, config_t config,
					   struct util_list *names)
{
	struct util_list *found, *notfound;
	char *flat;
	exit_code_t rc = EXIT_OK;

	found = strlist_new();
	notfound = strlist_new();

	if (SCOPE_ACTIVE(config))
		remove_settings(dt->active_settings, names, found, notfound, 1);

	if (SCOPE_PERSISTENT(config)) {
		remove_settings(dt->persistent_settings, names, found,
				notfound, 0);
	}

	if (!util_list_is_empty(notfound)) {
		flat = strlist_flatten(notfound, " ");
		delayed_err("Setting not found: %s\n", flat);
		free(flat);

		rc = EXIT_SETTING_NOT_FOUND;
	}

	strlist_free(found);
	strlist_free(notfound);

	return rc;
}

/* Perform --remove-all operation for specified config on devtype. */
static exit_code_t devtype_remove_all(struct devtype *dt, config_t config)
{
	int active, persistent;

	active = SCOPE_ACTIVE(config) ?
			count_removable(dt->active_settings, 1) : 0;
	persistent = SCOPE_PERSISTENT(config) ?
			count_removable(dt->persistent_settings, 0) : 0;
	if (active == 0 && persistent == 0) {
		delayed_err("No removable settings found\n");
		return EXIT_SETTING_NOT_FOUND;
	}
	if (active)
		remove_all_settings(dt->active_settings, 1);
	if (persistent)
		remove_all_settings(dt->persistent_settings, 0);

	return EXIT_OK;
}

static void print_type_config_info(struct devtype *dt, const char *title,
				   config_t config)
{
	char *changes;

	changes = setting_get_changes(
		  SCOPE_ACTIVE(config) ? dt->active_settings : NULL,
		  SCOPE_PERSISTENT(config) ? dt->persistent_settings : NULL,
		  NULL);
	if (changes)
		info("    %s: %s\n", title, changes);
	free(changes);
}

static void print_devtype_config_result(struct devtype *dt,
					config_t config, exit_code_t rc)
{
	if (rc) {
		/* Error message. */
		warn("%s device type configure failed\n", dt->name);

		/* Add the overall error message in case no other error message
		 * has been queued. */
		if (delayed_errors == 0)
			delayed_err("%s\n", exit_code_to_str(rc));
	} else if (!devtype_needs_writing(dt, config))
		/* Already done message. */
		printf("%s device type already configured\n", dt->name);
	else {
		/* Success message. */
		printf("%s device type configured\n", dt->name);
		if (verbose)
			print_type_config_info(dt, "Changes", config);
	}
	delayed_print(DELAY_INDENT);
}

/* Handle device type settings. */
static exit_code_t configure_devtype(struct options *opts)
{
	struct devtype *dt = opts->select->devtype;
	exit_code_t rc;

	/* Read settings. */
	rc = dt->read_settings(dt, opts->config);
	if (rc)
		goto out;

	/* Remove all settings. */
	if (opts->remove_all) {
		rc = devtype_remove_all(dt, opts->config);
		if (rc)
			goto out;
	}

	/* Remove a list of settings. */
	if (!util_list_is_empty(opts->remove)) {
		rc = devtype_remove_settings(dt, opts->config, opts->remove);
		if (rc)
			goto out;
	}

	/* Apply new settings. */
	rc = devtype_apply_strlist(dt, opts->config, opts->settings);
	if (rc)
		goto out;

	if (!devtype_needs_writing(dt, opts->config))
		goto out;

	/* Write settings. */
	if (SCOPE_PERSISTENT(opts->config))
		pers_mod_devtypes++;
	rc = dt->write_settings(dt, opts->config);

out:
	print_devtype_config_result(dt, opts->config, rc);

	return rc;
}

/* Apply persistent device type settings to active configuration. */
static exit_code_t apply_devtype(struct devtype *dt, int specified,
				 int *found_ptr)
{
	exit_code_t rc;

	/* Read settings. */
	rc = dt->read_settings(dt, config_all);
	if (rc)
		return rc;

	if (!dt->persistent_settings ||
	    setting_list_count_set(dt->persistent_settings) == 0) {
		/* No persistent configuration found. */
		if (!specified)
			return EXIT_OK;
		rc = EXIT_NO_DATA;
		goto out;
	}

	(*found_ptr)++;

	/* Apply new settings. */
	rc = devtype_apply_settings(dt, config_active,
				    &dt->persistent_settings->list);
	if (rc)
		goto out;

	if (!devtype_needs_writing(dt, config_active))
		goto out;

	/* Write settings. */
	rc = dt->write_settings(dt, config_active);

out:
	print_devtype_config_result(dt, config_active, rc);

	return rc;
}

/* Return a ptrlist of newly allocated struct table_attribs for all device type
 * attributes of a devtype. */
static struct util_list *get_type_attribs(struct devtype *dt,
					  struct util_list *names)
{
	int i;
	struct util_list *attribs;
	struct attrib *a;
	struct strlist_node *s;

	attribs = ptrlist_new();

	if (names) {
		util_list_iterate(names, s) {
			a = attrib_find(dt->type_attribs, s->str);
			if (!a)
				goto notfound;
			ptrlist_add(attribs, table_attrib_new(NULL, a));
		}
	} else {
		for (i = 0; (a = dt->type_attribs[i]); i++)
			ptrlist_add(attribs, table_attrib_new(NULL, a));
	}

	return attribs;

notfound:
	ptrlist_free(attribs, 1);
	error("%s type attribute '%s' not found!\n", dt->name, s->str);

	return NULL;
}

/* Return a ptrlist of all device attributes of a devtype without duplicates. */
static struct util_list *get_dev_attribs(struct devtype *dt,
					 struct subtype *st_only,
					 struct util_list *names)
{
	struct subtype *st;
	int i, j;
	struct util_list *attribs;
	struct attrib *a;
	struct strlist_node *s;
	bool found;

	attribs = ptrlist_new();

	if (names) {
		util_list_iterate(names, s) {
			a = NULL;
			found = false;
			for (i = 0; (st = dt->subtypes[i]); i++) {
				if (st_only && st != st_only)
					continue;
				a = attrib_find(st->dev_attribs, s->str);
				if (a) {
					ptrlist_add(attribs,
						    table_attrib_new(st, a));
					found = true;
				}
			}
			if (!found)
				goto notfound;
		}
	} else {
		for (i = 0; (st = dt->subtypes[i]); i++) {
			if (st_only && st != st_only)
				continue;
			for (j = 0; (a = st->dev_attribs[j]); j++)
				ptrlist_add(attribs, table_attrib_new(st, a));
		}
	}

	return attribs;

notfound:
	ptrlist_free(attribs, 0);
	if (st_only) {
		error("%s attribute '%s' not found!\n", st_only->devname,
		      s->str);
	} else {
		error("%s attribute '%s' not found!\n", dt->devname, s->str);
	}

	return NULL;
}

/* Remove duplicate struct type_attrib entries in ptrlist @list. A duplicate
 * entry is an entry that occurs @num_subtypes times in @list. */
static void remove_duplicate_attribs(struct util_list *list, int num_subtypes)
{
	struct ptrlist_node *curr, *check, *next;
	struct table_attrib *curr_t, *check_t;
	int num;

	if (!list)
		return;
	util_list_iterate(list, curr) {
		num = 1;
		curr_t = curr->ptr;
		for (check = util_list_next(list, curr); check;
		     check = util_list_next(list, check)) {
			check_t = check->ptr;
			if (curr_t->attrib == check_t->attrib)
				num++;
		}
		if (num != num_subtypes)
			continue;

		/* Remove duplicates. */
		curr_t->st = NULL;
		check = util_list_next(list, curr);
		while (check) {
			next = util_list_next(list, check);
			check_t = check->ptr;
			if (curr_t->attrib == check_t->attrib) {
				util_list_remove(list, check);
				free(check->ptr);
				free(check);
			}
			check = next;
		}
	}
}

static exit_code_t do_list_attribs(struct options *opts)
{
	struct devtype *dt = opts->select->devtype;
	struct subtype *st = opts->select->subtype;
	struct util_list *names;
	struct util_list *attribs;
	exit_code_t rc = EXIT_OK;

	names = opts->positional;
	if (names && util_list_is_empty(names))
		names = NULL;

	if (opts->type) {
		if (!dt->type_attribs[0]) {
			error("Device type %s does not provide type "
			      "attributes\n", dt->name);
			return EXIT_ATTRIB_NOT_FOUND;
		}

		attribs = get_type_attribs(dt, names);
	} else
		attribs = get_dev_attribs(dt, st, names);

	remove_duplicate_attribs(attribs, devtype_count_subtypes(dt));

	if (attribs) {
		table_attribs_show(attribs, 1, 0, dt);
		ptrlist_free(attribs, 1);
	} else
		rc = EXIT_ATTRIB_NOT_FOUND;

	return rc;
}

static exit_code_t do_help_attribs(struct options *opts)
{
	struct devtype *dt = opts->select->devtype;
	struct subtype *st = opts->select->subtype;
	struct util_list *names;
	struct util_list *attribs;
	exit_code_t rc = EXIT_OK;

	names = opts->positional;
	if (names && util_list_is_empty(names))
		names = NULL;

	if (opts->type)
		attribs = get_type_attribs(dt, names);
	else
		attribs = get_dev_attribs(dt, st, names);

	remove_duplicate_attribs(attribs, devtype_count_subtypes(dt));

	if (attribs) {
		table_attribs_show_details(attribs, dt);
		ptrlist_free(attribs, 1);
	} else
		rc = EXIT_ATTRIB_NOT_FOUND;

	return rc;
}

/* List known device types. */
static exit_code_t do_list_types(struct options *opts)
{
	return table_types_show(NULL, 1, 0);
}

static exit_code_t export_single_devtype(FILE *fd, struct devtype *dt,
					 struct options *opts, int *first_ptr)
{
	exit_code_t rc;

	/* Get settings. */
	rc = dt->read_settings(dt, opts->config);
	if (rc || dt->processed)
		return rc;

	dt->processed = 1;

	return export_write_devtype(fd, dt, opts->config, first_ptr);
}

static exit_code_t export_devtypes(FILE *fd, struct options *opts,
				   int *first_ptr)
{
	struct devtype *dt;
	int i;
	exit_code_t rc;

	rc = EXIT_OK;
	for (i = 0; (dt = devtypes[i]); i++) {
		if (opts->select->devtype && dt != opts->select->devtype)
			continue;

		rc = export_single_devtype(fd, dt, opts, first_ptr);
		if (rc)
			break;
	}

	return rc;
}

static void print_export_error(struct selected_dev_node *sel)
{
	const char *devname;

	if (sel->st)
		devname = sel->st->devname;
	else if (sel->dt)
		devname = sel->dt->devname;
	else
		devname = "Device";

	warn("%s %s export failed\n", devname, sel->id);
	warn("    Error: %s\n", exit_code_to_str(sel->rc));
}

static exit_code_t export_devices_and_devtypes(FILE *fd, struct options *opts,
					       int *first_ptr)
{
	struct util_list *selected;
	exit_code_t rc, drc = EXIT_OK;
	struct selected_dev_node *sel;
	struct device *dev;
	config_t config = opts->config;

	/* Determine list of selected devices. */
	selected = selected_dev_list_new();
	rc = select_devices(opts->select, selected, 1, 0, 0, opts->config,
			    scope_known, err_print);
	if (rc)
		goto out;
	if (util_list_is_empty(selected))
		goto out;

	/* Work on selected devices. */
	util_list_iterate(selected, sel) {
		if (sel->rc) {
			print_export_error(sel);
			rc = sel->rc;
			goto next;
		}
		rc = subtype_read_device(sel->st, sel->id, config, scope_known,
					 &dev);
		if (rc || dev->processed)
			goto next;
		dev->processed = 1;

		/* Write out device type configuration. */
		if (opts->type) {
			rc = export_single_devtype(fd, dev->subtype->devtype,
						   opts, first_ptr);
			if (rc)
				goto next;
		}

		/* Write out device configuration. */
		rc = export_write_device(fd, dev, opts->config, first_ptr);
next:
		if (rc && !drc)
			drc = rc;
	}

out:
	selected_dev_list_free(selected);

	return drc ? drc : rc;
}

static void action_note(const char *msg, config_t config)
{
	if (config == config_active)
		info("%s the active configuration only\n", msg);
	else if (config == config_persistent)
		info("%s the persistent configuration only\n", msg);
	else if (config == config_autoconf)
		info("%s the auto-configuration only\n", msg);
}

/* Export configuration of selected devices and/or device type to file. */
static exit_code_t do_export(struct options *opts)
{
	FILE *fd;
	exit_code_t rc = EXIT_OK;
	int devtype, devices, first;

	devtype = opts->type;
	devices = select_opts_dev_specified(opts->select);

	/* Open output stream. */
	if (strcmp(opts->export, "-") == 0) {
		fd = stdout;
		info("Exporting data to standard output\n");
	} else {
		info("Exporting data to %s\n", opts->export);
		if (!util_path_exists("%s", opts->export)) {
			rc = path_create(opts->export);
			if (rc)
				return rc;
		}
		fd = fopen(opts->export, "w");
	}
	if (!fd) {
		error("Could not write to file %s: %s\n", opts->export,
		      strerror(errno));
		return EXIT_RUNTIME_ERROR;
	}

	first = 1;

	/* Handle export of device type configuration if no device was
	 * specified. */
	if (devtype && !devices) {
		rc = export_devtypes(fd, opts, &first);
		if (rc)
			goto out;
	}

	/* Handle export of selected devices and associated device types. */
	if (devices)
		rc = export_devices_and_devtypes(fd, opts, &first);

out:
	if (rc == EXIT_OK) {
		if (first) {
			error("No settings found to export\n");
			rc = EXIT_EMPTY_SELECTION;
		}
	}

	/* Close stream. */
	if (fd != stdout)
		fclose(fd);

	return rc;
}

static exit_code_t import_devtype(struct devtype *dt, config_t config)
{
	exit_code_t rc;
	struct setting_list *active = NULL, *persistent = NULL;

	if (dt->processed)
		return EXIT_OK;

	/* Save settings. */
	if (dt->active_settings) {
		active = setting_list_copy(dt->active_settings);
		setting_list_free(dt->active_settings);
		dt->active_settings = NULL;
	}
	if (dt->persistent_settings) {
		persistent = setting_list_copy(dt->persistent_settings);
		setting_list_free(dt->persistent_settings);
		dt->persistent_settings = NULL;
	}

	/* Read settings. */
	rc = dt->read_settings(dt, config);
	if (rc)
		goto out;
	dt->processed = 1;

	/* Copy target settings to device configuration. */
	if (active) {
		rc = devtype_apply_settings(dt, config_active, &active->list);
		if (rc)
			goto out;
	}
	if (persistent) {
		rc = devtype_apply_settings(dt, config_persistent,
					    &persistent->list);
		if (rc)
			goto out;
	}

	if (!devtype_needs_writing(dt, config))
		goto out;

	/* Write settings. */
	if (SCOPE_PERSISTENT(config))
		pers_mod_devtypes++;
	rc = dt->write_settings(dt, config);

out:
	setting_list_free(persistent);
	setting_list_free(active);

	print_devtype_config_result(dt, config, rc);

	return rc;
}

static exit_code_t import_device(struct device *dev, struct options *opts)
{
	struct subtype *st = dev->subtype;
	exit_code_t rc;
	config_t config;
	int proc = 0, active, persistent, autoconf;

	if (SCOPE_ACTIVE(opts->config))
		active = (dev->active.exists || dev->active.definable);
	else
		active = 0;
	if (SCOPE_PERSISTENT(opts->config))
		persistent = dev->persistent.exists;
	else
		persistent = 0;
	if (SCOPE_AUTOCONF(opts->config))
		autoconf = dev->autoconf.exists;
	else
		autoconf = 0;

	if (!active && !persistent && !autoconf) {
		/* Nothing to import */
		return EXIT_OK;
	}
	config = get_config(active, persistent, autoconf);

	/* First check for prerequisite devices that need to be configured. */
	rc = cfg_prereqs(st, dev->id, opts, config, 0);
	if (rc)
		goto out;

	rc = cfg_import(st, dev->id, config, 0, NULL, &proc);

out:
	rc = print_config_result(NULL, dev, opts, config, rc, 0, proc);

	return rc;
}

static bool import_device_selected(struct device *dev, struct options *opts)
{
	struct select_opts *select = opts->select;
	struct subtype *st = dev->subtype;
	struct devtype *dt = st->devtype;
	struct namespace *ns = st->namespace;
	struct strlist_node *str;

	/* --type only */
	if (!select_opts_dev_specified(select))
		return false;

	/* Target configuration */
	if ((device_get_config(dev) & opts->config) == 0)
		return false;

	/* Devtype */
	if (select->devtype && dt != select->devtype)
		return false;

	/* Subtype */
	if (select->subtype && st != select->subtype)
		return false;

	/* Device ID */
	if (!util_list_is_empty(&select->devids)) {
		str = NULL;
		util_list_iterate(&select->devids, str) {
			if (ns->cmp_ids(str->str, dev->id) == 0)
				break;
		}
		if (str)
			return true;
		else
			return false;
	}

	/* State */
	if (select_match_state(dev, select))
		return true;

	return false;
}

static bool import_devtype_selected(struct devtype *dt, struct options *opts)
{
	if (!opts->type)
		return false;
	if (opts->config == config_active) {
		if (!dt->active_settings ||
		    util_list_is_empty(&dt->active_settings->list))
			return false;
	}
	if (opts->config == config_persistent) {
		if (!dt->persistent_settings ||
		    util_list_is_empty(&dt->persistent_settings->list))
			return false;
	}
	return true;
}

/* Remove export objects from @objects which are not matched by selection
 * options. */
static void apply_selection_to_import(struct util_list *objects,
				      struct options *opts)
{
	struct ptrlist_node *p, *n;
	struct export_object *obj;

	util_list_iterate_safe(objects, p, n) {
		obj = p->ptr;
		if (obj->type == export_device) {
			if (import_device_selected(obj->ptr.dev, opts))
				continue;
		} else if (obj->type == export_devtype) {
			if (import_devtype_selected(obj->ptr.dt, opts))
				continue;
		}

		util_list_remove(objects, p);
		free(p->ptr);
		free(p);
	}
}

/* Import configuration data. */
static exit_code_t do_import(struct options *opts)
{
	FILE *fd;
	exit_code_t rc;
	struct util_list *objects;
	struct ptrlist_node *p;
	struct export_object *obj;
	exit_code_t drc = EXIT_OK;
	const char *filename;
	int found;
	bool is_firmware;

	/* Open input stream. */
	if (strcmp(opts->import, "-") == 0) {
		fd = stdin;
		filename = "Standard input";
	} else {
		fd = fopen(opts->import, "r");
		filename = opts->import;
	}

	if (!fd) {
		error("Could not open file %s: %s\n", opts->import,
		      strerror(errno));
		return EXIT_RUNTIME_ERROR;
	}

	is_firmware = firmware_detect(fd);
	info("Importing data from %s%s\n", filename,
	     is_firmware ? " (firmware format)" : "");

	/* Read data. */
	objects = ptrlist_new();
	if (is_firmware)
		rc = firmware_read(fd, filename, -1, opts->config, objects);
	else
		rc = export_read(fd, filename, objects);
	if (rc)
		goto out;

	found = !util_list_is_empty(objects);
	apply_selection_to_import(objects, opts);

	if (util_list_is_empty(objects)) {
		if (found) {
			error("%s: Imported configuration data did not match "
			      "selection\n", filename);
			rc = EXIT_EMPTY_SELECTION;
		} else {
			info("%s: No settings found to import\n", filename);
			rc = EXIT_OK;
		}
		goto out;
	}

	util_list_iterate(objects, p) {
		obj = p->ptr;
		if (obj->type == export_devtype)
			rc = import_devtype(obj->ptr.dt, opts->config);
		else
			rc = import_device(obj->ptr.dev, opts);
		if (rc && !drc)
			drc = rc;
	}

out:
	ptrlist_free(objects, 1);
	/* Close stream. */
	if (fd != stdin)
		fclose(fd);

	return drc ? drc : rc;
}

static bool opts_stdout_data(struct options *opts)
{
	if (opts->export && strcmp(opts->export, "-") == 0)
		return true;
	return false;
}

static exit_code_t do_configure(struct options *opts)
{
	if (opts->type) {
		action_note("Configuring device type in", opts->config);
		return configure_devtype(opts);
	}

	action_note("Configuring devices in", opts->config);
	return configure_devices(opts, 1, NULL);
}

static exit_code_t do_deconfigure(struct options *opts)
{
	action_note("Deconfiguring devices in", opts->config);

	return deconfigure_devices(opts);
}

static exit_code_t apply_devtypes(struct options *opts, int *found_ptr,
				  int *specified_ptr)
{
	int i;
	struct devtype *dt;
	exit_code_t rc, drc = EXIT_OK;

	if (opts->select->devtype) {
		(*specified_ptr)++;
		return apply_devtype(opts->select->devtype, 1, found_ptr);
	}
	for (i = 0; (dt = devtypes[i]); i++) {
		rc = apply_devtype(dt, 0, found_ptr);
		if (rc && drc == EXIT_OK)
			drc = rc;
	}

	return drc;
}

static exit_code_t do_apply(struct options *opts)
{
	exit_code_t rc, drc = EXIT_OK;
	int found, specified;

	found = 0;
	specified = 0;

	/* Apply devtype configuration. */
	if (opts->type) {
		rc = apply_devtypes(opts, &found, &specified);
		if (rc && drc == EXIT_OK)
			drc = rc;
	}

	/* Apply device configuration. */
	if (select_opts_dev_specified(opts->select)) {
		specified++;
		rc = configure_devices(opts, 1, &found);
		if (rc && drc == EXIT_OK)
			drc = rc;
	}

	if (!found && !specified) {
		error("No configuration data found\n");
		if (drc == EXIT_OK)
			drc = EXIT_NO_DATA;
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
	if (opts_stdout_data(&opts))
		set_stdout_data();
	verbose	= opts.verbose;
	quiet	= opts.quiet;
	force	= opts.force;
	yes	= opts.yes;
	dryrun	= opts.dryrun;
	udev_no_settle = opts.no_settle;
	path_set_base(opts.base);

	if (dryrun)
		info("Starting dry-run, configuration will not be changed\n");

	/* Perform main action. */
	switch (get_action(&opts)) {
	case ACT_CONFIGURE:
		rc = do_configure(&opts);
		break;
	case ACT_DECONFIGURE:
		rc = do_deconfigure(&opts);
		break;
	case ACT_LIST_ATTRIBS:
		rc = do_list_attribs(&opts);
		break;
	case ACT_HELP_ATTRIBS:
		rc = do_help_attribs(&opts);
		break;
	case ACT_LIST_TYPES:
		rc = do_list_types(&opts);
		break;
	case ACT_EXPORT:
		rc = do_export(&opts);
		break;
	case ACT_IMPORT:
		rc = do_import(&opts);
		break;
	case ACT_APPLY:
		rc = do_apply(&opts);
		break;
	case ACT_HELP:
		print_usage();
		break;
	case ACT_VERSION:
		print_version();
		break;
	}

	if (rc) {
		if (!drc)
			drc = rc;
		goto out;
	}

	if (udev_need_settle)
		udev_settle();

	if ((pers_mod_devs || pers_mod_devtypes) && !opts.no_root_check &&
	    !dryrun) {
		/* If the root device/device type or early devices have been
		 * modified, additional work might be necessary. */
		rc = initrd_check(ZDEV_ALWAYS_UPDATE_INITRD);
		if (rc && !drc)
			drc = rc;
	}

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

	if (found_forceable && !force) {
		info("Note: You can use --force to override safety checks "
		     "(*)\n");
	}

	return drc ? drc : rc;
}
