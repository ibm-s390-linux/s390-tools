/*
 * chzcrypt - Tool to modify zcrypt configuration
 *
 * Copyright IBM Corp. 2008, 2023
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <argz.h>
#include <err.h>
#include <errno.h>
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
#include "lib/util_scandir.h"
#include "lib/zt_common.h"

#include "misc.h"

/* max seconds the se-association command will wait for completion */
#define MAX_ASSOC_POLL_TIME_IN_S  30

/* max seconds the se-unbind command will wait for unbind complete */
#define MAX_UNBIND_POLL_TIME_IN_S  30

/*
 * Private data
 */
static struct chzcrypt_l {
	int verbose;
} l;

/*
 * Program configuration
 */
static const struct util_prg prg = {
	.desc	= "Modify zcrypt configuration.",
	.args = "[DEVICE_IDS]",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2008,
			.pub_last = 2023,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Configuration of command line options
 */

#define OPT_CONFIG_ON  0x80
#define OPT_CONFIG_OFF 0x81
#define OPT_SE_ASSOC   0x82
#define OPT_SE_BIND    0x83
#define OPT_SE_UNBIND  0x84

static struct util_opt opt_vec[] = {
	{
		.option = { "enable", no_argument, NULL, 'e'},
		.argument = "DEVICE_IDS",
		.desc = "Set the given cryptographic device(s) online"
	},
	{
		.option = { "disable", no_argument, NULL, 'd'},
		.argument = "DEVICE_IDS",
		.desc = "Set the given cryptographic device(s) offline",
	},
	{
		.option = { "all", no_argument, NULL, 'a'},
		.desc = "Set all available cryptographic device(s) "
			"online/offline, must be used in conjunction "
			"with the enable or disable option",
	},
	{
		.option = { "config-on", no_argument, NULL, OPT_CONFIG_ON},
		.argument = "DEVICE_IDS",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Set the given cryptographic card device(s) configured"
	},
	{
		.option = { "config-off", no_argument, NULL, OPT_CONFIG_OFF},
		.argument = "DEVICE_IDS",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "Set the given cryptographic card device(s) deconfigured"
	},
	{
		.option = { "poll-thread-enable", no_argument, NULL, 'p'},
		.desc = "Enable zcrypt's poll thread",
	},
	{
		.option = { "poll-thread-disable", no_argument, NULL, 'n'},
		.desc = "Disable zcrypt's poll thread",
	},
	{
		.option = { "config-time", required_argument, NULL, 'c'},
		.argument = "TIMEOUT",
		.desc = "Set configuration timer for re-scanning the AP bus "
			"to TIMEOUT seconds",
	},
	{
		.option = { "poll-timeout", required_argument, NULL, 't'},
		.argument = "TIMEOUT",
		.desc = "Set poll timer to run poll tasklet all TIMEOUT "
			"nanoseconds after a request has been queued",
	},
	{
		.option = { "default-domain", required_argument, NULL, 'q'},
		.argument = "DOMAIN",
		.desc = "Set new default domain to DOMAIN",
	},
	{
		.option = { "verbose", no_argument, NULL, 'V'},
		.desc = "Print verbose messages",
	},
	{
		.option = { "se-associate", required_argument, NULL, OPT_SE_ASSOC},
		.argument = "assoc_idx",
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "SE guest with AP support only: Associate the given queue device",
	},
	{
		.option = { "se-bind", no_argument, NULL, OPT_SE_BIND},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "SE guest with AP support only: Bind the given queue device",
	},
	{
		.option = { "se-unbind", no_argument, NULL, OPT_SE_UNBIND},
		.flags = UTIL_OPT_FLAG_NOSHORT,
		.desc = "SE guest with AP support only: Unbind the given queue device",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

/*
 * Print if verbose is set
 */
#define verbose(x...)			\
do {					\
	if (!l.verbose)			\
		break;			\
	printf(x);			\
} while (0)

/*
 * Set poll settings
 */
static void poll_thread_set(const char *mode_str)
{
	long mode, mode_read = -1;
	char *attr;

	sscanf(mode_str, "%ld", &mode);
	if (mode == 1)
		verbose("Enabling poll thread.\n");
	else
		verbose("Disabling poll thread.\n");
	attr = util_path_sysfs("bus/ap/poll_thread");
	if (!util_path_is_writable(attr))
		errx(EXIT_FAILURE, "Error - can't write to %s.\n Wrong permissions"
		     " or wrong tools version.", attr);
	util_file_write_l(mode, 10, attr);
	util_file_read_l(&mode_read, 10, attr);
	if (mode != mode_read)
		errx(EXIT_FAILURE, "Error - unable to change poll thread setting.");
	free(attr);
}

/*
 * Set timer
 */
static void config_time_set(const char *timeout_str)
{
	long timeout, timeout_read;
	char *attr;

	if (sscanf(timeout_str, "%ld", &timeout) != 1) {
		errx(EXIT_FAILURE, "Error - invalid configuration timeout '%s'.", timeout_str);
	}
	attr = util_path_sysfs("bus/ap/config_time");
	verbose("Setting configuration timer to %ld seconds.\n", timeout);
	if (!util_path_is_writable(attr))
		errx(EXIT_FAILURE, "Error - can't write to %s.\n Wrong permissions"
		     " or wrong tools version.", attr);
	util_file_write_l(timeout, 10, attr);
	util_file_read_l(&timeout_read, 10, attr);
	if (timeout != timeout_read)
		errx(EXIT_FAILURE, "Error - unable to change configuration timer setting.");
	free(attr);
}

/*
 * Set poll timeout
 */
static void poll_timeout_set(const char *poll_timeout_str)
{
	long poll_timeout, poll_timeout_read;
	char *attr;

	if (sscanf(poll_timeout_str, "%ld", &poll_timeout) != 1)
		errx(EXIT_FAILURE, "Error - invalid poll timeout '%s'.", poll_timeout_str);
	attr = util_path_sysfs("bus/ap/poll_timeout");
	verbose("Setting poll timeout to %ld seconds.\n", poll_timeout);
	if (!util_path_is_writable(attr))
		errx(EXIT_FAILURE, "Error - can't write to %s.\n Wrong permissions"
		     " or wrong tools version.", attr);
	util_file_write_l(poll_timeout, 10, attr);
	util_file_read_l(&poll_timeout_read, 10, attr);
	if (poll_timeout != poll_timeout_read)
		errx(EXIT_FAILURE, "Error - unable to change poll timeout setting.");
	free(attr);
}

/*
 * Set default domain
 */
static void default_domain_set(const char *default_domain_str)
{
	long max_dom, default_domain, default_domain_read;
	char *attr, *ap_max_domain_id;

	sscanf(default_domain_str, "%li", &default_domain);
	ap_max_domain_id = util_path_sysfs("bus/ap/ap_max_domain_id");
	util_file_read_l(&max_dom, 10, ap_max_domain_id);
	if (default_domain < 0 || default_domain > max_dom)
		errx(EXIT_FAILURE, "Error - invalid default domain '%s'.", default_domain_str);
	attr = util_path_sysfs("bus/ap/ap_domain");
	if (!util_path_is_writable(attr))
		errx(EXIT_FAILURE, "Error - can't write to %s.\n Wrong permissions"
		     " or wrong tools version.", attr);
	verbose("Setting default domain to %ld.\n", default_domain);
	util_file_write_l(default_domain, 10, attr);
	util_file_read_l(&default_domain_read, 10, attr);
	if (default_domain != default_domain_read)
		errx(EXIT_FAILURE, "Error - unable to change default domain.");
	free(ap_max_domain_id);
	free(attr);
}

static void set_online(const char *online, const char *online_text,
		       char *dev_list, size_t len)
{
	long value;
	int id, dom;
	char *dev, *dev_path;
	char device[256], online_read[32];

	for (dev = dev_list; dev != NULL; dev = argz_next(dev_list, len, dev)) {
		if (strncmp(dev, "card", 4) == 0) {
			/* dev == "card2" */
			if (sscanf(dev, "card%02x", &id) != 1)
				errx(EXIT_FAILURE, "Error - unable to parse '%s'.", dev);
			sprintf(device, "card%02x", id);
		} else if (strncmp(dev, "0x", 2) == 0) {
			/* dev == "0x.." */
			if (sscanf(dev, "0x%02x", &id) != 1)
				errx(EXIT_FAILURE, "Error - unable to parse '%s'.", dev);
			sprintf(device, "card%02x", id);
		} else if (misc_regex_match(dev, "^[0-9a-fA-F]+$")) {
			/* dev == "2" */
			if (sscanf(dev, "%02x", &id) != 1)
				errx(EXIT_FAILURE, "Error - unable to parse '%s'.", dev);
			sprintf(device, "card%02x", id);
		} else {
			/* Form: 01.0003 ? */
			if (sscanf(dev, "%02x.%04x", &id, &dom) != 2)
				errx(EXIT_FAILURE,
				     "Error - cryptographic device %s malformed.", dev);
			sprintf(device, "card%02x/%02x.%04x", id, id, dom);
		}
		dev_path = util_path_sysfs("bus/ap/devices/%s", device);
		if (!util_path_is_dir(dev_path))
			errx(EXIT_FAILURE,
			     "Error - cryptographic device %s does not exist.", device);
		if (!util_path_is_writable("%s/online", dev_path))
			errx(EXIT_FAILURE, "Error - can't write to %s/online.\n"
			     " Wrong permissions or wrong tools version.", dev_path);
		if (*online == '1' && util_path_is_readable("%s/config", dev_path)) {
			util_file_read_l(&value, 10, "%s/config", dev_path);
			if (value <= 0) {
				warnx("Warning - device %s is deconfigured,"
				      " can't set to online.\n", dev);
				goto next;
			}
		}
		verbose("Setting cryptographic device %s %s\n", device, online_text);
		util_file_write_s(online, "%s/online", dev_path);
		util_file_read_line(online_read, sizeof(online_read), "%s/online", dev_path);
		if (strcmp(online, online_read) != 0)
			errx(EXIT_FAILURE, "Error - unable to set cryptographic device %s %s.",
			     device, online_text);
next:
		free(dev_path);
	}
}

static void set_config(const char *config, const char *config_text,
		       char *dev_list, size_t len)
{
	int id;
	char *dev, *dev_path;
	char device[256], config_read[32];

	for (dev = dev_list; dev != NULL; dev = argz_next(dev_list, len, dev)) {
		if (strncmp(dev, "card", 4) == 0) {
			/* dev == "card2" */
			if (sscanf(dev, "card%02x", &id) != 1)
				errx(EXIT_FAILURE, "Error - unable to parse '%s'.", dev);
			sprintf(device, "card%02x", id);
		} else if (strncmp(dev, "0x", 2) == 0) {
			/* dev == "0x.." */
			if (sscanf(dev, "0x%02x", &id) != 1)
				errx(EXIT_FAILURE, "Error - unable to parse '%s'.", dev);
			sprintf(device, "card%02x", id);
		} else if (misc_regex_match(dev, "^[0-9a-fA-F]+$")) {
			/* dev == "2" */
			if (sscanf(dev, "%02x", &id) != 1)
				errx(EXIT_FAILURE, "Error - unable to parse '%s'.", dev);
			sprintf(device, "card%02x", id);
		} else {
			errx(EXIT_FAILURE, "Error - invalid device %s\n"
			     " Config on/off is only valid for card devices.", dev);
		}
		dev_path = util_path_sysfs("bus/ap/devices/%s", device);
		if (!util_path_is_dir(dev_path))
			errx(EXIT_FAILURE,
			     "Error - cryptographic device %s does not exist.", device);
		if (!util_path_is_readable("%s/config", dev_path))
			errx(EXIT_FAILURE, "Error - can't read %s/config.\n"
			     "File may not exist due to an older zcrypt device driver.", dev_path);
		util_file_read_line(config_read, sizeof(config_read), "%s/config", dev_path);
		if (strcmp(config, config_read) == 0) {
			warnx("Warning - device %s is already %s.", device, config_text);
			goto next;
		}
		if (!util_path_is_writable("%s/config", dev_path))
			errx(EXIT_FAILURE, "Error - can't write to %s/config.\n"
			     "Wrong permissions or wrong tools version.", dev_path);
		verbose("Setting cryptographic device %s %s\n", device, config_text);
		util_file_write_s(config, "%s/config", dev_path);
		util_file_read_line(config_read, sizeof(config_read), "%s/config", dev_path);
		if (strcmp(config, config_read) != 0)
			errx(EXIT_FAILURE, "Error - unable to set cryptographic device %s %s.",
			     device, config_text);
next:
		free(dev_path);
	}
}

static void se_assoc(const char *assoc_idx, const char *dev)
{
	int i, idx, rc, ap, dom, loop;
	char *dev_path, *attr;
	char buf[256];

	if (!ap_bus_has_SB_support())
		errx(EXIT_FAILURE, "Error - AP bus: SE bind support is not available.");

	if (sscanf(dev, "%02x.%04x", &ap, &dom) != 2)
		errx(EXIT_FAILURE, "Error - Can't parse queue device '%s' as xy.abcd.",
		     dev);
	dev_path = util_path_sysfs("bus/ap/devices/card%02x/%02x.%04x",
				   ap, ap, dom);
	if (!util_path_is_dir(dev_path))
		errx(EXIT_FAILURE, "Error - Queue device %s does not exist.",
		     dev);

	if (sscanf(assoc_idx, "%i", &idx) != 1)
		errx(EXIT_FAILURE, "Error - Can't parse association index '%s' as number.",
		     assoc_idx);
	if (idx < 0 || idx > 0xFFFF)
		errx(EXIT_FAILURE, "Error - Association index needs to be in range [0...%d].",
		     0xffff);

	attr = util_path_sysfs("bus/ap/devices/card%02x/%02x.%04x/se_associate",
			       ap, ap, dom);
	if (!util_path_is_writable(attr))
		errx(EXIT_FAILURE, "Error - Can't write to %s (errno '%s').",
		     attr, strerror(errno));

	/* read se_associate attribute and check for 'unassociated' */
	rc = util_file_read_line(buf, sizeof(buf), attr);
	if (rc)
		errx(EXIT_FAILURE, "Error - Failure reading from %s (errno '%s').",
		     attr, strerror(errno));
	if (strcmp(buf, "unassociated"))
		errx(EXIT_FAILURE,
		     "Error - Queue device %s is NOT in 'unassociated' state (state '%s' found).",
		     dev, buf);

	/* write assocition index to the se_associate attribute */
	rc = util_file_write_l(idx, 10, attr);
	if (rc)
		errx(EXIT_FAILURE, "Error - Failure writing to %s (errno '%s').",
		     attr, strerror(errno));

	/* loop up to MAX_ASSOC_POLL_TIME_IN_S seconds for completion */
	for (loop = 0; loop < 2 * MAX_ASSOC_POLL_TIME_IN_S; usleep(500000), loop++) {
		rc = util_file_read_line(buf, sizeof(buf), attr);
		if (rc)
			errx(EXIT_FAILURE, "Error - Failure reading from %s (errno '%s').",
			     attr, strerror(errno));
		if (!strncmp(buf, "associated", strlen("associated")))
			break;
		if (!strcmp(buf, "unassociated"))
			errx(EXIT_FAILURE,
			     "Error - Failure associating queue device %s (state '%s' found).",
			     dev, buf);
	}
	if (loop >= 2 * MAX_ASSOC_POLL_TIME_IN_S)
		errx(EXIT_FAILURE,
		     "Error - Failure associating queue device %s (timeout after %d s).",
		     dev, MAX_ASSOC_POLL_TIME_IN_S);

	if (sscanf(buf, "associated %d", &i) != 1 || idx != i)
		errx(EXIT_FAILURE,
		     "Error - Failure associating queue device %s (state '%s' found).",
		     dev, buf);

	verbose("Queue device %s successful associated with index %d.\n",
		dev, idx);

	free(dev_path);
	free(attr);
}

static void se_bind(const char *dev)
{
	char *dev_path, *attr;
	int rc, ap, dom;
	char buf[256];

	if (!ap_bus_has_SB_support())
		errx(EXIT_FAILURE, "Error - AP bus: SE bind support is not available.");

	if (sscanf(dev, "%02x.%04x", &ap, &dom) != 2)
		errx(EXIT_FAILURE, "Error - Can't parse queue device '%s' as xy.abcd.",
		     dev);
	dev_path = util_path_sysfs("bus/ap/devices/card%02x/%02x.%04x",
				   ap, ap, dom);
	if (!util_path_is_dir(dev_path))
		errx(EXIT_FAILURE, "Error - Queue device %s does not exist.",
		     dev);

	attr = util_path_sysfs("bus/ap/devices/card%02x/%02x.%04x/se_bind",
			       ap, ap, dom);
	if (!util_path_is_writable(attr))
		errx(EXIT_FAILURE, "Error - Can't write to %s (errno '%s').",
		     attr, strerror(errno));

	/* read se_bind attribute and check for 'unboud' */
	rc = util_file_read_line(buf, sizeof(buf), attr);
	if (rc)
		errx(EXIT_FAILURE, "Error - Failure reading from %s (errno '%s').",
		     attr, strerror(errno));
	if (strcmp(buf, "unbound"))
		errx(EXIT_FAILURE,
		     "Error - Queue device %s is NOT in 'unbound' state (state '%s' found).",
		     dev, buf);

	/* write se_bind attribute, check for 'bound' afterwards */
	rc = util_file_write_l(1, 10, attr);
	if (rc)
		errx(EXIT_FAILURE, "Error - Failure writing to %s (errno '%s').",
		     attr, strerror(errno));
	rc = util_file_read_line(buf, sizeof(buf), attr);
	if (rc)
		errx(EXIT_FAILURE, "Error - Failure reading from %s (errno '%s').",
		     attr, strerror(errno));
	if (strcmp(buf, "bound"))
		errx(EXIT_FAILURE, "Error - Failure binding queue device %s (state '%s' found).",
		     dev, buf);

	verbose("Queue device %s successful bound.\n", dev);

	free(dev_path);
	free(attr);
}

static void se_unbind(const char *dev)
{
	int rc, ap, dom, loop;
	char *dev_path, *attr;
	char buf[256];

	if (!ap_bus_has_SB_support())
		errx(EXIT_FAILURE, "Error - AP bus: SE bind support is not available.");

	if (sscanf(dev, "%02x.%04x", &ap, &dom) != 2)
		errx(EXIT_FAILURE, "Error - Can't parse queue device '%s' as xy.abcd.",
		     dev);
	dev_path = util_path_sysfs("bus/ap/devices/card%02x/%02x.%04x",
				   ap, ap, dom);
	if (!util_path_is_dir(dev_path))
		errx(EXIT_FAILURE, "Error - Queue device %s does not exist.",
		     dev);

	attr = util_path_sysfs("bus/ap/devices/card%02x/%02x.%04x/se_bind",
			       ap, ap, dom);
	if (!util_path_is_writable(attr))
		errx(EXIT_FAILURE, "Error - Can't write to %s (errno '%s').",
		     attr, strerror(errno));

	/* write se_bind attribute */
	rc = util_file_write_l(0, 10, attr);
	if (rc)
		errx(EXIT_FAILURE, "Error - Failure writing to %s (errno '%s').",
		     attr, strerror(errno));

	/* loop up to MAX_UNBIND_POLL_TIME_IN_S seconds for completion */
	for (loop = 0; loop < 2 * MAX_UNBIND_POLL_TIME_IN_S; usleep(500000), loop++) {
		rc = util_file_read_line(buf, sizeof(buf), attr);
		if (rc)
			errx(EXIT_FAILURE, "Error - Failure reading from %s (errno '%s').",
			     attr, strerror(errno));
		if (!strcmp(buf, "unbound"))
			break;
	}
	if (loop >= 2 * MAX_UNBIND_POLL_TIME_IN_S)
		errx(EXIT_FAILURE,
		     "Error - Failure unbinding queue device %s (timeout after %d s).",
		     dev, MAX_UNBIND_POLL_TIME_IN_S);

	verbose("Queue device %s successful unbound.\n", dev);

	free(dev_path);
	free(attr);
}

/*
 * Print invalid commandline error message and then exit with error code
 */
#define invalid_cmdline_exit(x...)			\
do {							\
	fprintf(stderr, "%s: ", program_invocation_short_name);	\
	fprintf(stderr, x);				\
	util_prg_print_parse_error();			\
	exit(EXIT_FAILURE);				\
} while (0)

/*
 * Get device list from sysfs
 */
static void dev_list_all(char **argz, size_t *len)
{
	struct dirent **de_vec;
	int count, i;
	char *path;

	path = util_path_sysfs("bus/ap/devices/");
	count = util_scandir(&de_vec, NULL, path, "card.*");
	if (count < 0)
		errx(EXIT_FAILURE, "Error - Could not read directory %s.", path);
	*argz = NULL;
	*len = 0;
	for (i = 0; i < count; i++)
		util_assert(argz_add(argz, len, de_vec[i]->d_name) == 0,
			    "Out of memory\n");
	util_scandir_free(de_vec, count);
	free(path);
}

/*
 * Get device list from commandline
 */
static void dev_list_argv(char **argz, size_t *len, char * const argv[])
{
	if (argv[0] == NULL)
		errx(EXIT_FAILURE, "Need to specify at least one device ID.");

	util_assert(argz_create(argv, argz, len) == 0, "Out of memory\n");
}

/*
 * Describe adapter ids
 */
static void print_adapter_id_help(void)
{
	printf("\n");
	printf("DEVICE_IDS\n");
	printf("  List of cryptographic device ids separated by blanks which will be set\n");
	printf("  online/offline. Must be used in conjunction with the enable or disable option.\n");
	printf("  DEVICE_ID could either be card device id ('<card-id>') or queue device id\n");
	printf("  '<card-id>.<domain-id>').\n\n");
	printf("QUEUE_DEVICE:\n");
	printf("  An APQN queue device given as xy.abcd as it is listed by lszcrypt -V.\n\n");
	printf("EXAMPLE:\n");
	printf("  Disable the cryptographic device with card id '02' (inclusive all queues).\n");
	printf("  #>chzcrypt -d 02\n");
	printf("  \n");
	printf("  Enable the cryptographic devices with card id '03' and domain id '0005'.\n");
	printf("  #>chzcrypt -e 03.0005\n");
	printf("  \n");
}

/*
 * Parse options and execute the command
 */
int main(int argc, char *argv[])
{
	const char *default_domain = NULL, *config = NULL, *config_text = NULL;
	const char *online = NULL, *online_text = NULL, *poll_thread = NULL;
	const char *config_time = NULL, *poll_timeout = NULL;
	const char *queue_device = NULL, *assoc_idx = NULL;
	int c, i, j, action = 0;
	char *path, *dev_list;
	bool all = false;
	size_t len;

	for (i=0; i < argc; i++)
		for (j=2; j < (int) strlen(argv[i]); j++)
			if (argv[i][j] == '_')
				argv[i][j] = '-';

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);
	while (1) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;
		switch (c) {
		case 'e':
			action = c;
			online = "1";
			online_text = "online";
			break;
		case 'd':
			action = c;
			online = "0";
			online_text = "offline";
			break;
		case 'a':
			all = true;
			break;
		case 'p':
			action = c;
			poll_thread = "1";
			break;
		case 'n':
			action = c;
			poll_thread = "0";
			break;
		case 'c':
			action = c;
			config_time = optarg;
			break;
		case 't':
			action = c;
			poll_timeout = optarg;
			break;
		case 'q':
			action = c;
			default_domain = optarg;
			break;
		case 'V':
			l.verbose = true;
			break;
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			print_adapter_id_help();
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		case OPT_CONFIG_ON:
			action = c;
			config = "1";
			config_text = "config on";
			break;
		case OPT_CONFIG_OFF:
			action = c;
			config = "0";
			config_text = "config off";
			break;
		case OPT_SE_ASSOC:
			action = c;
			assoc_idx = optarg;
			break;
		case OPT_SE_BIND:
			action = c;
			break;
		case OPT_SE_UNBIND:
			action = c;
			break;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}
	if (!action)
		invalid_cmdline_exit("Error - missing argument.\n");
	path = util_path_sysfs("bus/ap");
	if (!util_path_is_dir(path))
		errx(EXIT_FAILURE, "Crypto device driver not available.");
	free(path);
	if (poll_thread) {
		poll_thread_set(poll_thread);
		return EXIT_SUCCESS;
	}
	if (config_time) {
		config_time_set(config_time);
		return EXIT_SUCCESS;
	}
	if (poll_timeout) {
		poll_timeout_set(poll_timeout);
		return EXIT_SUCCESS;
	}
	if (default_domain) {
		default_domain_set(default_domain);
		return EXIT_SUCCESS;
	}

	if (action == OPT_SE_ASSOC) {
		if (optind >= argc)
			errx(EXIT_FAILURE,
			     "Error - The --se-associate needs a queue device given.");
		queue_device = argv[optind];
		se_assoc(assoc_idx, queue_device);
		return EXIT_SUCCESS;
	}
	if (action == OPT_SE_BIND) {
		if (optind >= argc)
			errx(EXIT_FAILURE,
			     "Error - The --se-bind needs a queue device given.");
		queue_device = argv[optind];
		se_bind(queue_device);
		return EXIT_SUCCESS;
	}
	if (action == OPT_SE_UNBIND) {
		if (optind >= argc)
			errx(EXIT_FAILURE,
			     "Error - The --se-unbind needs a queue device given.");
		queue_device = argv[optind];
		se_unbind(queue_device);
		return EXIT_SUCCESS;
	}

	if (all)
		dev_list_all(&dev_list, &len);
	else
		dev_list_argv(&dev_list, &len, &argv[optind]);

	if ((online || config) && len == 0)
		errx(EXIT_FAILURE, "Error - missing cryptographic device id(s).");

	if (online)
		set_online(online, online_text, dev_list, len);
	else if (config)
		set_config(config, config_text, dev_list, len);

	return EXIT_SUCCESS;
}
