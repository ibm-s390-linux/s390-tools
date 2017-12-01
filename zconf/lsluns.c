/*
 * lsluns - list LUNs discovered in the FC SAN, or show encryption state of
 * attached LUNs
 *
 * Copyright IBM Corp. 2008, 2017
 * Copyright Red Hat Inc. 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify it under
 * the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_list.h"
#include "lib/util_opt.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_scandir.h"

/* From include/linux/fs.h */
#define BDEVNAME_SIZE 32

typedef unsigned long long ull;

struct lun {
	ull lun;
	char device[BDEVNAME_SIZE];
	struct util_list_node list;
};

struct port {
	ull port;
	struct util_list *luns;
	struct util_list_node list;
};

struct adapter {
	char addr[BDEVNAME_SIZE];
	struct util_list *ports;
	struct util_list_node list;
};

static const struct util_prg prg = {
	.desc = "This tool is designed for environments where all SCSI devices are attached\n"
		"through the zfcp device driver. Expect error messages in mixed environments\n"
		"such as with iSCSI.\n"
		"\n"
		"lsluns [-c <busid>] ... [-p <wwpn>] ... [-h] [-v]\n"
		"\n"
		"    List LUNs discovered in the Fibre Channel (FC) Storage Area Network (SAN).\n"
		"    This causes extra SAN traffic for each target port WWPN.\n"
		"      Discovering LUNs only makes sense for NPIV-enabled FCP devices\n"
		"    without zfcp automatic LUN scan. zfcp automatic LUN scan is available\n"
		"    as of kernel version 2.6.37, if not disabled with zfcp.allow_lun_scan=0.\n"
		"      For storage products that do not support a REPORT LUNS\n"
		"    well-known logical unit (such as IBM Storwize products),\n"
		"    ensure that LUN 0 represents a valid peripheral device type.\n"
		"    See the man page for more information.\n"
		"\n"
		"lsluns -a [-c <busid>] ... [-p <wwpn>] ... [-h] [-v]\n"
		"\n"
		"    Show encryption state of the attached LUNs.\n"
		"    This causes extra SAN traffic for each attached LUN.\n"
		"\n"
		"For all other uses, such as listing attached LUNs or properties other than\n"
		"encryption, use other tools such as \"lszfcp -D\" or \"lsscsi -tv\"\n"
		"or \"lszdev zfcp-lun -ii\".\n"
		"\n"
		"Limit the listing by specifying one or more adapters (FCP device\n"
		"bus-IDs) or target port WWPNs or both.",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2008,
			.pub_last = 2017,
		},
		{
			.owner = "Red Hat Inc.",
			.pub_first = 2017,
			.pub_last = 2017,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

/*
 * Define the command line options
 */
static struct util_opt opt_vec[] = {
	UTIL_OPT_SECTION("Options:"),
	{
		.option = { NULL, no_argument, NULL, 'a'},
		.flags = UTIL_OPT_FLAG_NOLONG,
		.desc = "Show encryption state of the attached LUNs.\n"
			"This causes extra SAN traffic for each attached LUN.",
	},
	{
		.option = { "ccw", required_argument, NULL, 'c' },
		.argument = "<busid>",
		.desc = "Filter LUNs by adapter with the specified FCP device bus-ID. "
			"Can be specified multiple times.\n"
			"For example: lsluns -c 0.0.3922",
	},
	{
		.option = { "port", required_argument, NULL, 'p' },
		.argument = "<wwpn>",
		.desc = "Filter LUNs by target port with the specified WWPN. "
			"Can be specified multiple times.\n"
			"For example: lsluns -p 0x5005123456789000",
	},
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

static bool active = false;

static const ull wlun = 0xc101000000000000;
static const ull lun0 = 0x0000000000000000;

static const char *drv_dir = "/sys/bus/ccw/drivers/zfcp";
static const char *sg_dir = "/sys/class/scsi_generic";

static char *udevsettle_call;

static void udevsettle_run(void)
{
	system(udevsettle_call);
}

static FILE *run_cmd(const char *fmt, ...)
{
	FILE *stream;
	va_list ap;
	char *cmd;

	va_start(ap, fmt);
	util_vasprintf(&cmd, fmt, ap);
	va_end(ap);

	stream = popen(cmd, "r");
	free(cmd);
	return stream;
}

static bool sysfs_read_and_compare_l(long value, char *fmt, ...)
{
	char path[PATH_MAX];
	va_list ap;
	long attr;
	int rc;

	UTIL_VSPRINTF(path, fmt, ap);
	rc = util_file_read_l(&attr, 10, path);
	if (rc == -1)
		warnx("Could not read '%s'", path);

	return (rc != -1) && (value == attr);
}

static bool sysfs_read_and_compare_s(const char *value, char *fmt, ...)
{
	char path[PATH_MAX], buf[PATH_MAX];
	va_list ap;
	int rc;

	UTIL_VSPRINTF(path, fmt, ap);
	rc = util_file_read_line(buf, sizeof(buf) - 1, path);
	if (rc == -1)
		warnx("Could not read '%s'", path);
	return (rc != -1) && (strcmp(buf, value) == 0);
}

static void sleep_f(float seconds)
{
	struct timespec ts;
	ts.tv_sec = (int)seconds;
	ts.tv_nsec = (seconds - ts.tv_sec) * 1000 * 1000 * 1000;
	if (nanosleep(&ts, NULL) != 0)
		warn("could not sleep");
}

static struct lun *lun_list_lun_get_or_insert(struct util_list *list,
					      ull lnum, const char *device)
{
	struct lun *l, *new;

	util_list_iterate(list, l) {
		if (l->lun == lnum)
			return l;
		else if (l->lun > lnum)
			break;
	}

	new = util_malloc(sizeof(struct lun));
	new->lun = lnum;
	strcpy(new->device, device);

	if (l)
		util_list_add_prev(list, new, l);
	else
		util_list_add_tail(list, new);

	return new;
}

static void lun_list_free(struct util_list *list)
{
	struct lun *l, *ln;

	util_list_iterate_safe(list, l, ln) {
		util_list_remove(list, l);
		free(l);
	}
	util_list_free(list);
}

static struct port *port_list_port_get(struct util_list *list, ull port)
{
	struct port *p;

	util_list_iterate(list, p) {
		if (p->port == port)
			return p;
		else if (p->port > port)
			break;
	}

	return NULL;
}

static bool port_list_contains(struct util_list *list, ull port)
{
	return port_list_port_get(list, port) != NULL;
}

static struct port *port_list_port_get_or_insert(struct util_list *list, ull port)
{
	struct port *p, *new;

	util_list_iterate(list, p) {
		if (p->port == port)
			return p;
		else if (p->port > port)
			break;
	}

	new = util_malloc(sizeof(struct port));
	new->port = port;
	new->luns = util_list_new(struct lun, list);

	if (p)
		util_list_add_prev(list, new, p);
	else
		util_list_add_tail(list, new);

	return new;
}

static void port_list_free(struct util_list *list)
{
	struct port *p, *pn;

	util_list_iterate_safe(list, p, pn) {
		util_list_remove(list, p);
		lun_list_free(p->luns);
		free(p);
	}
	util_list_free(list);
}

static struct adapter *adapter_list_adapter_get(struct util_list *list,
						const char *addr)
{
	struct adapter *a;

	util_list_iterate(list, a) {
		int cmp = strcmp(a->addr, addr);
		if (cmp == 0)
			return a;
		else if (cmp > 0)
			break;
	}

	return NULL;
}

static struct adapter *adapter_list_adapter_get_or_insert(struct util_list *list,
							  const char *addr)
{
	struct adapter *a, *new;

	util_list_iterate(list, a) {
		int cmp = strcmp(a->addr, addr);
		if (cmp == 0)
			return a;
		else if (cmp > 0)
			break;
	}

	new = util_malloc(sizeof(struct adapter));
	strcpy(new->addr, addr);
	new->ports = util_list_new(struct port, list);

	if (a)
		util_list_add_prev(list, new, a);
	else
		util_list_add_tail(list, new);

	return new;
}

static void adapter_list_adapter_insert_stripped(struct util_list *list,
						 const char *a_str)
{
	char buf[BDEVNAME_SIZE];
	int i, j;

	for (i = 0, j = 0; a_str[i] != '\0'; i++)
		if (!isspace(a_str[i]))
			buf[j++] = tolower(a_str[i]);
	buf[j] = '\0';
	adapter_list_adapter_get_or_insert(list, buf);
}

static bool adapter_list_contains(struct util_list *list, const char *addr)
{
	return adapter_list_adapter_get(list, addr) != NULL;
}

static void adapter_list_free(struct util_list *list)
{
	struct adapter *a, *an;

	util_list_iterate_safe(list, a, an) {
		util_list_remove(list, a);
		port_list_free(a->ports);
		free(a);
	}
	util_list_free(list);
}

/*
 * Look only for LUN0 and the REPORT LUNs WLUN. SAM specifies that the storage
 * only has to respond on one of those to the REPORT LUNs command
 *
 * Note: the term 'hash' is being used losely here to represent sorted lists
 * mapping adapters to ports, ports to luns, and luns to devices.
 */
static struct util_list *get_lun_hash(void)
{
	struct util_list *lun_hash = util_list_new(struct adapter, list);
	struct dirent **de_vec;
	int i, cnt;

	cnt = util_scandir(&de_vec, NULL, sg_dir, "sg.*");
	if (cnt <= 0)
		return lun_hash;

	for (i = 0; i < cnt; i++) {
		char *device, adapter_s[PATH_MAX];
		ull lun_num, port_num;
		int rc;

		if (de_vec[i]->d_type != DT_DIR &&
		    de_vec[i]->d_type != DT_LNK)
			continue;

		device = de_vec[i]->d_name;

		rc = util_file_read_line(adapter_s, sizeof(adapter_s) - 1,
					 "%s/%s/device/hba_id", sg_dir, device);
		if (rc == -1) {
			warnx("Could not read adapter for '%s'", device);
			continue;
		}
		rc = util_file_read_ull(&lun_num, 16, "%s/%s/device/fcp_lun",
				       sg_dir, device);
		if (rc == -1) {
			warnx("Could not read lun for '%s'", device);
			continue;
		}
		rc = util_file_read_ull(&port_num, 16, "%s/%s/device/wwpn",
					sg_dir, device);
		if (rc == -1) {
			warnx("Could not read port for '%s'", device);
			continue;
		}

		if (active || ((lun_num == lun0) || (lun_num == wlun))) {
			struct adapter *a;
			struct port *p;

			a = adapter_list_adapter_get_or_insert(lun_hash, adapter_s);
			p = port_list_port_get_or_insert(a->ports, port_num);
			lun_list_lun_get_or_insert(p->luns, lun_num, device);
		}
	}
	util_scandir_free(de_vec, cnt);

	return lun_hash;
}

static void remove_device(const char *sg_dev)
{
	if (util_file_write_l(1, 10, "%s/%s/device/delete", sg_dir, sg_dev) != 0)
		warnx("Could not remove device '%s'", sg_dev);
}

static void remove_lun(ull lun, const char *adapter, ull port)
{
	char *str;

	util_asprintf(&str, "0x%016llx", lun);

	if (util_file_write_s(str, "%s/%s/0x%llx/unit_remove",
			      drv_dir, adapter, port) != 0)
		warnx("Could not remove lun 0x%llx", lun);
	free(str);
}

static void add_lun(ull lun, const char *adapter, ull port)
{
	char *str;

	util_asprintf(&str, "0x%016llx", lun);

	if (util_file_write_s(str, "%s/%s/0x%llx/unit_add",
			      drv_dir, adapter, port) != 0)
		warnx("Could not add lun 0x%llx to port 0x%llx", lun, port);
	free(str);
}

/* Check whether the adapter is online and good to use */
static bool adapter_is_online(const char *adapter)
{
	return sysfs_read_and_compare_l(1, "%s/%s/online",
					drv_dir, adapter) &&
		sysfs_read_and_compare_s("good", "%s/%s/availability",
					 drv_dir, adapter) &&
		sysfs_read_and_compare_l(0, "%s/%s/failed",
					 drv_dir, adapter) &&
		sysfs_read_and_compare_l(0, "%s/%s/in_recovery",
					 drv_dir, adapter);
}

static bool port_is_offline(const char *adapter, ull port)
{
	return sysfs_read_and_compare_l(1, "%s/%s/0x%llx/access_denied",
					drv_dir, adapter, port) ||
		sysfs_read_and_compare_l(1, "%s/%s/0x%llx/failed",
					 drv_dir, adapter, port) ||
		sysfs_read_and_compare_l(1, "%s/%s/0x%llx/in_recovery",
					 drv_dir, adapter, port);
}

static bool lun_hash_defined(struct util_list *lun_hash, const char *a, ull p)
{
	struct adapter *lun_a = adapter_list_adapter_get(lun_hash, a);
	if (lun_a != NULL) {
		struct port *lun_p = port_list_port_get(lun_a->ports, p);
		return (lun_p != NULL) && !util_list_is_empty(lun_p->luns);
	}
	return false;
}

static bool attach_lun_and_reload_hash(struct util_list **lun_hash,
				       const char *adapter, ull port, ull lun)
{
	int i;

	add_lun(lun, adapter, port);

	for (i = 0; i < 4; i++) {
		udevsettle_run();

		if (*lun_hash != NULL)
			adapter_list_free(*lun_hash);
		*lun_hash = get_lun_hash();

		if (lun_hash_defined(*lun_hash, adapter, port))
			return true;

		sleep_f(0.1);
	}

	remove_lun(lun, adapter, port);

	return false;
}

static bool print_luns_from_device(const char *device)
{
	FILE *fp;
	char *line;
	size_t n = 0;

	while (!util_path_exists("/dev/%s", device))
		sleep_f(0.1);

	fp = run_cmd("sg_luns -q /dev/%s", device);
	if (fp == NULL) {
		printf("\t\tUnable to send the REPORT_LUNS command to "
		       "LUN: %s\n", strerror(errno));
		return false;
	}

	while (getline(&line, &n, fp) != -1)
		printf("\t\t0x%s", line);

	free(line);
	pclose(fp);

	return true;
}

static void scan_and_print_luns_on_adapter(struct adapter *adapter)
{
	const char *a = adapter->addr;
	struct util_list *lun_hash;
	struct port *port;

	if (!adapter_is_online(a)) {
		printf("Adapter %s is not in a good state; skipping LUN "
		       "scan.\n", a);
		return;
	}

	lun_hash = get_lun_hash();
	printf("Scanning for LUNs on adapter %s\n", a);
	util_list_iterate(adapter->ports, port) {
		ull p = port->port;
		struct adapter *lun_a;
		bool man_att = false;
		struct port *lun_p;
		struct lun *lun;
		int retries;

		if (!util_path_exists("%s/%s/0x%llx", drv_dir, a, p))
			continue;

		if (port_is_offline(a, p)) {
			printf("\t at port 0x%llx:\n", p);
			printf("\t\tPort not online. Cannot scan for LUNs.\n");
			continue;
		}

		printf("\tat port 0x%llx:\n", p);
		if (!lun_hash_defined(lun_hash, a, p)) {
			if (!attach_lun_and_reload_hash(&lun_hash, a, p, lun0) &&
			    !attach_lun_and_reload_hash(&lun_hash, a, p, wlun)) {
				printf("\t\tCannot attach WLUN / LUN0 for scanning.\n");
				continue;
			}
			man_att = true;
		}

		lun_a = adapter_list_adapter_get(lun_hash, a);
		lun_p = port_list_port_get(lun_a->ports, p);

		retries = 0;
		util_list_iterate(lun_p->luns, lun) {
			bool success = print_luns_from_device(lun->device);

			if (man_att) {
				remove_device(lun->device);
				sleep_f(0.1);
				remove_lun(lun->lun, a, p);
				man_att = false;
			}

			if (success || retries++ > 3)
				break;
		}
	}
	adapter_list_free(lun_hash);
}

static void list_luns(struct util_list *res_hash)
{
	struct adapter *a;

	util_list_iterate(res_hash, a) {
		scan_and_print_luns_on_adapter(a);

		if (!util_path_is_dir(sg_dir)) {
			printf("%s: Error: Please load/configure SCSI Generic "
			       "(sg) to use %s.\n",
			       program_invocation_short_name,
			       program_invocation_short_name);
		}
	}
}

static const char *type_to_str(unsigned short type)
{
	static const char *text[] = {"Disk", "Tape", "Printer", "Proc", "WRO",
		"CD/DVD", "Scanner", "OMD", "Changer", "Comm", "n/a",
		"n/a", "RAID", "Encl"};
	static char buf[8];

	if (type < UTIL_ARRAY_SIZE(text))
		return text[type];
	snprintf(buf, sizeof(buf) - 1, "%hd", type);

	return buf;
}

static char *rstrip(char *string)
{
	int i;

	for (i = strlen(string) - 1; i >= 0 && isspace(string[i]); i--)
		string[i] = '\0';

	return string;
}

static void print_lun_info(struct lun *lun)
{
	char vend[9], mod[17], line[256];
	short enc;
	FILE *fp;

	fp = run_cmd("sg_inq -r /dev/%s", lun->device);
	if (fp == NULL) {
		printf("\t\tlun = 0x%llx [offline]\n", lun->lun);
		return;
	}

	if (fread(line, 1, sizeof(line), fp) <= 0xa2)
		goto end;

	memcpy(vend, &line[0x8], 0x8);
	vend[0x8] = '\0';
	memcpy(mod, &line[0x10], 0x10);
	mod[0x10] = '\0';
	enc = strncmp(mod, "2107", 4) == 0 ? line[0xa2] : 0;
	printf("\t\tlun = 0x%llx%s\t/dev/%s\t%s\t%s:%s\n",
	       lun->lun, (enc & 0x80) ? "(X)" : "", lun->device,
	       type_to_str(line[0]), rstrip(vend), rstrip(mod));
end:
	pclose(fp);
}

static void show_attached_lun_info(struct util_list *adapters,
				   struct util_list *ports)
{
	struct util_list *lun_hash = get_lun_hash();
	struct adapter *adapter;
	struct dirent **de_vec;
	int cnt;

	cnt = util_scandir(&de_vec, NULL, "/sys/class/scsi_device/", ".*");
	if (cnt != 0 && !util_path_is_dir(sg_dir))
		fprintf(stderr, "Error: Please load/configure SCSI Generic (sg) "
			"to use %s", program_invocation_short_name);
	util_scandir_free(de_vec, cnt);

	util_list_iterate(lun_hash, adapter) {
		struct port *port;

		if (!adapter_list_contains(adapters, adapter->addr))
			continue;

		printf("adapter = %s\n", adapter->addr);
		util_list_iterate(adapter->ports, port) {
			struct lun *lun;

			if (!port_list_contains(ports, port->port))
				continue;

			printf("\tport = 0x%llx\n", port->port);
			util_list_iterate(port->luns, lun)
				print_lun_info(lun);
		}
	}

	adapter_list_free(lun_hash);
}

struct util_list *get_env_list(struct util_list *a_ref_list,
			       struct util_list *p_ref_list)
{
	struct util_list *res_hash = util_list_new(struct adapter, list);
	const char *path = "/sys/bus/ccw/drivers/zfcp/";
	struct dirent **de_vec_ccw;
	int i, cnt;

	/* Scan for all busid directories */
	cnt = util_scandir(&de_vec_ccw, alphasort, path,
			   "[[:digit:]]+\\.[[:digit:]]+\\.[[:alnum:]]+");
	if (cnt <= 0)
		return res_hash;

	for (i = 0; i < cnt; i++) {
		char path2[PATH_MAX], *name = de_vec_ccw[i]->d_name;
		struct dirent **de_vec_wwpn;
		struct adapter *a = NULL;
		int j, cnt2;

		if (de_vec_ccw[i]->d_type != DT_DIR &&
		    de_vec_ccw[i]->d_type != DT_LNK)
			continue;

		if (!util_list_is_empty(a_ref_list) &&
		    !adapter_list_contains(a_ref_list, name))
			continue;

		snprintf(path2, sizeof(path2) - 1, "%s/%s", path, name);

		/* Scan for all wwpn of current busid */
		cnt2 = util_scandir(&de_vec_wwpn, alphasort, path2, "0x.*");
		if (cnt2 <= 0)
			continue;

		for (j = 0; j < cnt2; j++) {
			ull p = strtoull(de_vec_wwpn[j]->d_name, NULL, 16);
			if (p == ULLONG_MAX)
				continue;

			if (de_vec_wwpn[j]->d_type != DT_DIR &&
			    de_vec_wwpn[j]->d_type != DT_LNK)
				continue;

			if (!util_list_is_empty(p_ref_list) &&
			    !port_list_contains(p_ref_list, p))
				continue;

			/* Just insert the adapter into the list if there is at
			 * least one port associated with it
			 */
			if (a == NULL)
				a =  adapter_list_adapter_get_or_insert(res_hash, name);
			port_list_port_get_or_insert(a->ports, p);
		}

		util_scandir_free(de_vec_wwpn, cnt2);
	}

	util_scandir_free(de_vec_ccw, cnt);

	if (util_list_is_empty(res_hash))
		printf("%s: Adapter and/or port filter(s) did not match anything\n",
		       program_invocation_short_name);

	return res_hash;
}

int
main(int argc, char *argv[])
{
	struct util_list *a_ref_list = util_list_new(struct adapter, list);
	struct util_list *p_ref_list = util_list_new(struct port, list);
	struct util_list *res_hash;
	ull port;
	int c;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	do {
		c = util_opt_getopt_long(argc, argv);
		switch (c) {
		case 'h':
			util_prg_print_help();
			util_opt_print_help();
			goto out;
		case 'v':
			util_prg_print_version();
			goto out;
		case 'c':
			adapter_list_adapter_insert_stripped(a_ref_list, optarg);
			break;
		case 'p':
			port = strtoull(optarg, NULL, 16);
			if (port == ULLONG_MAX) {
				warn("invalid port %s", optarg);
				goto err;
			}
			port_list_port_get_or_insert(p_ref_list, port);
			break;
		case 'a':
			active = true;
			break;
		case -1:
			break;
		default:
			util_opt_print_parse_error(c, argv);
			goto err;
		}
	} while (c != -1);

	if (system("/sbin/udevadm --version >/dev/null 2>&1") != 0)
		udevsettle_call = "/sbin/udevsettle 2>/dev/null";
	else
		udevsettle_call = "/sbin/udevadm settle 2>/dev/null";

	res_hash = get_env_list(a_ref_list, p_ref_list);

	if (active) {
		struct util_list *ports = util_list_new(struct port, list);
		struct adapter *adapter;

		util_list_iterate(res_hash, adapter) {
			struct port *port;
			util_list_iterate(adapter->ports, port) {
				port_list_port_get_or_insert(ports, port->port);
			}
		}
		show_attached_lun_info(res_hash, ports);
		port_list_free(ports);
	} else {
		list_luns(res_hash);
	}

	adapter_list_free(res_hash);

out:
	adapter_list_free(a_ref_list);
	port_list_free(p_ref_list);

	return EXIT_SUCCESS;

err:
	adapter_list_free(a_ref_list);
	port_list_free(p_ref_list);
	return EXIT_FAILURE;
}
