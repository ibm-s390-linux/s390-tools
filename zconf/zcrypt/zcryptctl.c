/*
 * zcryptctl - Maintain zcrypt multi device nodes.
 *
 * by Harald Freudenberger <freude@linux.ibm.com>
 * Copyright IBM Corp. 2018, 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_opt.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"
#include "lib/util_prg.h"
#include "lib/util_proc.h"
#include "lib/util_rec.h"
#include "lib/util_scandir.h"
#include "lib/zt_common.h"

#define MAX_ZDEV_IOCTLS 256
#define ZCRYPT_NAME  "zcrypt"
#define MAX_ZDEV_CARDIDS_EXT 256
#define MAX_ZDEV_DOMAINS_EXT 256
#define ZCRYPTDEVICE "/dev/z90crypt"
#define _UNUSED_ __attribute__((unused))

/*
 * Currently known commands
 */
#define CMD_LIST       0x0001
#define CMD_CREATE     0x0002
#define CMD_DESTROY    0x0003
#define CMD_ADD_AP     0x0004
#define CMD_DEL_AP     0x0005
#define CMD_ADD_DOM    0x0006
#define CMD_DEL_DOM    0x0007
#define CMD_ADD_IOCTL  0x0008
#define CMD_DEL_IOCTL  0x0009
#define CMD_CONFIG     0x000A
#define CMD_LISTCONFIG 0x000B
#define CMD_ADD_CTRL   0x000C
#define CMD_DEL_CTRL   0x000D

/*
 * Program configuration
 */
static const struct util_prg prg = {
	.args = "",
	.command_args = "COMMAND [COMMAND-PARAMS]",
	.desc = "Display and administrate zcrypt multiple device nodes.",
	.copyright_vec = {
		{
			.owner = "IBM Corp.",
			.pub_first = 2018,
			.pub_last = 2022,
		},
		UTIL_PRG_COPYRIGHT_END
	}
};

static struct util_opt opt_vec[] = {
	UTIL_OPT_HELP,
	UTIL_OPT_VERSION,
	UTIL_OPT_END
};

/*
 * List of currently known and supported ioctls
 */
static struct zcryptctl_ioctls_s {
	int nr;
	const char *name;
} zcryptctl_ioctls[] = {
	{
		.name = "ICARSAMODEXPO",
		.nr = 0x05,
	},
	{
		.name = "ICARSACRT",
		.nr = 0x06,
	},
	{
		.name = "ZSECSENDCPRB",
		.nr = 0x81,
	},
	{
		.name = "ZSENDEP11CPRB",
		.nr = 0x04,
	},
	{
		.name = "ZCRYPT_DEVICE_STATUS",
		.nr = 0x5f,
	},
	{
		.name = "ZCRYPT_STATUS_MASK",
		.nr = 0x58,
	},
	{
		.name = "ZCRYPT_QDEPTH_MASK",
		.nr = 0x59,
	},
	{
		.name = "ZCRYPT_PERDEV_REQCNT",
		.nr = 0x5a,
	},
	{
		.name = NULL,
		.nr = 0,
	},
};

static int ioctlstr2value(const char *str)
{
	int i;

	for (i = 0; zcryptctl_ioctls[i].name; i++)
		if (strcasecmp(str, zcryptctl_ioctls[i].name) == 0)
			return zcryptctl_ioctls[i].nr;

	return -1;
}

static const char *value2ioctlstr(int value)
{
	int i;

	for (i = 0; zcryptctl_ioctls[i].name; i++)
		if (value == zcryptctl_ioctls[i].nr)
			return zcryptctl_ioctls[i].name;

	return NULL;
}

static int check_nodename(const char *nodename)
{
	struct stat sb;
	const char *node;
	char pathname[PATH_MAX];

	node = strrchr(nodename, '/');
	node = node ? node + 1 : nodename;
	snprintf(pathname, sizeof(pathname), "/dev/%s", node);
	pathname[sizeof(pathname) - 1] = '\0';
	if (stat(pathname, &sb) != 0)
		return -1;
	if (!S_ISCHR(sb.st_mode))
		return -2;

	return 0;
}

static int check_zcrypt_class_dir(void)
{
	int rc = 0;
	char *afile;

	afile = util_path_sysfs("class/%s", ZCRYPT_NAME);
	if (!util_path_is_dir(afile))
		rc = -1;

	free(afile);
	return rc;
}

static int fetch_major_minor(const char *nodename, int *major, int *minor)
{
	FILE *f;
	int rc = 0;
	char *afile;
	const char *node;

	node = strrchr(nodename, '/');
	node = node ? node + 1 : nodename;
	afile = util_path_sysfs("class/%s/%s/dev", ZCRYPT_NAME, node);
	f = fopen(afile, "r");
	if (!f) {
		rc = -1;
		goto out;
	}
	if (fscanf(f, "%i:%i", major, minor) != 2) {
		fclose(f);
		rc = -2;
		goto out;
	}
	fclose(f);

out:
	free(afile);
	return rc;
}

static int write_dn_attr(const char *nodename, const char *attr,
			 const char *value)
{
	FILE *f;
	int rc = 0;
	char *afile;
	const char *node;

	if (nodename) {
		node = strrchr(nodename, '/');
		node = node ? node + 1 : nodename;
		afile = util_path_sysfs("class/%s/%s/%s",
					ZCRYPT_NAME, node, attr);
	} else
		afile = util_path_sysfs("class/%s/%s", ZCRYPT_NAME, attr);
	f = fopen(afile, "w");
	if (!f) {
		rc = -1;
		goto out;
	}
	if (fprintf(f, "%s\n", value) < 0) {
		fclose(f);
		rc = -2;
		goto out;
	}
	fflush(f);
	if (ferror(f)) {
		fclose(f);
		rc = -2;
		goto out;
	}

	fclose(f);

out:
	free(afile);
	return rc;
}

static int read_dn_attr(const char *nodename, const char *attr,
			char *value, int valuelen)
{
	int rc;
	FILE *f;
	char *afile;
	const char *node;

	node = strrchr(nodename, '/');
	node = node ? node + 1 : nodename;
	afile = util_path_sysfs("class/%s/%s/%s", ZCRYPT_NAME, node, attr);
	f = fopen(afile, "r");
	if (!f) {
		rc = -1;
		goto out;
	}
	value = fgets(value, valuelen, f);
	fclose(f);
	rc = value ? 0 : -2;

out:
	free(afile);
	return rc;
}

static int test_bit(int n, const char *hexbytestr)
{
	char c;
	int v, i = 0;

	if (strncmp(hexbytestr, "0x", 2) == 0)
		i += 2;
	c = hexbytestr[i + n / 4];
	if (c >= '0' && c <= '9')
		v = c - '0';
	else if (c >= 'a' && c <= 'f')
		v = 10 + c - 'a';
	else if (c >= 'A' && c <= 'F')
		v = 10 + c - 'A';
	else
		errx(EXIT_FAILURE,
		     "Could not parse hex digit '%c'", c);

	return v & (1 << (3 - (n % 4)));
}

static int cmd_list(int cmd,
		    const char *node _UNUSED_,
		    const char *arg _UNUSED_)
{
	DIR *dir;
	char *dirname;
	const char *p;
	struct dirent *de;
	int i, n, major, minor, count = 0;
	char buf[80], tab = (cmd == CMD_LISTCONFIG ? ' ' : '\t');

	dirname = util_path_sysfs("class/%s", ZCRYPT_NAME);
	dir = opendir(dirname);
	if (!dir)
		errx(EXIT_FAILURE,
		     "Could not read directory '%s' errno=%d (%s)",
		     dirname, errno, strerror(errno));
	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.' || de->d_type == DT_REG)
			continue;
		if (fetch_major_minor(de->d_name, &major, &minor) != 0)
			errx(EXIT_FAILURE,
			     "Could not fetch major/minor from sysfs for zcrypt node '%s'",
			     de->d_name);
		if (cmd == CMD_LISTCONFIG) {
			printf("node = %s\n", de->d_name);
			printf(" aps =");
		} else {
			printf("zcrypt node name:\t%s\n", de->d_name);
			printf("  device node:\t/dev/%s\n", de->d_name);
			printf("  major:minor:\t%d:%d\n", major, minor);
			printf("  adapter:");
		}
		if (read_dn_attr(de->d_name, "apmask", buf, sizeof(buf)) != 0)
			errx(EXIT_FAILURE,
			     "Could not fetch apmask attribute from sysfs for zcrypt node '%s'",
			     de->d_name);
		for (i = n = 0; i < MAX_ZDEV_CARDIDS_EXT; i++)
			if (test_bit(i, buf))
				printf("%c%d", n++ == 0 ? tab : ',', i);
		putchar('\n');
		if (cmd == CMD_LISTCONFIG)
			printf(" doms =");
		else
			printf("  domains:");
		if (read_dn_attr(de->d_name, "aqmask", buf, sizeof(buf)) != 0)
			errx(EXIT_FAILURE,
			     "Could not fetch aqmask attribute from sysfs for zcrypt node '%s'",
			     de->d_name);
		for (i = n = 0; i < MAX_ZDEV_DOMAINS_EXT; i++)
			if (test_bit(i, buf))
				printf("%c%d", n++ == 0 ? tab : ',', i);
		putchar('\n');
		if (cmd == CMD_LISTCONFIG)
			printf(" ctrls =");
		else
			printf("  control domains:");
		if (read_dn_attr(de->d_name, "admask", buf, sizeof(buf)) != 0)
			errx(EXIT_FAILURE,
			     "Could not fetch admask attribute from sysfs for zcrypt node '%s'",
			     de->d_name);
		for (i = n = 0; i < MAX_ZDEV_DOMAINS_EXT; i++)
			if (test_bit(i, buf))
				printf("%c%d", n++ == 0 ? tab : ',', i);
		putchar('\n');
		if (cmd == CMD_LISTCONFIG)
			printf(" ioctls =");
		else
			printf("  ioctls:");
		if (read_dn_attr(de->d_name, "ioctlmask",
				 buf, sizeof(buf)) != 0)
			errx(EXIT_FAILURE,
			     "Could not fetch ioctlmask attribute from sysfs for zcrypt node '%s'",
			     de->d_name);
		for (i = n = 0; i < MAX_ZDEV_IOCTLS; i++) {
			if (test_bit(i, buf)) {
				p = value2ioctlstr(i);
				if (p)
					printf("%c%s",
					       n++ == 0 ? tab : ',', p);
				else
					printf("%c%d",
					       n++ == 0 ? tab : ',', i);
			}
		}
		putchar('\n');
		count++;
	}
	closedir(dir);

	if (count == 0)
		printf("No additional zcrypt device nodes defined\n");

	return 0;
}

static int cmd_create(int cmd _UNUSED_,
		      const char *nodename,
		      const char *arg _UNUSED_)
{
	int rc;
	const char *node;
	char buf[PATH_MAX];

	if (nodename) {
		node = strrchr(nodename, '/');
		node = node ? node + 1 : nodename;
		strncpy(buf, node, sizeof(buf) - 1);
	} else
		strncpy(buf, "\n", sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = 0;

	rc = write_dn_attr(NULL, "create", buf);
	if (rc != 0)
		errx(EXIT_FAILURE,
		     "Could not write into sysfs entry to create zdev node");

	printf("Device node created\n");

	return 0;
}

static int cmd_destroy(int cmd _UNUSED_,
		       const char *nodename,
		       const char *arg _UNUSED_)
{
	int rc;
	struct stat sb;
	const char *node;
	char pathname[PATH_MAX];

	node = strrchr(nodename, '/');
	node = node ? node + 1 : nodename;
	snprintf(pathname, sizeof(pathname), "/dev/%s", node);
	pathname[sizeof(pathname) - 1] = '\0';
	rc = stat(pathname, &sb);
	if (rc != 0)
		errx(EXIT_FAILURE,
		     "Could not check status for '%s'", pathname);
	if (!S_ISCHR(sb.st_mode))
		errx(EXIT_FAILURE,
		     "File '%s' is not a character device node", pathname);

	rc = write_dn_attr(NULL, "destroy", node);
	if (rc != 0)
		errx(EXIT_FAILURE,
		     "Could not write into sysfs entry to destroy zdev node '%s'",
		     node);

	printf("Device node '%s' marked for destruction\n", node);

	return 0;
}

static void add_del_ap(int cmd, const char *node, int ap)
{
	int rc;
	char buf[PATH_MAX];

	if (cmd == CMD_ADD_AP)
		sprintf(buf, "+%d", ap);
	else
		sprintf(buf, "-%d", ap);
	rc = write_dn_attr(node, "apmask", buf);
	if (rc != 0)
		errx(EXIT_FAILURE,
		     "Could not write into sysfs entry to %s adapter %d for zdev node '%s'",
		     cmd == CMD_ADD_AP ? "add" : "remove", ap, node);
}

static int cmd_add_del_ap(int cmd, const char *node, const char *arg)
{
	int ap, all = 0;

	if (strcasecmp(arg, "ALL") == 0) {
		all = 1;
	} else {
		if (sscanf(arg, "%i", &ap) != 1)
			errx(EXIT_FAILURE,
			     "Invalid adapter argument '%s'", arg);
		if (ap < 0 || ap >= MAX_ZDEV_CARDIDS_EXT)
			errx(EXIT_FAILURE,
			     "Adapter argument '%s' out of range [0..%d]",
			     arg, MAX_ZDEV_CARDIDS_EXT - 1);
	}

	if (!all) {
		add_del_ap(cmd, node, ap);
		printf("Adapter %d %s\n", ap,
		       (cmd == CMD_ADD_AP ? "added" : "removed"));
	} else {
		for (ap = 0; ap < MAX_ZDEV_CARDIDS_EXT; ap++)
			add_del_ap(cmd, node, ap);
		printf("All adapters %s\n",
		       (cmd == CMD_ADD_AP ? "added" : "removed"));
	}

	return 0;
}

static void add_del_dom(int cmd, const char *node, int dom)
{
	int rc;
	char buf[PATH_MAX];

	if (cmd == CMD_ADD_DOM)
		sprintf(buf, "+%d", dom);
	else
		sprintf(buf, "-%d", dom);
	rc = write_dn_attr(node, "aqmask", buf);
	if (rc != 0)
		errx(EXIT_FAILURE,
		     "Could not write into sysfs entry to %s domain %d for zdev node '%s'",
		     cmd == CMD_ADD_DOM ? "add" : "remove", dom, node);
}

static int cmd_add_del_dom(int cmd, const char *node, const char *arg)
{
	int dom, all = 0;

	if (strcasecmp(arg, "ALL") == 0) {
		all = 1;
	} else {
		if (sscanf(arg, "%i", &dom) != 1)
			errx(EXIT_FAILURE,
			     "Invalid domain argument '%s'", arg);
		if (dom < 0 || dom >= MAX_ZDEV_DOMAINS_EXT)
			errx(EXIT_FAILURE,
			     "Domain argument '%s' out of range [0..%d]",
			     arg, MAX_ZDEV_DOMAINS_EXT - 1);
	}

	if (!all) {
		add_del_dom(cmd, node, dom);
		printf("Domain %d %s\n", dom,
		       (cmd == CMD_ADD_DOM ? "added" : "removed"));
	} else {
		for (dom = 0; dom < MAX_ZDEV_DOMAINS_EXT; dom++)
			add_del_dom(cmd, node, dom);
		printf("All domains %s\n",
		       (cmd == CMD_ADD_DOM ? "added" : "removed"));
	}

	return 0;
}

static void add_del_ctrl(int cmd, const char *node, int dom)
{
	int rc;
	char buf[PATH_MAX];

	if (cmd == CMD_ADD_CTRL)
		sprintf(buf, "+%d", dom);
	else
		sprintf(buf, "-%d", dom);
	rc = write_dn_attr(node, "admask", buf);
	if (rc != 0)
		errx(EXIT_FAILURE,
		     "Could not write into sysfs entry to %s domain %d for zdev node '%s'",
		     cmd == CMD_ADD_CTRL ? "add" : "remove", dom, node);
}

static int cmd_add_del_ctrl(int cmd, const char *node, const char *arg)
{
	int dom, all = 0;

	if (strcasecmp(arg, "ALL") == 0) {
		all = 1;
	} else {
		if (sscanf(arg, "%i", &dom) != 1)
			errx(EXIT_FAILURE,
			     "Invalid domain argument '%s'", arg);
		if (dom < 0 || dom >= MAX_ZDEV_DOMAINS_EXT)
			errx(EXIT_FAILURE,
			     "Domain argument '%s' out of range [0..%d]",
			     arg, MAX_ZDEV_DOMAINS_EXT - 1);
	}

	if (!all) {
		add_del_ctrl(cmd, node, dom);
		printf("Control domain %d %s\n", dom,
		       (cmd == CMD_ADD_CTRL ? "added" : "removed"));
	} else {
		for (dom = 0; dom < MAX_ZDEV_DOMAINS_EXT; dom++)
			add_del_ctrl(cmd, node, dom);
		printf("All control domains %s\n",
		       (cmd == CMD_ADD_CTRL ? "added" : "removed"));
	}

	return 0;
}

static void add_del_ioctl(int cmd, const char *node, int ioctlnr)
{
	int rc;
	char buf[PATH_MAX];

	if (cmd == CMD_ADD_IOCTL)
		sprintf(buf, "+%d", ioctlnr);
	else
		sprintf(buf, "-%d", ioctlnr);
	rc = write_dn_attr(node, "ioctlmask", buf);
	if (rc != 0)
		errx(EXIT_FAILURE,
		     "Could not write into sysfs entry to %s ioctl %d for zdev node '%s'",
		     cmd == CMD_ADD_IOCTL ? "add" : "remove", ioctlnr, node);
}

static int cmd_add_del_ioctl(int cmd, const char *node, const char *arg)
{
	int ioctlnr, all = 0;

	if (strcasecmp(arg, "ALL") == 0) {
		all = 1;
	} else {
		ioctlnr = ioctlstr2value(arg);
		if (ioctlnr < 0)
			if (sscanf(arg, "%i", &ioctlnr) != 1)
				errx(EXIT_FAILURE,
				     "Invalid ioctl argument '%s'", arg);
		if (ioctlnr < 0 || ioctlnr >= MAX_ZDEV_IOCTLS)
			errx(EXIT_FAILURE,
			     "Ioctl argument '%s' out of range [0..%d]",
			     arg, MAX_ZDEV_IOCTLS - 1);
	}

	if (!all) {
		add_del_ioctl(cmd, node, ioctlnr);
		printf("Ioctl %s %s\n", arg,
		       (cmd == CMD_ADD_IOCTL ? "added" : "removed"));
	} else {
		for (ioctlnr = 0; ioctlnr < MAX_ZDEV_IOCTLS; ioctlnr++)
			add_del_ioctl(cmd, node, ioctlnr);
		printf("All Ioctls %s\n",
		       (cmd == CMD_ADD_IOCTL ? "added" : "removed"));
	}

	return 0;
}

static int _match_keyword(char **p, const char *keyword)
{
	int n = strlen(keyword);

	if (strncmp(*p, keyword, n) == 0) {
		*p += n;
		return n;
	}

	return 0;
}

static int _match_character(char **p, char c)
{
	char *q = *p;

	while (isblank(*q))
		q++;
	if (*q != c)
		return 0;
	q++;
	while (isblank(*q))
		q++;
	*p = q;

	return 1;
}

static int _match_string(char **p, char *buf)
{
	int n = 0;
	char *q = *p;

	while (isblank(*q))
		q++;
	while (*q && *q != ',' && !isspace(*q)) {
		buf[n++] = *q;
		q++;
	}
	while (isblank(*q))
		q++;

	if (n > 0) {
		buf[n] = '\0';
		*p = q;
	}

	return n;
}

static int cmd_config(int cmd _UNUSED_,
		      const char *nodename _UNUSED_,
		      const char *arg)
{
	ssize_t n;
	size_t linesize = 0;
	int nr = 0, havenode = 0;
	FILE *f = fopen(arg, "r");
	char *p, *line = NULL, node[128], buf[128];

	if (!f)
		errx(EXIT_FAILURE,
		     "Could not open file '%s'", arg);

	while ((n = getline(&line, &linesize, f)) != -1) {
		nr++;
		p = line;
		while (isspace(*p))
			p++;
		if (*p == '\0' || *p == '#')
			continue;
		if (_match_keyword(&p, "node")) {
			if (!_match_character(&p, '='))
				errx(EXIT_FAILURE,
				     "Missing '=' at '%-8.8s...' in line %d '%s'",
				     p, nr, line);
			if (!_match_string(&p, node))
				errx(EXIT_FAILURE,
				     "Missing node name at '%-8.8s...' in line %d '%s'",
				     p, nr, line);
			cmd_create(CMD_CREATE, node, NULL);
			havenode = 1;
		} else if (_match_keyword(&p, "aps")) {
			if (!havenode)
				errx(EXIT_FAILURE,
				     "Missing node=... before processing any aps=... statements in line %d '%s'",
				     nr, line);
			if (!_match_character(&p, '='))
				errx(EXIT_FAILURE,
				     "Missing '=' at '%-8.8s...' in line %d '%s'",
				     p, nr, line);
			while (1) {
				while (isspace(*p))
					p++;
				if (*p == '\0' || *p == '#')
					break;
				if (!_match_string(&p, buf))
					errx(EXIT_FAILURE,
					     "Missing argument(s) for aps=... at '%-8.8s...' in line %d '%s'",
					     p, nr, line);
				cmd_add_del_ap(CMD_ADD_AP, node, buf);
				while (isblank(*p) || *p == ',')
					p++;
			}
		} else if (_match_keyword(&p, "doms")) {
			if (!havenode)
				errx(EXIT_FAILURE,
				     "Missing node=... before processing any doms=... statements in line %d '%s'",
				     nr, line);
			if (!_match_character(&p, '='))
				errx(EXIT_FAILURE,
				     "Missing '=' at '%-8.8s...' in line %d '%s'",
				     p, nr, line);
			while (1) {
				while (isspace(*p))
					p++;
				if (*p == '\0' || *p == '#')
					break;
				if (!_match_string(&p, buf))
					errx(EXIT_FAILURE,
					     "Missing argument(s) for doms=... at '%-8.8s...' in line %d '%s'",
					     p, nr, line);
				cmd_add_del_dom(CMD_ADD_DOM, node, buf);
				while (isblank(*p) || *p == ',')
					p++;
			}
		} else if (_match_keyword(&p, "ctrls")) {
			if (!havenode)
				errx(EXIT_FAILURE,
				     "Missing node=... before processing any ctrls=... statements in line %d '%s'",
				     nr, line);
			if (!_match_character(&p, '='))
				errx(EXIT_FAILURE,
				     "Missing '=' at '%-8.8s...' in line %d '%s'",
				     p, nr, line);
			while (1) {
				while (isspace(*p))
					p++;
				if (*p == '\0' || *p == '#')
					break;
				if (!_match_string(&p, buf))
					errx(EXIT_FAILURE,
					     "Missing argument(s) for ctrls=... at '%-8.8s...' in line %d '%s'",
					     p, nr, line);
				cmd_add_del_ctrl(CMD_ADD_CTRL, node, buf);
				while (isblank(*p) || *p == ',')
					p++;
			}
		} else if (_match_keyword(&p, "ioctls")) {
			if (!havenode)
				errx(EXIT_FAILURE,
				     "Missing node=... before processing any ioctls=... statements in line %d '%s'",
				     nr, line);
			if (!_match_character(&p, '='))
				errx(EXIT_FAILURE,
				     "Missing '=' at '%-8.8s...' in line %d '%s'",
				     p, nr, line);
			while (1) {
				while (isspace(*p))
					p++;
				if (*p == '\0' || *p == '#')
					break;
				if (!_match_string(&p, buf))
					errx(EXIT_FAILURE,
					     "Missing argument(s) for aps=... at '%-8.8s...' in line %d '%s'",
					     p, nr, line);
				cmd_add_del_ioctl(CMD_ADD_IOCTL, node, buf);
				while (isblank(*p) || *p == ',')
					p++;
			}
		} else
			errx(EXIT_FAILURE,
			     "Unknown keyword '%-8.8s...' in line %d '%s'",
			     p, nr, line);
	}

	free(line);
	fclose(f);

	return 0;
}

static struct zcryptctl_cmds_s {
	int cmd;
	const char *usage;
	const char *command;
	const char *description;
	int (*function)(int cmd, const char *node, const char *arg);
} zcryptctl_cmds[] = {
	{
		.cmd = CMD_LIST,
		.command = "list",
		.function = cmd_list,
		.usage = "zcryptctl list",
		.description =
		"List all currently known additional zcrypt device nodes.",
	},
	{
		.cmd = CMD_CREATE,
		.command = "create",
		.function = cmd_create,
		.usage = "zcryptctl create [nodename]",
		.description =
		"Create a new zcrypt device node.\n"
		"The node-name might be given and needs to be unique and not\n"
		"in use. If there is no node name provided, the zcrypt device\n"
		"driver will create a new one with pattern zcrypt_<x>\n"
		"with <x> being the next free number. By default all\n"
		"adapters, domains and ioctls are initially disabled on this\n"
		"new device node."
	},
	{
		.cmd = CMD_DESTROY,
		.command = "destroy",
		.function = cmd_destroy,
		.usage = "zcryptctl destroy <nodename>",
		.description =
		"Destroy an additional zcrypt device node.\n"
		"Mark the given zcrypt device node as disposable. The removal\n"
		"will take place when it is no longer used.",
	},
	{
		.cmd = CMD_ADD_AP,
		.command = "addap",
		.function = cmd_add_del_ap,
		.usage = "zcryptctl addap <adapter>",
		.description =
		"Update the filter for the specified zcrypt device node and\n"
		"add an crypto adapter to be accessible via this node. The\n"
		"adapter argument may be a number in the range 0-255 or the\n"
		"symbol ALL.",
	},
	{
		.cmd = CMD_DEL_AP,
		.command = "delap",
		.function = cmd_add_del_ap,
		.usage = "zcryptctl delap <adapter>",
		.description =
		"Update the filter for the specified zcrypt device node and\n"
		"remove a crypto adapter from the allowed adapters list. The\n"
		"adapter argument may be a number in the range 0-255 or the\n"
		"symbol ALL.",
	},
	{
		.cmd = CMD_ADD_DOM,
		.command = "adddom",
		.function = cmd_add_del_dom,
		.usage = "zcryptctl adddom <domain>",
		.description =
		"Update the filter for the specified zcrypt device node and\n"
		"add a crypto domain to be accessible via this node. The\n"
		"domain argument may be a number in the range 0-255 or the\n"
		"symbol ALL.",
	},
	{
		.cmd = CMD_DEL_DOM,
		.command = "deldom",
		.function = cmd_add_del_dom,
		.usage = "zcryptctl deldom <domain>",
		.description =
		"Update the filter for the specified zcrypt device node and\n"
		"remove a crypto domain from the allowed domains list. The\n"
		"domain argument may be a number in the range 0-255 or the\n"
		"symbol ALL.",
	},
	{
		.cmd = CMD_ADD_CTRL,
		.command = "addctrl",
		.function = cmd_add_del_ctrl,
		.usage = "zcryptctl addctrl <domain>",
		.description =
		"Update the filter for the specified zcrypt device node and\n"
		"add a crypto control domain to be accessible via this node.\n"
		"The domain argument may be a number in the range 0-255 or\n"
		"the symbol ALL.",
	},
	{
		.cmd = CMD_DEL_CTRL,
		.command = "delctrl",
		.function = cmd_add_del_ctrl,
		.usage = "zcryptctl delctrl <domain>",
		.description =
		"Update the filter for the specified zcrypt device node and\n"
		"remove a crypto control domain from the allowed domains list.\n"
		"The domain argument may be a number in the range 0-255 or\n"
		"the symbol ALL.",
	},
	{
		.cmd = CMD_ADD_IOCTL,
		.command = "addioctl",
		.function = cmd_add_del_ioctl,
		.usage = "zcryptctl addioctl <ioctlexp>",
		.description =
		"Update the filter for the specified zcrypt device node and\n"
		"add an ioctl number to be accessible via this node. The\n"
		"ioctlexp argument may be one of symbols ICARSAMODEXPO,\n"
		"ICARSACRT, ZSECSENDCPRB, ZSENDEP11CPRB, ZCRYPT_DEVICE_STATUS\n"
		"ZCRYPT_STATUS_MASK, ZCRYPT_QDEPTH_MASK, ZCRYPT_PERDEV_REQCNT\n"
		"or a number in the range 0-255 or the symbol ALL.",
	},
	{
		.cmd = CMD_DEL_IOCTL,
		.command = "delioctl",
		.function = cmd_add_del_ioctl,
		.usage = "zcryptctl delioctl <ioctlexp>",
		.description =
		"Update the filter for the specified zcrypt device node and\n"
		"remove an ioctl number from the allowed ioctls list. The\n"
		"ioctlexp argument may be one of symbols ICARSAMODEXPO,\n"
		"ICARSACRT, ZSECSENDCPRB, ZSENDEP11CPRB, ZCRYPT_DEVICE_STATUS\n"
		"ZCRYPT_STATUS_MASK, ZCRYPT_QDEPTH_MASK, ZCRYPT_PERDEV_REQCNT\n"
		"or a number in the range 0-255 or the symbol ALL.",
	},
	{
		.cmd = CMD_CONFIG,
		.command = "config",
		.function = cmd_config,
		.usage = "zcryptctl config <configfile>",
		.description =
		"Process a config file. The given config file is read line by\n"
		"line and the settings are applied. Syntax is simple:\n"
		"  node=<node_name>\n"
		"  aps=<list of ap numbers separated by space, tab or ','>\n"
		"  doms=<list of domains separated by space, tab or ','>\n"
		"  ioctls=<list of ioctl as number or symbolic number\n"
		"          separated by space, tab or ','>\n"
		"Empty lines are ignored and the '#' marks the rest of the\n"
		"line as comment.\n"
		"The node= line creates a new zcrypt device node, the\n"
		"aps=, doms= and ioctls= lines customize the previously\n"
		"created node. The symbol ALL is also recognized for aps,\n"
		"doms, and ioctls.\n"
		"Each action must fit into one line, spreading over multiple\n"
		"lines is not supported. But you can use more than one\n"
		"aps=, doms= and ioctls= lines to customize the very same\n"
		"node.\n"
		"Processing stops when a line cannot be parsed or the\n"
		"current action fails. When the config file has been\n"
		"processed successful, the zcryptctl return code is 0. A non\n"
		"zero return code (and some kind of failure message) is\n"
		"emitted on partial completion.",
	},
	{
		.cmd = CMD_LISTCONFIG,
		.command = "listconfig",
		.function = cmd_list,
		.usage = "zcryptctl listconfig",
		.description =
		"List all currently known additional zcrypt device nodes\n"
		"in a format suitable for the 'config' command.",
	},
	{
		.command = NULL,
		.cmd = 0,
	}
};

static int get_command_index(const char *cmdstr)
{
	int i;

	for (i = 0; zcryptctl_cmds[i].command; i++)
		if (!strcmp(zcryptctl_cmds[i].command, cmdstr))
			return i;

	return -1;
}

static void commands_print_help(void)
{
	int i;

	for (i = 0; zcryptctl_cmds[i].command; i++)
		if (zcryptctl_cmds[i].usage)
			printf(" %s\n", zcryptctl_cmds[i].usage);
}

int main(int argc, char *argv[])
{
	int c, cmdindex = -1;
	int rc = EXIT_SUCCESS;

	util_prg_init(&prg);
	util_opt_init(opt_vec, NULL);

	for (c = 1; c < argc; c++) {
		cmdindex = get_command_index(argv[c]);
		if (cmdindex >= 0)
			break;
	}

	while (1) {
		c = util_opt_getopt_long(argc, argv);
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			if (cmdindex < 0) {
				util_prg_print_help();
				commands_print_help();
				util_opt_print_help();
			} else {
				printf("Usage: %s\n",
				       zcryptctl_cmds[cmdindex].usage);
				printf("%s\n",
				       zcryptctl_cmds[cmdindex].description);
			}
			return EXIT_SUCCESS;
		case 'v':
			util_prg_print_version();
			return EXIT_SUCCESS;
		default:
			util_opt_print_parse_error(c, argv);
			return EXIT_FAILURE;
		}
	}

	if (cmdindex < 0)
		errx(EXIT_FAILURE, "Missing or invalid command argument");

	if (check_zcrypt_class_dir() != 0)
		errx(EXIT_FAILURE,
		     "Directory class/%s is missing in sysfs.\n"
		     "Multiple zcrypt node support is not available",
		     ZCRYPT_NAME);

	c = zcryptctl_cmds[cmdindex].cmd;
	switch (c) {
	case CMD_LIST:
	case CMD_LISTCONFIG:
		rc = zcryptctl_cmds[cmdindex].function(c, NULL, NULL);
		break;
	case CMD_CREATE:
		rc = zcryptctl_cmds[cmdindex].function(c,
						       optind + 1 < argc ?
						       argv[optind + 1] : NULL,
						       NULL);
		break;
	case CMD_DESTROY:
		if (optind + 1 >= argc)
			errx(EXIT_FAILURE, "Missing node name argument");
		if (check_nodename(argv[optind + 1]) != 0)
			errx(EXIT_FAILURE, "Invalid or unknown nodename '%s'",
			     argv[optind + 1]);
		rc = zcryptctl_cmds[cmdindex].function(c,
						       argv[optind + 1], NULL);
		break;
	case CMD_ADD_AP:
	case CMD_DEL_AP:
		if (optind + 1 >= argc)
			errx(EXIT_FAILURE, "Missing node name argument");
		if (optind + 2 >= argc)
			errx(EXIT_FAILURE, "Missing adapter argument");
		if (check_nodename(argv[optind + 1]) != 0)
			errx(EXIT_FAILURE, "Invalid or unknown nodename '%s'",
			     argv[optind + 1]);
		rc = zcryptctl_cmds[cmdindex].function(c,
						       argv[optind + 1],
						       argv[optind + 2]);
		break;
	case CMD_ADD_DOM:
	case CMD_DEL_DOM:
		if (optind + 1 >= argc)
			errx(EXIT_FAILURE, "Missing node name argument");
		if (optind + 2 >= argc)
			errx(EXIT_FAILURE, "Missing domain argument");
		if (check_nodename(argv[optind + 1]) != 0)
			errx(EXIT_FAILURE, "Invalid or unknown nodename '%s'",
			     argv[optind + 1]);
		rc = zcryptctl_cmds[cmdindex].function(c,
						       argv[optind + 1],
						       argv[optind + 2]);
		break;
	case CMD_ADD_CTRL:
	case CMD_DEL_CTRL:
		if (optind + 1 >= argc)
			errx(EXIT_FAILURE, "Missing node name argument");
		if (optind + 2 >= argc)
			errx(EXIT_FAILURE, "Missing domain argument");
		if (check_nodename(argv[optind + 1]) != 0)
			errx(EXIT_FAILURE, "Invalid or unknown nodename '%s'",
			     argv[optind + 1]);
		rc = zcryptctl_cmds[cmdindex].function(c,
						       argv[optind + 1],
						       argv[optind + 2]);
		break;
	case CMD_ADD_IOCTL:
	case CMD_DEL_IOCTL:
		if (optind + 1 >= argc)
			errx(EXIT_FAILURE, "Missing node name argument");
		if (optind + 2 >= argc)
			errx(EXIT_FAILURE, "Missing ioctl argument");
		if (check_nodename(argv[optind + 1]) != 0)
			errx(EXIT_FAILURE, "Invalid or unknown nodename '%s'",
			     argv[optind + 1]);
		rc = zcryptctl_cmds[cmdindex].function(c,
						       argv[optind + 1],
						       argv[optind + 2]);
		break;
	case CMD_CONFIG:
		if (optind + 1 >= argc)
			errx(EXIT_FAILURE, "Missing filename argument");
		rc = zcryptctl_cmds[cmdindex].function(c, NULL,
						       argv[optind + 1]);
		break;
	default:
		errx(EXIT_FAILURE, "Unknown command %d", c);
	}

	return rc;
}
