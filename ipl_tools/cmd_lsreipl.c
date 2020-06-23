/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * Command: lsreipl
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "ipl_tools.h"

static struct {
	int	ipl_set;		/* --ipl has been specified */
} l;

static const char *const usage_lsreipl =
"Usage: %s [OPTIONS]\n"
"\n"
"Show re-IPL or IPL settings.\n"
"\n"
"OPTIONS:\n"
"  -i, --ipl            Print the IPL setting\n"
"  -h, --help           Print this help, then exit\n"
"  -v, --version        Print version information, then exit\n";

static void __noreturn print_usage_lsreipl_exit(void)
{
	printf(usage_lsreipl, g.prog_name);
	exit(0);
}

static const char *get_ipl_banner(int show_ipl)
{
	if (show_ipl)
		return "IPL type:";
	else
		return "Re-IPL type:";
}

void print_nss(int show_ipl)
{
	char *dir = show_ipl ? "ipl" : "reipl/nss";
	char *path_bootparms = show_ipl ? "/sys/firmware/ipl/parm" :
		"/sys/firmware/reipl/nss/parm";

	printf("%-12s nss\n", get_ipl_banner(show_ipl));
	print_fw_str("Name:        %s\n", dir, "name");
	if (access(path_bootparms, R_OK) == 0)
		print_fw_str("Bootparms:   \"%s\"\n", dir, "parm");
}

void print_fcp(int show_ipl, int dump)
{
	char *dir = show_ipl ? "ipl" : "reipl/fcp";
	char *path_bootparms = show_ipl ? "/sys/firmware/ipl/scp_data" :
		"/sys/firmware/reipl/fcp/scp_data";
	char *path_loadparm = show_ipl ? "/sys/firmware/ipl/loadparm" :
		"/sys/firmware/reipl/fcp/loadparm";
	char loadparm[9], loadparm_path[PATH_MAX];
	char *path_reipl_clear = "/sys/firmware/reipl/fcp/clear";

	if (dump)
		printf("%-12s fcp_dump\n", get_ipl_banner(show_ipl));
	else
		printf("%-12s fcp\n", get_ipl_banner(show_ipl));

	print_fw_str("WWPN:        %s\n", dir, "wwpn");
	print_fw_str("LUN:         %s\n", dir, "lun");
	print_fw_str("Device:      %s\n", dir, "device");
	print_fw_str("bootprog:    %s\n", dir, "bootprog");
	print_fw_str("br_lba:      %s\n", dir, "br_lba");
	if (access(path_loadparm, R_OK) == 0) {
		sprintf(loadparm_path, "%s/%s", dir, "loadparm");
		read_fw_str(loadparm, loadparm_path, sizeof(loadparm));
		if (strcmp(loadparm, "        ") == 0)
			loadparm[0] = 0;
		printf("Loadparm:    \"%s\"\n", loadparm);
	}
	if (access(path_bootparms, R_OK) == 0)
		print_fw_str("Bootparms:   \"%s\"\n", dir, "scp_data");
	if (!show_ipl && access(path_reipl_clear, R_OK) == 0)
		print_fw_str("clear:       %s\n", dir, "clear");
}

void print_nvme(int show_ipl, int dump)
{
	char *dir = show_ipl ? "ipl" : "reipl/nvme";
	char *path_bootparms = show_ipl ? "/sys/firmware/ipl/scp_data" :
		"/sys/firmware/reipl/nvme/scp_data";
	char *path_loadparm = show_ipl ? "/sys/firmware/ipl/loadparm" :
		"/sys/firmware/reipl/nvme/loadparm";
	char loadparm[9], loadparm_path[PATH_MAX];
	char *path_reipl_clear = "/sys/firmware/reipl/nvme/clear";

	if (dump)
		printf("%-12s nvme_dump\n", get_ipl_banner(show_ipl));
	else
		printf("%-12s nvme\n", get_ipl_banner(show_ipl));

	print_fw_str("FID:         %s\n", dir, "fid");
	print_fw_str("NSID:        %s\n", dir, "nsid");
	print_fw_str("bootprog:    %s\n", dir, "bootprog");
	print_fw_str("br_lba:      %s\n", dir, "br_lba");
	if (access(path_loadparm, R_OK) == 0) {
		sprintf(loadparm_path, "%s/%s", dir, "loadparm");
		read_fw_str(loadparm, loadparm_path, sizeof(loadparm));
		if (strcmp(loadparm, "        ") == 0)
			loadparm[0] = 0;
		printf("Loadparm:    \"%s\"\n", loadparm);
	}
	if (access(path_bootparms, R_OK) == 0)
		print_fw_str("Bootparms:   \"%s\"\n", dir, "scp_data");
	if (!show_ipl && access(path_reipl_clear, R_OK) == 0)
		print_fw_str("clear:       %s\n", dir, "clear");
}

void print_ccw(int show_ipl)
{
	char loadparm[9], loadparm_path[PATH_MAX];
	char *dir = show_ipl ? "ipl" : "reipl/ccw";
	char *path_loadparm = show_ipl ? "/sys/firmware/ipl/loadparm" :
		"/sys/firmware/reipl/ccw/loadparm";
	char *path_bootparms = show_ipl ? "/sys/firmware/ipl/parm" :
		"/sys/firmware/reipl/ccw/parm";
	char *path_reipl_clear = "/sys/firmware/reipl/ccw/clear";

	printf("%-12s ccw\n", get_ipl_banner(show_ipl));
	print_fw_str("Device:      %s\n", dir, "device");
	if (access(path_loadparm, R_OK) == 0) {
		sprintf(loadparm_path, "%s/%s", dir, "loadparm");
		read_fw_str(loadparm, loadparm_path, sizeof(loadparm));
		if (strcmp(loadparm, "        ") == 0)
			loadparm[0] = 0;
		printf("Loadparm:    \"%s\"\n", loadparm);
	}
	if (access(path_bootparms, R_OK) == 0)
		print_fw_str("Bootparms:   \"%s\"\n", dir, "parm");
	if (!show_ipl && access(path_reipl_clear, R_OK) == 0)
		print_fw_str("clear:       %s\n", dir, "clear");
}

static void parse_lsreipl_options(int argc, char *argv[])
{
	int opt, idx;
	const struct option long_opts[] = {
		{ "help",	 no_argument,		NULL, 'h' },
		{ "ipl",	 no_argument,		NULL, 'i' },
		{ "version",	 no_argument,		NULL, 'v' },
		{ NULL,		 0,			NULL,  0  }
	};

	while ((opt = getopt_long(argc, argv, "hvi", long_opts, &idx)) != -1) {
		switch (opt) {
		case 'i':
			l.ipl_set = 1;
			break;
		case 'h':
			print_usage_lsreipl_exit();
		case 'v':
			print_version_exit();
		default:
			print_help_hint_exit();
		}
	}
	/* don't run with too many arguments */
	if (optind != argc)
		ERR_EXIT("Invalid positional parameter \"%s\" specified",
			 argv[optind]);
}

void cmd_lsreipl(int argc, char *argv[])
{
	char reipl_type_str[1024];

	parse_lsreipl_options(argc, argv);

	if (l.ipl_set)
		read_fw_str(reipl_type_str, "ipl/ipl_type",
			    sizeof(reipl_type_str));
	else
		read_fw_str(reipl_type_str, "reipl/reipl_type",
			    sizeof(reipl_type_str));

	if (strcmp(reipl_type_str, "fcp") == 0)
		print_fcp(l.ipl_set, 0);
	else if (strcmp(reipl_type_str, "fcp_dump") == 0)
		print_fcp(l.ipl_set, 1);
	else if (strcmp(reipl_type_str, "nvme") == 0)
		print_nvme(l.ipl_set, 0);
	else if (strcmp(reipl_type_str, "nvme_dump") == 0)
		print_nvme(l.ipl_set, 1);
	else if (strcmp(reipl_type_str, "ccw") == 0)
		print_ccw(l.ipl_set);
	else if (strcmp(reipl_type_str, "nss") == 0)
		print_nss(l.ipl_set);
	else
		printf("%s: %s (unknown)\n", get_ipl_banner(l.ipl_set),
		       reipl_type_str);
	exit(0);
}
