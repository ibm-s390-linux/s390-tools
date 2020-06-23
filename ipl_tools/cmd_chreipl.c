/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * Command: chreipl
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */


#include <ctype.h>
#include <sys/sysmacros.h>

#include "lib/util_libc.h"
#include "lib/zt_common.h"

#include "ipl_tools.h"
#include "proc.h"

#define BOOTPARMS_NSS_MAX	56
#define BOOTPARMS_CCW_MAX	64
#define BOOTPARMS_FCP_MAX	3452

enum target_type {
	TT_CCW,
	TT_FCP,
	TT_NSS,
	TT_NODE,
	TT_NVME,
};

enum reipl_type {
	REIPL_FCP,
	REIPL_CCW,
	REIPL_NSS,
	REIPL_NVME,
};

static const char *const usage_chreipl =
"Usage: %s [TARGET] [ARGS] [OPTIONS]\n"
"\n"
" chreipl [ccw] [-d] <DEVICE> [OPTIONS]\n"
" chreipl [fcp] [-d] <DEVICE> [-w] <WWPN> [-l] <LUN> [OPTIONS]\n"
" chreipl nvme  [-i] <FID> [-s] <NSID> [OPTIONS]\n"
" chreipl [node] <NODE|DIR> [OPTIONS]\n"
" chreipl nss [-n] <NAME> [OPTIONS]\n"
" chreipl [-h] [-v]\n"
"\n"
"The following re-IPL targets are supported:\n"
"  ccw      IPL from CCW device\n"
"  fcp      IPL from FCP device\n"
"  nvme     IPL from NVME device\n"
"  nss      IPL from NSS\n"
"  node     IPL from device specified by device node or directory\n"
"\n"
"General options:\n"
"  -f, --force             Allow targets that cannot be verified by the system\n"
"  -p, --bootparms <PARMS> Boot parameter specification\n"
"  -h, --help              Print this help, then exit\n"
"  -v, --version           Print version information, then exit\n"
"\n"
"Options for ccw target:\n"
"  -d, --device <DEVICE>   Device number of the CCW IPL device\n"
"  -L, --loadparm <PARM>   Loadparm specification\n"
"  -c, --clear 0|1         Control if memory is cleared on re-IPL\n"
"\n"
"Options for fcp target:\n"
"  -d, --device <DEVICE>   Device number of the adapter of the FCP IPL device\n"
"  -l  --lun <LUN>         Logical unit number of the FCP IPL device\n"
"  -w  --wwpn <WWPN>       World Wide Port Name of the FCP IPL device\n"
"  -b, --bootprog <BPROG>  Bootprog specification\n"
"  -L, --loadparm <PARM>   Loadparm specification\n"
"  -c, --clear 0|1         Control if memory is cleared on re-IPL\n"
"\n"
"Options for nvme target:\n"
"  -i, --fid <FUNCTION_ID>   PCI Function ID of NVME IPL device (hex)\n"
"  -s  --nsid <NAMESPACE_ID> Namespace ID of NVME IPL device (decimal, default 1)\n"
"  -b, --bootprog <BPROG>    Bootprog specification\n"
"  -L, --loadparm <PARM>     Loadparm specification\n"
"  -c, --clear 0|1         Control if memory is cleared on re-IPL\n"
"\n"
"Options for nss target:\n"
"  -n, --name <NAME>       Identifier of the NSS\n"
"\n"
"Options for node target:\n"
"  Depending on underlying target type (ccw or fcp)\n";

static struct locals {
	char			loadparm[9];	/* Entry in the boot menu */
	int			loadparm_set;
	char			bootprog[11];	/* bootprog number (32 bit)*/
	int			bootprog_set;
	char			wwpn[20];	/* 18 character +0x" */
	int			wwpn_set;
	char			lun[20];	/* 18 character +0x" */
	int			lun_set;
	char			busid[10];	/* Bus ID e.g. 0.0.4711 */
	int			fid_set;
	char			fid[FID_MAX_LEN];
	int			nsid_set;
	char			nsid[11];	/* 10 decimal chars + null */
	int			busid_set;
	char			dev[15];	/* Device (e.g. dasda) */
	int			dev_set;
	char			nss_name[9];	/* NSS name */
	int			nss_name_set;
	char			bootparms[4096];
	int			bootparms_set;
	int			force_set;
	enum target_type	target_type;	/* CCW,FCP,NVME,NSS or NODE */
	int			target_type_set;
	int			target_type_auto_mode;
	enum reipl_type		reipl_type;	/* CCW, FCP, NVME, NSS */
	int			reipl_clear;
} l;

static void __noreturn print_usage_chreipl_exit(void)
{
	printf(usage_chreipl, g.prog_name);
	exit(0);
}

static int busid_strtok(char *str, unsigned long max_len, unsigned long *val)
{
	char *token, *end;

	token = strtok(str, ".");
	if (!token)
		return -1;
	if (strlen(token) > max_len)
		return -1;
	*val = strtoul(token, &end, 16);
	if (*end)
		return -1;
	return 0;
}

static int mk_busid(char busid_out[9], const char *busid_in)
{
	unsigned long devno, cssid = 0, ssid = 0;
	char busid_tmp[10];

	if (strlen(busid_in) > 9)
		return -1;
	strcpy(busid_tmp, busid_in);
	if (strstr(busid_in, ".")) {
		/* Check xx.x.xxxx full bus-ID format */
		if (busid_strtok(busid_tmp, 2, &cssid))
			return -1;
		if (busid_strtok(NULL, 1, &ssid))
			return -1;
		if (busid_strtok(NULL, 4, &devno))
			return -1;
		/* Ensure that there are no more additional fields */
		if (strtok(NULL, "."))
			return -1;
	} else {
		/* Check xxxx short bus-ID format */
		if (busid_strtok(busid_tmp, 4, &devno))
			return -1;
	}
	sprintf(busid_out, "%lx.%lx.%04lx", cssid, ssid, devno);
	return 0;
}

static void set_device(const char *busid)
{
	if (mk_busid(l.busid, busid))
		ERR_EXIT("Invalid device number \"%s\" specified", busid);
	l.busid_set = 1;
}

static void set_nss_name(const char *nss_name)
{
	if (strlen(nss_name) > 8)
		ERR_EXIT("NSS name \"%s\" exceeds maximum of 8 characters",
			 nss_name);
	strcpy(l.nss_name, nss_name);
	l.nss_name_set = 1;
}

static void set_loadparm(const char *loadparm)
{
	if (strlen(loadparm) > 8)
		ERR_EXIT("Loadparm \"%s\" exceeds 8 characters", loadparm);
	strcpy(l.loadparm, loadparm);
	if (strcmp(l.loadparm, " ") == 0)
		l.loadparm[0] = '\0';
	l.loadparm_set = 1;
}

static void set_bootprog(const char *bootprog)
{
	long long bootprog_int;
	char *endptr;

	bootprog_int = strtoll(bootprog, &endptr, 10);
	if (*endptr)
		ERR_EXIT("Bootprog \"%s\" is not a decimal number", bootprog);
	if (bootprog_int > UINT_MAX)
		ERR_EXIT("Invalid bootprog specified");
	util_strlcpy(l.bootprog, bootprog, sizeof(l.bootprog));
	l.bootprog_set = 1;
}

static void set_bootparms(const char *bootparms)
{
	unsigned int i;

	for (i = 0; i < strlen(bootparms); i++) {
		if (isascii(bootparms[i]))
			continue;
		ERR_EXIT("Non ASCII characters found in boot parameters");
	}
	if (strlen(bootparms) + 1 > sizeof(l.bootparms))
		ERR_EXIT("Boot parameter line is too long");
	strcpy(l.bootparms, bootparms);
	l.bootparms_set = 1;
}

static void set_lun(const char *lun)
{
	unsigned long long lun_tmp;
	char *endptr;

	lun_tmp = strtoull(lun, &endptr, 16);
	if (*endptr)
		ERR_EXIT("LUN \"%s\" is not a hexadecimal number", lun);
	snprintf(l.lun, sizeof(l.lun), "0x%016llx", lun_tmp);
	l.lun_set = 1;
}

static void set_wwpn(const char *wwpn)
{
	unsigned long long wwpn_tmp;
	char *endptr;

	wwpn_tmp = strtoull(wwpn, &endptr, 16);
	if (*endptr)
		ERR_EXIT("WWPN \"%s\" is not a hexadecimal number", wwpn);
	snprintf(l.wwpn, sizeof(l.wwpn), "0x%016llx", wwpn_tmp);
	l.wwpn_set = 1;
}

static void set_nvme_nsid(const char *nsid)
{
	unsigned long long nsid_tmp;
	char *endptr;

	nsid_tmp = strtoull(nsid, &endptr, 10);
	if (*endptr)
		ERR_EXIT("NSID \"%s\" is not a decimal number", nsid);
	snprintf(l.nsid, sizeof(l.nsid), "%08llu", nsid_tmp);
	l.nsid_set = 1;
}

static void set_nvme_fid(const char *fid)
{
	unsigned long long fid_tmp;
	char *endptr;

	fid_tmp = strtoull(fid, &endptr, 16);
	if (*endptr)
		ERR_EXIT("FID \"%s\" is not a hexadecimal number", fid);
	snprintf(l.fid, sizeof(l.fid), "0x%08llx", fid_tmp);
	l.fid_set = 1;

	/* nsid defaults to 1, if not already set */
	if (!l.nsid_set)
		set_nvme_nsid("1");
}

static void parse_fcp_args(char *nargv[], int nargc)
{
	/*
	 * we might be called like this:
	 * chreipl fcp 4711 0x12345... 0x12345...
	 */
	if (l.busid_set || l.wwpn_set || l.lun_set)
		ERR_EXIT("Use either options or positional parameters");
	if (nargc > 3)
		ERR_EXIT("Too many arguments specified for \"fcp\" re-IPL "
			 "type");
	else if (nargc != 3)
		ERR_EXIT("The \"fcp\" re-IPL type requires device, WWPN, "
			 "and LUN");
	set_device(nargv[0]);
	set_wwpn(nargv[1]);
	set_lun(nargv[2]);
}

static void parse_nvme_args(char *nargv[], int nargc)
{
	/*
	 * we might be called like this:
	 * chreipl nvme 0x13 1
	 */
	if (l.busid_set || l.fid_set || l.nsid_set || l.dev_set)
		ERR_EXIT("Use either options or positional parameters");
	if (nargc > 2)
		ERR_EXIT("Too many arguments specified for \"nvme\" re-IPL "
			 "type");
	else if (nargc < 1)
		ERR_EXIT("The \"nvme\" re-IPL type requires function id, and "
			 "optional namespace id");
	set_nvme_fid(nargv[0]);

	if (nargc == 2)
		set_nvme_nsid(nargv[1]);
	else
		set_nvme_nsid("1");
}

static void parse_ccw_args(char *nargv[], int nargc)
{
	/*
	 * we might be called like this:
	 * chreipl ccw 4711
	 */
	if (l.busid_set)
		ERR_EXIT("Use either options or positional parameters");
	if (nargc == 0)
		ERR_EXIT("The \"ccw\" re-IPL type requires device");
	else if (nargc > 1)
		ERR_EXIT("Too many arguments specified for \"ccw\" re-IPL "
			 "type");
	set_device(nargv[0]);
}

static void parse_nss_args(char *nargv[], int nargc)
{
	/*
	 * we might be called like this:
	 * chreipl nss lnxnss
	 */
	if (l.nss_name_set)
		ERR_EXIT("Use either options or positional parameters");
	if (nargc == 0)
		ERR_EXIT("A NSS name must be specified");
	if (nargc > 1)
		ERR_EXIT("Too many arguments specified for \"nss\" re-IPL "
			 "type");
	set_nss_name(nargv[0]);
}

static void dev_from_part(char *dev_name)
{
	int i;

	for (i = strlen(dev_name) - 1; isdigit(dev_name[i]); i--)
		dev_name[i] = 0;
}

static void dev_from_part_nvme(char *dev_name)
{
	char *delim = strrchr(dev_name, 'p');
	if (delim)
		*delim = 0;
}

static int set_reipl_type(const char *dev_name)
{
	if (strncmp(dev_name, "dasd", strlen("dasd")) == 0 ||
	    strncmp(dev_name, "vd", strlen("vd")) == 0)
		l.reipl_type = REIPL_CCW;
	else if (strncmp(dev_name, "sd", strlen("sd")) == 0)
		l.reipl_type = REIPL_FCP;
	else if (strncmp(dev_name, "nvme", strlen("nvme")) == 0)
		l.reipl_type = REIPL_NVME;
	else
		return -1;

	util_strlcpy(l.dev, dev_name, sizeof(l.dev));

	if (l.reipl_type == REIPL_NVME)
		dev_from_part_nvme(l.dev);
	else
		dev_from_part(l.dev);

	l.dev_set = 1;
	return 0;
}

static int get_chreipl_helper_cmd(dev_t dev, char cmd[PATH_MAX])
{
	char *chreipl_helper;
	struct proc_dev_entry pde;

	if (proc_dev_get_entry(dev, 1, &pde) != 0)
		return -1;
	util_asprintf(&chreipl_helper,
		      "%s/%s.%s", TOOLS_LIBDIR, "chreipl_helper", pde.name);
	if (access(chreipl_helper, X_OK) != 0) {
		proc_dev_free_entry(&pde);
		free(chreipl_helper);
		return -1;
	}
	sprintf(cmd, "%s %d:%d", chreipl_helper, major(dev), minor(dev));
	proc_dev_free_entry(&pde);
	free(chreipl_helper);
	return 0;
}

/*
 * Use chreipl_helper (E.g. for device mapper devices)
 */
static int set_reipl_type_helper(int maj, int min)
{
	char helper_cmd[PATH_MAX], buf[4096];
	struct proc_part_entry ppe;
	int rc = -1;
	dev_t dev;
	FILE *fh;

	if (get_chreipl_helper_cmd(makedev(maj, min), helper_cmd) != 0)
		return -1;
	fh = popen(helper_cmd, "r");
	if (fh == NULL)
		ERR_EXIT_ERRNO("Could not start chreipl_helper");
	if (fread(buf, 1, sizeof(buf), fh) == 0)
		ERR_EXIT_ERRNO("Could not read from chreipl_helper");

	if (sscanf(buf, "%d:%d", &maj, &min) != 2)
		goto fail_pclose;
	dev = makedev(maj, min);
	if (proc_part_get_entry(dev, &ppe) != 0)
		goto fail_pclose;
	if (set_reipl_type(ppe.name))
		goto fail_part_free;
	rc = 0;
fail_part_free:
	proc_part_free_entry(&ppe);
fail_pclose:
	pclose(fh);
	return rc;
}

static void get_dev_by_path(const char *path, dev_t *dev)
{
	struct stat sb;

	if (stat(path, &sb) != 0)
		ERR_EXIT_ERRNO("Could not access device node \"%s\"", path);
	if (S_ISDIR(sb.st_mode))
		*dev = sb.st_dev;
	else if (S_ISBLK(sb.st_mode))
		*dev = sb.st_rdev;
	else
		ERR_EXIT("Only block device nodes or directories are valid for"
			 " \"node\" target");
}

static void parse_node_args(char *nargv[], int nargc)
{
	struct proc_part_entry ppe;
	char *path = nargv[0];
	dev_t dev;

	if (nargc == 0)
		ERR_EXIT("No device node specified");
	if (l.busid_set || l.wwpn_set || l.lun_set)
		ERR_EXIT("Do not use device, WWPN, or LUN for \"node\" target");

	get_dev_by_path(path, &dev);
	if (proc_part_get_entry(dev, &ppe) != 0)
		ERR_EXIT("Invalid device node \"%s\" specified", path);
	if (set_reipl_type(ppe.name) == 0)
		goto out;
	if (set_reipl_type_helper(major(dev), minor(dev)) == 0)
		goto out;
	ERR_EXIT("Unsupported device node \"%s\" specified", path);
out:
	proc_part_free_entry(&ppe);
}

static void parse_pos_args(char *nargv[], int nargc)
{
	switch (l.target_type) {
	case TT_FCP:
		parse_fcp_args(nargv, nargc);
		break;
	case TT_NVME:
		parse_nvme_args(nargv, nargc);
		break;
	case TT_CCW:
		parse_ccw_args(nargv, nargc);
		break;
	case TT_NSS:
		parse_nss_args(nargv, nargc);
		break;
	case TT_NODE:
		parse_node_args(nargv, nargc);
		break;
	}
}

static void check_fcp_opts(void)
{
	if (l.nss_name_set)
		ERR_EXIT("Invalid option for \"fcp\" target specified");
	if (!(l.busid_set && l.wwpn_set && l.lun_set))
		ERR_EXIT("The \"fcp\" target requires device, WWPN, "
			 "and LUN");
}

static void check_nvme_opts(void)
{
	if (l.nss_name_set || l.wwpn_set || l.lun_set || l.busid_set)
		ERR_EXIT("Invalid option for \"nvme\" target specified");
	if (!(l.fid_set && l.nsid_set))
		ERR_EXIT("The \"nvme\" target requires FID, and optional NSID");
}

static void check_ccw_opts(void)
{
	if (l.bootprog_set || l.lun_set || l.wwpn_set || l.nss_name_set)
		ERR_EXIT("Invalid option for \"ccw\" target specified");
	if (!l.busid_set)
		ERR_EXIT("The \"ccw\" target requires device");
}

static void check_nss_opts(void)
{
	if (l.bootprog_set || l.loadparm_set || l.busid_set || l.wwpn_set ||
	    l.lun_set)
		ERR_EXIT("Invalid option for \"nss\" target specified");
	if (!l.nss_name_set)
		ERR_EXIT("The \"nss\" target requires NSS name");
}

static void set_target_type(enum target_type tt, int mode_auto)
{
	l.target_type = tt;
	l.target_type_set = 1;
	l.target_type_auto_mode = mode_auto;
}

static void set_target_type_auto(const char *arg)
{
	char busid[10];

	if (access(arg, F_OK) == 0) {
		set_target_type(TT_NODE, 1);
		return;
	}
	if (mk_busid(busid, arg) == 0) {
		if (ccw_is_device(busid))
			set_target_type(TT_CCW, 1);
		else if (fcp_is_device(busid))
			set_target_type(TT_FCP, 1);
	}
}

static void set_reipl_clear(const char *arg)
{
	if (arg[0] == '1')
		l.reipl_clear = 1;
	else if (arg[0] == '0')
		l.reipl_clear = 0;
	else
		ERR_EXIT("re-IPL clear argument must be either 1 or 0");
}

static void parse_chreipl_options(int argc, char *argv[])
{
	int opt, idx;
	const struct option long_opts[] = {
		{ "help",	 no_argument,		NULL, 'h'},
		{ "bootprog",	 required_argument,	NULL, 'b' },
		{ "device",	 required_argument,	NULL, 'd' },
		{ "lun",	 required_argument,	NULL, 'l' },
		{ "wwpn",	 required_argument,	NULL, 'w' },
		{ "fid",	 required_argument,	NULL, 'i' },
		{ "nsid",	 required_argument,	NULL, 's' },
		{ "loadparm",	 required_argument,	NULL, 'L' },
		{ "name",	 required_argument,	NULL, 'n' },
		{ "bootparms",	 required_argument,	NULL, 'p' },
		{ "force",	 no_argument,		NULL, 'f' },
		{ "version",	 no_argument,		NULL, 'v' },
		{ "clear",	 required_argument,	NULL, 'c' },
		{ NULL,		 0,			NULL,  0  }
	};
	static const char optstr[] = "hd:vw:l:fL:b:n:p:c:i:s:";

	/* dont run without any argument */
	if (argc == 1)
		print_usage_chreipl_exit();

	if (strcmp(argv[1], "fcp") == 0)
		set_target_type(TT_FCP, 0);
	else if (strcmp(argv[1], "ccw") == 0)
		set_target_type(TT_CCW, 0);
	else if (strcmp(argv[1], "nss") == 0)
		set_target_type(TT_NSS, 0);
	else if (strcmp(argv[1], "nvme") == 0)
		set_target_type(TT_NVME, 0);
	else if (strcmp(argv[1], "node") == 0)
		set_target_type(TT_NODE, 0);
	else
		set_target_type_auto(argv[1]);

	l.reipl_clear = -1;

	while ((opt = getopt_long(argc, argv, optstr, long_opts, &idx)) != -1) {
		switch (opt) {
		case 'h':
			print_usage_chreipl_exit();
		case 'd':
			set_device(optarg);
			break;
		case 'i':
			set_nvme_fid(optarg);
			break;
		case 'l':
			set_lun(optarg);
			break;
		case 's':
			set_nvme_nsid(optarg);
			break;
		case 'w':
			set_wwpn(optarg);
			break;
		case 'L':
			set_loadparm(optarg);
			break;
		case 'b':
			set_bootprog(optarg);
			break;
		case 'n':
			set_nss_name(optarg);
			break;
		case 'p':
			set_bootparms(optarg);
			break;
		case 'f':
			l.force_set = 1;
			break;
		case 'c':
			set_reipl_clear(optarg);
			break;
		case 'v':
			print_version_exit();
		default:
			print_help_hint_exit();
		}
	}
	if (!is_root())
		ERR_EXIT("You must be root to perform this operation");
	if (!l.target_type_set)
		ERR_EXIT("No valid target specified");
	/*
	 * optind is a index which points to the first unrecognized
	 * command line argument. In case of no auto action we have to
	 * skip the action argument.
	 */
	if (!l.target_type_auto_mode)
		optind += 1;
	if (argc - optind > 0)
		parse_pos_args(&argv[optind], argc - optind);
}

static void check_exists(const char *path, const char *attr)
{
	char fpath[PATH_MAX];

	snprintf(fpath, sizeof(fpath), "/sys/firmware/%s", path);
	if (access(fpath, F_OK) != 0)
		ERR_EXIT("System does not allow to set %s", attr);
}

static void write_str_optional(char *string, char *file, int exit_on_fail,
			       const char *attr)
{
	if (write_str_errno(string, file) && exit_on_fail)
		ERR_EXIT("System does not allow to set %s", attr);
}

/*
 * Check if device is on the cio_ignore blacklist
 *
 * IMPLEMENTATION:
 *
 * "cio_ignore --is-ignored <busid>" returns 0 if the device is ignored,
 * 1 for internal errrors, and 2 if the device is not ignored.
 *
 * We get the "cio_ignore" exit status by the return code of the system()
 * function via WEXITSTATUS().
 *
 * If no shell is available or the "cio_ignore" tool is not available
 * we get system() rc != 0 and WEXITSTATUS() = 127.
 */
static int is_ignored(const char *busid)
{
	const char *fmt = "cio_ignore --is-ignored %s > /dev/null 2>&1";
	char cmd[256];
	int rc;

	snprintf(cmd, sizeof(cmd), fmt, busid);
	rc = system(cmd);
	if ((rc != -1) && (WEXITSTATUS(rc) == 0))
		return 1;
	return 0;
}

static void chreipl_ccw(void)
{
	check_ccw_opts();

	if (!ccw_is_device(l.busid) && !l.force_set) {
		if (is_ignored(l.busid))
			ERR_EXIT("Device is on cio_ignore list, try \"cio_ignore -r %s\"?", l.busid);
		ERR_EXIT("Could not find DASD CCW device \"%s\"", l.busid);
	}

	if (l.bootparms_set && strlen(l.bootparms) > BOOTPARMS_CCW_MAX) {
		ERR_EXIT("Maximum boot parameter length exceeded (%zu/%u)",
			 strlen(l.bootparms), BOOTPARMS_CCW_MAX);
	}

	if (l.reipl_clear >= 0) {
		check_exists("reipl/ccw/clear", "CCW re-IPL clear attribute");
		write_str(l.reipl_clear ? "1" : "0", "reipl/ccw/clear");
	}

	/*
	 * On old systems that use CCW reipl loadparm cannot be set
	 */
	write_str_optional(l.loadparm, "reipl/ccw/loadparm", l.loadparm_set,
			   "loadparm");
	write_str_optional(l.bootparms, "reipl/ccw/parm", l.bootparms_set,
			   "boot parameters");
	write_str(l.busid, "reipl/ccw/device");
	write_str("ccw", "reipl/reipl_type");

	print_ccw(0);
}

static void chreipl_fcp(void)
{
	check_fcp_opts();

	if (!fcp_is_device(l.busid) && !l.force_set) {
		if (is_ignored(l.busid))
			ERR_EXIT("Device is on cio_ignore list, try \"cio_ignore -r %s\"?", l.busid);
		ERR_EXIT("Could not find FCP device \"%s\"", l.busid);
	}
	check_exists("reipl/fcp/device", "\"fcp\" re-IPL target");
	if (l.bootparms_set && strlen(l.bootparms) > BOOTPARMS_FCP_MAX) {
		ERR_EXIT("Maximum boot parameter length exceeded (%zu/%u)",
			 strlen(l.bootparms), BOOTPARMS_FCP_MAX);
	}

	if (l.reipl_clear >= 0) {
		check_exists("reipl/fcp/clear", "FCP re-IPL clear attribute");
		write_str(l.reipl_clear ? "1" : "0", "reipl/fcp/clear");
	}

	/*
	 * On old systems the FCP reipl loadparm cannot be set
	 */
	write_str_optional(l.loadparm, "reipl/fcp/loadparm", l.loadparm_set,
			   "loadparm");
	write_str_optional(l.bootparms, "reipl/fcp/scp_data", l.bootparms_set,
			   "boot parameters");
	write_str(l.busid, "reipl/fcp/device");
	write_str(l.wwpn, "reipl/fcp/wwpn");
	write_str(l.lun, "reipl/fcp/lun");
	/*
	 * set the boot record logical block address. Master boot
	 * record. It is always 0 for Linux
	 */
	write_str("0", "reipl/fcp/br_lba");
	if (!l.bootprog_set)
		sprintf(l.bootprog, "0");
	write_str(l.bootprog,  "reipl/fcp/bootprog");
	write_str("fcp", "reipl/reipl_type");

	print_fcp(0, 0);
}

static void chreipl_nvme(void)
{
	check_nvme_opts();

	if (!nvme_is_device(l.fid, l.nsid) && !l.force_set) {
		ERR_EXIT("Could not find NVME device with fid %s and nsid %s",
			l.fid, l.nsid);
	}
	check_exists("reipl/nvme/fid", "\"nvme\" re-IPL target");

	if (l.bootparms_set && strlen(l.bootparms) > BOOTPARMS_FCP_MAX) {
		ERR_EXIT("Maximum boot parameter length exceeded (%zu/%u)",
			 strlen(l.bootparms), BOOTPARMS_FCP_MAX);
	}

	if (l.reipl_clear >= 0) {
		check_exists("reipl/nvme/clear", "NVME re-IPL clear attribute");
		write_str(l.reipl_clear ? "1" : "0", "reipl/nvme/clear");
	}

	write_str_optional(l.loadparm, "reipl/nvme/loadparm", l.loadparm_set,
			   "loadparm");
	write_str_optional(l.bootparms, "reipl/nvme/scp_data", l.bootparms_set,
			   "boot parameters");
	write_str(l.fid, "reipl/nvme/fid");
	write_str(l.nsid, "reipl/nvme/nsid");
	/*
	 * set the boot record logical block address. Master boot
	 * record. It is always 0 for Linux
	 */
	write_str("0", "reipl/nvme/br_lba");
	if (!l.bootprog_set)
		sprintf(l.bootprog, "0");
	write_str(l.bootprog,  "reipl/nvme/bootprog");
	write_str("nvme", "reipl/reipl_type");

	print_nvme(0, 0);
}

static void chreipl_nss(void)
{
	check_nss_opts();
	check_exists("reipl/nss/name", "\"nss\" re-IPL target");
	if (l.bootparms_set && strlen(l.bootparms) > BOOTPARMS_NSS_MAX) {
		ERR_EXIT("Maximum boot parameter length exceeded (%zu/%u)",
			 strlen(l.bootparms), BOOTPARMS_NSS_MAX);
	}
	write_str_optional(l.bootparms, "reipl/nss/parm", l.bootparms_set,
			   "boot parameters");
	write_str(l.nss_name, "reipl/nss/name");
	write_str("nss", "reipl/reipl_type");
	print_nss(0);
}

static void chreipl_node(void)
{
	char path[PATH_MAX];

	if (!l.dev_set)
		ERR_EXIT("No device node specified");
	snprintf(path, sizeof(path), "/sys/block/%s/device", l.dev);
	if (chdir(path) != 0)
		ERR_EXIT("Could not find device \"%s\"", l.dev);

	switch (l.reipl_type) {
	case REIPL_CCW:
		ccw_busid_get(l.dev, l.busid);
		l.busid_set = 1;
		chreipl_ccw();
		break;
	case REIPL_FCP:
		fcp_wwpn_get(l.dev, l.wwpn);
		l.wwpn_set = 1;
		fcp_lun_get(l.dev, l.lun);
		l.lun_set = 1;
		fcp_busid_get(l.dev, l.busid);
		l.busid_set = 1;
		chreipl_fcp();
		break;
	case REIPL_NVME:
		nvme_fid_get(l.dev, l.fid);
		l.fid_set = 1;
		nvme_nsid_get(l.dev, l.nsid);
		l.nsid_set = 1;
		chreipl_nvme();
		break;
	default:
		ERR_EXIT("Internal error: chreipl_node");
	}
}

void cmd_chreipl(int argc, char *argv[])
{
	parse_chreipl_options(argc, argv);
	switch (l.target_type) {
	case TT_CCW:
		chreipl_ccw();
		break;
	case TT_FCP:
		chreipl_fcp();
		break;
	case TT_NVME:
		chreipl_nvme();
		break;
	case TT_NSS:
		chreipl_nss();
		break;
	case TT_NODE:
		chreipl_node();
		break;
	}
}
