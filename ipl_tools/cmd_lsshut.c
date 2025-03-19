/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * Command: lsshut
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/util_path.h"
#include "lib/util_file.h"
#include "ipl_tools.h"

static const char *const usage_lsshut =
"Usage: %s [OPTIONS]\n"
"\n"
"Print the shutdown action configuration for Linux on System z.\n"
"\n"
"OPTIONS:\n"
"  -h, --help           Print this help, then exit\n"
"  -v, --version        Print version information, then exit\n";

static __noreturn void print_usage_lsshut_exit(void)
{
	printf(usage_lsshut, g.prog_name);
	exit(0);
}

static void parse_lsshut_options(int argc, char *argv[])
{

	int opt, idx;
	const struct option long_opts[] = {
		{ "help",	 no_argument,		NULL, 'h' },
		{ "version",	 no_argument,		NULL, 'v' },
		{ NULL,		 0,			NULL,  0  }
	};

	while ((opt = getopt_long(argc, argv, "hv", long_opts, &idx)) != -1) {
		switch (opt) {
		case 'h':
			print_usage_lsshut_exit();
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

/*
 * VMCMDs can have up to 128 characters. Newlines mark the end of a CP command.
 * Therefore we can have up to 64 single CP commands (with one character).
 * With quotes (2) and commas (1) we can have at most 4 * 64 = 256 characters
 * for the output string.
 */
static void read_vmcmd(char *str, const char *path)
{
	char *ptr_old, *ptr;
	char tmp[512];
	char *buf;

	*str = 0;
	buf = read_fw_str(path);
	ptr_old = ptr = buf;
	while ((ptr = strchr(ptr_old, '\n'))) {
		*ptr = 0;
		sprintf(tmp, "\"%s\",", ptr_old);
		strcat(str, tmp);
		ptr_old = ptr + 1;
	}
	sprintf(tmp, "\"%s\"", ptr_old);
	strcat(str, tmp);
	free(buf);
}

static void print_kdump(void)
{
	struct stat sb;
	char *path;
	char *tmp;

	path = util_path_sysfs("kernel/kexec_crash_loaded");
	if (stat(path, &sb) != 0) {
		free(path);
		return;
	}
	tmp = util_file_read_text_file(path, 1);
	if (strncmp(tmp, "1", 1) == 0)
		printf("kdump,");
	free(path);
	free(tmp);
}

static void shutdown_trigger_print(struct shutdown_trigger *trigger)
{
	char cmd[1024], path[PATH_MAX];
	char *tmp;

	sprintf(path, "shutdown_actions/%s", trigger->name_sysfs);

	printf("%-16s ", trigger->name_print);

	if ((trigger == &shutdown_trigger_panic ||
	     trigger == &shutdown_trigger_restart))
		print_kdump();
	tmp = read_fw_str(path);
	if (strncmp(tmp, "vmcmd", strlen("vmcmd")) == 0) {
		sprintf(path, "vmcmd/%s", trigger->name_sysfs);
		read_vmcmd(cmd, path);
		printf("vmcmd (%s)\n", cmd);
	} else {
		printf("%s\n", tmp);
	}
	free(tmp);
}

void cmd_lsshut(int argc, char *argv[])
{
	int i;

	parse_lsshut_options(argc, argv);
	shutdown_init();

	printf("Trigger          Action\n");
	printf("========================\n");

	for (i = 0; shutdown_trigger_vec[i]; i++) {
		if (!shutdown_trigger_vec[i]->available)
			continue;
		shutdown_trigger_print(shutdown_trigger_vec[i]);
	}
}
