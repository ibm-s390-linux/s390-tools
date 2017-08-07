/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * Command: chshut
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "ipl_tools.h"

static const char *const usage_chshut =
"Usage: %s TRIGGER ACTION [COMMAND] [OPTIONS]\n"
"\n"
"Change the shutdown actions for Linux on System z.\n"
"\n"
"TRIGGER specifies when the action is performed:\n"
"  halt      System has been shut down (e.g. shutdown -h -H now)\n"
"  poff      System has been shut down for power off (e.g. shutdown -h -P now)\n"
"  reboot    System has been shut down for reboot (e.g. shutdown -r)\n"
"  Note: Depending on the distribution, \"halt\" might be mapped to \"poff\".\n"
"\n"
"ACTION specifies the action to be performed:\n"
"  ipl       IPL with previous settings\n"
"  reipl     IPL with re-IPL settings (see chreipl)\n"
"  stop      Stop all CPUs\n"
"  vmcmd     Run z/VM CP command defined by COMMAND\n"
"\n"
"COMMAND defines the z/VM CP command to issue.\n"
"\n"
"OPTIONS:\n"
"  -h, --help        Print this help, then exit\n"
"  -v, --version     Print version information, then exit\n";

static void print_usage_chshut_exit(void)
{
	printf(usage_chshut, g.prog_name);
	exit(0);
}

static void parse_chshut_options(int argc, char *argv[])
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
			print_usage_chshut_exit();
		case 'v':
			print_version_exit();
		default:
			print_help_hint_exit();
		}
	}
	if (!is_root())
		ERR_EXIT("You must be root to perform this operation");
}

static struct shutdown_trigger *shutdown_trigger_get(const char *trigger)
{
	int i;

	for (i = 0; shutdown_trigger_vec[i]; i++) {
		if (strcmp(trigger, shutdown_trigger_vec[i]->name) != 0)
			continue;
		if (shutdown_trigger_vec[i]->available)
			return shutdown_trigger_vec[i];
		ERR_EXIT("Shutdown trigger \"%s\" is not available on "
			 "your system", trigger);
	}
	ERR_EXIT("Unknown shutdown trigger \"%s\" specified", trigger);
}

static struct shutdown_action *shutdown_action_get(const char *action)
{
	int i;

	for (i = 0; shutdown_action_vec[i]; i++) {
		if (strcmp(action, shutdown_action_vec[i]->name) == 0)
			return shutdown_action_vec[i];
	}
	ERR_EXIT("Unknown shutdown action \"%s\" specified", action);
}

/*
 * Multiple CP commands can be specified via "vmcmd XY1 vmcmd XY2 ..."
 */
static void vmcmd_set(struct shutdown_trigger *st, int argc, char *argv[])
{
	char vmcmd[1024], path[PATH_MAX];
	int first = 1, i;
	int vmcmd_length = 0;

	if (is_lpar())
		ERR_EXIT("vmcmd works only under z/VM");
	memset(vmcmd, 0, sizeof(vmcmd));
	for (i = 2; i < argc; i++) {
		if (strcmp(argv[i], "vmcmd") != 0)
			ERR_EXIT("Invalid vmcmd command specification");
		if (i == argc - 1)
			ERR_EXIT("vmcmd needs an additional argument");
		if (!first) {
			strcat(vmcmd, "\n");
			vmcmd_length++;
		} else {
			first = 0;
		}
		vmcmd_length += strlen(argv[i + 1]);
		if (vmcmd_length >= 127)
			ERR_EXIT("The vmcmd command must not exceed 127 "
				 "characters");

		strcat(vmcmd, argv[i + 1]);
		i++;
	}

	sprintf(path, "vmcmd/%s", st->name_sysfs);
	write_str(vmcmd, path);
}

void cmd_chshut(int argc, char *argv[])
{
	struct shutdown_trigger *st;
	struct shutdown_action *sa;
	char path[PATH_MAX];

	parse_chshut_options(argc, argv);

	if (argc < 2) {
		ERR("No trigger specified");
		print_help_hint_exit();
	}
	shutdown_init();
	st = shutdown_trigger_get(argv[1]);
	if (st == &shutdown_trigger_panic ||
	    st == &shutdown_trigger_restart)
		ERR_EXIT("Please use \"service dumpconf\" for "
			 "configuring the %s trigger",
			 st->name);
	if (argc < 3) {
		ERR("No action specified");
		print_help_hint_exit();
	}
	sa = shutdown_action_get(argv[2]);

	if (sa == &shutdown_action_vmcmd) {
		vmcmd_set(st, argc, argv);
	} else if (argc != 3) {
		ERR("Too many parameters specified");
		print_help_hint_exit();
	}
	sprintf(path, "shutdown_actions/%s", st->name_sysfs);
	if (write_str_errno(argv[2], path))
		ERR_EXIT_ERRNO("Could not set \"%s\"", path);
}
