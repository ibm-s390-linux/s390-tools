/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * Shutdown actions and triggers common functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "ipl_tools.h"

static struct shutdown_trigger shutdown_trigger_halt = {
	.name		= "halt",
	.name_print	= "Halt",
	.name_sysfs	= "on_halt",
};

static struct shutdown_trigger shutdown_trigger_poff = {
	.name		= "poff",
	.name_print	= "Power off",
	.name_sysfs	= "on_poff",
};

static struct shutdown_trigger shutdown_trigger_reboot = {
	.name		= "reboot",
	.name_print	= "Reboot",
	.name_sysfs	= "on_reboot",
};

struct shutdown_trigger shutdown_trigger_restart = {
	.name		= "restart",
	.name_print	= "Restart",
	.name_sysfs	= "on_restart",
};

struct shutdown_trigger shutdown_trigger_panic = {
	.name		= "panic",
	.name_print	= "Panic",
	.name_sysfs	= "on_panic",
};

struct shutdown_trigger *shutdown_trigger_vec[] = {
	&shutdown_trigger_halt,
	&shutdown_trigger_poff,
	&shutdown_trigger_reboot,
	&shutdown_trigger_restart,
	&shutdown_trigger_panic,
	NULL,
};

static struct shutdown_action shutdown_action_ipl = {
	.name		= "ipl",
};

static struct shutdown_action shutdown_action_reipl = {
	.name		= "reipl",
};

static struct shutdown_action shutdown_action_dump = {
	.name		= "dump",
};

static struct shutdown_action shutdown_action_dump_reipl = {
	.name		= "dump_reipl",
};

static struct shutdown_action shutdown_action_stop = {
	.name		= "stop",
};

struct shutdown_action shutdown_action_vmcmd = {
	.name		= "vmcmd",
};

struct shutdown_action *shutdown_action_vec[] = {
	&shutdown_action_ipl,
	&shutdown_action_reipl,
	&shutdown_action_dump,
	&shutdown_action_dump_reipl,
	&shutdown_action_stop,
	&shutdown_action_vmcmd,
	NULL,
};

void shutdown_init(void)
{
	char path[PATH_MAX];
	struct stat sb;
	int i;

	for (i = 0; shutdown_trigger_vec[i]; i++) {
		sprintf(path, "/sys/firmware/shutdown_actions/%s",
			shutdown_trigger_vec[i]->name_sysfs);
		if (stat(path, &sb) == 0)
			shutdown_trigger_vec[i]->available = 1;
	}
}
