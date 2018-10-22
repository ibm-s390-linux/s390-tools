/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>

#include "lib/util_libc.h"

#include "misc.h"
#include "nic.h"
#include "path.h"

/* Determine NIC data for the specified NIC. */
bool nic_data_get(const char *id, struct nic_data *data_ptr)
{
	struct nic_data data;
	char *cmd, *vmcp;
	char **argv = NULL;
	int argc = 0;
	bool result = false;

	cmd = misc_asprintf("%s query virtual nic %s 2>/dev/null", PATH_VMCP,
			    id);
	vmcp = misc_read_cmd_output(cmd, 0, 1);
	if (!vmcp)
		goto out;

	line_split(vmcp, &argc, &argv);

	/* Type. */
	if (argc < 4)
		goto out;
	if (strcmp(argv[3], "QDIO") == 0)
		data.type = nic_qdio;
	else if (strcmp(argv[3], "HIPERS") == 0)
		data.type = nic_hipers;
	else if (strcmp(argv[3], "IEDN") == 0)
		data.type = nic_iedn;
	else if (strcmp(argv[3], "INMN") == 0)
		data.type = nic_inmn;
	else
		goto out;

	/* Target. */
	if (argc < 13)
		goto out;
	if (strcmp(argv[10], "VSWITCH:") == 0)
		data.target = nic_vswitch;
	else if (strcmp(argv[10], "LAN:") == 0)
		data.target = nic_lan;
	else
		goto out;

	util_strlcpy(data.owner, argv[11], NIC_OWNER_SIZE);
	util_strlcpy(data.name, argv[12], NIC_NAME_SIZE);

	result = true;
	*data_ptr = data;
out:
	line_free(argc, argv);
	free(vmcp);
	free(cmd);

	return result;
}

/* Used for debugging. */
void nic_data_print(struct nic_data *data, int level)
{
	printf("%*snic_data at %p\n", level, "", (void *) data);
	level += 2;
	printf("%*stype=%d\n", level, "", data->type);
	printf("%*starget=%d\n", level, "", data->target);
	printf("%*starget owner=%s\n", level, "", data->owner);
	printf("%*starget name=%s\n", level, "", data->name);
}

/* Determine layer2 setting required for the specified vswitch. */
bool nic_vswitch_get_layer2(const char *name, int *layer2)
{
	char *cmd, *vmcp;
	char **argv = NULL;
	int argc = 0;
	bool result = false;

	cmd = misc_asprintf("%s query vswitch %s 2>/dev/null", PATH_VMCP, name);
	vmcp = misc_read_cmd_output(cmd, 0, 1);
	if (!vmcp)
		goto out;

	line_split(vmcp, &argc, &argv);
	if (argc < 12)
		goto out;
	if (strcmp(argv[11], "ETHERNET") == 0)
		*layer2 = 1;
	else if (strcmp(argv[11], "NONROUTER") == 0 ||
		 strcmp(argv[11], "PRIROUTER") == 0 ||
		 strcmp(argv[11], "IP") == 0)
		*layer2 = 0;
	else
		goto out;

	result = true;

out:
	line_free(argc, argv);
	free(vmcp);
	free(cmd);

	return result;
}

/* Determine layer2 setting required for the specified guest lan. */
bool nic_lan_get_layer2(const char *name, const char *owner, int *layer2)
{
	char *cmd, *vmcp;
	char **argv = NULL;
	int argc = 0;
	bool result = false;

	if (strcmp(name, "*") == 0)
		return false;
	cmd = misc_asprintf("%s query lan %s owner %s 2>/dev/null", PATH_VMCP,
			    name, owner);
	vmcp = misc_read_cmd_output(cmd, 0, 1);
	if (!vmcp)
		goto out;

	line_split(vmcp, &argc, &argv);
	if (argc < 12)
		goto out;
	if (strcmp(argv[11], "ETHERNET") == 0)
		*layer2 = 1;
	else if (strcmp(argv[11], "IP") == 0)
		*layer2 = 0;
	else
		goto out;

	result = true;

out:
	line_free(argc, argv);
	free(vmcp);
	free(cmd);

	return result;
}
