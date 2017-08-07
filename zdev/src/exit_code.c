/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "exit_code.h"

/* Textual representation of program exit codes. */
const char *exit_code_to_str(exit_code_t rc)
{
	switch (rc) {
	case EXIT_OK:
		return "Program finished successfully";
	case EXIT_USAGE_ERROR:
		return "Usage error";
	case EXIT_UNKNOWN_DEVTYPE:
		return "Unknown device type specified";
	case EXIT_DEVICE_NOT_FOUND:
		return "Device not found";
	case EXIT_ATTRIB_NOT_FOUND:
		return "Unknown attribute specified";
	case EXIT_INVALID_DEVTYPE:
		return "Invalid device type specified";
	case EXIT_INVALID_SETTING:
		return "Invalid attribute value specified";
	case EXIT_SETTING_NOT_FOUND:
		return "Setting not found";
	case EXIT_EMPTY_SELECTION:
		return "Empty selection";
	case EXIT_INVALID_CONFIG:
		return "Invalid configuration";
	case EXIT_INVALID_ID:
		return "Invalid device ID specified";
	case EXIT_INCOMPLETE_ID:
		return "Incomplete device ID specified";
	case EXIT_NO_DATA:
		return "Configuration data not found";
	case EXIT_UNKNOWN_COLUMN:
		return "Unknown column specified";
	case EXIT_INCOMPLETE_TYPE:
		return "None or incomplete type specified";
	case EXIT_RUNTIME_ERROR:
		return "A run-time error occurred";
	case EXIT_ABORTED:
		return "Operation aborted on user request";
	case EXIT_SETTING_FAILED:
		return "Error while applying setting";
	case EXIT_FORMAT_ERROR:
		return "File format error";
	case EXIT_MOD_BUSY:
		return "Kernel module is in use";
	case EXIT_MOD_UNLOAD_FAILED:
		return "Kernel module could not be unloaded";
	case EXIT_MOD_LOAD_FAILED:
		return "Kernel module could not be loaded";
	case EXIT_OUT_OF_MEMORY:
		return "Not enough available memory";
	case EXIT_ZFCP_FCP_NOT_FOUND:
		return "FCP device not found";
	case EXIT_ZFCP_INVALID_WWPN:
		return "Invalid WWPN specified";
	case EXIT_ZFCP_WWPN_NOT_FOUND:
		return "WWPN not found";
	case EXIT_ZFCP_INVALID_LUN:
		return "Invalid LUN specified";
	case EXIT_ZFCP_SCSI_NOT_FOUND:
		return "SCSI device not found";
	case EXIT_GROUP_NOT_FOUND:
		return "CCW group device: CCW device not found";
	case EXIT_GROUP_INVALID:
		return "CCW group device: CCW devices are not a valid group";
	case EXIT_GROUP_ALREADY:
		return "CCW group device: CCW device already grouped";
	case EXIT_GROUP_FAILED:
		return "CCW group device: Grouping failed";
	case EXIT_UNGROUP_FAILED:
		return "CCW group device: Ungrouping failed";
	case EXIT_INTERNAL_ERROR:
		return "An internal error occurred";
	default:
		break;
	}

	return "An unknown error occurred";
}
