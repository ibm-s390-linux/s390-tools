/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef EXIT_CODE_H
#define EXIT_CODE_H

/* Program exit codes. */
typedef enum {
	EXIT_OK			= 0,  /* Program finished successfully */

	/* Usage related */
	EXIT_USAGE_ERROR	= 1,  /* Usage error */
	EXIT_UNKNOWN_DEVTYPE	= 2,  /* Unknown device type specified */
	EXIT_DEVICE_NOT_FOUND	= 3,  /* Device not found */
	EXIT_ATTRIB_NOT_FOUND	= 4,  /* Attribute not found */
	EXIT_INVALID_DEVTYPE	= 5,  /* Invalid device type specified */
	EXIT_INVALID_SETTING	= 6,  /* Invalid attribute value specified */
	EXIT_SETTING_NOT_FOUND	= 7,  /* Setting not found */
	EXIT_EMPTY_SELECTION	= 8,  /* Empty selection */
	EXIT_INVALID_CONFIG	= 9,  /* Invalid configuration */
	EXIT_INVALID_ID		= 10, /* Invalid device ID specified */
	EXIT_INCOMPLETE_ID	= 11, /* Incomplete device ID specified */
	EXIT_NO_DATA		= 12, /* Configuration data not found */
	EXIT_UNKNOWN_COLUMN	= 13, /* Unknown column specified */
	EXIT_INCOMPLETE_TYPE	= 14, /* None or incomplete type specified */

	/* Run-time related */
	EXIT_RUNTIME_ERROR	= 15, /* A run-time error occurred */
	EXIT_ABORTED		= 16, /* Operation aborted on user request */
	EXIT_SETTING_FAILED	= 17, /* Error while applying setting */
	EXIT_FORMAT_ERROR	= 18, /* File format error */
	EXIT_MOD_BUSY		= 19, /* Module is in use */
	EXIT_MOD_UNLOAD_FAILED	= 20, /* Module could not be unloaded */
	EXIT_MOD_LOAD_FAILED	= 21, /* Module could not be loaded */
	EXIT_OUT_OF_MEMORY	= 22, /* Not enough available memory */

	/* zfcp related */
	EXIT_ZFCP_FCP_NOT_FOUND	= 23, /* FCP device not found */
	EXIT_ZFCP_INVALID_WWPN	= 24, /* Invalid WWPN specified */
	EXIT_ZFCP_WWPN_NOT_FOUND = 25, /* WWPN not found */
	EXIT_ZFCP_INVALID_LUN	= 26, /* Invalid LUN specified */
	EXIT_ZFCP_SCSI_NOT_FOUND = 27, /* SCSI device not found */

	/* ccwgroup related */
	EXIT_GROUP_NOT_FOUND	= 28, /* CCW device not found */
	EXIT_GROUP_INVALID	= 29, /* CCW devices are not a valid group */
	EXIT_GROUP_ALREADY	= 30, /* CCW device already grouped */
	EXIT_GROUP_FAILED	= 31, /* CCW group device grouping failed */
	EXIT_UNGROUP_FAILED	= 32, /* CCW group device ungrouping failed */

	EXIT_INTERNAL_ERROR	= 99, /* An internal error occurred */
} exit_code_t;

const char *exit_code_to_str(exit_code_t);

#endif /* EXIT_CODE_H */
