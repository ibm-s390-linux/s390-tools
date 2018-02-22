/*
 * vmcp - z/VM CP command library
 *
 * Copyright IBM Corp. 2005, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_VMCP_H
#define LIB_VMCP_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	VMCP_DEVICE_NODE	"/dev/vmcp"	/* VMCP device name */
#define	VMCP_DEFAULT_BUFSZ	0x4000		/* VMCP default buffer size */

/*
 * Error codes returned by vmcp() function. This enables the caller
 * to emit a detailed error message on the type of failure.
 */
#define	VMCP_SUCCESS	0	/* VMCP operation completed successfully */
#define	VMCP_ERR_OPEN		(-1)	/* Error Open of VMCP device */
#define	VMCP_ERR_SETBUF		(-2)	/* Error VMCP_SETBUF ioctl */
#define	VMCP_ERR_READ		(-3)	/* Error VMCP read system call */
#define	VMCP_ERR_GETCODE	(-4)	/* Error VMCP_GETCODE ioctl */
#define	VMCP_ERR_GETSIZE	(-5)	/* Error VMCP_GETSIZE ioctl */
#define	VMCP_ERR_TOOSMALL	(-6)	/* Error VMCP buffer too small for
					 * response
					 */
#define	VMCP_ERR_WRITE		(-7)	/* Error VMCP write system call */

struct vmcp_parm {
	const char *cpcmd;
	unsigned int buffer_size;
	bool do_upper;
	int cprc;
	char *response;
	unsigned int response_size;
};

int vmcp(struct vmcp_parm *cp);

#ifdef __cplusplus
}
#endif

#endif
