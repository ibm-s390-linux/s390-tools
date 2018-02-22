/**
 * vmcp_example - Example program for vmcp.c
 *
 * Copyright 2018 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

//! [code]
#include <stdio.h>
#include <stdlib.h>
#include <err.h>

#include "lib/vmcp.h"

/*
 * Demonstrate vmcp() function usage
 */
int main(void)
{
	struct vmcp_parm cp;
	int rc;

	cp.cpcmd = "q osa";
	cp.buffer_size = VMCP_DEFAULT_BUFSZ;
	cp.do_upper = true;

	rc = vmcp(&cp);

	switch (rc) {
	case VMCP_SUCCESS:
		printf("%s\n", cp.response);
		free(cp.response);
		break;
	case VMCP_ERR_OPEN:
		errx(EXIT_FAILURE, "Could not open device %s", VMCP_DEVICE_NODE);
		break;
	case VMCP_ERR_SETBUF:
		errx(EXIT_FAILURE, "Could not set buffer size");
		break;
	case VMCP_ERR_GETCODE:
		errx(EXIT_FAILURE, "Could not query return code");
		break;
	case VMCP_ERR_GETSIZE:
		errx(EXIT_FAILURE, "Could not query response size");
		break;
	case VMCP_ERR_WRITE:
		errx(EXIT_FAILURE, "Could not issue CP command");
		break;
	case VMCP_ERR_READ:
		errx(EXIT_FAILURE, "Could not read CP response");
		break;
	case VMCP_ERR_TOOSMALL:
		free(cp.response);
		printf("Response truncated (requires %u bytes)\n",
		       cp.response_size);
		errx(EXIT_FAILURE, "Response buffer (%u bytes) too small",
		     cp.buffer_size);
		break;
	}
	return EXIT_SUCCESS;
}

//! [code]
