/*
 * vmcp - z/VM CP function library
 *
 * Copyright IBM Corp. 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "lib/util_libc.h"
#include "lib/vmcp.h"

#define	VMCP_DEVICE_NODE	"/dev/vmcp"
#define	VMCP_GETSIZE		_IOR(0x10, 3, int)
#define	VMCP_SETBUF		_IOW(0x10, 2, int)
#define	VMCP_GETCODE		_IOR(0x10, 1, int)

/*
 * Read at most COUNT bytes from FD into memory at location BUF.
 * Return number of bytes read on success, -1 on error.
 */
static ssize_t read_buffer(int fd, char *buf, ssize_t count)
{
	ssize_t ret, done;

	for (done = 0; done < (ssize_t)count; done += ret) {
		ret = read(fd, &buf[done], count - done);
		if (ret == -1 && errno == EINTR)
			continue;
		if (ret == -1)
			return -1;
		if (ret == 0)
			break;
	}
	return done;
}

/**
 * Submit a command to z/VM CP and return the response, the size in bytes
 * of the response and CP command response code.
 *
 * The member response contains the response from CP. It is a pointer
 * to a malloc'ed buffer which must be freed by the caller when the return
 * code is zero or VMCP_ERR_TOOSMALL.
 *
 * @param[in,out] cmd		Pointer to struct vmcp_parm.
 * @param[in] cpcmd		Pointer to CP command string.
 * @param[in] do_upper		If true convert cpcmd string to upper case.
 * @param[out] cprc		Return code of the CP command.
 * @param[out] response		Return buffer, has been allocated via malloc()
 *				must be freed by caller, see below.
 * @param[out] response_size	Size of the response in bytes, can be larger
 *				than buffer_size.
 *
 * @returns	Zero on success or a negative error number on failure.
 * @retval VMCP_SUCCESS		Success valid members: cprc, response,
 *				response_size
 * @retval VMCP_ERR_OPEN	Error opening VMCP device, valid members: none
 * @retval VMCP_ERR_SETBUF	Error setting buffer, valid members: none
 * @retval VMCP_ERR_GETCODE	Error getting cp exit code, valid members: none
 * @retval VMCP_ERR_WRITE	Error write CP command, valid members: none
 * @retval VMCP_ERR_GETSIZE	Error reading response size,
 *				valid members: cprc
 * @retval VMCP_ERR_READ	Error reading resp
 * @retval VMCP_ERR_TOOSMALL	Error response buffer too small, response
 *				truncated, valid members: cprc, response,
 *				response_size
 */
int vmcp(struct vmcp_parm *cmd)
{
	int rc = VMCP_SUCCESS, fd, len;
	char *cpcmd;

	cmd->response = NULL;
	cmd->response_size = 0;
	cmd->cprc = 0;

	fd = open(VMCP_DEVICE_NODE, O_RDWR);
	if (fd == -1)
		return VMCP_ERR_OPEN;

	cpcmd = util_strdup(cmd->cpcmd);	/* Exits on failure */
	if (cmd->do_upper)
		util_str_toupper(cpcmd);

	if (ioctl(fd, VMCP_SETBUF, &cmd->buffer_size) == -1) {
		rc = VMCP_ERR_SETBUF;
		goto fail;
	}

	if (write(fd, cpcmd, strlen(cpcmd)) == -1) {
		rc = VMCP_ERR_WRITE;
		goto fail;
	}

	if (ioctl(fd, VMCP_GETCODE, &cmd->cprc) == -1) {
		rc = VMCP_ERR_GETCODE;
		goto fail;
	}

	if (ioctl(fd, VMCP_GETSIZE, &cmd->response_size) == -1) {
		rc = VMCP_ERR_GETSIZE;
		goto fail;
	}

	if (cmd->response_size <= cmd->buffer_size) {
		len = cmd->response_size;
	} else {
		len = cmd->buffer_size;
		rc = VMCP_ERR_TOOSMALL;
	}

	/* Exits on failure */
	cmd->response = (char *)util_zalloc(len + 1);

	if (read_buffer(fd, cmd->response, len) == -1) {
		rc = VMCP_ERR_READ;
		free(cmd->response);
		cmd->response = NULL;
	}

fail:
	close(fd);
	free(cpcmd);
	return rc;
}
