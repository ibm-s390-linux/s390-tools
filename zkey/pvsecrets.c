/*
 * zkey - Generate, re-encipher, and validate secure keys
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/util_base.h"
#include "lib/util_file.h"
#include "lib/util_libc.h"
#include "lib/util_panic.h"
#include "lib/util_path.h"

#include "pvsecrets.h"

#define pr_verbose(verbose, fmt...)	do {				\
						if (verbose)		\
							warnx(fmt);	\
					} while (0)

/**
 * Opens the ultravisor device and returns its file descriptor.
 * This only succeeds when running in a secure execution guest.
 * A failure of this function indicates that it is not running in a secure
 * execution guest.
 *
 * @param verbose            if true, verbose messages are printed
 *
 * @returns the file descriptor or -1 to indicate an error
 */
int uv_open_device(bool verbose)
{
	unsigned int pvguest = 0, max_retr_secrets = 0;
	char *path = NULL;
	int uv_fd, err;

	uv_fd = open(UVDEVICE, O_RDWR);
	if (uv_fd < 0) {
		err = errno;
		warnx("File '%s:' %s\n", UVDEVICE, strerror(errno));
		if (err == EACCES)
			warnx("Only the 'root' user is allowed to perform "
			      "this command");
		else
			warnx("Ensure that you are running in a secure "
			      "execution guest, and that the 'uvdevice' "
			      "kernel module is loaded.");
		return -1;
	}

	path = util_path_sysfs(SYSFS_UV);
	if (util_file_read_ui(&pvguest, 10, SYSFS_UV_PV_GUEST, path) != 0 ||
	    pvguest != 1) {
		warnx("You are not running in a secure execution guest.");
		goto error;
	}

	if (util_file_read_ui(&max_retr_secrets, 10, SYSFS_UV_MAX_SECRETS,
			      path) != 0 ||
	    max_retr_secrets == 0) {
		warnx("The ultravisor device is at a too old version, or "
		      "the ultravisor does not support retrievable secrets.");
		goto error;
	}
	free(path);

	pr_verbose(verbose, "Device '%s' has been opened successfully",
		   UVDEVICE);
	return uv_fd;

error:
	free(path);
	close(uv_fd);

	return -1;
}

/**
 * Retrieves a list of secrets from the ultravisor. Calls the supplied callback
 * function for each secret found.
 *
 * @param uv_fd              the file descriptor of the ultravisor device
 * @param cb                 the callback function
 * @param cb_private         private data to pass to the callback function
 * @param verbose            if true, verbose messages are printed
 *
 * @returns 0 on success, a negative errno in case of an error
 */
static int uv_list_secrets(int uv_fd, int (*cb)(u16 idx, u16 type, u32 len,
						const u8 id[UV_SECRET_ID_LEN],
						void *cb_private),
			   void *cb_private, bool verbose)
{
	struct uvio_list_secrets *list;
	struct uvio_ioctl_cb io;
	unsigned int i;
	int rc;

	util_assert(uv_fd != -1, "Internal error: uv_fd is -1");
	util_assert(cb != NULL, "Internal error: cb is NULL");

	list = util_zalloc(UVIO_LIST_SECRETS_MAX_LEN);

	memset(&io, 0, sizeof(io));
	io.argument_addr = list;
	io.argument_len = UVIO_LIST_SECRETS_MAX_LEN;

	rc = ioctl(uv_fd, UVIO_IOCTL_LIST_SECRETS, &io);
	if (rc != 0) {
		rc = -errno;

		pr_verbose(verbose, "ioctl UVIO_IOCTL_LIST_SECRETS: %s",
			   strerror(-rc));

		if (rc == -ENOTTY || rc == -EINVAL)
			warnx("The ultravisor device is at a too old version");

		goto out;
	}

	if (io.uv_rc != UVIO_RC_SUCCESS) {
		pr_verbose(verbose, "ioctl UVIO_IOCTL_LIST_SECRETS' uv_rc: %u",
			   io.uv_rc);
		rc = -EIO;
		goto out;
	}

	pr_verbose(verbose, "Number of secrets: %u", list->num_secrets_stored);

	for (i = 0; i < list->num_secrets_stored &&
		    i < ARRAY_SIZE(list->secret_entries); i++) {
		if (list->secret_entries[i].secret_type <=
						UV_SECRET_TYPE_AP_ASSOCIATION)
			continue;

		rc = cb(list->secret_entries[i].secret_idx,
			list->secret_entries[i].secret_type,
			list->secret_entries[i].secret_len,
			list->secret_entries[i].secret_id,
			cb_private);
		if (rc != 0)
			break;
	}

out:
	free(list);

	return rc;
}
