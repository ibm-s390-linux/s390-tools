/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Write dump to the file descriptor (fd)
 *
 * Copyright IBM Corp. 2001, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "zg.h"
#include "dfi.h"
#include "dfo.h"
#include "output.h"

int write_dump(int fd)
{
	const u64 output_size = dfo_size();
	char buf[8UL * PAGE_SIZE];
	u64 written = 0;

	if (fd < 0)
		ERR_EXIT("fd must be a valid file descriptor");

	if (!dfi_feat_copy())
		ERR_EXIT("Copying not possible for %s dumps", dfi_name());
	STDERR("Format Info:\n");
	STDERR("  Source: %s\n", dfi_name());
	STDERR("  Target: %s\n", dfo_name());
	STDERR("\n");
	zg_progress_init("Copying dump", output_size);
	while (written != output_size) {
		ssize_t rc;
		u64 cnt;

		cnt = dfo_read(buf, sizeof(buf));
		rc = write(fd, buf, cnt);
		if (rc == -1)
			ERR_EXIT_ERRNO("Error: Write failed");
		if (rc != (ssize_t) cnt)
			ERR_EXIT("Error: Could not write full block");
		written += cnt;
		zg_progress(written);
	};
	STDERR("\n");
	STDERR("Success: Dump has been copied\n");
	return 0;
}
