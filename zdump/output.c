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

#define BUFFER_SIZE	(1 * MIB)

int write_dump(FILE *stream)
{
	const u64 output_size = dfo_size();
	char *buf = zg_alloc(BUFFER_SIZE);
	u64 written = 0;

	if (!dfi_feat_copy())
		ERR_EXIT("Copying not possible for %s dumps", dfi_name());
	STDERR("Format Info:\n");
	STDERR("  Source: %s\n", dfi_name());
	STDERR("  Target: %s\n", dfo_name());
	STDERR("\n");
	zg_progress_init("Copying dump", output_size);
	while (written != output_size) {
		size_t rc;
		u64 cnt;

		cnt = dfo_read(buf, BUFFER_SIZE);
		rc = fwrite(buf, cnt, 1, stream);
		if (rc != 1 && ferror(stream))
			ERR_EXIT("Error: Write failed");
		written += cnt;
		zg_progress(written);
	};
	STDERR("\n");
	STDERR("Success: Dump has been copied\n");
	zg_free(buf);
	return 0;
}
