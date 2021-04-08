/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_HSA_FILE_H
#define _HSAVMCORE_HSA_FILE_H

#include <stdbool.h>

#include "hsa.h"

/*
 * This concrete HSA memory reader copies the whole HSA memory from /proc/vmcore
 * to a temporary file.
 * In order for it to work, the system must provide enough file storage.
 * The advantage of this reader is that it doesn't require extra memory for
 * caching.
 */
struct hsa_reader *make_hsa_file_reader(const char *zcore_hsa_path,
					const char *vmcore_path,
					const char *workdir_path, long hsa_size,
					bool release_hsa_flag);

#endif
