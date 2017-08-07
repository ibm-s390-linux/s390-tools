/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Caches for user and group ID lookups
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef IDCACHE_H
#define IDCACHE_H

#include <stdlib.h>
#include <sys/types.h>

/* Buffer sizes for getpwuid_r and getgid_r calls (bytes) */
#define PWD_BUFFER_SIZE	4096
#define GRP_BUFFER_SIZE	4096

void uid_to_name(uid_t uid, char *name, size_t len);
void gid_to_name(gid_t gid, char *name, size_t len);
void idcache_cleanup(void);

#endif /* IDCACHE_H */
