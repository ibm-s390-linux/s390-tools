/*
 * Copyright IBM Corp. 2001, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZFUSE_H
#define ZFUSE_H

#if HAVE_FUSE == 0
static inline int zfuse_mount_dump(void)
{
	ERR_EXIT("Program compiled without fuse support");
}
static inline void zfuse_umount(void)
{
	ERR_EXIT("Program compiled without fuse support");
}
#else
int zfuse_mount_dump(void);
void zfuse_umount(void);
#endif

#endif /* ZFUSE_H */
