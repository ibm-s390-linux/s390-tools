/**
 * @defgroup util_lockfile_h util_lockfile: File locking utility
 * @{
 * @brief Create file-based locks
 *
 * Copyright IBM Corp. 2022
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef LIB_UTIL_LOCKFILE_H
#define LIB_UTIL_LOCKFILE_H

#define UTIL_LOCKFILE_OK	   0 /* Lock acquired/released successfully */
#define UTIL_LOCKFILE_LOCK_FAIL	   1 /* Lock already held, ran out of retries */
#define UTIL_LOCKFILE_RELEASE_NONE 2 /* Lock not held */
#define UTIL_LOCKFILE_RELEASE_FAIL 3 /* Lock not held by specified pid */
#define UTIL_LOCKFILE_ERR	   4 /* Other, unexpected error conditions */

int util_lockfile_lock(char *lockfile, int retries);
int util_lockfile_lock_cw(char *lockfile, int retries, unsigned int waitinc,
			  unsigned int maxwait);
int util_lockfile_parent_lock(char *lockfile, int retries);
int util_lockfile_parent_lock_cw(char *lockfile, int retries,
				 unsigned int waitinc, unsigned int maxwait);

int util_lockfile_release(char *lockfile);
int util_lockfile_parent_release(char *lockfile);

int util_lockfile_peek_owner(char *lockfile, int *pid);

#endif /** LIB_UTIL_LOCKFILE_H @} */
