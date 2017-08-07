/*
 * dump2tar - tool to dump files and command output into a tar archive
 *
 * Reference counting for directory handles
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <dirent.h>
#include <pthread.h>
#include <sys/types.h>

#include "dref.h"
#include "global.h"
#include "misc.h"

/* dref_mutex serializes access to drefs */
static pthread_mutex_t dref_mutex = PTHREAD_MUTEX_INITIALIZER;

static unsigned long num_open_dirs;
static unsigned long num_open_dirs_max;

/* Lock dref mutex */
static void dref_lock(void)
{
	if (!global_threaded)
		return;
	pthread_mutex_lock(&dref_mutex);
}

/* Unlock dref mutex */
static void dref_unlock(void)
{
	if (!global_threaded)
		return;
	pthread_mutex_unlock(&dref_mutex);
}

/* Create a reference count managed directory handle for @dirname */
struct dref *dref_create(const char *dirname)
{
	struct dref *dref;
	DIR *dd;

	dd = opendir(dirname);
	DBG("opendir(%s)=%p (total=%lu)", dirname, dd, ++num_open_dirs);
	if (!dd) {
		num_open_dirs--;
		return NULL;
	}

	if (num_open_dirs > num_open_dirs_max)
		num_open_dirs_max = num_open_dirs;

	dref = mmalloc(sizeof(struct dref));
	dref->dd = dd;
	dref->dirfd = dirfd(dd);
	dref->count = 1;

	return dref;
}

/* Obtain a reference to @dref */
struct dref *dref_get(struct dref *dref)
{
	if (dref) {
		dref_lock();
		dref->count++;
		dref_unlock();
	}

	return dref;
}

/* Release a reference to @dref. If this was the last reference, lose the
 * associated directory handle and free @dref. */
void dref_put(struct dref *dref)
{
	if (dref) {
		dref_lock();
		dref->count--;
		if (dref->count == 0) {
			num_open_dirs--;
			DBG("closedir(%p) (total=%lu, max=%lu)", dref->dd,
			    num_open_dirs, num_open_dirs_max);
			closedir(dref->dd);
			free(dref);
		}
		dref_unlock();
	}
}
