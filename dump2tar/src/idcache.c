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

#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>

#include "global.h"
#include "idcache.h"
#include "misc.h"

/* Maximum user and group name lengths as defined in tar header */
#define ID_NAME_MAXLEN	32

/* Types for user and group ID caches */
typedef uid_t generic_id_t; /* Assumes that uid_t == gid_t */

struct id_cache_entry {
	generic_id_t id;
	char name[ID_NAME_MAXLEN];
};

struct id_cache {
	unsigned int num;
	struct id_cache_entry entries[];
};

/* cache_mutex serializes access to cached uid and gid data */
static pthread_mutex_t id_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct id_cache *id_cache_uid;
static struct id_cache *id_cache_gid;

/* Lock cache mutex */
static void cache_lock(void)
{
	if (!global_threaded)
		return;
	pthread_mutex_lock(&id_cache_mutex);
}

/* Unlock cache mutex */
static void cache_unlock(void)
{
	if (!global_threaded)
		return;
	pthread_mutex_unlock(&id_cache_mutex);
}

/* Copy the name associated with @id in @cache to at most @len bytes at @dest.
 * Return %true if name was found in cache, %false otherwise. */
static bool strncpy_id_cache_entry(char *dest, struct id_cache *cache,
				   generic_id_t id, size_t len)
{
	unsigned int i;
	bool hit = false;

	cache_lock();
	if (cache) {
		for (i = 0; i < cache->num; i++) {
			if (cache->entries[i].id == id) {
				strncpy(dest, cache->entries[i].name, len);
				hit = true;
				break;
			}
		}
	}
	cache_unlock();

	return hit;
}

/* Add a new entry consisting of @id and @name to ID cache in @*cache_ptr.
 * Update @cache_ptr if necessary. */
static void add_id_cache_entry(struct id_cache **cache_ptr, generic_id_t id,
			       char *name)
{
	struct id_cache *cache;
	unsigned int cache_num;
	size_t new_size;
	struct id_cache *new_cache;

	cache_lock();

	cache = *cache_ptr;
	cache_num = cache ? cache->num : 0;
	new_size = sizeof(struct id_cache) +
		   sizeof(struct id_cache_entry) * (cache_num + 1);
	new_cache = mrealloc(cache, new_size);
	if (cache_num == 0)
		new_cache->num = 0;
	new_cache->entries[cache_num].id = id;
	strncpy(new_cache->entries[cache_num].name, name, ID_NAME_MAXLEN);
	new_cache->num++;
	*cache_ptr = new_cache;

	cache_unlock();
}

/* Copy the user name corresponding to user ID @uid to at most @len bytes
 * at @name */
void uid_to_name(uid_t uid, char *name, size_t len)
{
	struct passwd pwd, *pwd_ptr;
	char buffer[PWD_BUFFER_SIZE], *result;

	if (strncpy_id_cache_entry(name, id_cache_uid, uid, len))
		return;

	/* getpwuid() can be slow so cache results */
	getpwuid_r(uid, &pwd, buffer, PWD_BUFFER_SIZE, &pwd_ptr);
	if (!pwd_ptr || !pwd_ptr->pw_name)
		return;
	result = pwd_ptr->pw_name;

	add_id_cache_entry(&id_cache_uid, uid, result);

	strncpy(name, result, len);
}

/* Copy the group name corresponding to group ID @gid to at most @len bytes
 * at @name */
void gid_to_name(gid_t gid, char *name, size_t len)
{
	struct group grp, *grp_ptr;
	char buffer[GRP_BUFFER_SIZE], *result;

	if (strncpy_id_cache_entry(name, id_cache_gid, gid, len))
		return;

	/* getgrgid() can be slow so cache results */
	getgrgid_r(gid, &grp, buffer, GRP_BUFFER_SIZE, &grp_ptr);
	if (!grp_ptr || !grp_ptr->gr_name)
		return;
	result = grp_ptr->gr_name;

	add_id_cache_entry(&id_cache_gid, gid, result);

	strncpy(name, result, len);
}

void idcache_cleanup(void)
{
	free(id_cache_uid);
	free(id_cache_gid);
}
