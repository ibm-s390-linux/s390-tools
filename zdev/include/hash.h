/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef HASH_H
#define HASH_H

#include "lib/util_list.h"

/* A hash is a list of entries. Each entry provides an ID. A hashing function
 * maps the ID to an integer bucket number. When adding entries to a hash, the
 * entry is stored in a list associated with this bucket number. This approach
 * can greatly reduce the effort needed to find an entry in a hash by ID. */

/* Return the ID of an entry. */
typedef const void *(*hash_id_fn_t)(void *);

/* Check if two IDs are identical. */
typedef int (*hash_cmp_fn_t)(const void *, const void *);

/* Return the bucket number for an ID. */
typedef int (*hash_fn_t)(const void *);

/**
 * hash - A hash supported list
 * @list: Sequential list of entries
 * @buckets: Number of hash buckets
 * @get_id: Return the ID of an entry
 * @cmp_id: Return 0 if two IDs are identical
 * @get_hash: Function that returns a hash index for an ID
 * @hash: Lists per hash index
 */
struct hash {
	struct util_list list;
	int buckets;
	hash_id_fn_t get_id;
	hash_cmp_fn_t cmp_id;
	hash_fn_t get_hash;
	struct util_list **hash;
};

#define hash_init(hash, buckets, get_id, cmp_id, get_hash, type, member) \
	_hash_init((hash), (buckets), (get_id), (cmp_id), (get_hash), \
	offsetof(type, member))
#define hash_new(buckets, get_id, cmp_id, get_hash, type, member) \
	_hash_new((buckets), (get_id), (cmp_id), (get_hash), \
	offsetof(type, member))

void _hash_init(struct hash *hash, int buckets, hash_id_fn_t get_id,
		hash_cmp_fn_t cmp_id, hash_fn_t get_hash, unsigned long offset);
struct hash *_hash_new(int buckets, hash_id_fn_t get_id, hash_cmp_fn_t cmp_id,
		       hash_fn_t get_hash, unsigned long offset);
void hash_clear(struct hash *hash, void (*free_fn)(void *));
void hash_free(struct hash *hash, void (*free_fn)(void *));
void hash_add(struct hash *hash, void *entry);
void hash_remove(struct hash *hash, void *entry);
void *hash_find_by_id(struct hash *hash, const void *id);
void hash_print(struct hash *hash, int ind);

#endif /* HASH_H */
