/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <string.h>

#include "hash.h"
#include "misc.h"

/* Initialize hash. */
void _hash_init(struct hash *hash, int buckets, hash_id_fn_t get_id,
		hash_cmp_fn_t cmp_id, hash_fn_t get_hash, unsigned long offset)
{
	int i;

	memset(hash, 0, sizeof(struct hash));
	util_list_init_offset(&hash->list, offset);
	hash->buckets = buckets;
	hash->get_id = get_id;
	hash->cmp_id = cmp_id;
	hash->get_hash = get_hash;
	hash->hash = misc_malloc(sizeof(struct util_list) * buckets);
	for (i = 0; i < buckets; i++)
		hash->hash[i] = ptrlist_new();
}

/* Return a newly allocated hash. */
struct hash *_hash_new(int buckets, hash_id_fn_t get_id, hash_cmp_fn_t cmp_id,
		       hash_fn_t get_hash, unsigned long offset)
{
	struct hash *hash;

	hash = misc_malloc(sizeof(struct hash));
	_hash_init(hash, buckets, get_id, cmp_id, get_hash, offset);

	return hash;
}

/* Release all resources associated with @hash, excluding @hash. If @free_fn
 * is specified, this function is called to release all resources associated
 * with each entry. */
void hash_clear(struct hash *hash, void (*free_fn)(void *))
{
	void *c, *n;
	int i;

	util_list_iterate_safe(&hash->list, c, n) {
		util_list_remove(&hash->list, c);
		if (free_fn)
			free_fn(c);
	}

	for (i = 0; i < hash->buckets; i++)
		ptrlist_free(hash->hash[i], 0);
	free(hash->hash);
}

/* Release all resources associated with @hash. If @free_fn is specified,
 * this function is called to release all resources associated with each
 * entry. */
void hash_free(struct hash *hash, void (*free_fn)(void *))
{
	hash_clear(hash, free_fn);
	free(hash);
}

/* Add a new entry to the hash. */
void hash_add(struct hash *hash, void *entry)
{
	int bucket;

	util_list_add_tail(&hash->list, entry);
	if (hash->buckets > 0) {
		bucket = hash->get_hash(hash->get_id(entry));
		ptrlist_add(hash->hash[bucket], entry);
	}
}

/* Remove an entry from the hash. */
void hash_remove(struct hash *hash, void *entry)
{
	int bucket;

	util_list_remove(&hash->list, entry);
	if (hash->buckets > 0) {
		bucket = hash->get_hash(hash->get_id(entry));
		ptrlist_remove(hash->hash[bucket], entry);
	}
}

void hash_print(struct hash *hash, int ind)
{
	int i;

	indent(ind, "hash at %p\n", hash);
	ind += 2;
	indent(ind, "buckets=%d\n", hash->buckets);
	indent(ind, "get_id=%p\n", hash->get_id);
	indent(ind, "cmp_id=%p\n", hash->cmp_id);
	indent(ind, "get_hash=%p\n", hash->get_hash);

	for (i = 0; i < hash->buckets; i++) {
		indent(ind, "bucket[%d]: len=%d\n", i,
		       util_list_len(hash->hash[i]));
	}
}

/* Find entry by ID. @cmp_fn compares two IDs and returns 0 when IDs match. */
void *hash_find_by_id(struct hash *hash, const void *id)
{
	int bucket;
	struct ptrlist_node *p;

	if (hash->buckets > 0) {
		bucket = hash->get_hash(id);
		util_list_iterate(hash->hash[bucket], p) {
			if (hash->cmp_id(hash->get_id(p->ptr), id) == 0)
				return p->ptr;
		}
	}

	return NULL;
}
