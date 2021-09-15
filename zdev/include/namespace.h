/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef NAMESPACE_H
#define NAMESPACE_H

#include "exit_code.h"
#include "misc.h"

struct ns_range_iterator {
	void *devid;
	void *devid_last;
	char *id;
};

/**
 * ns_range_for_each - Loop over all valid IDs in a range
 * @ns: The namespace for the IDs
 * @range: The range in text form
 * @it: The range iterator object. This must be allocated using
 *      ns_range_iterator_new(). After the loop it must be freed using
 *      ns_range_iterator_free(). During the loop, the ID field of the
 *      iterator object contains the current ID as a string.
 */
#define ns_range_for_each(ns, range, it) \
	for ((ns)->range_start((it), (range)); (it)->id; \
	     (ns)->range_next((it)))

struct namespace;
struct subtype;

/* NULL-terminated list of namespaces. */
#define NUM_NAMESPACES	6
extern struct namespace *namespaces[NUM_NAMESPACES + 1];

/* struct namespace - Definition of a device ID namespace
 * @devname: Short name for devices of this namespace
 * @is_id_valid: Check if string is a valid device ID and print corresponding
 *               error messages if requested.
 * @is_id_similar: Optional: Check if an ID looks similar to a namespace ID.
 *                 ID doesn't have to be a valid ID.
 * @cmp_ids: Compare two device IDs (same return codes as strcmp)
 * @normalize_id: Return a newly allocated string containing a normalized ID
 * @parse_id: Return a newly allocated parsed device ID object. Display
 *            warnings for invalid IDs if specified.
 * @cmp_parsed_ids: Compare two parsed device IDs (same return codes as strcmp)
 * @qsort_cmp: Compare two device IDs for strlist_sort_unique
 *
 * @hash_buckets: Optional: Number of hash buckets to use for device ID hashes
 * @hash_parsed_id: Optional: Return hash bucket for specified ID in parsed
 *                  format
 *
 * @is_id_range_valid: Check if string is a valid range of device IDs
 * @num_ids_in_range: Return the number of device IDs in the specified range
 * @is_id_in_range: Check if the specified ID is within the range
 * @range_start: If the specified range is a valid range in this namespace
 *               allocate and return a corresponding range iterator object,
 *               otherwise return NULL.
 * @range_next: Move the range iterator to the next device ID in range. If
 *              there is no next device ID in range, release the range iterator
 *              object and return false.
 *
 * @is_blacklist_active: Optional callback: Check if a blacklist is active.
 * @is_id_blacklisted: Optional callback: Check if specified ID is on the
 *                     blacklist.
 * @is_id_range_blacklisted: Optional callback: Check if at least one ID of
 *                           the specified ID range is on the blacklist.
 * @unblacklist_id: Optional callback: Remove specified ID from blacklist.
 * @unblacklist_id_range: Optional callback: Remove specified ID range from
 *                        blacklist.
 * @blacklist_persist: Optional callback: Persistently remove all configured
 *                     devices of this namespace from blacklist.
 */
struct namespace {
	const char *	devname;

	/* IDs. */
	exit_code_t	(*is_id_valid)(const char *, err_t);
	bool		(*is_id_similar)(const char *);
	int		(*cmp_ids)(const char *, const char *);
	char *		(*normalize_id)(const char *);
	void *		(*parse_id)(const char *, err_t);
	int		(*cmp_parsed_ids)(const void *, const void *);
	int		(*qsort_cmp)(const void *, const void *);

	/* ID Hash. */
	int		hash_buckets;
	int		(*hash_parsed_id)(const void *);

	/* Ranges. */
	exit_code_t	(*is_id_range_valid)(const char *, err_t);
	unsigned long	(*num_ids_in_range)(const char *);
	bool	(*is_id_in_range)(const char *, const char *);

	void		(*range_start)(struct ns_range_iterator *,
				       const char *);
	void		(*range_next)(struct ns_range_iterator *);

	/* Blacklist. */
	bool	(*is_blacklist_active)(void);
	bool	(*is_id_blacklisted)(const char *);
	bool	(*is_id_range_blacklisted)(const char *);
	void		(*unblacklist_id)(const char *);
	void		(*unblacklist_id_range)(const char *);
	exit_code_t	(*blacklist_persist)(void);
};

exit_code_t namespace_exit(void);
void namespace_set_modified(struct namespace *);

int namespaces_index(struct namespace *);
bool namespaces_is_id_valid(const char *);
bool namespaces_is_id_range_valid(const char *);
bool namespaces_device_exists(struct namespace *, const char *,
				  config_t, struct subtype **);

struct ns_range_iterator *ns_range_iterator_new(void);
void ns_range_iterator_free(struct ns_range_iterator *);

bool ns_is_id_valid(struct namespace *, const char *);
bool ns_is_id_range_valid(struct namespace *, const char *);

#endif /* NAMESPACE_H */
