/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stddef.h>
#include <stdlib.h>

#include "ccw.h"
#include "ctc.h"
#include "devtype.h"
#include "lcs.h"
#include "namespace.h"
#include "qeth.h"
#include "zfcp_lun.h"

struct namespace *namespaces[] = {
	&ccw_namespace,
	&zfcp_lun_namespace,
	&qeth_namespace,
	&ctc_namespace,
	&lcs_namespace,
	NULL,
};

static int ns_modified[NUM_NAMESPACES];

/* Return the index of NS in the namespaces array. */
int namespaces_index(struct namespace *ns)
{
	int i;

	for (i = 0; namespaces[i]; i++) {
		if (namespaces[i] == ns)
			return i;
	}

	/* Should not happen. */
	return -1;
}

/* Check if the specified string is a valid ID for any known namespace. */
bool namespaces_is_id_valid(const char *id)
{
	struct namespace *ns;
	int i;

	for (i = 0; (ns = namespaces[i]); i++) {
		if (ns_is_id_valid(ns, id))
			return true;
	}

	return false;
}

/* Check if the specified string is a valid ID range for any known namespace. */
bool namespaces_is_id_range_valid(const char *range)
{
	struct namespace *ns;
	int i;

	for (i = 0; (ns = namespaces[i]); i++) {
		if (ns_is_id_range_valid(ns, range))
			return true;
	}

	return false;
}

/* Check known subtypes of the same namespace for the existence of a device
 * with the specified ID. Return pointer to first matching subtype found. */
bool namespaces_device_exists(struct namespace *ns, const char *id,
			      config_t config, struct subtype **st_ptr)
{
	int i, j;
	struct devtype *dt;
	struct subtype *st;

	for (i = 0; (dt = devtypes[i]); i++) {
		for (j = 0; (st = dt->subtypes[j]); j++) {
			if (st->namespace != ns)
				continue;
			if (subtype_device_exists(st, id, config)) {
				if (st_ptr)
					*st_ptr = st;
				return true;
			}
		}
	}

	return false;
}

/* Mark a namespace as modified. */
void namespace_set_modified(struct namespace *target)
{
	struct namespace *ns;
	int i;

	for (i = 0; (ns = namespaces[i]); i++) {
		if (ns == target) {
			ns_modified[i] = 1;
			break;
		}
	}
}

/* Make all modified blacklists persistent. */
exit_code_t namespace_exit(void)
{
	struct namespace *ns, *ns_done;
	int i, j;
	exit_code_t rc, drc = EXIT_OK;

	for (i = 0; (ns = namespaces[i]); i++) {
		if (!ns->blacklist_persist || !ns_modified[i])
			continue;

		/* In case of shared blacklist persist functions, call function
		 * only once. */
		for (j = 0; j < i; j++) {
			ns_done = namespaces[j];
			if (!ns_modified[j])
				continue;
			if (ns->blacklist_persist == ns_done->blacklist_persist)
				break;
		}
		if (j < i)
			continue;

		rc = ns->blacklist_persist();
		if (rc && !drc)
			drc = rc;
	}

	return drc;
}

/* Return a newly allocated and initialized namespace iterator object. */
struct ns_range_iterator *ns_range_iterator_new(void)
{
	return misc_malloc(sizeof(struct ns_range_iterator));
}

/* Release all resources associated the specified namespace iterator object. */
void ns_range_iterator_free(struct ns_range_iterator *it)
{
	free(it->devid);
	free(it->devid_last);
	free(it->id);
	free(it);
}

/* Check if the specified @id is valid for the given namespace @ns. */
bool ns_is_id_valid(struct namespace *ns, const char *id)
{
	if (ns->is_id_valid(id, err_ignore) == EXIT_OK)
		return true;

	return false;
}

/* Check if the specified @range is valid for the given namespace @ns. */
bool ns_is_id_range_valid(struct namespace *ns, const char *range)
{
	if (ns->is_id_range_valid(range, err_ignore) == EXIT_OK)
		return true;

	return false;
}
