/*
 * util - Utility function library
 *
 * Linked list functions
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/util_libc.h"
#include "lib/util_list.h"

/*
 * Node to entry
 */
static inline void *n2e(struct util_list *list, struct util_list_node *node)
{
	return ((void *) node) - list->offset;
}

/*
 * Entry to node
 */
static inline struct util_list_node *e2n(struct util_list *list, void *entry)
{
	return entry + list->offset;
}

/*
 * Initialize linked list
 */
void util_list_init_offset(struct util_list *list, unsigned long offset)
{
	memset(list, 0, sizeof(*list));
	list->offset = offset;
}

/*
 * Create new linked list
 */
struct util_list *util_list_new_offset(unsigned long offset)
{
	struct util_list *list = util_malloc(sizeof(*list));

	util_list_init_offset(list, offset);
	return list;
}

/*
 * Free linked list
 */
void util_list_free(struct util_list *list)
{
	free(list);
}

/*
 * Add new element to end of list
 */
void util_list_add_tail(struct util_list *list, void *entry)
{
	struct util_list_node *node = e2n(list, entry);

	node->next = NULL;
	if (!list->start) {
		list->start = node;
		node->prev = NULL;
	} else {
		list->end->next = node;
		node->prev = list->end;
	}
	list->end = node;
}

/*
 * Add new element to front of list
 */
void util_list_add_head(struct util_list *list, void *entry)
{
	struct util_list_node *node = e2n(list, entry);

	node->prev = NULL;
	node->next = NULL;
	if (!list->start) {
		list->end = node;
	} else {
		list->start->prev = node;
		node->next = list->start;
	}
	list->start = node;
}

/*
 * Add new element (entry) after an existing element (list_entry)
 */
void util_list_add_next(struct util_list *list, void *entry, void *list_entry)
{
	struct util_list_node *node = e2n(list, entry);
	struct util_list_node *list_node = e2n(list, list_entry);

	node->next = list_node->next;
	node->prev = list_node;
	if (list_node->next)
		list_node->next->prev = node;
	else
		list->end = node;
	list_node->next = node;
}

/*
 * Add new element (entry) before an existing element (list_entry)
 */
void util_list_add_prev(struct util_list *list, void *entry, void *list_entry)
{
	struct util_list_node *node = e2n(list, entry);
	struct util_list_node *list_node = e2n(list, list_entry);

	node->prev = list_node->prev;
	node->next = list_node;
	if (list_node->prev)
		list_node->prev->next = node;
	else
		list->start = node;
	list_node->prev = node;
}

/*
 * Remove element from list
 */
void util_list_remove(struct util_list *list, void *entry)
{
	struct util_list_node *node = e2n(list, entry);

	if (list->start == node)
		list->start = node->next;
	if (list->end == node)
		list->end = node->prev;
	if (node->prev)
		node->prev->next = node->next;
	if (node->next)
		node->next->prev = node->prev;
}

/*
 * Get first element of list
 */
void *util_list_start(struct util_list *list)
{
	if (!list->start)
		return NULL;
	return ((void *) list->start) - list->offset;
}

/*
 * Get last element of list
 */
void *util_list_end(struct util_list *list)
{
	if (!list->end)
		return NULL;
	return n2e(list, list->end);
}

/*
 * Get next element after entry
 */
void *util_list_next(struct util_list *list, void *entry)
{
	struct util_list_node *node;

	if (!entry)
		return NULL;
	node = e2n(list, entry);
	node = node->next;
	if (!node)
		return NULL;
	return n2e(list, node);
}

/*
 * Get previous element before entry
 */
void *util_list_prev(struct util_list *list, void *entry)
{
	struct util_list_node *node;

	if (!entry)
		return NULL;
	node = e2n(list, entry);
	node = node->prev;
	if (!node)
		return NULL;
	return n2e(list, node);
}

/*
 * Get number of list entries
 */
unsigned long util_list_len(struct util_list *list)
{
	unsigned long cnt = 0;
	void *entry;

	util_list_iterate(list, entry)
		cnt++;
	return cnt;
}

/*
 * Sort table (bubble sort)
 */
void util_list_sort(struct util_list *list, util_list_cmp_fn cmp_fn,
		    void *data)
{
	struct util_list_node *node1, *node2;
	unsigned long list_cnt, i, j;
	void *entry1, *entry2;

	list_cnt = util_list_len(list);

	for (i = 1; i < list_cnt; i++) {
		node1 = list->start;
		for (j = 0; j < list_cnt - i; j++) {
			node2 = node1->next;
			entry1 = n2e(list, node1);
			entry2 = n2e(list, node2);
			if (cmp_fn(entry1, entry2, data) > 0) {
				node1->next = node2->next;
				if (node1->next)
					node1->next->prev = node1;
				else
					list->end = node1;
				node2->next = node1;
				node2->prev = node1->prev;
				if (node2->prev)
					node2->prev->next = node2;
				else
					list->start = node2;
				node1->prev = node2;
			} else {
				node1 = node2;
			}
		}
	}
}

/*
 * Check if list is empty
 */
int util_list_is_empty(struct util_list *list)
{
	return list->start == NULL;
}
