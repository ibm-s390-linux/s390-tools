/*
 * util - Utility function library
 *
 * Linked lists
 *
 * Copyright IBM Corp. 2013, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef LIB_UTIL_LIST_H
#define LIB_UTIL_LIST_H

#include <stddef.h>

struct util_list {
	unsigned long offset;		/* Offset of struct util_list_node */
	struct util_list_node *start;	/* First element */
	struct util_list_node *end;	/* Last element */
};

struct util_list_node {
	struct util_list_node *next;
	struct util_list_node *prev;
};

#define util_list_new(type, member) util_list_new_offset(offsetof(type, member))
#define util_list_init(list, type, member) \
	util_list_init_offset(list, offsetof(type, member))
void util_list_free(struct util_list *list);
struct util_list *util_list_new_offset(unsigned long offset);
void util_list_init_offset(struct util_list *list, unsigned long offset);
void util_list_add_tail(struct util_list *list, void *entry);
void util_list_add_head(struct util_list *list, void *entry);
void util_list_add_next(struct util_list *list, void *entry, void *list_entry);
void util_list_add_prev(struct util_list *list, void *entry, void *list_entry);
void util_list_remove(struct util_list *list, void *entry);
void *util_list_next(struct util_list *list, void *entry);
void *util_list_prev(struct util_list *list, void *entry);
void *util_list_start(struct util_list *list);
void *util_list_end(struct util_list *list);
int util_list_is_empty(struct util_list *list);
unsigned long util_list_len(struct util_list *list);

/*
 * The compare function should return the following:
 *  a < b --> < 0
 *  a > b --> > 0
 *  a = b --> = 0
 */
typedef int (*util_list_cmp_fn)(void *a, void *b, void *data);
void util_list_sort(struct util_list *list, util_list_cmp_fn fn, void *data);

#define util_list_iterate(list, i)		\
	for (i = util_list_start(list);		\
	     i != NULL;				\
	     i = util_list_next(list, i))	\

#define util_list_iterate_safe(list, i, n)				\
	for (i = util_list_start(list), n = util_list_next(list, i);	\
	     i != NULL;							\
	     i = n, n = util_list_next(list, i))			\

#endif /* LIB_UTIL_LIST_H */
