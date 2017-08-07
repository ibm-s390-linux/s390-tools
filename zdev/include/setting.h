/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef SETTING_H
#define SETTING_H

#include "lib/util_list.h"

#include "exit_code.h"
#include "misc.h"

struct attrib;

/**
 * struct setting - An attribute setting
 * @node: List node for adding to list
 * @attrib: Attribute definition - optional for unknown attribute settings
 * @name: Attribute name
 * @value: Attribute value
 * @values: List of values for multi-value attributes
 * @actual_value: Current attribute value
 * @actual_values: List of current values for multi-value attributes
 * @modified: Setting was modified or is new
 * @specified: User specified a value for this setting
 * @derived: The actual value was not read from the configuration
 * @removed: Setting was removed
 * @readonly: Setting cannot be written to
 */
struct setting {
	struct util_list_node node;
	struct attrib *attrib;
	char *name;
	char *value;
	struct util_list *values;
	char *actual_value;
	struct util_list *actual_values;
	unsigned int modified:1;
	unsigned int specified:1;
	unsigned int removed:1;
	unsigned int derived:1;
	unsigned int readonly:1;
};

/**
 * struct setting_list - A list of attribute settings
 * @list: List for maintaining settings
 * @modified: Indication of whether this list was modified
 */
struct setting_list {
	struct util_list list;
	unsigned int modified:1;
};

struct setting *setting_new(struct attrib *, const char *, const char *);
struct setting *setting_copy(const struct setting *);
bool setting_is_set(struct setting *);
exit_code_t setting_write(const char *, struct setting *s);
void setting_print(struct setting *, int);

struct setting_list *setting_list_new(void);
void setting_list_free(struct setting_list *);
void setting_list_clear(struct setting_list *);
void setting_list_add(struct setting_list *, struct setting *);
struct setting *setting_list_find(struct setting_list *, const char *);
void setting_list_get_bool_state(struct setting_list *, const char *, int *,
				 int *);
struct setting *setting_list_apply(struct setting_list *, struct attrib *,
				   const char *, const char *);
struct setting *setting_list_apply_specified(struct setting_list *,
					     struct attrib *, const char *,
					     const char *);

struct setting *setting_list_apply_actual(struct setting_list *,
					  struct attrib *, const char *,
					  const char *);

bool setting_list_modified(struct setting_list *);
char *setting_list_flatten(struct setting_list *);
void setting_list_print(struct setting_list *, int);
struct util_list *setting_list_get_sorted(struct setting_list *);
bool setting_list_check_conflict(struct setting_list *, config_t, err_t);

void setting_list_apply_defaults(struct setting_list *, struct attrib **, bool);
void setting_list_merge(struct setting_list *, struct setting_list *, bool,
			bool);
struct setting_list *setting_list_copy(struct setting_list *);
void setting_list_map_values(struct setting_list *);
void setting_list_mark_default_derived(struct setting_list *);
int setting_list_count_set(struct setting_list *);
void setting_list_remove_derived(struct setting_list *);
char *setting_get_changes(struct setting_list *, struct setting_list *);
bool setting_match_value(struct setting *, const char *);

#endif /* SETTING_H */
