/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2018
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>

#include "attrib.h"
#include "misc.h"
#include "path.h"
#include "setting.h"

/* Create and initialize a new setting. */
struct setting *setting_new(struct attrib *attrib, const char *name,
			    const char *val)
{
	struct setting *s;

	s = misc_malloc(sizeof(struct setting));
	s->attrib = attrib;
	if (attrib && !name)
		s->name = misc_strdup(attrib->name);
	else
		s->name = misc_strdup(name);
	s->value = misc_strdup(val);
	if (attrib && attrib->multi) {
		/* Split multi-line value into multiple values. */
		s->values = strlist_new();
		strlist_add_multi(s->values, val, "\n", 0);
	}

	return s;
}

/* Release all resources associated with the specified setting. */
static void setting_free(struct setting *s)
{
	if (!s)
		return;
	free(s->name);
	free(s->value);
	free(s->actual_value);
	strlist_free(s->values);
	strlist_free(s->actual_values);
	free(s);
}

/* Create a newly allocated setting copy. */
struct setting *setting_copy(const struct setting *s)
{
	struct setting *copy;

	copy = misc_malloc(sizeof(struct setting));
	copy->attrib = s->attrib;
	copy->name = misc_strdup(s->name);
	copy->value = misc_strdup(s->value);
	if (s->values)
		copy->values = strlist_copy(s->values);
	if (s->actual_value)
		copy->actual_value = misc_strdup(s->actual_value);
	if (s->actual_values)
		copy->actual_values = strlist_copy(s->actual_values);
	copy->modified = s->modified;
	copy->removed = s->removed;

	return copy;
}

/* Replace or add to the value of a setting. */
static void setting_mod_value(struct setting *s, const char *value)
{
	char *new_value;

	if (s->values) {
		/* Check if this is a rewrite of a previous value. */
		if (!s->derived && s->attrib && !s->attrib->rewrite &&
		    strlist_find(s->values, value))
			return;
		/* Attribute supports multiple values - add. */
		new_value = misc_asprintf("%s%s%s", s->value,
					  *s->value ? "\n" : "", value);
		free(s->value);
		s->value = new_value;
		strlist_add(s->values, value);
	} else {
		/* Check if this is a rewrite of a previous value. */
		if (!s->derived && s->attrib && !s->attrib->rewrite &&
		    strcmp(s->value, value) == 0)
			return;
		/* Attribute unknown or does not support multiple values -
		 * replace. */
		free(s->value);
		s->value = misc_strdup(value);
	}

	s->modified = 1;
	s->removed = 0;
}

/* Determine if a setting is set (that is configured). */
bool setting_is_set(struct setting *s)
{
	if (s->removed)
		return false;
	if (s->modified)
		return true;
	if (s->derived)
		return false;
	return true;
}

static void setting_set_actual(struct setting *s, const char *value)
{
	free(s->actual_value);
	s->actual_value = misc_strdup(value);
	if (s->attrib && s->attrib->multi) {
		strlist_free(s->actual_values);
		s->actual_values = strlist_new();
		strlist_add_multi(s->actual_values, value, "\n", 0);
	}
}

/* Write a single setting value to a sysfs attribute. */
static exit_code_t write_setting_value(const char *path, struct setting *s,
				       const char *value)
{
	struct attrib *a = s->attrib;
	int newline, rewrite, unstable, writeonly;
	exit_code_t rc = EXIT_OK;
	char *currvalue = NULL, *newvalue = NULL;

	newline = a ? a->newline : 0;
	rewrite = a ? a->rewrite : 0;
	unstable = a ? a->unstable : 0;
	writeonly = a ? a->writeonly : 0;

	/* Do we need to check for a rewrite? */
	if (rewrite || unstable || force)
		goto do_write;

	/* Get current value if necessary. */
	if (!s->actual_value && !writeonly) {
		currvalue = misc_read_text_file(path, 1, err_ignore);
		if (!currvalue)
			goto do_write;
		setting_set_actual(s, currvalue);
		free(currvalue);
	}

	/* Check if value is already set. */
	if (s->actual_values) {
		if (strlist_find(s->actual_values, value))
			goto out;
	} else if (s->actual_value) {
		if (strcmp(s->actual_value, value) == 0)
			goto out;
	}

do_write:
	/* Ensure newline if required. */
	if (newline && !ends_with(value, "\n"))
		newvalue = misc_asprintf("%s\n", value);

	rc = misc_write_text_file_retry(path, newvalue ? newvalue : value,
					err_delayed_print);
	if (rc)
		rc = EXIT_SETTING_FAILED;

out:
	free(newvalue);

	return rc;
}

/* Write a single setting to a sysfs attribute. */
exit_code_t setting_write(const char *path, struct setting *s)
{
	exit_code_t rc;
	struct strlist_node *str;

	if (!s->values) {
		/* Single value attribute. */
		return write_setting_value(path, s, s->value);
	}
	util_list_iterate(s->values, str) {
		rc = write_setting_value(path, s, str->str);
		if (rc)
			return rc;
	}

	return EXIT_OK;
}

/* Used for debugging. */
void setting_print(struct setting *s, int level)
{
	struct strlist_node *str;
	int i;

	printf("%*ssetting at %p\n", level, "", (void *) s);
	if (!s)
		return;
	level += 4;
	if (s->attrib)
		printf("%*sattrib=%s\n", level, "", s->attrib->name);
	else
		printf("%*sattrib=<none>\n", level, "");
	printf("%*sname='%s'\n", level, "", s->name);
	printf("%*svalue='%s'\n", level, "", s->value);
	if (s->values) {
		i = 0;
		util_list_iterate(s->values, str) {
			printf("%*svalues[%d]='%s'\n", level, "", i++,
			       str->str);
		}
	}
	if (s->actual_value)
		printf("%*sactual_value='%s'\n", level, "", s->actual_value);
	else
		printf("%*sactual_value=<none>\n", level, "");
	if (s->actual_values) {
		i = 0;
		util_list_iterate(s->actual_values, str) {
			printf("%*sactual_values[%d]='%s'\n", level, "", i++,
			       str->str);
		}
	}
	printf("%*smodified='%d'\n", level, "", s->modified);
	printf("%*sspecified='%d'\n", level, "", s->specified);
	printf("%*sremoved='%d'\n", level, "", s->removed);
	printf("%*sderived='%d'\n", level, "", s->derived);
	printf("%*sreadonly='%d'\n", level, "", s->readonly);
}

/* Create and initialize a new setting_list. */
struct setting_list *setting_list_new(void)
{
	struct setting_list *list;

	list = misc_malloc(sizeof(struct setting_list));
	util_list_init(&list->list, struct setting, node);

	return list;
}

/* Remove all settings from list. */
void setting_list_clear(struct setting_list *list)
{
	struct setting *s, *n;

	util_list_iterate_safe(&list->list, s, n) {
		util_list_remove(&list->list, s);
		setting_free(s);
	}
}

/* Release resources used by list and enlisted settings. */
void setting_list_free(struct setting_list *list)
{
	if (!list)
		return;
	setting_list_clear(list);

	free(list);
}

/* Add a new element to a list and mark the list as modified. */
void setting_list_add(struct setting_list *list, struct setting *setting)
{
	util_list_add_tail(&list->list, setting);
	list->modified = 1;
}

/* Find an element in the list. */
struct setting *setting_list_find(struct setting_list *list, const char *name)
{
	struct setting *s;

	util_list_iterate(&list->list, s) {
		if (strcmp(s->name, name) == 0)
			return s;
	}

	return NULL;
}

static struct setting *add_setting(struct setting_list *list,
				   struct attrib *attrib,
				   const char *name, const char *value,
				   int new_modified)
{
	struct setting *s;

	s = setting_list_find(list, name);
	if (s)
		setting_mod_value(s, value);
	else {
		s = setting_new(attrib, name, value);
		setting_list_add(list, s);
		if (new_modified)
			s->modified = 1;
	}

	return s;
}

/* Modify existing setting or add new one. */
struct setting *setting_list_apply(struct setting_list *list,
				   struct attrib *attrib, const char *name,
				   const char *value)
{
	return add_setting(list, attrib, name, value, 1);
}

/* Modify existing setting or add new one based on user request. */
struct setting *setting_list_apply_specified(struct setting_list *list,
					     struct attrib *attrib,
					     const char *name,
					     const char *value)
{
	struct setting *s;

	s = add_setting(list, attrib, name, value, 1);
	s->specified = 1;

	return s;
}

/* Set actual value for existing setting or add new one. */
struct setting *setting_list_apply_actual(struct setting_list *list,
					  struct attrib *attrib,
					  const char *name, const char *value)
{
	struct setting *s;

	s = add_setting(list, attrib, name, value, 0);
	setting_set_actual(s, value);

	return s;
}

/* Check if a setting was modified. */
bool setting_list_modified(struct setting_list *list)
{
	struct setting *s;

	if (!list)
		return false;
	util_list_iterate(&list->list, s) {
		if (s->modified)
			return true;
	}

	return false;
}

/* Determine the state of a boolean attribute with the given name in the
 * specified setting list. */
void setting_list_get_bool_state(struct setting_list *list, const char *name,
				 int *changed, int *set)
{
	struct setting *s;

	s = setting_list_find(list, name);
	if (!s) {
		*changed = 0;
		*set = 0;
		return;
	}

	if (strcmp(s->value, "1") == 0)
		*set = 1;
	else
		*set = 0;

	if (s->actual_value && strcmp(s->value, s->actual_value) != 0)
		*changed = 1;
	else
		*changed = 0;
}

/* Return a newly allocated space-separated string containing all non-removed
 * settings in KEY=VALUE format. */
char *setting_list_flatten(struct setting_list *list)
{
	struct setting *s;
	int i;
	char *str;

	/* Determine total string length. */
	i = 1;
	util_list_iterate(&list->list, s) {
		if (s->removed)
			continue;
		i += strlen(s->name) + 1 + strlen(s->value) + 1;
	}
	str = misc_malloc(i);

	/* Combine string. */
	i = 0;
	util_list_iterate(&list->list, s) {
		if (s->removed)
			continue;
		i += sprintf(&str[i], "%s%s=%s", i == 0 ? "" : " ", s->name,
			     s->value);
	}

	return str;
}

/* Used for debugging. */
void setting_list_print(struct setting_list *list, int level)
{
	struct setting *s;

	printf("%*ssetting list at %p\n", level, "", (void *) list);
	if (!list)
		return;
	util_list_iterate(&list->list, s)
		setting_print(s, level + 4);
}

/* Determine the order of applying attributes based on the attribute order
 * information. */
static int setting_cmp(struct setting *a, struct setting *b)
{
	int result;

	if (!a->attrib || !b->attrib)
		return 0;

	/* Try order_cmp first if available. */
	if (a->attrib && a->attrib->order_cmp) {
		result = a->attrib->order_cmp(a, b);
		if (result != 0)
			return result;
	}
	if (b->attrib && b->attrib->order_cmp) {
		result = b->attrib->order_cmp(b, a);
		if (result != 0)
			return -result;
	}

	/* Try static ordering next. */
	if (a->attrib->order < b->attrib->order)
		return -1;
	if (a->attrib->order > b->attrib->order)
		return 1;

	/* Don't fallback to strcmp or similar here since that could
	 * conflict with an actual ordering requirement reported by
	 * a cmp callback. */

	return 0;
}

/* Return a newly allocated ptrlist of settings sorted according to
 * order_cmp. */
struct util_list *setting_list_get_sorted(struct setting_list *list)
{
	struct util_list *result;
	struct setting *s;
	struct ptrlist_node *p;

	result = ptrlist_new();
	p = NULL;
	util_list_iterate(&list->list, s) {
		/* Find first element that should be after new element
		 * in list. */
		util_list_iterate(result, p) {
			if (setting_cmp(p->ptr, s) > 0)
				break;
		}
		if (p)
			ptrlist_add_before(result, p, s);
		else
			ptrlist_add(result, s);
	}
	return result;
}

/* Check if there is any conflict between settings in @list. Display errors
 * according to @err. Return %false if there is a conflict, %true otherwise. */
bool setting_list_check_conflict(struct setting_list *list, config_t config,
				 err_t err)
{
	struct setting *a, *b;

	util_list_iterate(&list->list, a) {
		if (!a->attrib || !a->attrib->check)
			continue;
		if (a->removed)
			continue;
		if (!a->modified && !a->specified)
			continue;
		util_list_iterate(&list->list, b) {
			if (a == b)
				continue;
			if (!a->attrib->check(a, b, config))
				goto conflict;
		}
	}

	return true;

conflict:
	err_t_print(err, "Cannot set %s='%s' while %s='%s'\n", a->name,
		    a->value, b->name, b->value);

	return false;
}

/* Add settings with default values to @list for all attributes in @attribs
 * for which no setting has been added. If @mand_only is specified, only
 * apply default values for mandatory settings. */
void setting_list_apply_defaults(struct setting_list *list,
				 struct attrib **attribs, bool mand_only)
{
	int i;
	struct attrib *a;
	struct setting *s;

	for (i = 0; (a = attribs[i]); i++) {
		if (!a->defval)
			continue;
		if (mand_only && !a->mandatory)
			continue;
		s = setting_list_find(list, a->name);
		if (s)
			continue;
		s = setting_list_apply_actual(list, a, a->name, a->defval);
		s->derived = 1;
	}
}

/* Merge settings from setting list @from into @to. If @specified is true,
 * also copy specified flag. If @modified is true, also copy modified flag. */
void setting_list_merge(struct setting_list *to, struct setting_list *from,
			bool specified, bool modified)
{
	struct setting *s, *n;

	util_list_iterate(&from->list, s) {
		n = setting_list_apply(to, s->attrib, s->name, s->value);
		if (specified)
			n->specified = s->specified;
		if (modified)
			n->modified = s->modified;
	}
}

/* Return a copy of setting list @list. */
struct setting_list *setting_list_copy(struct setting_list *list)
{
	struct setting_list *copy;
	struct setting *s;

	copy = setting_list_new();
	util_list_iterate(&list->list, s)
		util_list_add_tail(&copy->list, setting_copy(s));
	copy->modified = list->modified;

	return copy;
}

/* Apply the attribute value replacement map for all settings in list which
 * define such a map. */
void setting_list_map_values(struct setting_list *list)
{
	struct setting *s;
	struct attrib *a;
	const char *to;

	util_list_iterate(&list->list, s) {
		a = s->attrib;
		if (!a || !a->map)
			continue;
		to = attrib_map_value(a, s->value);
		if (!to)
			continue;
		free(s->value);
		s->value = misc_strdup(to);
	}
}

/* Mark all settings in @list as derived which have an actual_value equal
 * to the default value. */
void setting_list_mark_default_derived(struct setting_list *list)
{
	struct setting *s;

	util_list_iterate(&list->list, s) {
		if (!s->attrib || !s->attrib->defval || !s->actual_value)
			continue;
		if (!attrib_match_default(s->attrib, s->actual_value))
			continue;
		s->derived = 1;
	}
}

/* Return the number of settings in @list that are set. */
int setting_list_count_set(struct setting_list *list)
{
	struct setting *s;
	int set;

	set = 0;
	util_list_iterate(&list->list, s) {
		if (setting_is_set(s))
			set++;
	}
	return set;
}

/* Remove all settings in @list which are derived. */
void setting_list_remove_derived(struct setting_list *list)
{
	struct setting *s, *n;

	util_list_iterate_safe(&list->list, s, n) {
		if (!s->derived)
			continue;
		util_list_remove(&list->list, s);
		setting_free(s);
	}
}

static void add_changes(struct util_list *list, struct setting *s)
{
	struct strlist_node *str;

	if (s->values) {
		/* Multi value attribute. */
		util_list_iterate(s->values, str)
			strlist_add(list, "%s=%s", s->name, str->str);
	} else {
		/* Single value attribute. */
		strlist_add(list, "%s=%s", s->name, s->value);
	}
}

/* Return a newly allocated string containing the setting changes found
 * in PERS and ACT or NULL if no change was found. */
char *setting_get_changes(struct setting_list *act, struct setting_list *pers,
			  struct setting_list *ac)
{
	struct util_list *out;
	struct util_list *processed;
	struct setting *s;
	char *result;

	out = strlist_new();
	processed = strlist_new();

	/* Collect modified settings. */
	if (pers) {
		util_list_iterate(&pers->list, s) {
			if (s->removed)
				strlist_add(out, "-%s", s->name);
			else if (s->modified)
				add_changes(out, s);
			else
				continue;
			strlist_add(processed, s->name);
		}
	}
	if (ac) {
		util_list_iterate(&ac->list, s) {
			if (s->removed)
				strlist_add(out, "-%s", s->name);
			else if (s->modified)
				add_changes(out, s);
			else
				continue;
			strlist_add(processed, s->name);
		}
	}
	if (act) {
		util_list_iterate(&act->list, s) {
			if (!s->modified && !s->removed)
				continue;
			if (strlist_find(processed, s->name))
				continue;
			if (s->removed)
				strlist_add(out, "-%s", s->name);
			else
				add_changes(out, s);
			strlist_add(processed, s->name);
		}
	}

	if (!util_list_is_empty(out))
		result = strlist_flatten(out, " ");
	else
		result = NULL;

	strlist_free(processed);
	strlist_free(out);

	return result;
}

/* Check if @value matches the value of setting @s. */
bool setting_match_value(struct setting *s, const char *value)
{
	struct strlist_node *str;

	if (s->values) {
		util_list_iterate(s->values, str) {
			if (strcmp(str->str, value) == 0)
				return true;
		}
	}
	if (s->value) {
		if (strcmp(s->value, value) == 0)
			return true;
	}

	return false;
}
