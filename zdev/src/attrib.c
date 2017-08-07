/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "attrib.h"
#include "misc.h"

/* Parse the string in VAL as a number of notation N. If NUM is non-null
 * store the resulting number there and return true. Return false
 * in case of parse error. */
static bool parse_num(struct notation *n, const char *val, long long *num)
{
	int i;
	long long r;
	char d;

	/* Check for octal number first in case of leading 0. */
	for (i = 0; val[i]; i++)
		if (isspace(val[i]))
			return false;
	if (n->oct && (strlen(val) > 1) && (val[0] == '0') && isdigit(val[1])) {
		if (sscanf(val, "%llo %c", (unsigned long long *) &r, &d) == 1)
			goto ok;
	}
	if (n->dec) {
		if (sscanf(val, "%lld %c", &r, &d) == 1)
			goto ok;
	}
	if (n->hex) {
		if (sscanf(val, "%llx %c", (unsigned long long *) &r, &d) == 1)
			goto ok;
	}
	if (n->oct) {
		if (sscanf(val, "%llo %c", (unsigned long long *) &r, &d) == 1)
			goto ok;
	}

	return false;

ok:
	if (num)
		*num = r;

	return true;
}

/* Check if the specified value is a number in the acceptable notations
 * which is equal to n->val. */
static bool check_num(struct val_number *n, const char *val)
{
	long long num;

	if (!parse_num(&n->notation, val, &num))
		return false;
	if (num != n->val)
		return false;

	return true;
}

/* Check if the specified value is a number in the acceptable notations
 * which is greater or equal than n->val. */
static bool check_num_ge(struct val_number *n, const char *val)
{
	long long num;

	if (!parse_num(&n->notation, val, &num))
		return false;
	if (num < n->val)
		return false;

	return true;
}

/* Check if the specified value is a number in the acceptable notations
 * which is between n->from and n->to (from and to inclusively). */
static bool check_range(struct val_range *r, const char *val)
{
	long long num;

	if (!parse_num(&r->notation, val, &num))
		return false;
	if (num < r->from || num > r->to)
		return false;

	return true;
}

/* Check if value is acceptable for attribute. */
bool attrib_check_value(struct attrib *attrib, const char *val)
{
	struct accept_def *a;
	int i;

	if (!attrib->accept)
		return true;

	for (i = 0; attrib->accept[i].type != VAL_NONE; i++) {
		a = &attrib->accept[i];

		switch (a->type) {
		case VAL_NUM:
			if (check_num(&a->content.number, val))
				return true;
			break;
		case VAL_NUM_GE:
			if (check_num_ge(&a->content.number, val))
				return true;
			break;
		case VAL_RANGE:
			if (check_range(&a->content.range, val))
				return true;
			break;
		case VAL_STRING:
			if (strcmp(a->content.string, val) == 0)
				return true;
			break;
		case VAL_FUNC:
			if (a->content.func(attrib, val))
				return true;
			break;
		default:
			break;
		}
	}

	return false;
}

static const char *notation_to_str(struct notation *n)
{
	if (n->dec && n->hex && n->oct)
		return " in decimal, hexadecimal or octal notation";
	if (n->dec && n->hex)
		return " in decimal or hexadecimal notation";
	if (n->dec && n->oct)
		return " in decimal or octal notation";
	if (n->hex && n->oct)
		return " in hexadecimal or octal notation";
	if (n->dec)
		return "";
	if (n->hex)
		return " in hexadecimal notation";
	if (n->oct)
		return " in octal notation";

	return "";
}

#define pr_val(x, ...)	do { if ((x) < 0) \
				delayed_info(__VA_ARGS__); \
			else \
				indent((x), __VA_ARGS__); } while (0)

/* List acceptable values for the specified attributes. If @ind is a negative
 * number, messages are printed using delayed_info(), otherwise messages
 * are indented by the corresponding number of blank characters. */
void attrib_print_acceptable(struct attrib *attrib, int ind)
{
	struct accept_def *a;
	int i;

	if (!attrib->accept) {
		pr_val(ind, "All values are accepted\n");
		return;
	}

	for (i = 0; attrib->accept[i].type != VAL_NONE; i++) {
		a = &attrib->accept[i];

		switch (a->type) {
		case VAL_NUM:
			pr_val(ind, "- Integer %lld%s\n",
			       a->content.number.val,
			       notation_to_str(&a->content.number.notation));
			break;
		case VAL_NUM_GE:
			pr_val(ind, "- Integers greater or equal to %lld%s\n",
			       a->content.number.val,
			       notation_to_str(&a->content.number.notation));
			break;
		case VAL_RANGE:
			pr_val(ind, "- Integers in the range %lld - %lld%s\n",
			       a->content.range.from, a->content.range.to,
			       notation_to_str(&a->content.range.notation));
			break;
		case VAL_STRING:
			pr_val(ind, "- Text string '%s'\n", a->content.string);
			break;
		case VAL_FUNC:
			pr_val(ind, "- Other value checked dynamically\n");
			break;
		default:
			break;
		}

	}
}

/* Check if provided value matches default value. */
bool attrib_match_default(struct attrib *attrib, const char *val)
{
	size_t l1, l2;

	if (!attrib->defval)
		return false;
	/* Exact match. */
	if (strcmp(attrib->defval, val) == 0)
		return true;
	/* Match with new-line at the end. */
	l1 = strlen(attrib->defval);
	l2 = strlen(val);
	if (l2 == (l1 + 1) && val[l2 - 1] == '\n' &&
	    strncmp(attrib->defval, val, l1) == 0)
		return true;
	return false;
}

/* Find an attribute by name in a NULL-terminated array of attributes. */
struct attrib *attrib_find(struct attrib **attribs, const char *name)
{
	int i;

	for (i = 0; attribs[i]; i++) {
		if (strcmp(attribs[i]->name, name) == 0)
			return attribs[i];
	}

	return NULL;
}

/* Return a replacement for @value read from attribute @attrib or NULL if
 * there is no replacement. */
const char *attrib_map_value(struct attrib *attrib, const char *value)
{
	int i;

	if (!attrib->map)
		return NULL;
	for (i = 0; attrib->map[i].from; i++) {
		if (strcmp(value, attrib->map[i].from) == 0)
			return attrib->map[i].to;
	}

	return NULL;
}

/* Determine if attribute name @name starts with attribute name prefix
 * @prefix. */
bool attrib_match_prefix(const char *name, const char *prefix)
{
	size_t len;

	len = strlen(prefix);
	if (strncmp(name, prefix, len) == 0 && name[len] == '/')
		return true;

	return false;
}

/* Return attribute name @name without prefix @prefix. */
const char *attrib_rem_prefix(const char *name, const char *prefix)
{
	size_t len;

	len = strlen(prefix);
	if (strncmp(name, prefix, len) == 0 && name[len] == '/')
		name += len + 1;

	return name;
}
