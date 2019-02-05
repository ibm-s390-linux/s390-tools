/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2019
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ATTRIB_H
#define ATTRIB_H

#include <stdbool.h>
#include <stddef.h>

#include "misc.h"

struct setting;

/**
 * enum val_type_t - Enumeration of acceptable value definition types
 * @VAL_NUM:    A single integer number
 * @VAL_NUM_GE: Any integer number with a lower limit
 * @VAL_RANGE:  A range of integer numbers
 * @VAL_STRING: A single text string
 * @VAL_FUNC:   A function that checks the input
 * @VAL_NONE:   Value to indicate the end of a struct value_accept list
 */
typedef enum {
	VAL_NONE = 0,
	VAL_NUM,
	VAL_NUM_GE,
	VAL_RANGE,
	VAL_STRING,
	VAL_FUNC,
	/* Array delimiter. */
} val_type_t;

/**
 * struct notation - Define acceptable notations for a number
 * dec:  Decimal numbers are acceptable
 * hex:  Hexadecimal numbers are acceptable
 * oct:  Octal numbers are acceptable
 */
struct notation {
	unsigned int dec:1;
	unsigned int hex:1;
	unsigned int oct:1;
};

/**
 * struct val_number - Define parameters for an acceptable integer
 * val:      Acceptable value
 * notation: Acceptable notations in which the number can be presented
 */
struct val_number {
	long long val;
	struct notation notation;
};

/**
 * struct val_range - Define parameters for acceptable integers within a range
 * from:     Minimum acceptable value
 * to:       Maximum acceptable value
 * notation: Acceptable notations in which the number can be presented
 */
struct val_range {
	long long from;
	long long to;
	struct notation notation;
};

struct attrib;

/**
 * union accept_def_content - Content of an attribute value definition
 * @number:  Define an acceptable integer or lower limit (VAL_NUM+VAL_NUM_GE)
 * @range:   Define a range of acceptable integers (VAL_RANGE)
 * @string:  Define an acceptable string (VAL_STRING)
 * @func:    Define a function that checks for acceptable values (VAL_FUNC)
 */
union accept_def_content {
	struct val_number number;
	struct val_range range;
	const char *string;
	int (*func)(struct attrib *, const char *);
};

/**
 * struct accept_def - Define an acceptable attribute value
 * @type:    Basic value type
 */
struct accept_def {
	val_type_t type;
	union accept_def_content content;
};

/* Helpers to more easily define acceptable attribute values. */

/* Accept decimal integer value equal to NUM. */
#define ACCEPT_NUM(num)					\
	{						\
	  .type = VAL_NUM,				\
	  .content = {					\
			.number = {			\
				.val = (num),		\
				.notation = {		\
					.dec = 1	\
				},			\
			},				\
		 }					\
	}

/* Accept decimal integer values greater than or equal to NUM. */
#define ACCEPT_NUM_GE(num)				\
	{						\
	  .type = VAL_NUM_GE,				\
	  .content = {					\
			.number = {			\
				.val = (num),		\
				.notation = {		\
					.dec = 1	\
				},			\
			},				\
		 }					\
	}

/* Accept decimal integer values from START to END. */
#define ACCEPT_RANGE(start, end)				\
	{						\
	  .type = VAL_RANGE,				\
	  .content = {					\
			.range = {			\
				.from = (start),	\
				.to = (end),		\
				.notation = {		\
					.dec = 1	\
				},			\
			},				\
		 }					\
	}

/* Accept string value STR. */
#define ACCEPT_STR(str)					\
	{						\
	  .type = VAL_STRING,				\
	  .content = {					\
			.string = (str)			\
		 }					\
	}

/* Start a list of ACCEPT_* macros and terminate with VAL_NONE element. */
#define ACCEPT_ARRAY(...)                               \
	((struct accept_def[]) { __VA_ARGS__, { .type = VAL_NONE } })

#define ATTRIB_TITLE_LEN	50

#define ATTRIB_ARRAY(...)				\
	((struct attrib *[]) { __VA_ARGS__ NULL })

/**
 * struct value_map - Define a value mapping for an attribute
 * @from: Value which should be replaced when read in the active config
 * @to:   Target value for mapping
 */
struct value_map {
	const char *from;
	const char *to;
};

#define VALUE_MAP(a, b)		{ .from = (a), .to = (b) }
#define VALUE_MAP_ARRAY(...)				\
	((struct value_map []) { __VA_ARGS__, { .from = NULL, .to = NULL }, })

/**
 * struct attrib - Define an attribute
 * @name:       Attribute name
 * @title:      Short, one-line attribute description (max 50 characters)
 * @desc:       Detailed, multi-line attribute description
 * @multi:      This attribute accepts multiple values
 * @activeonly: This attribute should only be changed in the active config
 * @unstable:   The value read is not the last value written
 * @writeonly:  This attribute cannot be read from
 * @readonly:   This attribute cannot be written to
 * @rewrite:    Writing the same value multiple times has side-effects
 * @mandatory:	This attribute cannot be removed from a configured device
 * @newline:    There must be a newline when writing to this attribute
 * @activerem:  This attribute can be removed in the active configuration
 * @defunset:   There is no difference between not set and set to default value
 *              in the persistent configuration
 * @nounload:   (Device type attributes only) This attribute can be set while
 *              the corresponding kernel module remains loaded.
 * @internal:   This attribute only affects internal handling
 * @order:	A number indicating the order in which to apply attribute
 * @order_cmp:  A function determining if a setting for this attribute should
 *              be applied before (-1) or after (1) another setting, or
 *              if there are no ordering requirements (0).
 * @check:      Check if settings for this attribute are compatible with
 *              settings of another attribute.
 * @defval:     Default attribue value (optional)
 * @accept:     List of acceptable settings (optional)
 * @map:        List of values read in the active config that should be replaced
 * @st_data:    Subtype specific attribute data (optional)
 */
struct attrib {
	const char *name;
	const char title[ATTRIB_TITLE_LEN + 1];
	const char *desc;

	/* Flags */
	unsigned int multi	:1;
	unsigned int activeonly	:1;
	unsigned int unstable	:1;
	unsigned int writeonly	:1;
	unsigned int readonly	:1;
	unsigned int rewrite	:1;
	unsigned int mandatory	:1;
	unsigned int newline	:1;
	unsigned int activerem	:1;
	unsigned int defunset	:1;
	unsigned int nounload	:1;
	unsigned int internal	:1;

	/* Optional */
	int order;
	int (*order_cmp)(struct setting *, struct setting *);
	bool (*check)(struct setting *, struct setting *, config_t);
	const char *defval;
	struct accept_def *accept;
	struct value_map *map;
	void *st_data;
};

bool attrib_check_value(struct attrib *, const char *);
void attrib_print_acceptable(struct attrib *, int);
bool attrib_match_default(struct attrib *, const char *);
struct attrib *attrib_find(struct attrib **, const char *);
const char *attrib_map_value(struct attrib *, const char *);
bool attrib_match_prefix(const char *, const char *);
const char *attrib_rem_prefix(const char *, const char *);

#endif /* ATTRIB_H */
