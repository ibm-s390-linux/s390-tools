/*
 * util_fmt - Format structured key-value data as JSON, text pairs, or CSV
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 * This module provides helper functions for converting structured key-value
 * data into different output formats.
 *
 * Benefits:
 * - Output format can be dynamically configured at run-time
 * - Callers do not need to add extra code for each output format
 * - Some format-specific requirements such as quoting, indentation, and
 *   comma-placement are automated
 *
 * Basic API calling sequence:
 *
 * util_fmt_init()      => Select output format
 * util_fmt_obj_start() => Start a new object or list
 * util_fmt_pair()      => Emit a key-value pair
 * util_fmt_obj_end()   => End the latest object or list
 * util_fmt_exit()      => Cleanup
 *
 * Note:
 * - Supported data elements are objects, lists and key-value pairs (mappings)
 * - Scalars are only supported as part of a mapping
 * - For CSV output and key filtering, mapping keys must be unique - this can
 *   be achieved either by choosing unique key names or by including object
 *   names via the FMT_PREFIX flag
 * - For CSV output, at least one object or list with the FMT_ROW flag must be
 *   emitted
 * - Common tool-specific meta-information such as API-level, tool version,
 *   etc. is automatically added to the output
 */

#ifndef LIB_UTIL_FMT_H
#define LIB_UTIL_FMT_H

#include <stdbool.h>
#include <stdio.h>

/* Flag value for default behavior (all flag types). */
#define FMT_DEFAULT	0

/* Names of supported output format types. */
#define FMT_TYPE_NAMES	"json json-seq pairs csv"

/**
 * enum util_fmt_t - Output format types.
 * @FMT_JSON:    JavaScript Object Notation output data structure
 * @FMT_JSONSEQ: Sequence of JSON data structures according to RFC7464
 * @FMT_PAIRS:   Textual key=value pairs
 * @FMT_CSV:     Comma-separated-values output
 *
 * Use these types with util_fmt_init() to control the output format.
 */
enum util_fmt_t {
	FMT_JSON,
	FMT_JSONSEQ,
	FMT_PAIRS,
	FMT_CSV,
};

/**
 * enum util_fmt_flags_t - Format control flags.
 * @FMT_NOPREFIX:  (pairs) Remove object hierarchy prefix from keys
 * @FMT_KEEPINVAL: (all)   Print mappings even if value is marked as invalid
 *                         Values will be replaced with null (JSON) or an empty
 *                         string
 * @FMT_QUOTEALL:  (all)   Add quotes to all mapping values
 * @FMT_FILTER:    (all)   Ignore keys not announced via util_fmt_add_key()
 * @FMT_HANDLEINT: (json)  Ensure correct JSON closure when interrupted
 * @FMT_NOMETA:    (all)   Do not emit tool meta-data
 * @FMT_WARN:      (all)   Warn about incorrect API usage
 *
 * Use these flags with util_fmt_init() to control generic aspects.
 */
enum util_fmt_flags_t {
	FMT_NOPREFIX  = (1 << 0),
	FMT_KEEPINVAL = (1 << 1),
	FMT_QUOTEALL  = (1 << 2),
	FMT_FILTER    = (1 << 3),
	FMT_HANDLEINT = (1 << 4),
	FMT_NOMETA    = (1 << 5),
	FMT_WARN      = (1 << 6),
};

/**
 * enum util_fmt_oflags_t - Object flags.
 * @FMT_LIST:   (all) Object is a list
 * @FMT_ROW:    (csv) Start a new CSV row with this object
 * @FMT_PREFIX: (all) Include object name in key prefix for CSV headings
 *                    and filter keys
 *
 * Use these flags with util_fmt_obj_start() to control object related
 * aspects.
 */
enum util_fmt_oflags_t {
	FMT_LIST   = (1 << 0),
	FMT_ROW    = (1 << 1),
	FMT_PREFIX = (1 << 2),
};

/**
 * enum util_fmt_mflags_t - Mapping flags.
 * @FMT_QUOTE:   (all) Quote value
 * @FMT_INVAL:   (all) Mark value as invalid
 * @FMT_PERSIST: (csv) Keep value across CSV rows until overwritten
 *
 * Use these flags with util_fmt_pair() to control mapping related aspects.
 */
enum util_fmt_mflags_t {
	FMT_QUOTE   = (1 << 0),
	FMT_INVAL   = (1 << 1),
	FMT_PERSIST = (1 << 2),
};

/**
 * util_fmt_init() - Initialize output formatter.
 * @fd   : Output file descriptor
 * @type : Output format type
 * @flags: Formatting parameters
 * @api_level: Output format level indicator
 *
 * Prepare for writing formatted output with the given @type to @fd. Additional
 * @flags can be specified to control certain output aspects (see &enum
 * util_fmt_flags_t).
 *
 * @api_level represents an application-specific output format version number:
 * this number starts at 1 and must be increased whenever an incompatible format
 * change is introduced, e.g. when a non-optional object or mapping is removed
 * or used for different data.
 */
void util_fmt_init(FILE *fd, enum util_fmt_t type, unsigned int flags,
		   int api_level);

/**
 * util_fmt_exit() - Release resources used by output formatter.
 *
 * Release all resources currently in use by the output formatter.
 */
void util_fmt_exit(void);

/**
 * util_fmt_name_to_type() - Convert format name to type identifier.
 * @name: Format name
 * @type: Pointer to resulting format type identifier
 *
 * Search supported output format types for a type with associated @name. If
 * found, store resulting type identifier in @type.
 *
 * Return: %true if type is found, %false otherwise.
 */
bool util_fmt_name_to_type(const char *name, enum util_fmt_t *type);

/**
 * util_fmt_set_indent() - Set indentation parameters.
 * @base    : Base indentation level to apply to all output lines (default 0)
 * @width   : Number of indentation characters per intendation level (default 2)
 * @ind_char: Indentation characters to use (default space).
 */
void util_fmt_set_indent(unsigned int base, unsigned int width, char ind_char);

/**
 * util_fmt_add_key() - Register expected mapping keys.
 * @fmt: Format string to generate key
 *
 * Register a mapping key before the associated key-value pair is emitted.
 *
 * Use this function together with format control flag @FMT_FILTER to ignore all
 * key-value pairs for which the key has not been registered. This can be
 * useful to allow for dynamically configured filtering of output based on
 * a static list of emitted mappings.
 *
 * When creating CSV output, use this function to register all column keys
 * in advance to enable a stable column list in case of rows that do not
 * provide data for all columns.
 */
void util_fmt_add_key(const char *fmt, ...);

/**
 * util_fmt_obj_start() - Start a new data object.
 * @oflags: Flags controlling aspects of this object.
 * @fmt   : Format string for generating an object name or %NULL.
 *
 * Use this function to start a new object in output data. Depending on
 * @oflags, the new object represents either a normal object or a list. @oflags
 * can also be used to indicated that an object corresponds to a new row of
 * CSV data. If @fmt is non-%NULL, the resulting name is used in a format
 * type specified way:
 *
 * Pairs:
 *   - Object names are reflected as dot-separated component in the mapping
 *     prefix, e.g. 'a.b.key=value'
 *   - An index is generated for mappings and objects that are part of list,
 *     e.g. 'a.b[1].key=value'
 * JSON:
 *   - Object names are reflected as key-object mappings, e.g.
 *     <name>: { }
 *   - Required commas between objects and mappings are automatically generated
 * CSV:
 *   - Object names and the list type flag have no effect
 *   - When flag @FMT_ROW is specified, a CSV row will be emitted when
 *     util_fmt_obj_end() is called for the associated object
 */
void util_fmt_obj_start(unsigned int oflags, const char *fmt, ...);

/**
 * util_fmt_obj_end() - Announce the end of the latest data object started.
 *
 * Each object started with util_fmt_obj_start() must be ended with an
 * associated util_fmt_obj_end() call.
 */
void util_fmt_obj_end(void);

/**
 * util_fmt_pair() - Emit a key-value pair.
 * @mflags: Flags controlling this pair.
 * @key   : Key for this pair, excluding prefix.
 * @fmt   : Format string used to generated the pair value.
 *
 * Emit a key-value pair with the specified @key and the value that results
 * from format string @fmt.
 *
 * Notes:
 * - For JSON, a mapping can only occur after util_fmt_obj_start()
 * - For CSV, each @key must be unique, either by choosing unique key names
 *   or by including object names as prefix via the use of FMT_PREFIX in
 *   parent objects
 */
void util_fmt_pair(unsigned int mflags, const char *key, const char *fmt, ...);

#endif /* LIB_UTIL_FMT_H */
