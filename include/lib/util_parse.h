/* SPDX-License-Identifier: MIT */
/*
 * util - Utility function library
 *
 * String parsing utility functions
 *
 * Copyright IBM Corp. 2026
 */

#ifndef LIB_UTIL_PARSE_H
#define LIB_UTIL_PARSE_H

#include <stdbool.h>
#include <stddef.h>

struct util_range {
	size_t start;
	size_t end;
};

/*
 * Parse a boolean input string into a boolean value
 * Accepts: "0"/"1", "n"/"y", "no"/"yes", "f"/"t", "false"/"true", "off"/"on"
 * Case-insensitive
 * @param input: Input string to parse
 * @return: 1 for true, 0 for false, -EINVAL for invalid input
 */
int util_parse_bool(const char *input);

/*
 * Parse byte sizes with optional unit suffixes
 * Supports: K/KiB, M/MiB, G/GiB, T/TiB, P/PiB, E/EiB
 * K/M/G/T/P/E use 1000-based multipliers
 * KiB/MiB/GiB/TiB/PiB/EiB use 1024-based multipliers
 * @param input: Input string to parse
 * @param bytes: Pointer to store parsed byte size
 * @return: 0 on success, negative error code on failure
 */
int util_parse_byte_size(const char *input, size_t *bytes);

/*
 * Parse numeric ranges in the format "start-end"
 * @param input: Input string to parse (format: "start-end")
 * @param range: Pointer to util_range struct to store result
 * @return: 0 on success, negative error code on failure
 */
int util_parse_range(const char *input, struct util_range *range);

/*
 * Parse integers with support for different bases
 * Supports: decimal, hex (0x prefix), binary (0b prefix), octal (0o prefix)
 * @param input: Input string to parse
 * @param value: Pointer to store parsed integer value
 * @return: 0 on success, negative error code on failure
 */
int util_parse_int(const char *input, size_t *value);

#endif
