/*
 * util_fmt_example - Example program for util_fmt
 *
 * Copyright IBM Corp. 2024
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdlib.h>
#include <string.h>

#include "lib/util_base.h"
#include "lib/util_fmt.h"

#define API_LEVEL	1

static void meta_example(enum util_fmt_t format)
{
	util_fmt_init(stdout, format, FMT_DEFAULT, API_LEVEL);

	/*
	 * First call to util_fmt_obj_start() automatically adds meta-data
	 * object as required by s390-tools convention.
	 */
	util_fmt_obj_start(FMT_DEFAULT, NULL);
	util_fmt_pair(FMT_QUOTE, "key", "value");
	util_fmt_obj_end();

	util_fmt_exit();
}

static void simple_example(enum util_fmt_t format, int fmt_flags)
{
	/*
	 * Note: Meta-data is excluded in this example for readability but
	 * must be included in actual tool output.
	 */
	util_fmt_init(stdout, format, fmt_flags | FMT_NOMETA, API_LEVEL);

	/*
	 * {
	 *   "child": {
	 *     "key": "value",
	 *     "invalid":"invalidvalue"      <== Marked as invalid
	 *     }
	 * }
	 */
	util_fmt_obj_start(FMT_DEFAULT, NULL);
	util_fmt_obj_start(FMT_DEFAULT, "child");
	util_fmt_pair(FMT_QUOTE, "key", "value");
	util_fmt_pair(FMT_QUOTE | FMT_INVAL, "invalid", "invalidvalue");
	util_fmt_obj_end();
	util_fmt_obj_end();

	util_fmt_exit();
}

static void list_example(enum util_fmt_t format, int flags)
{
	int i;

	/*
	 * Note: Meta-data is excluded in this example for readability but
	 * must be included in actual tool output.
	 */
	util_fmt_init(stdout, format, flags | FMT_NOMETA, API_LEVEL);

	/*
	 * "cond","key"
	 * condvalue0,value0
	 * "",value1
	 * "",value2
	 * "",value3
	 */
	util_fmt_obj_start(FMT_DEFAULT, NULL);
	util_fmt_obj_start(FMT_LIST, "list");

	for (i = 0; i < 4; i++) {
		util_fmt_obj_start(FMT_ROW, NULL);
		if (i == 0)
			util_fmt_pair(flags, "cond", "condvalue%d", i);
		util_fmt_pair(FMT_DEFAULT, "key", "value%d", i);
		util_fmt_obj_end();
	}

	util_fmt_obj_end();
	util_fmt_obj_end();

	util_fmt_exit();
}

#define NUM_KEYS	4

static void vary_example(enum util_fmt_t format, bool add)
{
	const char *keys[NUM_KEYS] = { "key_a", "key_b", "key_c", "key_d" };
	int i;

	/*
	 * Note: Meta-data is excluded in this example for readability but
	 * must be included in actual tool output.
	 */
	util_fmt_init(stdout, format, FMT_NOMETA, API_LEVEL);

	if (add) {
		/* Make keys known before starting output. */
		for (i = 0; i < NUM_KEYS; i++)
			util_fmt_add_key(keys[i]);
	}

	util_fmt_obj_start(FMT_LIST, "list");
	for (i = 0; i < 4; i++) {
		util_fmt_obj_start(FMT_ROW, NULL);
		util_fmt_pair(FMT_DEFAULT, keys[i], "value%d", i);
		util_fmt_obj_end();
	}
	util_fmt_obj_end();

	util_fmt_exit();
}

static void filter_example(enum util_fmt_t format)
{
	/*
	 * Note: Meta-data is excluded in this example for readability but
	 * must be included in actual tool output.
	 */
	util_fmt_init(stdout, format, FMT_FILTER | FMT_NOMETA, API_LEVEL);
	util_fmt_add_key("key_a");
	/*
	 * {
	 *   "key_a": "value_a",
	 *   "key_b": "value_b"   <== Not announced via util_fmt_add_key()
	 * }
	 */
	util_fmt_obj_start(FMT_DEFAULT, NULL);
	util_fmt_pair(FMT_QUOTE, "key_a", "value_a");
	util_fmt_pair(FMT_QUOTE, "key_b", "value_b");
	util_fmt_obj_end();

	util_fmt_exit();
}

static void prefix_example(enum util_fmt_t format, bool do_prefix)
{
	/*
	 * Note: Meta-data is excluded in this example for readability but
	 * must be included in actual tool output.
	 */
	util_fmt_init(stdout, format, FMT_NOMETA, API_LEVEL);

	/*
	 * {
	 *  "key": "value0",
	 *  "obj1": {  // Marked as prefix object
	 *    "key": "value1"
	 *  }
	 * }
	 */
	util_fmt_obj_start(FMT_DEFAULT, "obj0");
	util_fmt_pair(FMT_QUOTE, "key", "value0");
	util_fmt_obj_start(do_prefix ? FMT_PREFIX : FMT_DEFAULT, "obj1");
	util_fmt_pair(FMT_QUOTE, "key", "value1");
	util_fmt_obj_end();
	util_fmt_obj_end();

	util_fmt_exit();
}

static void announce(const char *example_name)
{
	static int example_number;
	int i;

	if (example_number++ > 0)
		printf("\n");

	printf("%d. %s\n====", example_number, example_name);
	for (i = strlen(example_name); i > 0; i--)
		printf("=");
	printf("\n");
}

int main(int UNUSED(argc), char *UNUSED(argv[]))
{
	announce("JSON output");
	simple_example(FMT_JSON, FMT_KEEPINVAL);

	announce("JSON without invalid pairs");
	simple_example(FMT_JSON, FMT_DEFAULT);

	announce("JSON formatted as sequence");
	simple_example(FMT_JSONSEQ, FMT_DEFAULT);

	announce("Pairs output");
	simple_example(FMT_PAIRS, FMT_KEEPINVAL);

	announce("Pairs output without invalid pairs");
	simple_example(FMT_PAIRS, FMT_DEFAULT);

	announce("Pairs without prefix");
	simple_example(FMT_PAIRS, FMT_NOPREFIX);

	announce("CSV output");
	simple_example(FMT_CSV, FMT_KEEPINVAL);

	announce("CSV list output");
	list_example(FMT_CSV, FMT_DEFAULT);

	announce("CSV list with persistent cond value");
	list_example(FMT_CSV, FMT_PERSIST);

	announce("JSON with filtered key");
	filter_example(FMT_JSON);

	announce("Pairs with filtered key");
	filter_example(FMT_PAIRS);

	announce("CSV with filtered key");
	filter_example(FMT_CSV);

	announce("CSV list with varying keys");
	vary_example(FMT_CSV, false);

	announce("CSV list with pre-announced varying keys");
	vary_example(FMT_CSV, true);

	announce("JSON output with meta-data");
	meta_example(FMT_JSON);

	announce("JSON sequence output with meta-data");
	meta_example(FMT_JSONSEQ);

	announce("Pairs output with meta-data");
	meta_example(FMT_PAIRS);

	announce("CSV output with meta-data");
	meta_example(FMT_CSV);

	announce("JSON output with duplicate keys");
	prefix_example(FMT_JSON, false);

	announce("CSV output with duplicate keys");
	prefix_example(FMT_CSV, false);

	announce("CSV output with duplicate keys distinguished by prefix");
	prefix_example(FMT_CSV, true);

	return 0;
}
