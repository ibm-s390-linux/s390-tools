/*
 * test_allow - Test program for the IUCV Terminal Applications
 *
 * Test program to check common functions that use the regex api
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <stdio.h>
#include <unistd.h>

#include "iucvterm/config.h"
#include "iucvterm/functions.h"
#include "test.h"


static int test_userid_cpy(char padded[9])
{
	char uid[8];
	char id_str[9];
	size_t len;

	memcpy(uid, padded, 8);
	userid_cpy(id_str, uid);

	len = strlen(id_str);
	assert(0 == memcmp(padded, id_str, len));

	if (strchr(id_str, ' ') != NULL)
		__fail();

	return len;
}

int main(void)
{
	char re_ok[]    = "^T63[[:digit:]]{1,5}$";
	char re_wrong[] = "^t63[[:alpha:]+$";
	char re_short[] = "^lnx[[:digit:]]{3}$";
	char id_short[9];
	char user_id[8];

	/* redirect stderr to /dev/null to avoid regex error output */
	freopen("/dev/null", "w", stderr);

	assert(-1 == is_regex_valid(re_wrong));
	assert(-1 == is_regex_valid(NULL));
	assert(0  == is_regex_valid(re_ok));
	assert(0  == is_regex_valid(re_short));

	/* simple */
	assert(0 == strmatch("T6345050", "T6345050"));
	/* using re */
	assert(0 == strmatch("T6345050", re_ok));
	assert(0 == strmatch("t6345050", re_ok)); /* icase */
	assert(-1 == strmatch("T6345050", NULL));
	assert(-1 == strmatch("T6345050", re_wrong));
	assert(1 == strmatch("T634505A", re_ok));

	/* test userid_cpy() function */
	snprintf(id_short, 9, "%-8s", "");
	assert(0 == test_userid_cpy(id_short));
	snprintf(id_short, 9, "1");
	assert(1 == test_userid_cpy(id_short));
	snprintf(id_short, 9, "12345678");
	assert(8 == test_userid_cpy(id_short));
	snprintf(id_short, 9, "ABCD");
	assert(4 == test_userid_cpy(id_short));

	/* check for user IDs < 8 characters */
	snprintf(id_short, 9, "%-8s", "LNX001");
	memcpy(user_id, id_short, 8);
	userid_cpy(id_short, user_id);
	assert(0 == strmatch(id_short, re_short));

	return 0;
}
