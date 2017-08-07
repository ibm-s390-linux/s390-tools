/*
 * test_auditlog - Test program for the IUCV Terminal Applications
 *
 * Test program for the session logging functions used by iucvconn(1).
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

#include "iucvterm/functions.h"
#include "test.h"

#define BUF_SIZE 1024


static void do_cleanup(const char *filename)
{
	char tmp[64];

	if (access(filename, W_OK) == 0)
		unlink(filename);

	snprintf(tmp, 64, "%s.timing", filename);
	if (access(tmp, W_OK) == 0)
		unlink(tmp);

	snprintf(tmp, 64, "%s.info", filename);
	if (access(tmp, W_OK) == 0)
		unlink(tmp);
}

int main(int argc, char* argv[]){

	char *filepath = NULL;
	char *buf;
	char  tmpfile[64];
	int   interactive;
	ssize_t rc;


	if (argc < 2) {
		fprintf(stderr, "Usage: %s <filepath>\n", argv[0]);
		sprintf(tmpfile, "/tmp/test_auditlog.a1b2c3.%u", getpid());
		fprintf(stderr, "now using file %s\n", tmpfile);
		filepath = tmpfile;
		/* cleanup stale file */
		if (access(tmpfile, W_OK) == 0)
			do_cleanup(tmpfile);
		interactive = 0;
	} else {
		interactive = 1;
		filepath = argv[1];
	}
	buf = malloc(BUF_SIZE);

	rc = open_session_log(filepath);
	assert(rc == 0);

	write_session_info("The name of the log file is: %s\n", filepath);

	sprintf(buf, "This is an entry\n");
	rc = write_session_log(buf, strlen(buf));
	assert(rc == 0);

	close_session_log();

	free(buf);
	if (!interactive)
		do_cleanup(tmpfile);
	return 0;
}
