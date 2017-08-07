/*
 * test_afiucv - Test program for the IUCV Terminal Applications
 *
 * Test program to check if the AF_IUCV family is supported by
 * the running Linux kernel
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "af_iucv.h"


int main(void)
{
	int sk;

	sk = socket(AF_IUCV, SOCK_STREAM, 0);
	if (sk == -1) {
		if (errno == EAFNOSUPPORT)
			perror("AF_IUCV address family not supported");
		return -1;
	} else
		close(sk);

	return 0;
}
