/*
 * test_common - Test program for the IUCV Terminal Applications
 *
 * Definition of common functions for test programs
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#ifndef __TEST_H_
#define __TEST_H_


#include <assert.h>
#include <stdlib.h>

#include "lib/util_base.h"
#include "iucvterm/proto.h"

#define __fail()	assert(0);


extern int __socketpair(int sv[2]);
extern int __msgcmp(const struct iucvtty_msg *, const struct iucvtty_msg *);

#endif /* __TEST_H_ */
