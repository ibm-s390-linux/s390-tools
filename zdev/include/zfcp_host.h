/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ZFCP_HOST_H
#define ZFCP_HOST_H

#include "exit_code.h"

struct subtype;

extern struct subtype zfcp_host_subtype;

exit_code_t zfcp_host_check_npiv(const char *, int *);

#endif /* ZFCP_HOST_H */
