/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef ROOT_H
#define ROOT_H

#include "exit_code.h"

exit_code_t initrd_check(bool all_pers);

#endif /* ROOT_H */
