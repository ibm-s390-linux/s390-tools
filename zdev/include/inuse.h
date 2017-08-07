/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef INUSE_H
#define INUSE_H

struct util_list;
struct device;

void inuse_exit(void);
struct util_list *inuse_get_resources(struct device *dev);

#endif /* INUSE_H */
