/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef FINDMNT_H
#define FINDMNT_H

struct util_list;

struct util_list *findmnt_get_devnodes_by_path(const char *path);

#endif /* FINDMNT_H */
