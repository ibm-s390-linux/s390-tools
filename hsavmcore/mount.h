/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_MOUNT_H
#define _HSAVMCORE_MOUNT_H

int mount_debugfs(const char *target);

int bind_mount(const char *src, const char *target);

int unmount_detach(const char *target);

#endif
