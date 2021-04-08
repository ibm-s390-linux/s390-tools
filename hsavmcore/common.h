/*
 * Copyright IBM Corp. 2021
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _HSAVMCORE_COMMON_H
#define _HSAVMCORE_COMMON_H

#define NAME "hsavmcore"

#define DEBUGFS_MOUNT_POINT "/sys/kernel/debug"

#define ZCORE_HSA DEBUGFS_MOUNT_POINT "/zcore/hsa"

#define VMCORE_FILE "vmcore"

#define PROC_VMCORE "/proc/" VMCORE_FILE

#define WORKDIR "/var/crash"

#define HSA_CACHE_FILE NAME "-hsa-cache.bin"

#define OVERLAY_MOUNT_POINT "/tmp/" NAME "-overlay/"

#endif
