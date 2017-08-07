/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef SCSI_H
#define SCSI_H

#include <stdbool.h>
#include <stdint.h>

struct zfcp_lun_devid;
struct util_list;

/* HCTL = Host:Channel:Target:LUN tuple for identifying a SCSI device. */

void scsi_exit(void);
void scsi_reread(void);
uint64_t scsi_lun_to_fcp_lun(uint64_t);
uint64_t scsi_lun_from_fcp_lun(uint64_t);
char *scsi_hctl_to_zfcp_lun_id(const char *);
char *scsi_hctl_from_zfcp_lun_devid(struct zfcp_lun_devid *);
char *scsi_hctl_from_zfcp_lun_id(const char *);
bool scsi_hctl_exists(const char *);
void scsi_hctl_add_zfcp_lun_ids(struct util_list *);
char *scsi_hctl_from_devpath(const char *);

#endif /* SCSI_H */
