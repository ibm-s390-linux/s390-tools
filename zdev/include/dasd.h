/*
 * zdev - Modify and display the persistent configuration of devices
 *
 * Copyright IBM Corp. 2016, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef DASD_H
#define DASD_H

struct devtype;
struct subtype;

extern struct devtype dasd_devtype;
extern struct subtype dasd_subtype_eckd;
extern struct subtype dasd_subtype_fba;

#endif /* DASD_H */
