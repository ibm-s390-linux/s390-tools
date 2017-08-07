/**
 * ccw - Channel Command Word function library
 *
 * Process ccw_devid
 *
 * Copyright 2017 IBM Corp.
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <string.h>

#include "lib/ccw.h"

/**
 * Parse a string into a ccw_devid structure
 *
 * @param[in,out] devid   Pointer to ccw_devid structure to be initialized
 * @parm[in]      id      String to parse
 *
 * @returns       true if the input string has been parsed successfully;
 *                otherwise false.
 */
bool ccw_parse_str(struct ccw_devid *devid, const char *id)
{
	unsigned int cssid, ssid, devno;
	char d;

	if (strncasecmp(id, "0x", 2) == 0)
		return false;
	if (sscanf(id, "%4x %c", &devno, &d) == 1) {
		cssid = 0;
		ssid = 0;
	} else if (sscanf(id, "%2x.%1x.%4x %c", &cssid, &ssid, &devno,
		   &d) != 3) {
		return false;
	}
	ccw_devid_init(devid, cssid, ssid, devno);
	return true;
}
