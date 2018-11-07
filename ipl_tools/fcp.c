/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * FCP device functions
 *
 * Copyright IBM Corp. 2008, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include "lib/util_libc.h"
#include "ipl_tools.h"

/*
 * Check if the specified device number is a valid device number
 * which can be found in the /sys/bus/ccw/drivers/zfcp/ structure
 */
int fcp_is_device(const char *devno)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/sys/bus/ccw/drivers/zfcp/%s", devno);
	if (chdir(path) != 0)
		return 0;
	return 1;
}

/*
 * Return the wwpn of a device
 */
void fcp_wwpn_get(const char *device, char *wwpn)
{
	char path[PATH_MAX], buf[20];
	FILE *fh;
	int rc;

	snprintf(path, sizeof(path), "/sys/block/%s/device/wwpn", device);
	fh = fopen(path, "r");
	if (fh == NULL)
		ERR_EXIT_ERRNO("Could not open \"%s\"", path);
	rc = fscanf(fh, "%s", buf);
	if (rc <= 0)
		ERR_EXIT("Could not lookup WWPN \"%s\"", path);
	util_strlcpy(wwpn, buf, 20);
	fclose(fh);
}


/*
 * Return the lun of a device
 */
void fcp_lun_get(const char *device, char *lun)
{
	char path[PATH_MAX], buf[20];
	FILE *fh;
	int rc;

	snprintf(path, sizeof(path), "/sys/block/%s/device/fcp_lun", device);
	fh = fopen(path, "r");
	if (fh == NULL)
		ERR_EXIT_ERRNO("Could not open \"%s\"", path);
	rc = fscanf(fh, "%s", buf);
	if (rc <= 0)
		ERR_EXIT("Could not lookup LUN \"%s\"", path);
	util_strlcpy(lun, buf, 20);
	fclose(fh);
}

/*
 * Return the device number of a device
 */
void fcp_busid_get(const char *device, char *devno)
{
	char buf[4096], path[PATH_MAX];
	FILE *fh;
	int rc;

	snprintf(path, sizeof(path), "/sys/block/%s/device/hba_id", device);
	fh = fopen(path, "r");
	if (fh == NULL)
		ERR_EXIT_ERRNO("Could not open \"%s\"", path);
	rc = fscanf(fh, "%s", buf);
	if (rc <= 0)
		ERR_EXIT("Could not find device \"%s\"", path);
	strcpy(devno, buf);
	fclose(fh);
}
