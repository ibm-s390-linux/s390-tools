/*
 * dasd_ioctl - Library for dasd-related ioctls
 *
 * DASD related helper functions for accessing device information via ioctls
 *
 * Copyright IBM Corp. 2013, 2017
 * Copyright Red Hat Inc. 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lib/dasd_base.h"

#define COULD_NOT_OPEN_WARN(device) \
	warn("Could not open device '%s'", device)

#define COULD_NOT_CLOSE_WARN \
	warn("Unable to close device")

#define RUN_IOCTL(fd, req, argp)				\
	do {							\
		if (ioctl(fd, req, argp) != 0) {		\
			int err = errno;			\
			if (err != EBADF)			\
				dasd_close_device(fd);		\
			return err;				\
		}						\
	} while (0)

static int dasd_open_device(const char *device, int flags)
{
	int fd;

	fd = open(device, flags);
	if (fd == -1)
		COULD_NOT_OPEN_WARN(device);

	return fd;
}

static void dasd_close_device(int fd)
{
	if (close(fd) != 0)
		COULD_NOT_CLOSE_WARN;
}

/*
 * Get DASD block size information for device
 *
 * @param[in] device node	device node's name
 * @param[out] blksize		the block size
 *
 * @retval 0		in case of success
 * @retval errno	in case of failure
 *
 */
int dasd_get_blocksize(const char *device, unsigned int *blksize)
{
	int fd;

	fd = dasd_open_device(device, O_RDONLY);
	RUN_IOCTL(fd, BLKSSZGET, blksize);
	dasd_close_device(fd);

	return 0;
}

/*
 * Get DASD block size information (in bytes) for device
 *
 * @param[in] device node	device node's name
 * @param[out] blksize		block size in bytes
 *
 * @retval 0		in case of success
 * @retval errno	in case of failure
 */
int dasd_get_blocksize_in_bytes(const char *device, unsigned long long *blksize)
{
	int fd;

	fd = dasd_open_device(device, O_RDONLY);
	RUN_IOCTL(fd, BLKGETSIZE64, blksize);
	dasd_close_device(fd);

	return 0;
}

/*
 * Get DASD disk information for device
 *
 * @param[in] device node	device node's name
 * @param[out] info		pointer to dasd information
 *
 * @retval 0		in case of success
 * @retval errno	in case of failure
 */
int dasd_get_info(const char *device, dasd_information2_t *info)
{
	int fd;

	fd = dasd_open_device(device, O_RDONLY);
	RUN_IOCTL(fd, BIODASDINFO2, info);
	dasd_close_device(fd);

	return 0;
}

/*
 * Get DASD disk geometry information for device
 *
 * @param[in] device node	device node's name
 * @param[out] geo		pointer to device geometry information
 *
 * @retval errno	in case of failure
 * @retval 0		in case of success
 */
int dasd_get_geo(const char *device, struct hd_geometry *geo)
{
	int fd;

	fd = dasd_open_device(device, O_RDONLY);
	RUN_IOCTL(fd, HDIO_GETGEO, geo);
	dasd_close_device(fd);

	return 0;
}

/*
 * Get DASD read/write status information for device
 *
 * @param[in] device node	device node's name
 * @param[out] ro		read-only status (1 for ro, 0 for rw)
 *
 * @retval 0		in case of success
 * @retval errno	in case of failure
 */
int dasd_is_ro(const char *device, bool *ro)
{
	int fd, val;

	fd = dasd_open_device(device, O_RDWR);
	RUN_IOCTL(fd, BLKROGET, &val);
	*ro = (val != 0) ? true : false;

	return 0;
}

/*
 * Disable DASD disk.
 *
 * @param[in] device node	device node's name
 *
 * @retval 0		in case of success
 * @retval errno	in case of failure
 *
 * Note: Before BIODASDFMT can be called, a DASD has to be disabled (or rather
 * put into a BASIC state) via BIODASDDISABLE. However, if you disable the DASD,
 * close the file descriptor, and then try to reopen it, it won't work as the
 * device isn't fully usable anymore. For BIODASDFMT to work, the file
 * descriptor opened for BIODASDISABLE has to be kept open until BIODASDFMT has
 * finished.
 */
int dasd_disk_disable(const char *device, int *fd)
{
	*fd = dasd_open_device(device, O_RDWR);
	RUN_IOCTL(*fd, BIODASDDISABLE, NULL);

	return 0;
}

/*
 * Enable DASD disk
 *
 * @param[in] device node	device node's name
 *
 * @retval 0		in case of success
 * @retval errno	in case of failure
 */
int dasd_disk_enable(int fd)
{
	RUN_IOCTL(fd, BIODASDENABLE, NULL);
	dasd_close_device(fd);

	return 0;
}

/*
 * Format DASD disk
 *
 * @param[in] fd		device node's file descriptor
 * @param[in] p			format options
 *
 * @retval 0		in case of success
 * @retval errno	in case of failure
 */
int dasd_format_disk(int fd, format_data_t *p)
{
	RUN_IOCTL(fd, BIODASDFMT, p);

	return 0;
}

/*
 * Check DASD format
 *
 * @param[in] device node	device node's name
 * @param[in] p			format params
 *
 * @retval 0		in case of success
 * @retval errno	in case of failure
 */
int dasd_check_format(const char *device, format_check_t *p)
{
	int fd;

	fd = dasd_open_device(device, O_RDONLY);
	RUN_IOCTL(fd, BIODASDCHECKFMT, p);
	dasd_close_device(fd);

	return 0;
}

/*
 * Reread partition table
 *
 * @param[in] device node	device node's name
 * @param[in] ntries		maximum number of tries
 *
 * @retval 0		in case of success
 * @retval errno	in case of failure
 */
int dasd_reread_partition_table(const char *device, int ntries)
{
	int i, fd, err = 0;

	fd = dasd_open_device(device, O_RDONLY);

	/*
	 * If the BLKRRPART ioctl fails, it is most likely due to the device
	 * just being in use by udev. So it is worthwhile to retry the ioctl
	 * after a second as it is likely to succeed.
	 */
	for (i = 0; i < ntries; i++) {
		if (ioctl(fd, BLKRRPART, NULL) != 0) {
			err = errno;
			sleep(1);
		} else {
			err = 0;
			break;
		}
	}
	dasd_close_device(fd);

	return err;
}
