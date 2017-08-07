/*
 *
 * Copyright IBM Corp. 2004, 2017
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 *
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>

#include "lib/u2s.h"
#include "misc.h"

#define DEV_BUFFER_LENGTH 20
#define PATH_BUFFER_LENGTH 256
#define BUSIDSIZE 9

#define BLOCKPATH "/sys/block/"
#define DEVICE_LINK "device"
#define DEV_ATTRIBUTE "dev"


/*
 * Helper function that expects a file name and returns 1 if this
 * is a directory or 0 otherwise.
 */
static int isdir(char *name) {

	struct stat statbuf;

	if (stat(name, &statbuf) < 0)
 		return 0;
	return S_ISDIR(statbuf.st_mode);
}

/*
 * Helper function that expects a directory name in sysfs of the form
 * /sys/block/<devname>/ or /sys/block/<devname>/<partname>/.
 * It will try to read the file "dev" in this directory and compare
 * it's contents with the given dev string of the form <major>:<minor>.
 * Trailing white space (newline) is ignored.
 * The buffer name is expected to be long enough to hold the additional "dev".
 * Returns 1 if the directory matches dev, 0 otherwise.
 */
static int check_directory(char *name, char *dev) {

	char buffer[DEV_BUFFER_LENGTH];
	char *end;
	int fd;
	ssize_t count;
	int dev_attr_len, dev_parm_len;
	unsigned int namelen;

	namelen = strlen(name);
	if ((PATH_BUFFER_LENGTH - namelen) < sizeof(DEV_ATTRIBUTE))
		return 0;
	end = name + namelen;
	strcpy(end, DEV_ATTRIBUTE);
	fd = open(name, O_RDONLY);
	*end = 0;
	if (fd < 0)
		return 0;
	count = read(fd, buffer, DEV_BUFFER_LENGTH);
	close(fd);
	if (count < 0)
		return 0;
	dev_attr_len = strspn(buffer, "1234567890:");
	dev_parm_len = strlen(dev);
	if (dev_attr_len != dev_parm_len )
		return 0;
	return (strncmp(dev, buffer, dev_parm_len) == 0);
}

/*
 * Helper function that expects a directory name in sysfs of the form
 * /sys/block/<devname>/. It will try to read a link "device"
 * in this directory and extract the busid, which is the last part
 * of that link. The buffer name is expected to be long enough
 * to hold the additional "device".
 * name: block device path in sysfs.
 * busid: buffer in which the busid string will be returned
 * returns 0 for successful operation and -1 in case of an error.
 */
static int extract_busid(char *name, char *busid) {

	int count;
	unsigned int namelen;
	char linkbuffer[PATH_BUFFER_LENGTH];
	char *start, *end;
	size_t len;

	namelen = strlen(name);
	if ((PATH_BUFFER_LENGTH - namelen) < sizeof(DEVICE_LINK))
		return 0;
	end = name + namelen;
	strcpy(end, DEVICE_LINK);
	count = readlink(name, linkbuffer, PATH_BUFFER_LENGTH - 1);
	if (count < 0)
		return -1;
	linkbuffer[count] = 0;
	start = strrchr(linkbuffer, '/');
	if (!start)
		return -1;
	start++;
	len = misc_strlcpy(busid, start, BUSIDSIZE);
	if (len >= BUSIDSIZE)
		return -1;

	return 0;
};

/*
 * Helper function that makes some basic checks on a directory entry.
 * The function checks if there is still enough space left in the buffer
 * for the new string, excludes '.' and '..', and verifies that the entry
 * is actually a directory.
 * buffer: the beginning of the name buffer
 * oldend: the current end of the string in the name buffer
 * dir: the dirent in question
 * returns: a pointer to the new end of the string in buffer or NULL if
 * one of the checks failed
 */

static char *append_if_directory(char *buffer, char *oldend, struct dirent *dir) {

	char *newend;
	int oldlength, dirlength;

	if (strcmp(dir->d_name, ".") == 0 ||
	    strcmp(dir->d_name, "..") == 0)
		return NULL;
	oldlength = strlen(buffer);
	dirlength = strlen(dir->d_name);
	if (PATH_BUFFER_LENGTH < oldlength + dirlength + 2)
		return NULL;
	strcpy(oldend, dir->d_name);
	if (!isdir(buffer)) {
		*oldend = 0;
		return NULL;
	}
	newend = oldend + dirlength;
	strcpy(newend, "/");
	newend++;

	return newend;
}

/*
 * helper function that searches for a specific block device and returns
 * it's busid
 * dev: <major>:<minor> of the device
 * busid: buffer in which the busid string will be returned
 * returns 0 for successful operation and -1 in case of an error.
 */
static int find_busid_in_sysfs(char *dev, char *busid) {

	DIR *blockdir, *diskdir;
	struct dirent *blockde, *diskde;
	int found = 0;
	char namebuffer[PATH_BUFFER_LENGTH];
	char *blockend, *diskend = NULL, *partend;

	/* everything, including the other helper functions, works on the
	 * same buffer area 'namebuffer'. The pointers blockend, diskend
	 * and partend point to the end of the various names.
	 * Example:
	 * "/sys/block/dasda/dasda1/"
	 *             ^ blockend
	 *                   ^ diskend
	 *                          ^ partend
	 */

	strcpy(namebuffer,BLOCKPATH);
	blockdir = opendir(namebuffer);
	if (!blockdir)
 		return -1;
	blockend = namebuffer + strlen(namebuffer);
	/* check each entry in /sys/block */
	while ((blockde = readdir(blockdir))) {
		diskend = append_if_directory(namebuffer, blockend, blockde);
		if (!diskend)
			continue;
		found = check_directory(namebuffer, dev);
		if (found)
			break;
		diskdir = opendir(namebuffer);
		if (!diskdir)
			continue;
		/* check each entry in /sys/block/<disk name> */
		while ((diskde = readdir(diskdir))) {
			partend = append_if_directory(
				namebuffer, diskend, diskde);
			if (!partend)
				continue;
			found = check_directory(namebuffer, dev);
			if (found)
				break;
		}
		closedir(diskdir);
		if (found)
			break;
	}
	closedir(blockdir);
	if (found) {
		*diskend = 0; /* remove partition directory from name */
		return extract_busid(namebuffer, busid);
	} else
		return -1;
}

/*
 * helper function that searches for a specific block device in
 * /proc/dasd/devices and returns it's bus-ID
 * maja, mina: <major>, <minor> of the device
 * busid: buffer in which the bus-ID string will be returned
 * returns 0 for successful operation and -1 in case of an error
 * e.g. /proc/dasd/devices does not exist.
 *
 * An entry looks like:
 * 0.0.XXXX(DISCIPLINE) at ( MAJ:   MIN) is dasdX       :
 * active at blocksize: BLOCKSIZE, BLOCKS blocks, SIZE MB
 */
static int find_busid_in_proc(int maja, int mina, char *busid)
{
	FILE *filp;
	char bus[BUSIDSIZE];
	int majb, minb, rc;
	size_t len;

	rc = -1;

	filp = fopen("/proc/dasd/devices", "r");
	if (!filp)
		return rc;
	while (fscanf(filp, "%[^(] %*[^)] ) at ( %d : %d %*[^\n]\n",
		      bus, &majb, &minb) != EOF) {
		if ((maja == majb) && (mina == minb)) {
			len = misc_strlcpy(busid, bus, BUSIDSIZE);
			if (len < BUSIDSIZE)
				rc = 0;
			break;
		}
	}

	fclose(filp);
	return rc;
}

/*
 * Return the busid of a given device node.
 * Works only for block devices.
 * devicenode: path to the device node
 * busid: buffer in which the busid string will be returned
 * returns 0 for successful operation and -1 in case of an error.
 */
int u2s_getbusid(char *devicenode, char *busid)
{
        int maj, min, rc;
        struct stat stat_buf;
        char dev_string[DEV_BUFFER_LENGTH];

	/*
	 * Get major and minor information of the device special file
	 * and combine them to a <maj>:<min> string, as returned by
         * the dev attributes in sysfs
	 */
        if (stat(devicenode, &stat_buf))
                return -1;
        if (!S_ISBLK(stat_buf.st_mode))
                return -1;
        maj = major(stat_buf.st_rdev);
        min = minor(stat_buf.st_rdev);

	rc = find_busid_in_proc(maj, min, busid);
	if (rc) {
		snprintf(dev_string, DEV_BUFFER_LENGTH, "%u:%u", maj, min);
		rc = find_busid_in_sysfs(dev_string, busid);
	}

	return rc;
}

/*
 * Attempts to find the sysfs entry for the given busid and reads
 * the contents of a specified attribute to the buffer
 */
int u2s_read_attribute(char *busid, char *attribute, char *buffer,
		       size_t count)
{
	char path[100];
	int rc, fd;
	ssize_t rcount;

	rc = 0;
	snprintf(path, sizeof(path), "/sys/bus/ccw/devices/%s/%s",
		 busid, attribute);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return errno;
	rcount = read(fd, buffer, count);
	if (rcount < 0)
		rc = errno;
	close(fd);
	return rc;
}

int u2s_get_host_access_count(char *devicenode)
{
	char busid[BUSIDSIZE];
	unsigned long value;
	char buffer[10];
	char *endp;

	u2s_getbusid(devicenode, busid);
	u2s_read_attribute(busid, "host_access_count", buffer, sizeof(buffer));

	value = strtoul(buffer, &endp, 0);

	if (endp == buffer)
		return -EINVAL;

	return value;
}
