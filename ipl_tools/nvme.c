/*
 * ipl_tools - Linux for System z reipl and shutdown tools
 *
 * NVMe device functions
 *
 * Copyright IBM Corp. 2020
 *
 * s390-tools is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/util_libc.h"
#include "lib/util_file.h"
#include "ipl_tools.h"

/*
 * Return the fid of a device
 */
void nvme_fid_get(const char *device, char *fid)
{
	char path[PATH_MAX], buf[FID_MAX_LEN];

	snprintf(path, PATH_MAX, "/sys/block/%s/device/device/function_id",
		device);
	if (util_file_read_line(buf, FID_MAX_LEN, path))
		ERR_EXIT_ERRNO("Could not read from \"%s\"", path);

	util_strlcpy(fid, buf, FID_MAX_LEN);
}
/*
 * Return the nsid of a device
 */
void nvme_nsid_get(const char *device, char *nsid)
{
	char path[PATH_MAX], buf[FID_MAX_LEN];

	snprintf(path, PATH_MAX, "/sys/block/%s/nsid", device);
	if (util_file_read_line(buf, FID_MAX_LEN, path))
		ERR_EXIT_ERRNO("Could not read from \"%s\"", path);

	util_strlcpy(nsid, buf, FID_MAX_LEN);
}

static int next_entry(DIR *dir, char *in_path, char *out_path,
	unsigned char entry_type)
{
	struct dirent *dirent;
	char temp_path[NVME_PATH_MAX];

	while ((dirent = readdir(dir)) != NULL) {
		if (strcmp(dirent->d_name, ".") == 0 ||
		    strcmp(dirent->d_name, "..") == 0 ||
		    dirent->d_type != entry_type)
			continue;

		/* Resolve the symlink, if needed */
		if (dirent->d_type == DT_LNK) {
			snprintf(temp_path, sizeof(temp_path), "%s/%s", in_path,
				dirent->d_name);
			if (!realpath(temp_path, out_path))
				ERR_EXIT_ERRNO("Could not resolve link %s",
					temp_path);
			return 1;
		}

		snprintf(out_path, NVME_PATH_MAX, "%s/%s", in_path,
			dirent->d_name);
		return 1;
	}
	return 0;
}

static int nvme_getdev_by_fid(char *fidstr, char *devpath)
{
	char temp_path[PATH_MAX+19], real_path[PATH_MAX];
	char *sys_path = "/sys/class/nvme";
	u_int64_t target_fid, curfid;
	DIR *dir;
	char *end;
	int rc = -1;

	target_fid = strtoul(fidstr, &end, 16);
	if (*end)
		ERR_EXIT("Invalid function_id given %s", fidstr);

	dir = opendir(sys_path);
	if (!dir)
		ERR_EXIT("Could not open %s", sys_path);

	errno = 0;
	while (next_entry(dir, sys_path, real_path, DT_LNK)) {
		snprintf(temp_path, sizeof(temp_path), "%s/%s", real_path,
			"device/function_id");
		if (access(temp_path, F_OK))
			continue;

		if (util_file_read_ul(&curfid, 16, temp_path))
			ERR_EXIT("Invalid function_id found in %s", temp_path);

		if (curfid == target_fid) {
			strncpy(devpath, real_path, PATH_MAX);
			rc = 0;
			break;
		}
	}

	closedir(dir);
	return rc;
}

static int nvme_getdev_by_nsid(char *nsid_str, char *path, char *dev_path)
{
	char full_path[NVME_PATH_MAX+1], nsid_path[sizeof(full_path)+5];
	char *end;
	u_int64_t nsid, curnsid;
	DIR *dir;

	nsid = strtoul(nsid_str, &end, 10);
	if (*end)
		ERR_EXIT_ERRNO("Invalid namespace id given %s", nsid_str);

	dir = opendir(path);
	if (!dir)
		ERR_EXIT_ERRNO("Could not open %s", path);

	errno = 0;
	while (next_entry(dir, path, full_path, DT_DIR)) {
		snprintf(nsid_path, sizeof(nsid_path), "%s/%s", full_path,
			"nsid");
		if (access(nsid_path, F_OK))
			continue;

		if (util_file_read_ul(&curnsid, 10, nsid_path))
			ERR_EXIT("Invalid namespace id found in %s", nsid_path);

		if (curnsid == nsid) {
			strncpy(dev_path, full_path, NVME_PATH_MAX+1);
			closedir(dir);
			return 0;
		}
	}
	closedir(dir);
	return -1;
}

static int nvme_getdev(char *fid_str, char *nsid_str, char *dev_path)
{
	char path_tmp[NVME_PATH_MAX];

	if (nvme_getdev_by_fid(fid_str, path_tmp))
		return -1;

	return nvme_getdev_by_nsid(nsid_str, path_tmp, dev_path);
}

/*
 * Check if the specified fid and nsid leads to a valid nvme device
 */
int nvme_is_device(char *fid_str, char *nsid_str)
{
	char path_tmp[NVME_PATH_MAX+1];

	return !(nvme_getdev(fid_str, nsid_str, path_tmp));
}
