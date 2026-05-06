#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright IBM Corp.

set -eu

mntp="/boot"
block_dev="$(blkid -L boot)"

if [[ -z "${block_dev}" ]]; then
	echo "Unable to find partition with label boot"
	exit 1
elif [[ ! -b "${block_dev}" ]]; then
	echo "Unable to find block device ${block_dev}"
	exit 1
else
	echo "Found block device ${block_dev}"
fi

if [[ ! -d "${mntp}" ]]; then
	echo "Mountpoint ${mntp} does not exist, creating..."
	mkdir "${mntp}"
else
	echo "Mountpoint ${mntp} exists"
fi

echo "Mounting ${block_dev} to ${mntp}"
mount --options ro "${block_dev}" "${mntp}"

exit 0
