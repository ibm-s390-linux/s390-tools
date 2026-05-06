#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright IBM Corp.

set -eu

IBM_RSRC_DIR="/etc/sel-ebc"
block_dev="$(blkid -L cryptroot)"

if [[ -z "${block_dev}" ]]; then
	echo "Unable to find partition with label cryptroot"
	exit 1
elif [[ ! -b "${block_dev}" ]]; then
	echo "Unable to find block device ${block_dev}"
	exit 1
else
	echo "Found block device ${block_dev}"
fi

if [[ ! -f "${IBM_RSRC_DIR}/crypttab" ]]; then
	echo "Error: source file $IBM_RSRC_DIR/crypttab does not exist"
	exit 1
fi

# Unconditionally override /etc/crypttab to ensure correct EBC configuration
cp "${IBM_RSRC_DIR}/crypttab" "/etc/crypttab"

systemctl daemon-reload

udevadm trigger --subsystem-match=block --settle

if ! systemctl restart systemd-cryptsetup@cryptroot_mapper.service; then
        systemctl status systemd-cryptsetup@cryptroot_mapper.service
        exit 1
fi

exit 0
