#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright IBM Corp.

IBM_RSRC_DIR="/etc/sel-ebc"

if [[ ! -f "${IBM_RSRC_DIR}/crypttab" ]]; then
	echo "Error: source file $IBM_RSRC_DIR/crypttab does not exist"
	exit 1
fi

# Unconditionally override /etc/crypttab to ensure correct EBC configuration
cp "${IBM_RSRC_DIR}/crypttab" "/etc/crypttab"

systemctl daemon-reload

systemctl restart systemd-cryptsetup@cryptroot_mapper.service

exit 0
