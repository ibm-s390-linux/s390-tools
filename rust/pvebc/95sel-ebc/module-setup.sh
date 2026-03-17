#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright IBM Corp.


# Called by dracut
check() {
	# always include
	return 0
}

# Called by dracut
depends() {
	# We need systemd in the initramfs
	echo systemd
	echo systemd-udevd
	echo crypt
	echo dm
	return 0
}

# Called by dracut
installkernel() {
	# kernel modules needed for opening an encrypted rfs
	instmods -c uvdevice
	instmods -c paes_s390
	instmods -c pkey_uv
	instmods -c pkey_pckmo
	instmods -c pkey
}

# Called by dracut
install() {
	# shellcheck disable=SC2154
	# moddir, systemdsystemunitdir, and initdir are provided by dracut
	# Copy the units into the initramfs' systemd unit dir
	inst_simple "$moddir/sel-ebc.target" \
		"$systemdsystemunitdir/sel-ebc.target"
	inst_simple "$moddir/sel-ebc-pvebc.service" \
		"$systemdsystemunitdir/sel-ebc-pvebc.service"
	inst_simple "$moddir/sel-ebc-paes-enforce.service" \
		"$systemdsystemunitdir/sel-ebc-paes-enforce.service"
	inst_simple "$moddir/sel-ebc-override-crypttab.service" \
		"$systemdsystemunitdir/sel-ebc-override-crypttab.service"
	inst_simple "$moddir/boot.mount" \
		"$systemdsystemunitdir/boot.mount"

	# already exisitng unit we depend on for kernel modules
	inst_simple /usr/lib/systemd/system/systemd-modules-load.service \
		"$systemdsystemunitdir/systemd-modules-load.service"

	# wrapper for sel-ebc.service
	inst_simple "$moddir/pvebc-wrapper.sh" \
		"/etc/sel-ebc/pvebc-wrapper.sh"

	# override crypttab
	inst_simple "$moddir/override-crypttab.sh" \
		"/etc/sel-ebc/override-crypttab.sh"

	# copy main application
	inst_binary "/usr/bin/pvebc"
	inst_binary "/usr/bin/pvsecret"

	inst_simple "$moddir/sel-ebc.crypttab" "/etc/sel-ebc/crypttab"

	# Create the enablement symlinks in the image using host systemctl:
	# shellcheck disable=SC2154
	inst_dir "$initdir/etc/systemd/system"
	systemctl --root "$initdir" --no-reload --quiet enable sel-ebc.target
	systemctl --root "$initdir" --no-reload --quiet enable sel-ebc-pvebc.service
	systemctl --root "$initdir" --no-reload --quiet enable sel-ebc-override-crypttab.service
	systemctl --root "$initdir" --no-reload --quiet enable sel-ebc-paes-enforce.service
	systemctl --root "$initdir" --no-reload --quiet enable systemd-modules-load.service
	systemctl --root "$initdir" --no-reload --quiet enable boot.mount
}
