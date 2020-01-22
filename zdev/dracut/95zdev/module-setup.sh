#!/bin/bash
#
# Copyright IBM Corp. 2016, 2017
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
#
# 95zdev/module_setup.sh
#   This module installs configuration files (udev rules and modprobe.conf
#   files) required to enable the root device on s390. It will only work when
#   the root device was configured using the chzdev tool. In addition,
#   a hook is installed to parse rd.zdev= kernel parameters.
#

check() {
    local _arch=$(uname -m)

    # Ensure that we're running on s390
    [ "$_arch" = "s390" -o "$_arch" = "s390x" ] || return 1

    # Ensure that required tools are available
    require_binaries chzdev lszdev || return 1

    return 0
}

depends() {
    return 0
}

installkernel() {
    # Add modules for all device types supported by chzdev (required for
    # auto-configuration)
    instmods ctcm lcs qeth qeth_l2 qeth_l3 dasd_mod dasd_eckd_mod dasd_fba_mod \
	     dasd_diag_mod zfcp
}

install() {
    local _tempfile

    # Ensure that required tools are available
    inst_multiple chzdev lszdev vmcp

    # Hook to parse zdev kernel parameter
    inst_hook cmdline 95 "$moddir/parse-zdev.sh"

    # Obtain early + root device configuration
    _tempfile=$(mktemp --tmpdir dracut-zdev.XXXXXX)
    chzdev --export "$_tempfile" --persistent --by-path / --quiet \
	   --type 2>/dev/null
    chzdev --export - --persistent --by-attrib "zdev:early=1" --quiet \
	   --type 2>/dev/null >> "$_tempfile"

    # Apply via --import to prevent other devices from being configured
    chzdev --import "$_tempfile" --persistent --base "/etc=$initdir/etc" \
           --yes --quiet --no-root-update --force >/dev/null

    rm -f "$_tempfile"

    return 0
}
