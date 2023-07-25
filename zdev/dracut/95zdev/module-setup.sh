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
    local _arch
    _arch=$(uname -m)

    # Ensure that we're running on s390
    [ "$_arch" = "s390" ] || [ "$_arch" = "s390x" ] || return 1

    # shellcheck source=/dev/null
    source "${moddir:?}/zdev-lib.sh"

    # Leave kdump device configuration to module zdev-kdump to
    # ensure a minimal device footprint
    is_kdump && return 1

    # Ensure that required tools are available
    require_binaries chzdev lszdev /lib/s390-tools/zdev_id || return 1

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
    inst_multiple chzdev lszdev vmcp /lib/s390-tools/zdev_id

    # Hook to parse zdev kernel parameter
    inst_hook cmdline 95 "$moddir/parse-zdev.sh"

    # Rule to automatically enable devices when running in DPM
    inst_rules "81-dpm.rules"

    # Obtain early + root device configuration
    _tempfile=$(mktemp --tmpdir dracut-zdev.XXXXXX)
    function check_zdev() {
        local _dev=$1
        local _devsysfs _bdevpath
        _devsysfs=$(
            cd -P /sys/dev/block/"$_dev" && echo "$PWD"
                 )
        _bdevpath=/dev/${_devsysfs##*/}
        chzdev --export - --persistent --by-node "$_bdevpath" --quiet \
               --type 2>/dev/null >> "$_tempfile"
    }
    for_each_host_dev_and_slaves_all check_zdev

    chzdev --export - --persistent --by-attrib "zdev:early=1" --quiet \
	   --type 2>/dev/null >> "$_tempfile"

    # Obtain early device configuration for site-specific settings
    for (( site=0; site<10; site++ ))
    do
    chzdev --export - --persistent --by-attrib "zdev:early=1" --site $site \
           --quiet 2>/dev/null >> "$_tempfile"
    done

    # Apply via --import to prevent other devices from being configured
    chzdev --import "$_tempfile" --persistent --base "/etc=${initdir:?}/etc" \
           --yes --quiet --no-root-update --force >/dev/null
    # Apply site-specific configurations via --import
    for (( site=0; site<10; site++ ))
    do
    chzdev --import "$_tempfile" --persistent --base "/etc=$initdir/etc" \
           --site $site --yes --quiet --no-root-update --force >/dev/null
    done

    rm -f "$_tempfile"

    return 0
}
