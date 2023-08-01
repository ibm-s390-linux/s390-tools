#!/bin/bash
#
# Copyright IBM Corp. 2023
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
#
# 95zdev-kdump/module_setup.sh
#   This module installs configuration files (udev rules and modprobe.conf
#   files) required to enable the kdump target on s390.
#

# called by dracut
check() {
    local _arch=${DRACUT_ARCH:-$(uname -m)}

    # Ensure that we're running on s390
    [ "$_arch" = "s390" -o "$_arch" = "s390x" ] || return 1

    source "$moddir/../95zdev/zdev-lib.sh"

    # Ensure this module is only included when building kdump initrd
    is_kdump || return 1

    # Ensure that required tools are available
    require_binaries chzdev || return 1

    return 0
}

# called by dracut
depends() {
    return 0
}

# called by dracut
installkernel() {
    # Add modules for all device types supported by chzdev (required for
    # auto-configuration)
    instmods ctcm lcs qeth qeth_l2 qeth_l3 dasd_mod dasd_eckd_mod dasd_fba_mod \
             dasd_diag_mod zfcp
}

# called by dracut
install() {
    local _tempfile

    # zdev_id is not functionally required for kdump but optionally
    # installing avoids error messages from zdev site udev rule processing
    inst_multiple -o /lib/s390-tools/zdev_id

    # Obtain kdump target device configuration

    _tempfile=$(mktemp --tmpdir dracut-zdev.XXXXXX)

    # work with systems that are not based on chzdev persistent config
    local _configuration="--active"
    # disable zfcp auto LUN scan to prevent OOM situations on systems with
    # many zFCP LUNs
    inst_dir /etc/modprobe.d
    chzdev zfcp --type "allow_lun_scan=0" --persistent \
           --base "/etc=$initdir/etc" --yes --quiet --no-root-update \
           --force >/dev/null
    # drop /etc/zfcp.conf from dracut module 95zfcp
    echo "rd.zfcp.conf=0" > "$initdir/etc/cmdline.d/00-no-zfcp-conf.conf"
    # => only activate individual zfcp paths found as required below

    function check_zdev() {
        local _dev=$1
        local _devsysfs _bdevpath
        _devsysfs=$(
            cd -P /sys/dev/block/"$_dev" && echo "$PWD"
                 )
        _bdevpath=/dev/${_devsysfs##*/}
        # do not export device type information potentially unknown on import
        chzdev --export - "$_configuration" --by-node "$_bdevpath" --quiet \
               2>/dev/null >> "$_tempfile"
    }
    for_each_host_dev_and_slaves_all check_zdev
    sed -i -e 's/^\[active /\[persistent /' "$_tempfile"

    # Apply via --import to prevent other devices from being configured
    chzdev --import "$_tempfile" --persistent --base "/etc=$initdir/etc" \
           --yes --quiet --no-root-update --force >/dev/null

    rm -f "$_tempfile"

    # these are purely generated udev rules so we have to glob expand
    # within $initdir and strip the $initdir prefix for mark_hostonly
    local -a _array
    local _nullglob=$(shopt -p nullglob)
    shopt -u nullglob
    readarray -t _array < \
	      <(ls -1 $initdir/etc/udev/rules.d/41-*.rules 2> /dev/null)
    [[ ${#_array[@]} -gt 0 ]] && mark_hostonly "${_array[@]#$initdir}"
    readarray -t _array < \
	      <(ls -1 $initdir/etc/modprobe.d/s390x-*.conf 2> /dev/null)
    [[ ${#_array[@]} -gt 0 ]] && mark_hostonly "${_array[@]#$initdir}"
    $_nullglob

    return 0
}
