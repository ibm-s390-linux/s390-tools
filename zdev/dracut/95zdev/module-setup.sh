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
#   the root device was configured using the chzdev tool.
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
    local _modules=$(lszdev --by-path / --columns MODULES --no-headings)

    [ ! -z "$_modules" ] && instmods $_modules
}

install() {
    local _tempfile=$(mktemp dracut-zdev.XXXX)

    if chzdev --export - --persistent --by-path / >/dev/null 2>&1 ; then
        # Use persistent configuration
        chzdev --export "$_tempfile" --persistent --by-path / --quiet --type
    else
        # Use active configuration
        chzdev --export "$_tempfile" --active --by-path / --quiet --type
        sed -i -e 's/active/persistent/g' "$_tempfile"
    fi

    # Apply via --import to prevent other devices from being configured
    chzdev --import "$_tempfile" --persistent --base "/etc=$initdir/etc" \
           --yes --quiet --no-root-update --force >/dev/null

    rm -f "$_tempfile"

    return 0
}
