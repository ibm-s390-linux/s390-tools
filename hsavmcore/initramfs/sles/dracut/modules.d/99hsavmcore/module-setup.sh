#!/bin/bash

. /lib/kdump/setup-kdump.functions

kdump_needed() {
    # Building a kdump initrd?
    if [[ " $dracutmodules $add_dracutmodules $force_add_dracutmodules" == *\ $_mod\ * ]]; then
        return 0
    fi

    # Is FADUMP active?
    if [ "$KDUMP_FADUMP" = "yes" ]; then
        return 0
    fi

    # Do not include kdump by default
    return 1
}

check() {
    # Get configuration
    kdump_get_config || return 1

    kdump_needed || return 1

    return 0
}

depends() {
    echo "systemd"
    return 0
}

installkernel() {
    hostonly='' instmods fuse
}

install() {
    inst_simple /usr/sbin/hsavmcore
    inst_simple /etc/hsavmcore.conf

    inst "$moddir/hsavmcore.service" "$systemdsystemunitdir/hsavmcore.service"
    mkdir -p "$initdir/$systemdsystemunitdir/initrd.target.wants"
    ln_r "$systemdsystemunitdir/hsavmcore.service" "$systemdsystemunitdir/initrd.target.wants/hsavmcore.service"

    inst_hook pre-mount 30 "$moddir/setup-fuse.sh"
}
