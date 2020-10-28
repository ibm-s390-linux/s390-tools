#!/usr/bin/bash

. $dracutfunctions

if ! [[ -d "${initdir}/tmp" ]]; then
    mkdir -p "${initdir}/tmp"
fi

check() {
    [[ $debug ]] && set -x
    #kdumpctl sets this explicitly
    if [ -z "$IN_KDUMP" ]
    then
        return 1
    fi
    return 0
}

depends() {
    local _dep="base shutdown"
    echo $_dep
    return 0
}

installkernel() {
    hostonly='' instmods fuse
}

install() {
    inst "/usr/sbin/hsavmcore" "/usr/sbin/hsavmcore"
    inst "/etc/hsavmcore.conf" "/etc/hsavmcore.conf"
    inst "$moddir/hsavmcore.service" "$systemdsystemunitdir/hsavmcore.service"
    mkdir -p "$initdir/$systemdsystemunitdir/initrd.target.wants"
    ln_r "$systemdsystemunitdir/hsavmcore.service" "$systemdsystemunitdir/initrd.target.wants/hsavmcore.service"

    inst_hook pre-mount 30 "$moddir/setup-fuse.sh"
}
