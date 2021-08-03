#!/bin/bash
#
# Copyright IBM Corp. 2021
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

check() {
    require_binaries sync poweroff || return 1
    require_binaries cut sha256sum findmnt makedumpfile || return 1
    # Only include the dracut module, if another module requires it
    # or if explicitly specified in the config file or on the argument list.
    return 255
}

depends() {
    echo "base shutdown systemd"
}

installkernel() {
    instmods nvme ext4
}

install() {
    mkdir -p "${initdir}/ngdump"

    inst sync
    inst poweroff
    inst cut
    inst sha256sum
    inst findmnt
    inst makedumpfile

    inst "$moddir/ngdump.sh" "/usr/bin/ngdump.sh"
    inst "$moddir/ngdump-reipl.sh" "/usr/bin/ngdump-reipl.sh"
    inst "$moddir/ngdump.service" "$systemdsystemunitdir/ngdump.service"

    systemctl -q --root "$initdir" add-wants initrd.target ngdump.service
}
