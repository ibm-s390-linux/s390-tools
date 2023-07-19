#
# Copyright IBM Corp. 2023
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
#
# 95zdev/zdev-lib.sh
#   Common shell library functionality for 95zdev and 95zdev-kdump.
#
# shellcheck shell=bash

is_kdump() {
    # https://src.fedoraproject.org/rpms/kexec-tools/c/4eedcae5e1540690a3761857fe2e692774c44960
    # https://src.fedoraproject.org/rpms/kexec-tools/blob/rawhide/f/mkdumprd
    # https://src.fedoraproject.org/rpms/kexec-tools/blob/rawhide/f/dracut-module-setup.sh
    if [[ $hostonly && "$hostonly_mode" == "strict" && -n "$IN_KDUMP" ]]; then
        return 0
    fi
    # https://github.com/openSUSE/kdump/blob/master/dracut/module-setup.sh
    if [[ " $dracutmodules $add_dracutmodules $force_add_dracutmodules " == *\ kdump\ * ]]; then
        return 0
    fi
    return 1
}
