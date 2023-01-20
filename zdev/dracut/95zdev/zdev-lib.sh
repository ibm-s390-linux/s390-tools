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

zdev_is_kdump() {
    # https://src.fedoraproject.org/rpms/kexec-tools/c/4eedcae5e1540690a3761857fe2e692774c44960
    # https://src.fedoraproject.org/rpms/kexec-tools/blob/rawhide/f/mkdumprd
    # https://src.fedoraproject.org/rpms/kexec-tools/blob/rawhide/f/dracut-module-setup.sh
    # shellcheck disable=SC2154
    if [[ $hostonly && "$hostonly_mode" == "strict" && -n "$IN_KDUMP" ]]; then
        return 0
    fi
    # https://github.com/openSUSE/kdump/blob/master/dracut/module-setup.sh
    # shellcheck disable=SC2154
    if [[ " $dracutmodules $add_dracutmodules $force_add_dracutmodules " == *\ kdump\ * ]]; then
        return 0
    fi
    return 1
}

zdev_zfcp_auto_lun_scan_active() {
    local _fcpdevsysfs=$1
    local _porttype _lunscan
    read -r _porttype < "$_fcpdevsysfs"/host*/fc_host/host*/port_type
    read -r _lunscan < /sys/module/zfcp/parameters/allow_lun_scan
    if [[ "$_porttype" == "NPIV VPORT" && "$_lunscan" == "Y" ]]; then
        return 0
    fi
    return 1
}

# zdev_check_dev() can be extended for other device types such as DASD or PCIe
zdev_check_dev() {
    local _dev=$1
    local _devsysfs _devtype _subsystem _driver
    local _intlun _fcplun _scsitarget _wwpn _hbaid
    _devsysfs=$(
        cd -P /sys/dev/block/"$_dev" 2> /dev/null && echo "$PWD"
             )
    # This is roughly what systemd's udev-builtin-path_id does for zfcp:
    while [[ -n "$_devsysfs" ]]; do
        # ascend to parent: strip last path part
        _devsysfs=${_devsysfs%/*}
        _subsystem=$(
            cd -P "$_devsysfs"/subsystem 2> /dev/null && echo "$PWD"
              )
        if [[ "${_subsystem##*/}" == "scsi" ]]; then
            _devtype=$(grep "^DEVTYPE=" "$_devsysfs"/uevent)
            # check for FCP LUN
            if [[ "$_devtype" == "DEVTYPE=scsi_device" ]]; then
                _intlun=${_devsysfs##*:}
                # convert _intlun to _fcplun [int_to_scsilun()]
                _fcplun=0
                ((_fcplun |= (_intlun & 0x000000000000ffff) << 48))
                ((_fcplun |= (_intlun & 0x00000000ffff0000) << 16))
                ((_fcplun |= (_intlun & 0x0000ffff00000000) >> 16))
                ((_fcplun |= (_intlun & 0xffff000000000000) >> 48))
                printf -v _fcplun "0x%016x" "$_fcplun"
                # bail out if not scsi_transport_fc
                [[ "${_devsysfs/*rport-*/FOUND}" == "FOUND" ]] || return 0
                continue
            fi
            # check for target WWPN
            if [[ "$_devtype" == "DEVTYPE=scsi_target" ]]; then
                _scsitarget=${_devsysfs##*/}
                read -r _wwpn < "$_devsysfs/fc_transport/$_scsitarget/port_name"
                continue
            fi
        fi
        if [[ "${_subsystem##*/}" == "ccw" ]]; then
            _driver=$(
                cd -P "$_devsysfs"/driver 2> /dev/null && echo "$PWD"
                  )
            # check for FCP device (vHBA) bus-ID
            if [[ "${_driver##*/}" == "zfcp" ]]; then
                _hbaid=${_devsysfs##*/}
                # drop full path and use zfcp auto LUN scan, if:
                # - not building for kdump which has zfcp auto LUN scan off
                # - and zfcp auto LUN scan is available
                if ! zdev_is_kdump && \
                        zdev_zfcp_auto_lun_scan_active "$_devsysfs"; then
                    unset _wwpn
                    unset _fcplun
                fi
                if [[ -n "$_wwpn" ]] && [[ -n "$_fcplun" ]]; then
                    printf " rd.zfcp=%s,%s,%s\n" "$_hbaid" "$_wwpn" "$_fcplun"
                else
                    printf " rd.zfcp=%s\n" "$_hbaid"
                fi
                break
            fi
        fi
    done
}
