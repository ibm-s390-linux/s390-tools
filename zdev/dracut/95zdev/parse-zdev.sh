#!/bin/sh
#
# Copyright IBM Corp. 2017,2021
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
# 95zdev/parse-zdev.sh
#   Parse the kernel command line for rd.zdev kernel parameters. These
#   parameters are evaluated and used to configure z Systems specific devices.
#
# Format:
#   rd.zdev=no-auto
#   rd.zdev=<type>,<device-spec>[,<attribute>=<value>]...
#
#     where
#
#   no-auto:       Indicates that firmware-provided I/O configuration data
#                  should not be applied. This also affects automatic
#                  activation of PCI and crypto devices when running in a DPM
#                  LPAR.
#
#   <type>:        A chzdev device type, for example qeth or dasd-eckd.
#
#   <device-spec>: A chzdev device ID or group device ID. Commas separate the
#                  fields of this parameter, so group devices use the chzdev
#                  colon notation. Repeat rd.zdev= for further devices.
#
#   <attribute>:   Any attribute supported by chzdev for that device type, for
#                  example portno or layer2. Attributes are passed to chzdev
#                  verbatim.
#
#   Examples:
#     rd.zdev=qeth,0.0.0600:0.0.0601:0.0.0602,layer2=0,portno=1
#     rd.zdev=qeth,600,layer2=0,portno=1
#
#   Any device specification accepted by chzdev may be used, including the
#   short form shown above, which chzdev expands to the full group device.
#

# Optional: only required for rd.zdev device specifications. Sourcing it
# defensively keeps firmware auto-configuration working unchanged should the
# file be absent.
[ -r /lib/zdev-cmdline-lib.sh ] && . /lib/zdev-cmdline-lib.sh

zdev_fw_file="/sys/firmware/sclp_sd/config/data"
zdev_base_args="--force --yes --no-root-update --no-settle --auto-conf --quiet"
zdev_id="/lib/s390-tools/zdev_id"

# s390 line-mode consoles (3215/3270) make the journal impractical to reach
# during boot, so mirror diagnostics to /dev/kmsg.
# <30> = facility LOG_DAEMON(3) << 3 | level LOG_INFO(6).
zdev_log() {
    while read -r _line || [ -n "$_line" ] ; do
        echo "<30>zdev: $_line" > /dev/kmsg
    done
}
zdev_msg() { echo "$*" | zdev_log ; }

if [ -e "$zdev_fw_file" ] ; then
    zdev_auto=1
else
    zdev_auto=0
fi

zdev_specs=""
for zdev_arg in $(getargs rd.zdev); do
    if [ "$zdev_arg" = "no-auto" ] ; then
        zdev_auto=0
    else
        zdev_specs="$zdev_specs $zdev_arg"
    fi
done

# Explicit device specifications are applied before firmware
# auto-configuration. portno and layer2 may only be set while the device is
# offline, and the firmware path below brings devices online. Persistent rules
# are written to /etc/udev/rules.d and mask same-named auto-configuration
# rules in /run/udev/rules.d per device, so devices not named here keep their
# firmware-provided configuration.
if [ -n "$zdev_specs" ] && ! type zdev_check_spec >/dev/null 2>&1 ; then
    zdev_msg "rd.zdev device specifications need zdev-cmdline-lib.sh, ignoring"
    zdev_specs=""
fi

for zdev_spec in $zdev_specs; do
    if ! zdev_reason=$(zdev_check_spec "$zdev_spec") ; then
        zdev_msg "ignoring malformed rd.zdev=$zdev_spec: $zdev_reason"
        continue
    fi
    zdev_msg "configuring $zdev_spec"
    # shellcheck disable=SC2046,SC2086
    zdev_out=$(chzdev $zdev_cmdline_args \
                      $(zdev_spec_to_args "$zdev_spec") zdev:early=1 2>&1)
    zdev_rc=$?
    [ -n "$zdev_out" ] && printf '%s\n' "$zdev_out" | zdev_log
    if [ $zdev_rc -ne 0 ] ; then
        # Never abort: the user must still be able to reach the interactive
        # installer.
        zdev_msg "rd.zdev=$zdev_spec failed (rc=$zdev_rc), continuing"
    fi
done

if [ $zdev_auto -eq 1 ] ; then
    # shellcheck disable=SC2086
    chzdev --import "$zdev_fw_file" $zdev_base_args

    # Get information about DPM environment
    tmp="/tmp/zdev_id.env"
    if "$zdev_id" >"$tmp"; then
        while IFS='=' read -r key val; do
            case "$key" in
            ZDEV_*)
                val=${val#\"}
                val=${val%\"}
                export "$key=$val"
                ;;
            esac
        done <"$tmp"
    fi
    rm -f "$tmp"

    if [ "$ZDEV_IS_DPM,$ZDEV_NEST_LEVEL,$ZDEV_HYPERVISOR_0" = "1,1,LPAR" ] ; then
      # Manually iterate over existing PCI devices - there is a udev rule
      # that handles this for PCI devices added at runtime but that doesn't
      # work for PCI devices defined before boot because there is no coldplug
      # trigger for /sys/bus/pci/slots
      for slot in /sys/bus/pci/slots/* ; do
        read -r power < "$slot/power"
        if [ "$power" = "0" ] ; then
            echo 1 > "$slot/power"
        fi
      done
    fi
fi
