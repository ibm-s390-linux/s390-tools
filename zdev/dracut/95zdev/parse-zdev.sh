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
#
#     where
#
#   no-auto:       Indicates that firmware-provided I/O configuration data
#                  should not be applied. This also affects automatic
#                  activation of PCI and crypto devices when running in a DPM
#                  LPAR.
#

zdev_fw_file="/sys/firmware/sclp_sd/config/data"
zdev_base_args="--force --yes --no-root-update --no-settle --auto-conf --quiet"
zdev_id="/lib/s390-tools/zdev_id"

if [ -e "$zdev_fw_file" ] ; then
    zdev_auto=1
else
    zdev_auto=0
fi

for zdev_arg in $(getargs rd.zdev); do
    if [ "$zdev_arg" = "no-auto" ] ; then
        zdev_auto=0
    fi
done

if [ $zdev_auto -eq 1 ] ; then
    chzdev --import "$zdev_fw_file" $zdev_base_args

    # Get information about DPM environment
    for line in $($zdev_id) ; do
        eval "$line"
    done

    if [ "$ZDEV_IS_DPM,$ZDEV_NEST_LEVEL,$ZDEV_HYPERVISOR_0" = "1,1,LPAR" ] ; then
      # Manually iterate over existing PCI devices - there is a udev rule
      # that handles this for PCI devices added at runtime but that doesn't
      # work for PCI devices defined before boot because there is no coldplug
      # trigger for /sys/bus/pci/slots
      for slot in /sys/bus/pci/slots/* ; do
        read power < "$slot/power"
        if [ "$power" = "0" ] ; then
            echo 1 > "$slot/power"
        fi
      done
    fi
fi
