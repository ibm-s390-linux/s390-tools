#!/bin/sh
#
# Copyright IBM Corp. 2017
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
#                  should not be applied.
#

zdev_fw_file="/sys/firmware/sclp_sd/config/data"
zdev_base_args="--force --yes --no-root-update --no-settle --auto-conf --quiet"

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
fi
