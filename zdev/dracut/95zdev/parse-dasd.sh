#!/bin/sh
#
# Copyright IBM Corp. 2023
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
# 95zdev/parse-dasd.sh
#   Parse the command line for rd.dasd parameters. These
#   parameters are evaluated and used to configure dasd devices.
#

# shellcheck source=/dev/null
type zdev_parse_dasd_list > /dev/null 2>&1 || . /lib/s390-tools/zdev-from-dasd_mod.dasd

# at this point in time dracut's vinfo() only logs to journal which is hard for
# s390 users to find and access on a line mode console such as 3215 mode
# so use a vinfo alternative that still prints to the console via kmsg
zdev_vinfo() {
    local _zdev_vinfo_line
    while read -r _zdev_vinfo_line || [ -n "$_zdev_vinfo_line" ]; do
        # Prefix "<30>" represents facility LOG_DAEMON 3 and loglevel INFO 6:
        # (facility << 3) | level.
        echo "<30>dracut: $_zdev_vinfo_line" > /dev/kmsg
    done
}

zdev_parse_rd_dasd() {
    local _zdev_dasd _zdev_dasd_list
    for _zdev_dasd in $(getargs rd.dasd -d 'rd_DASD='); do
        _zdev_dasd_list="${_zdev_dasd_list:+${_zdev_dasd_list},}$_zdev_dasd"
    done
    echo "$_zdev_dasd_list"
}

zdev_parse_rd_dasd | zdev_parse_dasd_list globals 2>&1 | zdev_vinfo
zdev_parse_rd_dasd | zdev_parse_dasd_list ranges 2>&1 | zdev_vinfo
