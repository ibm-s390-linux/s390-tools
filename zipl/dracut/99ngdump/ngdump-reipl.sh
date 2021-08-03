#!/bin/sh
#
# Copyright IBM Corp. 2021
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

#
# The following steps make the firmware IPL the production system again.
# Otherwise, the firmware will boot the dumper again.
#

dir=$(findmnt -n -o TARGET debugfs)
if [ -z "$dir" ]; then
	dir=/sys/kernel/debug
	mount -t debugfs none "$dir"
fi
echo 1 > "$dir/zcore/reipl"
poweroff
