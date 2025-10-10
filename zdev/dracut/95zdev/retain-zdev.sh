#!/bin/sh
#
# Copyright IBM Corp. 2023
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
# 95zdev/retain-zdev.sh
#   Copy zdev persistent config from initrd to root-fs.
#

chzdev --export /run/zdev.initrd.config --configured --type --persistent --quiet

# Apart from debugging purposes, this is useful for distro installers,
# which can import the early config into their own environment early
# after starting:
# chzdev --import /run/zdev.initrd.config --persistent --yes --no-root-update --force --verbose
#
# After that, distro installers can modify/add the device config based
# on interactive or unattended installation choices using
# chzdev --enable --active --persistent ...
#
# Finally, distro installers can likewise transfer the entire device config
# to the installed system mounted under $SYSROOT:
# chzdev --export /tmp/zdev.config --all --type --persistent --verbose
# chzdev --import /tmp/zdev.config --persistent --yes --no-root-update --force --verbose --base "$SYSROOT"
