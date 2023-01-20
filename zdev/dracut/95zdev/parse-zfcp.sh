#!/bin/sh
#
# Copyright IBM Corp. 2023
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
# 95zdev/parse-zfcp.sh
#   Parse the command line for rd.zfcp parameters. These
#   parameters are evaluated and used to configure zfcp devices.
#

zdev_zfcp_base_args="--no-settle --yes --quiet --no-root-update --force"

for zdev_zfcp_arg in $(getargs rd.zfcp -d 'rd_ZFCP='); do
    (
        IFS_SAVED="$IFS"
        IFS="," # did not work in front of built-in set command below
        # shellcheck disable=SC2086
        set -- $zdev_zfcp_arg
        IFS=":" args="$*"
        IFS="$IFS_SAVED"
        if [ "$#" -eq 1 ]; then
            # shellcheck disable=SC2086
            chzdev --enable --persistent $zdev_zfcp_base_args \
                   zfcp-host "$args"
        else
            # shellcheck disable=SC2086
            chzdev --enable --persistent $zdev_zfcp_base_args \
                   zfcp-lun "$args"
        fi
    )
done
unset zdev_zfcp_arg
unset zdev_zfcp_base_args
