#!/bin/sh
#
# ap-check.sh - Wrapper script for 'ap-check' binary
#
# mdevctl has deprecated the /etc/mdevctl.d/scripts.d/callouts/ location in
# newer releases.  This wrapper ensures that mdevctl 1.2.0 and older can
# still access 'ap-check' for now, and will be removed at a later time.
#
# Copyright 2022 IBM Corp.
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

[ -e /usr/lib/mdevctl/scripts.d/callouts/ap-check ] && /usr/lib/mdevctl/scripts.d/callouts/ap-check "$@"
