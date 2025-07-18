#!/bin/sh
#
# Copyright IBM Corp. 2021
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

. /lib/dracut-lib.sh

MNTDIR="/ngdump"
DUMP="dump.elf"
META="ngdump.meta"
VMCORE="/proc/vmcore"

is_dump_part_ok()
{
	ismounted "$MNTDIR" && [ -e "$MNTDIR/$META" ]
}

save_logs()
{
	is_dump_part_ok || return
	[ -e "$VMCORE" ] && makedumpfile -f --dump-dmesg "$VMCORE" "$MNTDIR/crash.log"
	journalctl -b >"$MNTDIR/boot.log"
}

cleanup()
{
	sync
	umount "$MNTDIR"
}

bail_out()
{
	warn "$1"
	save_logs
	cleanup
	exit 1
}

save_meta()
{
	local hash=$(sha256sum "$MNTDIR/$DUMP" | cut -f1 -d ' ')

	cat >"$MNTDIR/$META" <<EOF
version=1
file=$DUMP
sha256sum=$hash
EOF
}

info "NGDump started"

is_dump_part_ok || { bail_out "Dump partition not found"; }

#
# We must save the dump as ELF format, because
# kdump compressed format is not supported by zgetdump yet
#
makedumpfile -f -E --message-level 7 -d 31 "$VMCORE" "$MNTDIR/$DUMP"

[ $? -eq 0 ] || { bail_out "makedumpfile failed"; }

#
# Create a file containing meta information for zgetdump
#
save_meta
[ $? -eq 0 ] || { bail_out "Could not update $META"; }
save_logs
cleanup

exit 0
