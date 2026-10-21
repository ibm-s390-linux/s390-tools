#
# Copyright IBM Corp. 2026
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#
# zdev-cmdline-lib.sh
#   Shared parsing of rd.zdev device specifications, sourced by both the
#   dracut module and the initramfs-tools boot script so that the two cannot
#   drift apart.
#
# Format:
#   rd.zdev=no-auto
#   rd.zdev=<type>,<device-spec>[,<attribute>=<value>]...
#
# Commas separate fields, so <device-spec> must not contain commas: use the
# chzdev colon notation for group devices, and repeat rd.zdev= for further
# devices. Attributes are passed to chzdev verbatim -- chzdev and the kernel
# arbitrate, never this parser.
#

# Arguments for user-provided configuration. Deliberately not --auto-conf:
# explicit user intent must not be recorded as firmware-provided, and must
# take precedence over it. Persistent-only, so that the offline-only attribute
# check never applies to the active configuration and devices come online in
# exactly one place: the cold-plug that follows.
zdev_cmdline_args="--enable --persistent --yes --force --no-root-update --no-settle"

# Validate one rd.zdev value.
# Returns 0 if usable, else 1 with a human-readable reason on stdout.
zdev_check_spec() {
	_spec="$1"
	_saved_ifs="$IFS"
	IFS=","
	# shellcheck disable=SC2086
	set -- $_spec
	IFS="$_saved_ifs"

	if [ $# -lt 2 ] ; then
		echo "expected <type>,<device-spec>[,<attr>=<val>]..."
		return 1
	fi
	if [ -z "$1" ] || [ -z "$2" ] ; then
		echo "empty device type or device specification"
		return 1
	fi
	case "$1" in *=*)
		echo "device type '$1' must not contain '='"
		return 1 ;;
	esac
	case "$2" in *=*)
		echo "device specification '$2' must not contain '='"
		return 1 ;;
	esac
	shift 2
	for _tok in "$@" ; do
		case "$_tok" in
		*=*) ;;
		*)
			echo "unexpected token '$_tok' (device lists use ':' not ',')"
			return 1 ;;
		esac
	done
	return 0
}

# Split one rd.zdev value into chzdev arguments, one per line.
# Safe to use unquoted in a command substitution: a kernel command line token
# cannot contain whitespace, so IFS splitting of the result is lossless.
zdev_spec_to_args() {
	_saved_ifs="$IFS"
	IFS=","
	# shellcheck disable=SC2086
	set -- $1
	IFS="$_saved_ifs"
	for _f in "$@" ; do printf '%s\n' "$_f" ; done
}
