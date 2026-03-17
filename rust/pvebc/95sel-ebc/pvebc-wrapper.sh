#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright IBM Corp.

SYSFS=/sys/firmware/uv/prot_virt_guest
SICS=/boot/sics
EBC_TMPFS=/run/sel-ebc
TOC=toc.asr
ASR_NAME=luks-rfs-passphrase

# Early exit for non SEL guests
if [[ ! -e $SYSFS ]]; then
	echo "Not running in a SEL guest."
	exit 1
fi
if [[ $(cat $SYSFS) -ne 1 ]]; then
	echo "Not running in a SEL guest."
	exit 1
fi
echo "Running in SEL guest."

# Copy EBC resources from /boot/sics to tmpfs for security
# This protects against host injection attacks by moving resources to UV-protected RAM
echo "Copying EBC resources from $SICS to $EBC_TMPFS"
if ! mkdir -p "$EBC_TMPFS"; then
	echo "Failed to create $EBC_TMPFS"
	exit 1
fi

# Copy only .asr and .pol files
for file in "$SICS"/*.asr "$SICS"/*.pol; do
	if [[ -f "$file" && ! -L "$file" ]]; then
		cp "$file" "$EBC_TMPFS/" || {
			echo "Failed to copy $file to $EBC_TMPFS"
			exit 1
		}
	fi
done

# Verify toc.asr was copied
if [[ ! -f "$EBC_TMPFS/$TOC" ]]; then
	echo "Error: $EBC_TMPFS/$TOC does not exist after copy"
	exit 1
fi

# execute the actual tool with the copied toc.asr
pvebc --toc "$EBC_TMPFS/$TOC"
rc=$?
if [[ $rc -ne 0 ]]; then
	exit $rc
fi

# Retrieve and check for dummy LUKS passphrase
pvsecret retrieve --inform name -o "$EBC_TMPFS/$ASR_NAME" --outform bin "$ASR_NAME"

if [[ ! -f "$EBC_TMPFS/$ASR_NAME" ]]; then
	echo "$EBC_TMPFS/$ASR_NAME does not exist"
fi

chmod 400 "$EBC_TMPFS/$ASR_NAME"

exit 0
