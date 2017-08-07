#!/bin/bash
#
# start_hsnc.sh - HiperSockets Network Concentrator
#
# Wrapper start script for ip_watcher.pl, also cleanup, when ip_watcher.pl
# gets killed.
#
# Copyright IBM Corp. 2003, 2017
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

#
# functions
#

function __usage
{
	echo ""
	echo "For more information about HiperSocket Network Concentrator"
	echo "please refer to the 'Device Drivers, Features, and Commands'"
	echo "manual."
	exit 0

}

function PrintVersion
{
        echo "$script_name version %S390_TOOLS_VERSION%"
        echo "Copyright IBM Corp. 2003, 2017"
}
#
# main
#

script_name="HiperSocket Network Concentrator"      # name of this script
#
# what is the kernel version we are on ?
#
kernel_version=`uname -r`
xcec_bridge="yes"
if [ "${kernel_version:0:1}" \> 2 ]; then
	kernel_version="ok"
else
	if [ "${kernel_version:4:2}" \< 26 ]; then
		xcec_bridge="no"
	fi
	if [ "${kernel_version:2:1}" \> 4 ]; then
		kernel_version="ok"
	else
		echo kernel version too old for this hsnc version.
		exit 1
	fi
fi


#
# parse options (currently none avail)  
#
case "$1" in
   -v | --version  ) PrintVersion
     	     exit 0 ;;
   -h | --help  ) __usage ;;               
esac

if [ X${1}X != XX ] && [ $kernel_version = "ok" ] ; then
	if ! ls /sys/class/net | grep "^$1$" > /dev/null; then
		echo interface $1 does not exist.
		exit 1
	fi
else
	if [ $xcec_bridge = "no" ] ; then
		echo kernel version too old for this hsnc version.
		exit 1
	fi
fi

ip_watcher.pl $*

echo ip_watcher.pl was terminated, cleaning up.

if [ X${1}X == XX ] ; then
	echo killing xcec-bridge
	killall xcec-bridge
fi

echo removing all parp entries from mc interfaces
if [ X${1}X == XX ] ; then
	for DEV in $(ls /sys/devices/qeth/ | egrep '^.+\..+\..+')
	do
		if_name=`cat /sys/devices/qeth/$DEV/if_name | sed 's/$/\$/'`
		rtr=`cat /sys/devices/qeth/$DEV/route4 2> /dev/null | egrep 'multicast'`
		if [ -n "$rtr" ] ; then
			echo $if_name >> /tmp/ip_watcher.cleanup1
		fi
	done
else
	echo ${1}$ > /tmp/ip_watcher.cleanup1
fi

qethconf rxip list | sed 's/add/del/' | egrep -f /tmp/ip_watcher.cleanup1 > /tmp/ip_watcher.cleanup2


while read line; do
	qethconf $line > /dev/null 2>&1
done < /tmp/ip_watcher.cleanup2
rm /tmp/ip_watcher.cleanup1
rm /tmp/ip_watcher.cleanup2

echo removing all routes from connector interfaces
for DEV in $(ls /sys/devices/qeth/ | egrep '^.+\..+\..+')
do
	if_name=`cat /sys/devices/qeth/$DEV/if_name | sed 's/$/\$/'`
	rtr=`cat /sys/devices/qeth/$DEV/route4 2> /dev/null | egrep 'connector'`
	if [ -n "$rtr" ] ; then
		echo $if_name >> /tmp/ip_watcher.cleanup1
	fi
done
route -n | egrep -f /tmp/ip_watcher.cleanup1 > /tmp/ip_watcher.cleanup2
while read line; do
	route del -net `echo $line | awk '{print $1 " netmask " $3 " dev " $8}'`
done < /tmp/ip_watcher.cleanup2
rm /tmp/ip_watcher.cleanup1
rm /tmp/ip_watcher.cleanup2
