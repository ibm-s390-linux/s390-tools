#!/bin/sh
#
# dbginfo.sh - Tool to collect runtime, configuration, and trace information
#
# Copyright IBM Corp. 2002, 2021
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

# Switching to neutral locale
LC_ALL=C
export LC_ALL

# The general name of this script
readonly SCRIPTNAME="${0##*/}"


########################################
# print version info
print_version() {
    cat <<EOF
${SCRIPTNAME}: Debug information script version %S390_TOOLS_VERSION%
Copyright IBM Corp. 2002, 2021
EOF
}


########################################
# print how to use this script
print_usage()
{
    print_version

    cat <<EOF


Usage: ${SCRIPTNAME} [OPTION]

This script collects runtime, configuration and trace information on
a Linux on IBM Z installation for debugging purposes.

It also traces information about z/VM if the Linux runs under z/VM.


The collected information is written to a TAR archive named

    /tmp/DBGINFO-[date]-[time]-[hostname]-[processorid].tgz

where [date] and [time] are the date and time when debug data is collected.
[hostname] indicates the hostname of the system the data was collected from.
The [processorid] is taken from the processor 0 and indicates the processor
identification.

Options:

	-d|--directory     specify the directory where the data collection
			   stores the temporary data and the final archive.
	-h|--help          print this help
	-v|--version       print version information


Please report bugs to: linux390@de.ibm.com

EOF
}


#######################################
# Parsing the command line and pre checks
#
paramWORKDIR_BASE="/tmp/"

while [ ${#} -gt 0 ]; do
    case ${1} in
	--help|-h)
	    print_usage
	    exit 0
	    ;;
	--version|-v)
	    print_version
	    exit 0
	    ;;
	--directory|-d)
	    paramWORKDIR_BASE=${2}
	    if test -z "${paramWORKDIR_BASE}"; then
	        echo "${SCRIPTNAME}: Error: No directory specified for data collection!"
		echo
		exit 1
	    else
	        # jump to next param, if already last the final shift can do termination
		shift
	    fi
	    ;;
	-*|--*|*)
	    echo
	    echo "${SCRIPTNAME}: invalid option \"${1}\""
	    echo "Try '${SCRIPTNAME} --help' for more information"
	    echo
	    exit 1
	    ;;
    esac
    # next parameter
    shift
done

# check for a valid path
if test ! -d "${paramWORKDIR_BASE}"; then
    echo "${SCRIPTNAME}: Error: The specified directory \"${paramWORKDIR_BASE}\" does not exist!"
    echo
    exit 1
fi

# finally verification to run as root
if test "$(/usr/bin/id -u 2>/dev/null)" -ne 0; then
    echo "${SCRIPTNAME}: Error: You must be user root to run \"${SCRIPTNAME}\"!"
    exit 1
fi


########################################
# Global used variables
#
# The base working directory
readonly WORKDIR_BASE="$(echo "${paramWORKDIR_BASE}" | sed -e 's#/$##')/"

# The terminal
readonly TERMINAL="$(tty 2>/dev/null)"

# The hostname of the system
readonly SYSTEMHOSTNAME="$(hostname -s 2>/dev/null)"

# The kernel release version as delivered from uname -r
readonly KERNEL_RELEASE_VERSION="$(uname -r 2>/dev/null)"

# The processor ID for the first processor
readonly PROCESSORID="$(grep -E ".*processor 0:.*" /proc/cpuinfo | \
                      sed 's/.*identification[[:space:]]*\=[[:space:]]*\([[:alnum:]]*\).*/\1/g')"
# The processor version for the first processor
readonly PROCESSORVERSION="$(grep -E ".*processor 0:.*" /proc/cpuinfo | \
                      sed 's/.*version[[:space:]]*\=[[:space:]]*\([[:alnum:]]*\).*/\1/g')"
# The current date
readonly DATETIME="$(date +%Y-%m-%d-%H-%M-%S 2>/dev/null)"

# The current working directory for the actual script execution
if test -z "${PROCESSORID}"; then
    readonly WORKDIR_CURRENT="DBGINFO-${DATETIME}-${SYSTEMHOSTNAME:-localhost}"
else
    readonly WORKDIR_CURRENT="DBGINFO-${DATETIME}-${SYSTEMHOSTNAME:-localhost}-${PROCESSORID}"
fi

# The current path where the collected information is put together
readonly WORKPATH="${WORKDIR_BASE}${WORKDIR_CURRENT}/"

# The current TAR archive that finally includes all collected information
readonly WORKARCHIVE="${WORKDIR_BASE}${WORKDIR_CURRENT}.tgz"

# The log file of activities from this script execution
readonly LOGFILE="${WORKPATH}dbginfo.log"

# The file to indicate that another instance of the script is already running
readonly LOCKFILE="/tmp/${SCRIPTNAME}.lock"

# File that includes output of Linux commands
readonly OUTPUT_FILE_CMD="${WORKPATH}runtime.out"

# File that includes output of z/VM commands (if running in z/VM)
readonly OUTPUT_FILE_VMCMD="${WORKPATH}zvm_runtime.out"

# File that includes content of files from sysfs
readonly OUTPUT_FILE_SYSFS="${WORKPATH}sysfsfiles.out"

# File that includes the output of lsof
readonly OUTPUT_FILE_LSOF="${WORKPATH}open_files.out"

# File that includes content of OSA OAT
readonly OUTPUT_FILE_OSAOAT="${WORKPATH}osa_oat"

# File that includes content of Ethtool commands
readonly OUTPUT_FILE_ETHTOOL="${WORKPATH}ethtool.out"

# File that includes content of tc commands
readonly OUTPUT_FILE_TC="${WORKPATH}tc.out"

# File that includes content of bridge commands
readonly OUTPUT_FILE_BRIDGE="${WORKPATH}bridge.out"

# File that includes the output of journalctl
readonly OUTPUT_FILE_JOURNALCTL="${WORKPATH}journalctl.out"

# File that includes the output of OpenVSwitch
readonly OUTPUT_FILE_OVS="${WORKPATH}openvswitch"

# File that includes the docker inspect output
readonly OUTPUT_FILE_DOCKER="${WORKPATH}docker_inspect.out"

# File that includes nvme related information
readonly OUTPUT_FILE_NVME="${WORKPATH}nvme.out"

# File that includes KVM related information
readonly OUTPUT_FILE_KVM="${WORKPATH}kvm_runtime.out"

# Mount point of the debug file system
readonly MOUNT_POINT_DEBUGFS="/sys/kernel/debug"

# The kernel version (e.g. '2' from 2.6.32 or '3' from 3.2.1)
readonly KERNEL_VERSION=$(uname -r 2>/dev/null | cut -d'.' -f1)

# The kernel major revision number (e.g. '6' from 2.6.32 or '2' from 3.2.1)
readonly KERNEL_MAJOR_REVISION=$(uname -r 2>/dev/null | cut -d'.' -f2)

# The kernel mainor revision number (e.g. '32' from 2.6.32 or '1' from 3.2.1)
readonly KERNEL_MINOR_REVISION=$(uname -r 2>/dev/null | cut -d'.' -f3 | sed 's/[^0-9].*//g')

# Is this kernel supporting sysfs - since 2.4 (0=yes, 1=no)
if test "${KERNEL_VERSION}" -lt 2 ||
    ( test  "${KERNEL_VERSION}" -eq 2 && test "${KERNEL_MAJOR_REVISION}" -le 4 ); then
    readonly LINUX_SUPPORT_SYSFS=1
else
    readonly LINUX_SUPPORT_SYSFS=0
fi

# Is this kernel potentially using the /sys/kernel/debug feature - since 2.6.13 (0=yes, 1=no)
if test "${KERNEL_VERSION}" -lt 2 ||
    ( test "${KERNEL_VERSION}" -eq 2 &&
	( test "${KERNEL_MAJOR_REVISION}" -lt 6 ||
	    ( test "${KERNEL_MAJOR_REVISION}" -eq 6 && test "${KERNEL_MINOR_REVISION}" -lt 13 ))); then
    readonly LINUX_SUPPORT_SYSFSDBF=1
else
    readonly LINUX_SUPPORT_SYSFSDBF=0
fi

if test "x${PROCESSORVERSION}" = "xFF" || test "x${PROCESSORVERSION}" = "xff"; then
    readonly RUNTIME_ENVIRONMENT=$(grep -E "VM00.*Control Program.*" /proc/sysinfo| sed 's/.*:[[:space:]]*\([[:graph:]]*\).*/\1/g')
else
    readonly RUNTIME_ENVIRONMENT="LPAR"
fi

# define order of collection steps
ALL_STEPS="\
 collect_cmdsout\
 collect_vmcmdsout\
 collect_procfs\
 collect_sysfs\
 collect_logfiles\
 collect_configfiles\
 collect_osaoat\
 collect_ethtool\
 collect_tc\
 collect_bridge\
 collect_ovs\
 collect_docker\
 collect_nvme\
 collect_kvm\
 post_processing\
 create_package\
 environment_cleanup\
 "

# The amount of steps running the whole collections, without last cleanup
readonly COLLECTION_COUNT=`expr $(echo ${ALL_STEPS} | wc -w) - 1`

########################################

# Collection of proc fs entries
PROCFILES="\
  /proc/buddyinfo\
  /proc/cio_ignore\
  /proc/cmdline\
  /proc/cpuinfo\
  /proc/crypto\
  /proc/dasd/devices\
  /proc/dasd/statistics\
  /proc/devices\
  /proc/diskstats\
  /proc/driver/z90crypt\
  /proc/interrupts\
  /proc/iomem\
  /proc/kallsyms\
  /proc/mdstat\
  /proc/meminfo\
  /proc/misc\
  /proc/modules\
  /proc/mounts\
  /proc/net/vlan\
  /proc/net/bonding\
  /proc/net/softnet_stat\
  /proc/partitions\
  /proc/qeth\
  /proc/qeth_perf\
  /proc/qeth_ipa_takeover\
  /proc/sched_debug\
  /proc/schedstat\
  /proc/service_levels\
  /proc/slabinfo\
  /proc/softirqs\
  /proc/stat\
  /proc/swaps\
  /proc/sys/kernel\
  /proc/sys/vm\
  /proc/sysinfo\
  /proc/version\
  /proc/zoneinfo\
  "

# Adding files to PROCFILES in case scsi devices are available
if test -e /proc/scsi; then
    PROCFILES="${PROCFILES}\
      $(find /proc/scsi -type f -perm /444 2>/dev/null)\
      "
fi

# Adding files to PROCFILES in case we run on Kernel 2.4 or older
if test "${LINUX_SUPPORT_SYSFS}" -eq 1; then
    PROCFILES="${PROCFILES}\
      /proc/chpids\
      /proc/chandev\
      /proc/ksyms\
      /proc/lvm/global\
      /proc/subchannels\
      "
fi

# Adding s390dbf files to PROCFILE in case we run on Kernel lower than 2.6.13
if test "${LINUX_SUPPORT_SYSFSDBF}" -eq 1; then
    if test -e /proc/s390dbf; then
	PROCFILES="${PROCFILES}\
	  $(find /proc/s390dbf -type f -not -path "*/raw" -not -path "*/flush" 2>/dev/null)\
	  "
    fi
fi

########################################

LOGFILES="\
  /var/log/anaconda.*\
  /var/log/audit\
  /var/log/boot*\
  /var/log/cron*\
  /var/log/dmesg*\
  /var/log/dracut.log*\
  /var/log/IBMtape.trace\
  /var/log/IBMtape.errorlog\
  /var/log/libvirt\
  /sys/module/kvm/parameters\
  /var/log/lin_tape.trace\
  /var/log/lin_tape.errorlog\
  /var/log/messages*\
  /var/log/syslog*\
  /var/log/sa\
  /var/log/yum.log\
  /var/log/openvswitch/ovs-vswitchd.log\
  /var/log/openvswitch/ovsdb-server.log\
  /run/docker/libcontainerd/containerd/events.log\
  /run/containerd/events.log\
  "

########################################

CONFIGFILES="\
  /boot/grub2/grub.cfg\
  /boot/zipl/active_devices.txt\
  /boot/zipl/config\
  /etc/*.conf\
  /etc/anacrontab\
  /etc/auto.*\
  /etc/cron.*\
  /etc/crontab\
  /etc/crypttab\
  /etc/default\
  /etc/depmod.d\
  /etc/dracut.conf.d\
  /etc/exports\
  /etc/fstab\
  /etc/groups\
  /etc/grub.d\
  /etc/hosts*\
  /etc/iscsi\
  /etc/inittab\
  /etc/libvirt\
  /etc/logrotate.d\
  /etc/lvm\
  /etc/modprobe.conf*\
  /etc/modprobe.d\
  /etc/mtab\
  /etc/multipath\
  /etc/network\
  /etc/networks\
  /etc/pam.d\
  /etc/profile\
  /etc/profile.d\
  /etc/pki/tls/openssl.cnf\
  /etc/rc.d\
  /etc/rc.local\
  /etc/resolv.*\
  /etc/rsyslog.d\
  /etc/ssl/openssl.conf\
  /etc/ssl/openssl.cnf\
  /etc/sysconfig\
  /etc/sysctl.d\
  /etc/syslog*\
  /etc/systemd\
  /etc/udev*\
  /etc/xinet.d\
  /etc/*release\
  $(find /lib/modules -name modules.dep 2>/dev/null)\
  /etc/docker\
  /lib/systemd/system/docker.service\
  /usr/lib/systemd/system\
  /etc/apparmor.d\
  "

########################################
CMDS="uname -a\
  :uptime\
  :runlevel\
  :iptables -L\
  :ulimit -a\
  :ps -emo pid,tid,nlwp,policy,user,tname,ni,pri,psr,sgi_p,stat,wchan,start_time,time,pcpu,pmem,vsize,size,rss,share,command\
  :ps -eHo pid,tid,nlwp,policy,user,tname,ni,pri,psr,sgi_p,stat,wchan,start_time,time,pcpu,pmem,vsize,size,rss,share,command\
  :ps axX\
  :dmesg -s 1048576\
  :last\
  :lsshut\
  :ifconfig -a\
  :nm-tool\
  :route -n\
  :ip route list\
  :ip route list table all\
  :ip rule list\
  :ip neigh list\
  :ip link show\
  :ip ntable\
  :ip a sh\
  :ip -s -s link\
  :firewall-cmd --list-all\
  :ipcs -a\
  :netstat -pantu\
  :netstat -s\
  :dmsetup ls\
  :dmsetup ls --tree\
  :dmsetup table\
  :dmsetup table --target multipath\
  :dmsetup status\
  :multipathd -k'show config'\
  :multipathd -k'show maps'\
  :multipathd -k'show topo'\
  :multipathd -k'show paths'\
  :multipathd -k'show maps stats'\
  :multipathd -k'show maps status'\
  :multipathd -k'show status'\
  :multipathd -k'show daemon'\
  :multipathd -k'show blacklist'\
  :multipathd -k'show devices'\
  :multipath -v6 -ll\
  :multipath -d\
  :multipath -t\
  :lsqeth\
  :lschp\
  :lscss\
  :lscpu -ae\
  :lscpu -ye\
  :lsmem\
  :lsdasd\
  :lsdasd -u\
  :ziorep_config -ADM\
  :lsmod\
  :lszdev\
  :lsscsi\
  :lstape\
  :lszfcp\
  :lszfcp -D\
  :lszfcp -V\
  :icainfo\
  :icastats\
  :lszcrypt -VV\
  :ivp.e\
  :pkcsconf -mlist\
  :cat /var/lib/opencryptoki/pk_config_data\
  :ls -al /usr/lib64/opencryptoki/stdll\
  :SPident\
  :rpm -qa | sort\
  :sysctl -a\
  :lsof \
   > '${OUTPUT_FILE_LSOF}'\
  :mount\
  :df -h\
  :df -i\
  :pvpath -qa\
  :find /boot -print0 | sort -z | xargs -0 -n 10 ls -ld\
  :find /dev -print0 | sort -z | xargs -0 -n 10 ls -ld\
  :java -version\
  :cat /root/.bash_history\
  :env\
  :journalctl --all --no-pager --lines=100000 --output=short-precise\
   > '${OUTPUT_FILE_JOURNALCTL}'\
  :openssl engine\
  :systemd-delta\
  :systemctl --all --no-pager show\
  :systemctl --all --no-pager list-units\
  :systemctl --all --no-pager list-unit-files\
  :docker info\
  :docker images\
  :docker network ls\
  :docker ps -a\
  :docker version\
  :docker stats --no-stream\
  :systemctl status docker.service\
  :blockdev --report\
  :lvdisplay\
  :lspci -vv\
  :smc_dbg\
  "

########################################
VM_CMDS="q userid\
  :q users\
  :q privclass\
  :q cplevel\
  :q cpservice\
  :q cpprot user\
  :q specex\
  :q ssi\
  :q cpus\
  :q srm\
  :q vtod\
  :q time full\
  :q timezone\
  :q loaddev\
  :q v osa\
  :q v dasd\
  :q v crypto\
  :q v fcp\
  :q v pav\
  :q v sw\
  :q v st\
  :q v nic\
  :q st\
  :q xstore\
  :q xstore user system\
  :q sxspages\
  :q vmlan\
  :q vswitch\
  :q vswitch details\
  :q vswitch access\
  :q vswitch active\
  :q vswitch accesslist\
  :q vswitch promiscuous\
  :q vswitch controller\
  :q port group all active details\
  :q set\
  :q comm\
  :q controller all\
  :q fcp\
  :q frames\
  :q lan\
  :q lan all details\
  :q lan all access\
  :q memassist\
  :q nic\
  :q pav\
  :q proc\
  :q proc topology\
  :q mt\
  :q qioass\
  :q spaces\
  :q swch all\
  :q trace\
  :q mdcache\
  :q alloc page\
  :q alloc spool\
  :q dump\
  :q dumpdev\
  :q reorder VMUSERID\
  :q quickdsp VMUSERID\
  :q pcifunction\
  :q vmrelocate\
  :ind load\
  :ind sp\
  :ind user\
  :qemu-ga -V\
  "
###############################################################################
KVM_CMDS="virsh version\
  :virsh nodeinfo\
  :virsh nodememstats\
  :virsh nodecpustats\
  :virsh list --all\
  :virsh iface-list\
  :virsh net-list\
  :virsh nwfilter-list\
  :virsh nodedev-list --tree\
  :virsh pool-list\
  :virt-host-validate\
  "

########################################
collect_cmdsout() {
    local cmd
    local ifs_orig

    ifs_orig="${IFS}"
    pr_syslog_stdout "${step_num} Collecting command output"

    IFS=:
    for cmd in ${CMDS}; do
	IFS=${ifs_orig}	call_run_command "${cmd}" "${OUTPUT_FILE_CMD}"
    done
    IFS="${ifs_orig}"

    if echo "${RUNTIME_ENVIRONMENT}" | grep -qi "z/VM" >/dev/null 2>&1; then
        call_run_command "hyptop -b -d 1 -n 5 -f \#,c,m,C:s,M:s,o -S c" "${OUTPUT_FILE_CMD}"
    else call_run_command "hyptop -b -d 1 -n 5 -f \#,T,c,e,m,C:s,E:s,M:s,o -S c" "${OUTPUT_FILE_CMD}"
    fi

    pr_log_stdout " "
}


########################################
collect_vmcmdsout() {
    local vm_command
    local cp_command
    local vm_cmds
    local vm_userid
    local module_loaded
    local ifs_orig
    local cp_buffer_size
    local rc_buffer_size

    module_loaded=1
    ifs_orig="${IFS}"

    if echo "${RUNTIME_ENVIRONMENT}" | grep -qi "z/VM" >/dev/null 2>&1; then
	pr_syslog_stdout "${step_num} Collecting z/VM command output"

	if which vmcp >/dev/null 2>&1; then
	    cp_command="vmcp"
	    if ! lsmod 2>/dev/null | grep -q vmcp && modinfo vmcp >/dev/null 2>&1; then
		modprobe vmcp && module_loaded=0 && sleep 2
	    fi
	elif which hcp >/dev/null 2>&1; then
	    cp_command="hcp"
	    if ! lsmod 2>/dev/null | grep -q cpint; then
		modprobe cpint && module_loaded=0 && sleep 2
	    fi
	else
	    pr_log_stdout " "
	    pr_log_stdout "${SCRIPTNAME}: Warning: No program found to communicate to z/VM CP"
	    pr_log_stdout "       Skipping collection of z/VM command output"
	    pr_log_stdout " "
	    return 1
	fi
	vm_userid=$(${cp_command} q userid 2>/dev/null | sed -ne 's/^\([^[:space:]]*\).*$/\1/p')

	vm_cmds=$(echo "${VM_CMDS}" | sed "s/VMUSERID/${vm_userid}/g")

	IFS=:
	for vm_command in ${vm_cmds}; do
	    IFS="${ifs_orig}"
	    cp_buffer_size=2
	    rc_buffer_size=2
	    while test ${rc_buffer_size} -eq 2 && test ${cp_buffer_size} -lt 1024; do
		cp_buffer_size=$(( cp_buffer_size * 2 ))

		eval ${cp_command} -b ${cp_buffer_size}k "${vm_command}" >/dev/null 2>&1
		rc_buffer_size=$?
	    done
	    call_run_command "${cp_command} -b ${cp_buffer_size}k ${vm_command}" "${OUTPUT_FILE_VMCMD}"
	    IFS=:
	done
	IFS=${ifs_orig}

	if test ${module_loaded} -eq 0 && test "x${cp_command}" = "xhcp"; then
	    rmmod cpint
	elif test ${module_loaded} -eq 0 && test "x${cp_command}" = "xvmcp"; then
	    rmmod vmcp
	fi
    else
	pr_syslog_stdout "${step_num} Collecting z/VM command output skipped - no z/VM environment"
    fi

    pr_log_stdout " "
}


########################################
collect_procfs() {
    local file_name

    pr_syslog_stdout "${step_num} Collecting procfs"

    for file_name in ${PROCFILES}; do
	call_collect_file "${file_name}"
    done

    pr_log_stdout " "
}


########################################
collect_sysfs() {
    local debugfs_mounted
    local dir_name
    local file_name

    debugfs_mounted=0
    # Requires kernel version newer then 2.4
    if test "${LINUX_SUPPORT_SYSFS}" -eq 0; then
	pr_syslog_stdout "${step_num} Collecting sysfs"
	# Requires kernel version of 2.6.13 or newer
	if test "${LINUX_SUPPORT_SYSFSDBF}" -eq 0; then
	    if ! grep -qE "${MOUNT_POINT_DEBUGFS}.*debugfs" /proc/mounts 2>/dev/null; then
		if mount -t debugfs debugfs "${MOUNT_POINT_DEBUGFS}" >/dev/null 2>&1; then
		    sleep 2
		    debugfs_mounted=1
		else
		    pr_log_stdout "${SCRIPTNAME}: Warning: Unable to mount debugfs at \"${MOUNT_POINT_DEBUGFS}\""
		fi
	    fi
	fi

	# Collect sysfs files using multiple threads (-J 1) while excluding
	# files known to block on read (-x). Stop reading a file that takes
	# more than 5 seconds (-T 5) such as an active ftrace buffer.
	dump2tar /sys -z -o "${WORKPATH}/sysfs.tgz" -x '*/tracing/trace_pipe*' \
		 -x '*/tracing/per_cpu/*' --ignore-failed-read -J 1 -T 5

	if [ $? -ne 0 ] ; then
	    echo "${SCRIPTNAME}: Warning: dump2tar failed or is unavailable - falling back to slow path"
	    call_run_command "find /sys -print0 | sort -z | xargs -0 -n 10 ls -ld" "${OUTPUT_FILE_SYSFS}"

	    find /sys -noleaf -type d 2>/dev/null | while IFS= read -r dir_name; do
	        mkdir -p "${WORKPATH}${dir_name}"
	    done

	    find /sys -noleaf -type f -perm /444\
		      -a -not -name "*trace_pipe*"\
		      2>/dev/null | while IFS= read -r file_name; do
		echo " ${file_name}"
		if ! dd if="${file_name}" status=noxfer iflag=nonblock of="${WORKPATH}${file_name}" >/dev/null 2>&1; then
		    echo "${SCRIPTNAME}: Warning: failed to copy \"${file_name}\""
		fi
	    done
	fi

	if test ${debugfs_mounted} -eq 1; then
	    umount "${MOUNT_POINT_DEBUGFS}"
	fi
    else
	pr_syslog_stdout "${step_num} Collecting sysfs skipped. Kernel $(uname -r) must be newer than 2.4"
    fi

    pr_log_stdout " "
}


########################################
collect_logfiles() {
    local file_name

    pr_syslog_stdout "${step_num} Collecting log files"

    for file_name in ${LOGFILES}; do
	call_collect_file "${file_name}"
    done

    pr_log_stdout " "
}


########################################
collect_configfiles() {
    local file_name

    pr_syslog_stdout "${step_num} Collecting config files"

    for file_name in ${CONFIGFILES}; do
	call_collect_file "${file_name}"
    done

    pr_log_stdout " "
}


########################################
collect_osaoat() {
    local network_devices
    local network_device

    network_devices=$(lsqeth 2>/dev/null | grep "Device name" \
                     | sed 's/.*:[[:space:]]\+\([^[:space:]]*\)[[:space:]]\+/\1/g')
    if which qethqoat >/dev/null 2>&1; then
	if test -n "${network_devices}"; then
	    pr_syslog_stdout "${step_num} Collecting osa oat output"
	    for network_device in ${network_devices}; do
		call_run_command "qethqoat ${network_device}" "${OUTPUT_FILE_OSAOAT}.out" &&
		call_run_command "qethqoat -r ${network_device}" "${OUTPUT_FILE_OSAOAT}_${network_device}.raw"
	    done
	else
	    pr_syslog_stdout "${step_num} Collecting osa oat output skipped - no devices"
	fi
    else
	pr_syslog_stdout "${step_num} Collecting osa oat output skipped - not available"
    fi

    pr_log_stdout " "
}

########################################
collect_ethtool() {
    local network_devices
    local network_device

    network_devices=$(ls /sys/class/net 2>/dev/null)
    if which ethtool >/dev/null 2>&1; then
	if test -n "${network_devices}"; then
	    pr_syslog_stdout "${step_num} Collecting ethtool output"
	    for network_device in ${network_devices}; do
		call_run_command "ethtool ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool -k ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool -a ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool -c ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool --per-queue ${network_device} --show-coalesce" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool -g ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool -i ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool -l ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool -P ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool -S ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
		call_run_command "ethtool -T ${network_device}" "${OUTPUT_FILE_ETHTOOL}"
	    done
	else
	    pr_syslog_stdout "${step_num} Collecting ethtool output skipped - no devices"
	fi
    else
	pr_syslog_stdout "${step_num} Collecting ethtool output skipped - not available"
    fi

    pr_log_stdout " "
}

########################################
collect_tc() {
    local network_devices
    local network_device

    network_devices=$(ls /sys/class/net 2>/dev/null)
    if which tc >/dev/null 2>&1; then
	if test -n "${network_devices}"; then
	    pr_syslog_stdout "${step_num} Collecting tc output"
	    for network_device in ${network_devices}; do
		call_run_command "tc -s qdisc show dev ${network_device}" "${OUTPUT_FILE_TC}"
	    done
	else
	    pr_syslog_stdout "${step_num} Collecting tc output skipped - no devices"
	fi
    else
	pr_syslog_stdout "${step_num} Collecting tc output skipped - not available"
    fi

    pr_log_stdout " "
}

########################################
collect_bridge() {
    local network_devices
    local network_device

    network_devices=$(ls /sys/class/net 2>/dev/null)
    if which bridge >/dev/null 2>&1; then
	if test -n "${network_devices}"; then
	    pr_syslog_stdout "${step_num} Collecting bridge output"
	    for network_device in ${network_devices}; do
		call_run_command "bridge -d link show dev ${network_device}" "${OUTPUT_FILE_BRIDGE}"
		call_run_command "bridge -s fdb show dev ${network_device}" "${OUTPUT_FILE_BRIDGE}"
		call_run_command "bridge -d mdb show dev ${network_device}" "${OUTPUT_FILE_BRIDGE}"
	    done
	else
	    pr_syslog_stdout "${step_num} Collecting bridge output skipped - no devices"
	fi
    else
	pr_syslog_stdout "${step_num} Collecting bridge output skipped - not available"
    fi

    pr_log_stdout " "
}

########################################
# OpenVSwitch
collect_ovs() {
    local br_list
    local ovscmd
    local bridge
    local ovsbrcmd
    local ovscmds
    local ovsbrcmds

    br_list=$(ovs-vsctl list-br)
    ovscmds="ovs-dpctl -s show\
            :ovs-vsctl -t 5 show\
            :ovsdb-client dump\
            "
    if test -n "${br_list}"; then
        pr_syslog_stdout "${step_num} Collecting OpenVSwitch output"
        IFS=:
          for ovscmd in ${ovscmds}; do
            IFS=${ifs_orig} call_run_command "${ovscmd}" "${OUTPUT_FILE_OVS}.out"
          done
        IFS="${ifs_orig}"

        for bridge in ${br_list}; do
        ovsbrcmds="ovs-ofctl show ${bridge}\
                    :ovs-ofctl dump-flows ${bridge}\
                    :ovs-appctl fdb/show ${bridge}\
                    "
         IFS=:
          for ovsbrcmd in ${ovsbrcmds}; do
            IFS=${ifs_orig} call_run_command "${ovsbrcmd}" "${OUTPUT_FILE_OVS}.out"
          done
         IFS="${ifs_orig}"
        done
    else
        pr_syslog_stdout "${step_num} Collecting OpenVSwitch output skipped"
    fi

    pr_log_stdout " "
}

########################################
collect_docker() {
    local item_list
    local item

    # call docker inspect for all containers
    item_list=$(docker ps -qa)
    if test -n "${item_list}"; then
        pr_syslog_stdout "${current_step}a of ${COLLECTION_COUNT}: Collecting docker container output"
        for item in ${item_list}; do
            call_run_command "docker inspect ${item}" "${OUTPUT_FILE_DOCKER}"
        done
    else
        pr_syslog_stdout "${current_step}a of ${COLLECTION_COUNT}: Collecting docker container output skipped"
    fi

    # call docker inspect for all networks
    item_list=$(docker network ls -q)
    if test -n "${item_list}"; then
        pr_syslog_stdout "${current_step}b of ${COLLECTION_COUNT}: Collecting docker network output"
        for item in ${item_list}; do
            call_run_command "docker network inspect ${item}" "${OUTPUT_FILE_DOCKER}"
        done
    else
        pr_syslog_stdout "${current_step}b of ${COLLECTION_COUNT}: Collecting docker network output skipped"
    fi

    pr_log_stdout " "
}

########################################
collect_nvme() {
    local NVME

    pr_syslog_stdout "${step_num} Collecting nvme output"
    call_run_command "nvme list" "${OUTPUT_FILE_NVME}"

    for NVME in /dev/nvme[0-9]*; do
	if [ -c $NVME ]; then
	    call_run_command "smartctl -x $NVME" "${OUTPUT_FILE_NVME}"
	    call_run_command "nvme fw-log $NVME" "${OUTPUT_FILE_NVME}"
	    call_run_command "nvme smart-log $NVME" "${OUTPUT_FILE_NVME}"
	    call_run_command "nvme error-log $NVME" "${OUTPUT_FILE_NVME}"
	fi
    done

    pr_log_stdout " "
}

########################################
collect_kvm() {
    local cmd
    local ifs_orig
    local domain_list
    local domain

    # check if KVM virsh command exists
    if type virsh >/dev/null 2>&1;
    then
        pr_syslog_stdout "${step_num} Collecting KVM data"
        ifs_orig="${IFS}"
	IFS=:
	for cmd in ${KVM_CMDS}; do
            IFS=${ifs_orig} call_run_command "${cmd}" "${OUTPUT_FILE_KVM}"
	done
	IFS="${ifs_orig}"

	# domain/guest specific commands
        domain_list=$(virsh list --all --name)
        if test -n "${domain_list}"; then
	  for domain in ${domain_list}; do
	    call_run_command "virsh dominfo ${domain}" "${OUTPUT_FILE_KVM}"
	    call_run_command "virsh domblklist ${domain}" "${OUTPUT_FILE_KVM}"
	    call_run_command "virsh domstats ${domain}" "${OUTPUT_FILE_KVM}"
          done
	else
	  echo "no KVM doamins found" | tee -a ${OUTPUT_FILE_KVM}
        fi
    else
        pr_syslog_stdout "${step_num} Skip KVM data - no virsh command"
    fi

    pr_log_stdout " "
}

########################################
post_processing() {
    local file_mtime
    local file_mtime_epoche
    local tmp_file
    local file_name

    pr_syslog_stdout "${step_num} Postprocessing"

    find "${WORKPATH}etc/libvirt/qemu/" -maxdepth 1 -name "*.xml" 2>/dev/null | while IFS= read -r file_name; do
	file_mtime_epoche=$(stat --format=%Y "${file_name}")
	file_mtime=$(date +%Y%m%d%H%M.%S --date="@${file_mtime_epoche}")
	tmp_file=${file_name}.$$

	echo " ${file_name}"
	if ! sed "s/\( \+passwd='\).*\('\)/\1********\2/g" "${file_name}" > "${tmp_file}"; then
	    echo "${SCRIPTNAME}: Warning: Postprocessing failed on ${file_name}"
	    echo
	fi

	mv "${tmp_file}" "${file_name}"
	touch --time=mtime -t "${file_mtime}" "${file_name}"
    done

    find "${WORKPATH}etc/libvirt/" -name "auth.conf" 2>/dev/null | while IFS= read -r file_name; do
        file_mtime_epoche=$(stat --format=%Y "${file_name}")
        file_mtime=$(date +%Y%m%d%H%M.%S --date="@${file_mtime_epoche}")
        tmp_file=${file_name}.$$

        echo " ${file_name}"
        if ! sed "s/\(password=\).*/\1********/g" "${file_name}" > "${tmp_file}"; then
            echo "${SCRIPTNAME}: Warning: Postprocessing failed on ${file_name}"
            echo
        fi

        mv "${tmp_file}" "${file_name}"
        touch --time=mtime -t "${file_mtime}" "${file_name}"
    done

    find "${WORKPATH}" -maxdepth 1 -name "*.xml" 2>/dev/null | while IFS= read -r file_name; do
        file_mtime_epoche=$(stat --format=%Y "${file_name}")
        file_mtime=$(date +%Y%m%d%H%M.%S --date="@${file_mtime_epoche}")
        tmp_file=${file_name}.$$

        echo " ${file_name}"
        if ! sed "s/\( \+passwd='\).*\('\)/\1********\2/g" "${file_name}" > "${tmp_file}"; then
            echo "${SCRIPTNAME}: Warning: Postprocessing failed on ${file_name}"
            echo
        fi

        mv "${tmp_file}" "${file_name}"
        touch --time=mtime -t "${file_mtime}" "${file_name}"
    done

    find "${WORKPATH}proc/" -name "kallsyms" 2>/dev/null | while IFS= read -r file_name; do
        tmp_file=${file_name}-`uname -r`.tgz
        ch_dir="${WORKPATH}proc/"
        orig_file="kallsyms"


        echo " ${file_name}"
        if ! test -e "${file_name}"; then
            echo "${SCRIPTNAME}: Warning: Postprocessing failed on ${file_name}"
            echo
        fi

        tar -cvzf "${tmp_file}" -C "${ch_dir}" "${orig_file}"
        rm -f  "${file_name}"

    done

    pr_log_stdout " "
}


########################################
# Be aware that this output must be
# redirected into a separate logfile
call_run_command() {
    local cmd
    local logfile
    local raw_cmd

    cmd="${1}"
    logfile="${2}"
    raw_cmd=$(echo "${cmd}" | sed -ne 's/^\([^[:space:]]*\).*$/\1/p')

    echo "#######################################################" >> "${logfile}"
    echo "${USER}@${SYSTEMHOSTNAME:-localhost}> ${cmd}" >> "${logfile}"

    # check if command exists
    if ! which "${raw_cmd}" >/dev/null 2>&1; then
	# check if command is a builtin
	if ! command -v "${raw_cmd}" >/dev/null 2>&1; then
	    echo "${SCRIPTNAME}: Warning: Command \"${raw_cmd}\" not available" >> "${logfile}"
	    echo >> "${logfile}"
	    return 1
	fi
    fi

    if ! eval "${cmd}" >> "${logfile}" 2>&1; then
	echo "${SCRIPTNAME}: Warning: Command \"${cmd}\" failed" >> "${logfile}"
	echo >> "${logfile}"
	return 1
    else
	echo >> "${logfile}"
	return 0
    fi
}


########################################
call_collect_file() {
    local directory_name
    local file_name

    file_name="${1}"
    echo " ${file_name}"

    directory_name=$(dirname "${file_name}" 2>/dev/null)
    if test ! -e "${WORKPATH}${directory_name}"; then
	mkdir -p "${WORKPATH}${directory_name}" 2>&1
    fi
    if ! cp -r --preserve=mode,timestamps -d -L --parents "${file_name}" "${WORKPATH}" 2>&1; then
	return 1
    else
	return 0
    fi
}


###############################################################################


########################################
# print that an instance is already running
print_alreadyrunning() {
    print_version

    cat <<EOF


Please check the system if another instance of '${SCRIPTNAME}' is already
running. If this is not the case, please remove the lock file
'${LOCKFILE}'.
EOF
}


########################################
# Setup the environment
environment_setup()
{
    if test ! -e "${WORKDIR_BASE}"; then
	mkdir -p "${WORKDIR_BASE}"
    elif test ! -d "${WORKDIR_BASE}"; then
	echo "${SCRIPTNAME}: Error: \"${WORKDIR_BASE}\" exists but this is a file!"
	echo "       Please make sure \"${WORKDIR_BASE}\" is a directory."
	exit 1
    fi

    if test -e "${LOCKFILE}"; then
	print_alreadyrunning
	exit 1
    else
	touch "${LOCKFILE}"
	echo "${DATETIME}" > "${LOCKFILE}"
    fi

    if ! mkdir "${WORKPATH}" 2>/dev/null; then
	echo "${SCRIPTNAME}: Error: Target directory \"${WORKPATH}\" already exists or"
	echo "       \"${WORKDIR_BASE}\" does not exist!"
	exit 1
    fi
    chmod 0700 "${WORKPATH}"
}


########################################
# create gzip-ped tar file
create_package()
{
    local rc_tar
    pr_stdout "${step_num} Finalizing: Creating archive with collected data"
    cd "${WORKDIR_BASE}"

    touch "${WORKARCHIVE}"
    chmod 0600 "${WORKARCHIVE}"
    tar -czf "${WORKARCHIVE}" "${WORKDIR_CURRENT}"
    rc_tar=$?
    if [ $rc_tar -eq 0 ]; then
        chmod 0600 "${WORKARCHIVE}"
        pr_stdout " "
        pr_stdout "Collected data was saved to:"
        pr_stdout " >>  ${WORKARCHIVE}  <<"
        pr_stdout " "
        pr_stdout "Review the collected data before sending to your service organization. "
        pr_stdout " "
    elif [ $rc_tar -eq 127 ]; then
        pr_stdout " "
        pr_stdout "${SCRIPTNAME}: Error: tar command is not available!"
        pr_stdout "     Please install the corresponding package!"
    else
        pr_stdout " "
        pr_stdout "${SCRIPTNAME}: Error: Collection of data failed!"
        pr_stdout "       The creation of \"${WORKARCHIVE}\" was not successful."
        pr_stdout "       Please check the directory \"${WORKDIR_BASE}\""
        pr_stdout "       to provide enough free available space."
    fi
}


########################################
# Cleaning up the prepared/collected information
environment_cleanup()
{
    if ! rm -rf "${WORKPATH}" 2>/dev/null; then
	pr_stdout " "
	pr_stdout "${SCRIPTNAME}: Warning: Deletion of \"${WORKPATH}\" failed"
	pr_stdout "       Please remove the directory manually"
	pr_stdout " "
    fi
    if ! rm -f "${LOCKFILE}" 2>/dev/null; then
	pr_stdout " "
	pr_stdout "${SCRIPTNAME}: Warning: Deletion of \"${WORKDIR_BASE}${SCRIPTNAME}\" failed"
	pr_stdout "       Please remove the file manually"
	pr_stdout " "
    fi
}


########################################
# Function to perform a cleanup in case of a received signal
emergency_exit()
{
    pr_stdout " "
    pr_stdout "${SCRIPTNAME}: Info: Data collection has been interrupted"
    pr_stdout "       Cleanup of temporary collected data"
    environment_cleanup
    pr_stdout "${SCRIPTNAME}: Info: Emergency exit processed"

    pr_stdout " "
    logger -t "${SCRIPTNAME}" "Data collection interrupted"
    exit
}


########################################
# Function to print to stdout when rediretion is active
pr_stdout()
{
    echo "${@}" >&8
}


########################################
# Function to print to stdout and into log file when rediretion is active
pr_log_stdout()
{
    echo "$@"
    echo "$@" >&8
}


########################################
# Function to print to stdout and into log file when rediretion is active
pr_syslog_stdout()
{
    echo "$@"
    echo "$@" >&8
    logger -t "${SCRIPTNAME}" "$@"
}


###############################################################################
# Running the script

environment_setup
print_version

# saving stdout/stderr and redirecting stdout/stderr into log file
exec 8>&1 9>&2 >"${LOGFILE}" 2>&1

# trap on SIGHUP=1 SIGINT=2 SIGTERM=15
trap emergency_exit SIGHUP SIGINT SIGTERM

pr_log_stdout ""
pr_log_stdout "Hardware platform     = $(uname -i)"
pr_log_stdout "Kernel version        = ${KERNEL_VERSION}.${KERNEL_MAJOR_REVISION}.${KERNEL_MINOR_REVISION} ($(uname -r 2>/dev/null))"
pr_log_stdout "Runtime environment   = ${RUNTIME_ENVIRONMENT}"
pr_log_stdout ""

logger -t "${SCRIPTNAME}" "Starting data collection"

# step counter
current_step=1
# run all collection steps
for step in ${ALL_STEPS}; do
  # generate step numbering
  step_num="${current_step} of ${COLLECTION_COUNT}: "
  # calling step procedure
  ${step}
  current_step=`expr ${current_step} + 1`
done

logger -t "${SCRIPTNAME}" "Data collection completed"

exec 1>&8 2>&9 8>&- 9>&-

#EOF
