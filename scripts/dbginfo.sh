#!/bin/sh
#
# dbginfo.sh - Tool to collect runtime, configuration, and trace information
#
# Copyright IBM Corp. 2002, 2025
#
# s390-tools is free software; you can redistribute it and/or modify
# it under the terms of the MIT license. See LICENSE for details.
#

# Switching to neutral locale
LC_ALL=C
export LC_ALL

########################################
# Global used variables
readonly SCRIPTNAME="${0##*/}" # general name of this script
readonly FULLPATHSCRIPT="$(readlink -f "${0}")"
#
readonly DATETIME="$(date +%Y-%m-%d-%H-%M-%S 2>/dev/null)"
readonly DOCKER=$(if type docker >/dev/null 2>&1; then echo "YES"; else echo "NO"; fi)
readonly DUMP2TAR_OK=$(if type dump2tar >/dev/null 2>&1; then echo "YES"; else echo "NO"; fi)
readonly HW="$(uname -m 2>/dev/null)"
readonly IFS_ORI="${IFS}"
# retrieve and split kernel version
readonly KERNEL_BASE="$(uname -r 2>/dev/null)"
readonly KERNEL_VERSION=$(echo ${KERNEL_BASE} | cut -d'.' -f1 )
readonly KERNEL_MAJOR_REVISION=$(echo ${KERNEL_BASE} | cut -d'.' -f2 )
readonly KERNEL_MINOR_REVISION=$(echo ${KERNEL_BASE} | cut -d'.' -f3 | sed 's/[^0-9].*//g')
readonly KERNEL_INFO=${KERNEL_VERSION}.${KERNEL_MAJOR_REVISION}.${KERNEL_MINOR_REVISION}
readonly KUBERNETES=$(if type kubectl >/dev/null 2>&1; then echo "YES"; else echo "NO"; fi)
readonly KUBERNETES_LOG_LINES=50
readonly KVM=$(if type virsh >/dev/null 2>&1; then echo "YES"; else echo "NO"; fi)
# The file to indicate that another instance of the script is already running
readonly LOCKFILE="/tmp/${SCRIPTNAME}.lock"
# check limits for logfiles like /var/log/messages
readonly LOG_FILE_SIZE_CHECK=50  # max logfile size in MB
readonly LOG_FILE_AGE_CHECK=7  # age in days to include for size checking
# Mount point of the debug file system
readonly MOUNT_POINT_DEBUGFS="/sys/kernel/debug"
# Network devices
readonly NETWORK_DEVS=$(cd /sys/class/net; ls -d */ 2>/dev/null |  sed 's/\///g')
# distro info
readonly OSPRETTY="$(cat /etc/os* 2>/dev/null | grep -m1 PRETTY_NAME | sed 's/\"//g')"
readonly OS_NAME="${OSPRETTY##*=}"
# The processor ID for the first processor
readonly PROCESSORID="$(grep -E ".*processor 0:.*" /proc/cpuinfo | \
	sed 's/.*identification[[:space:]]*\=[[:space:]]*\([[:alnum:]]*\).*/\1/g')"
readonly PROCESSORVERSION="$(grep -E ".*processor 0:.*" /proc/cpuinfo | \
	sed 's/.*version[[:space:]]*\=[[:space:]]*\([[:alnum:]]*\).*/\1/g')"
if test "x${PROCESSORVERSION}" = "xFF" || test "x${PROCESSORVERSION}" = "xff"; then
	RUNTIME_ENVIRONMENT=$(grep -E "VM00.*Control Program.*" /proc/sysinfo | \
	sed 's/.*:[[:space:]]*\([[:graph:]]*\).*/\1/g')
else
	RUNTIME_ENVIRONMENT="LPAR"
fi
# check for Dynamic Partition Mode
readonly DPM_UUID=$(grep "LPAR UUID" /proc/sysinfo | \
	sed 's/.*:[[:space:]]*\([[:graph:]]*\).*/\1/g')
if test "${#DPM_UUID}" -eq 0; then
	DPM_MODE="NO"
else
	DPM_MODE="YES"
fi
readonly SYSTEMHOSTNAME="$(hostname -s 2>/dev/null)" # hostname of system being analysed
readonly TERMINAL="$(tty 2>/dev/null)"
# timeout seconds TOS / kill timeout TOKS
readonly TOS=15
readonly TOKS=30
readonly TIMEOUT=$(if type timeout >/dev/null 2>&1; then echo "YES"; else echo "NO"; fi)
readonly TIMEOUT_OK=$(if test "x${TIMEOUT}" = "xYES"; then
	if test $(timeout -k ${TOKS} ${TOS} uname 2>/dev/null) = $(uname); then
		echo "YES"; else echo "WRONG_VERSION"; fi
	else echo "NO"; fi)
readonly ZDEV_CONF=$(lszdev --configured 2>/dev/null | wc -l)
readonly ZDEV_OFF=$(lszdev --offline 2>/dev/null | wc -l)
readonly ZDEV_ONL=$(lszdev --online 2>/dev/null | wc -l)

paramWORKDIR_BASE="/tmp"  # initial default path

########################################
# print dbginfo.sh version info
print_version() {
	cat <<EOF
${SCRIPTNAME}: Debug information script version %S390_TOOLS_VERSION%
Copyright IBM Corp. 2002, 2025
EOF
}

########################################
# print how to use this script
print_usage() {
	print_version

	cat <<EOF

Usage: ${SCRIPTNAME} [OPTION]

This script collects runtime, configuration and trace information on
a Linux on IBM Z installation for debugging purposes.

It also traces information about z/VM if the Linux runs under z/VM.
Virtualization platform data is collected on a host serving this.

Default location for data collection and final tar file is "/tmp/".
The collected information is written to a TAR archive named

    DBGINFO-[date]-[time]-[hostname]-[processorid].tgz

where [date] and [time] are the date and time when debug data is collected.
[hostname] indicates the hostname of the system the data was collected from.
The [processorid] is taken from the processor 0 and indicates the processor
identification.

Options:
        -d|--directory     specify the directory where the data collection
                           stores the temporary data and the final archive.
        -h|--help          print this help
        -v|--version       print version information
        -c|--check         online base system information (no data collection)

EOF
}

########################################
# check for oversize logfiles and missing rotation
logfile_checker() {
	local counter
	local logfile
	local logfiles

	# find files bigger than recommended
	counter=$(find $1 -maxdepth 1 -type f -mtime -${LOG_FILE_AGE_CHECK} \
			-size ${LOG_FILE_SIZE_CHECK}M | wc -l)

	echo " ${counter} logfiles over ${LOG_FILE_SIZE_CHECK} MB"
	# maybe check for rotation of base names
	if [ ${counter} -ne 0 ]; then
		for logfile in $(find $1 -maxdepth 1 -type f -mtime -${LOG_FILE_AGE_CHECK} \
					-size ${LOG_FILE_SIZE_CHECK}M -print); do
			# use a neutral separtor ':' as concat is different in some bash
			# insert the 'blank' for later use in for loop
			# add the base name before '.' or '-' only for checks
			logfiles="${logfiles}: ${logfile%%[.-]*}"
		done
		# change separator to new line for sorting
		logfiles=$(echo "${logfiles}" | sed s'/:/\n/g' | sort -u)
		for logfile in ${logfiles}; do
			counter=$(ls ${logfile}* 2>/dev/null | wc -l)
			if [ ${counter} -eq 1 ]; then
				echo " CHECK - ${logfile} may miss a rotation"
			else
				echo "    OK - ${logfile}* may have a rotation "\
				       "in place: ${counter} files"
			fi
		done
	fi
}

########################################
# print basic info and online checks
print_check() {
	print_version
	cat <<EOF

Hardware platform     = ${HW}
Runtime environment   = ${RUNTIME_ENVIRONMENT} - DPM: ${DPM_MODE}
$(cat /proc/sysinfo | grep 'Name')
Kernel version        = ${KERNEL_INFO}
OS version / distro   = ${OS_NAME}
KVM host              = ${KVM}
container host        Kubernetes: ${KUBERNETES} - docker: ${DOCKER}

Current user          = $(whoami) (must be root for data collection)
Date and time         = $(date)
Uptime                =$(uptime)
Number of coredumps   = $(corecumpctl 2>/dev/null | wc -l)
zdevice onl/conf/offl = ${ZDEV_ONL} / ${ZDEV_CONF} / ${ZDEV_OFF}
Log file check        =$(logfile_checker "/var/log*")

Working directory     = $(ls -d ${paramWORKDIR_BASE} 2>&1 && df -k ${paramWORKDIR_BASE})
$(ls -ltr ${paramWORKDIR_BASE}/DBGINFO*tgz 2>/dev/null | tail -2)
$(ls ${LOCKFILE} 2>/dev/null && echo "     Warning: dbginfo running since: $(cat ${LOCKFILE})")
Tool/command dependency check successful:
        timeout       = ${TIMEOUT_OK}
        dump2tar      = ${DUMP2TAR_OK}

This is a console output only - no data was saved using option -c !

EOF
}

#######################################
# Parsing the command line and pre checks
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
		elif test ! -d "${paramWORKDIR_BASE}"; then
			echo "${SCRIPTNAME}: Error: The specified directory does not exist!"
			echo
			exit 1
		else
			# jump to next param
			shift
		fi
		;;
	--check|-c)
		print_check
		exit 0
		;;
	-*|--*|*)
		echo
		echo "${SCRIPTNAME}: invalid option \"${1}\""
		echo "Try '${SCRIPTNAME} --help' for more information"
		echo
		exit 1
		;;
	esac
	# next parameter, if already last the final shift will do termination
	shift
done

# finally verification to run as root
if test "$(/usr/bin/id -u 2>/dev/null)" -ne 0; then
	echo "${SCRIPTNAME}: Error: You must be user root to run data collection \"${SCRIPTNAME}\"!"
	echo "${SCRIPTNAME}: Hint: for base system information you may run \"${SCRIPTNAME} -c\""
	exit 1
fi

#########################################
# The base working directory and derieved path info
readonly WORKDIR_BASE="$(echo "${paramWORKDIR_BASE}" | sed -e 's#/$##')/"
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
# File names for output files per section (duplicates are ok)
readonly OUTPUT_FILE_BRIDGE="${WORKPATH}network.out"
readonly OUTPUT_FILE_CMD="${WORKPATH}runtime.out"
readonly OUTPUT_FILE_COREDUMPCTL="${WORKPATH}coredump.out" # separate file needed
readonly OUTPUT_FILE_DASD="${WORKPATH}dasd.out"
readonly OUTPUT_FILE_DOCKER="${WORKPATH}docker_runtime.out"
readonly OUTPUT_FILE_ETHTOOL="${WORKPATH}network.out"
readonly OUTPUT_FILE_HYPTOP="${WORKPATH}runtime.out"
readonly OUTPUT_FILE_JOURNALCTL="${WORKPATH}journalctl.out"
readonly OUTPUT_FILE_KVM="${WORKPATH}kvm_runtime.out"
readonly OUTPUT_FILE_LSOF="${WORKPATH}open_files.out"
readonly OUTPUT_FILE_NETWORK="${WORKPATH}network.out"
readonly OUTPUT_FILE_NVME="${WORKPATH}runtime.out"
readonly OUTPUT_FILE_OVS="${WORKPATH}network.out"
readonly OUTPUT_FILE_ISW="${WORKPATH}installed_sw.out"
readonly OUTPUT_FILE_TC="${WORKPATH}network.out"
readonly OUTPUT_FILE_VMCMD="${WORKPATH}zvm_runtime.out"
readonly OUTPUT_FILE_UDEVDB="${WORKPATH}udevdb.out"
# Base file names for different output files - no extension !
readonly OUTPUT_FILE_KUBERNETES="${WORKPATH}kubernetes"
readonly OUTPUT_FILE_OSAOAT="${WORKPATH}network"
readonly OUTPUT_FILE_SYSFS="${WORKPATH}sysfs"

# define order of collection steps
# - state/debug files are collected first, to avoid overwriting by command execution
ALL_STEPS="\
  collect_sysfs\
  collect_procfs\
  collect_configfiles\
  collect_initrd_configfiles\
  collect_cmdsout\
  collect_hyptop\
  collect_vmcmdsout\
  collect_network\
  collect_osaoat\
  collect_ethtool\
  collect_tc\
  collect_bridge\
  collect_ovs\
  collect_kvm\
  collect_container\
  collect_nvme\
  collect_dasd\
  collect_logfiles\
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
  /proc/net/sockstat\
  /proc/net/sockstat6\
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

########################################

LOGFILES="\
  /root/anaconda-ks.cfg\
  /root/original-ks.cfg\
  /run/containerd/events.log\
  /run/docker/libcontainerd/containerd/events.log\
  /run/udev/chreiplzfcpmp-[0-9][0-9][a-z][a-z][a-z][a-z]-*\
  /var/log/anaconda\
  /var/log/anaconda.*\
  /var/log/audit\
  /var/log/boot*\
  /var/log/cron*\
  /var/log/dmesg*\
  /var/log/dnf.*\
  /var/log/dracut.log*\
  /var/log/IBMtape.trace\
  /var/log/IBMtape.errorlog\
  /var/log/kdump.log\
  /var/log/libvirt\
  /var/log/lin_tape.trace\
  /var/log/lin_tape.errorlog\
  /var/log/messages*\
  /var/log/openvswitch/ovs-vswitchd.log\
  /var/log/openvswitch/ovsdb-server.log\
  /var/log/pbl.log\
  /var/log/sa\
  /var/log/syslog*\
  /var/log/yum.log\
  /var/log/YaST2\
  /var/log/zypp*\
  "

########################################

CONFIGFILES="\
  /boot/grub2/grub.cfg\
  /boot/loader/entries/*.conf\
  /boot/zipl/active_devices.txt\
  /boot/zipl/config\
  /conf/\
  /etc/*.conf\
  /etc/*release\
  /etc/anacrontab\
  /etc/apparmor.d\
  /etc/auto.*\
  /etc/cmdline\
  /etc/cmdline.d\
  /etc/conf.d\
  /etc/cron.*\
  /etc/crontab\
  /etc/crypttab\
  /etc/dasd.*\
  /etc/default\
  /etc/depmod.d\
  /etc/dnf/dnf.conf\
  /etc/docker\
  /etc/dracut.conf.d\
  /etc/exports\
  /etc/fstab\
  /etc/groups\
  /etc/grub.d\
  /etc/hosts*\
  /etc/iscsi\
  /etc/inittab\
  /etc/kdump\
  /etc/libvirt\
  /etc/logrotate.d\
  /etc/lvm\
  /etc/modprobe.conf*\
  /etc/modprobe.d\
  /etc/modules-load.d/*.conf\
  /etc/mtab\
  /etc/multipath\
  /etc/network\
  /etc/networks\
  /etc/opencryptoki/*.conf\
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
  /etc/zfcp.*\
  /lib/modprobe.d\
  $(find /lib/modules -name modules.dep 2>/dev/null)\
  /lib/systemd/system/docker.service\
  /lib/udev/rules.d\
  /usr/lib/modprobe.d\
  /usr/lib/modules-load.d/*.conf\
  /usr/lib/systemd/system/\
  /usr/local/lib/modprobe.d\
  /usr/local/lib/modules-load.d/*.conf\
  /run/modprobe.d\
  /run/modules-load.d/*.conf\
  /run/udev/chreiplzfcpmp-ipl-volume-id\
  /run/udev/rules.d\
  /run/zdev_id.env\
  /run/zdev.*\
  "

########################################
# system state commands (non alphabetical order here)
CMDS="uname -a\
  :uptime\
  :timedatectl\
  :zhypinfo\
  :last\
  :lscpu -ae\
  :lscpu -ye\
  :lscpumf -i\
  :lsmem\
  :lsmod\
  :lsshut\
  :runlevel\
  :sysctl -a\
  :systemctl --all --no-pager show\
  :systemctl --all --no-pager list-units\
  :systemctl --all --no-pager list-unit-files\
  :systemd-delta\
  :ulimit -a\
  :env --null | sort --zero-terminated | tr '\000' '\n'\
  :find /boot -print0 | sort -z | xargs -0 -n 10 ls -ld\
  :find /var/crash -print0 | sort -z | xargs -0 -n 10 ls -ld\
  :df -h\
  :df -i\
  :mount\
  "

# Z device subsystem commands (first commands in non alphabetical order)
CMDS="${CMDS}\
  :lschp\
  :lscss --vpm\
  :lszdev\
  :find /dev -print0 | sort -z | xargs -0 -n 10 ls -ld\
  :lspci -t\
  :lspci -vvv\
  :lstape\
  :smc_dbg\
  "

# block device and other scsi device commands (in non alphabetical order)
#   command groups itself have an intentional topical grouping and order
CMDS="${CMDS}\
  :lsblk\
  :lsdasd\
  :lsdasd -u\
  :lvdisplay\
  :pvpath -qa\
  :dmsetup ls\
  :dmsetup ls --tree\
  :dmsetup table\
  :dmsetup table --target multipath\
  :dmsetup status\
  :multipathd -k'show config'\
  :multipathd -k'show config local'\
  :multipathd -k'show maps'\
  :multipathd -k'show topo'\
  :multipathd -k'show paths'\
  :multipathd -k'show paths format %w|%a|%r|%L|%p|%i|%d|%D|%t|%T|%o|%0|%C' | sort\
  :multipathd -k'show maps stats'\
  :multipathd -k'show maps status'\
  :multipathd -k'show status'\
  :multipathd -k'show daemon'\
  :multipathd -k'show blacklist'\
  :multipathd -k'show devices'\
  :multipath -v6 -ll\
  :multipath -d\
  :multipath -t\
  :lszfcp\
  :lszfcp -D\
  :lszfcp -V\
  :ziorep_config -ADM\
  :lsscsi\
  "

# crypto specific commands
CMDS="${CMDS}\
  :cpacfinfo # for MSA 13 info\
  :cpacfinfo -m -f -a -n\
  :ep11info -D\
  :ep11info -H\
  :ep11info -M\
  :icainfo\
  :icastats --all\
  :ivp.e # IBM CCA package install check\
  :ls -al /usr/lib64/opencryptoki/stdll\
  :lszcrypt -VV\
  :pkcsconf -i\
  :pkcsconf -s\
  :pkcsconf -l\
  :pkcsconf -t\
  :pkcsconf -m\
  :systemctl status pkcsslotd\
  "

# product / distro specific commands
CMDS="${CMDS}\
  :java -version\
  :qemu-ga -V\
  :SPident # SLES service package\
  "

# commands with long output at the end
CMDS="${CMDS}\
  :cat /root/.bash_history\
  :dmesg -s 1048576\
  :ps -emo pid,tid,nlwp,policy,user,tname,ni,pri,psr,sgi_p,stat,wchan,start_time,time,pcpu,pmem,vsize,size,rss,share,command\
  :ps -eHo pid,tid,nlwp,policy,user,tname,ni,pri,psr,sgi_p,stat,wchan,start_time,time,pcpu,pmem,vsize,size,rss,share,command\
  :ps axX\
  "

# commands with separate output file
CMDS="${CMDS}\
  :apt list >> '${OUTPUT_FILE_ISW}'\
  :coredumpctl && coredumpctl info -o ${OUTPUT_FILE_COREDUMPCTL}\
  :journalctl --all --no-pager --lines=100000 --output=short-precise\
   >> '${OUTPUT_FILE_JOURNALCTL}'\
  :lsof >> '${OUTPUT_FILE_LSOF}'\
  :rpm -qa | sort >> '${OUTPUT_FILE_ISW}'\
  :udevadm info --export-db >> '${OUTPUT_FILE_UDEVDB}'\
  "

########################################
# network comamnds for separate output file with ip -br a as header command
NETWORK_CMDS="ip -br a\
  :firewall-cmd --list-all\
  :ifconfig -a\
  :ip a sh\
  :ip -s -s link\
  :ip link show\
  :ip neigh list\
  :ip ntable\
  :ip route list\
  :ip route list table all\
  :ip rule list\
  :ipcs -a\
  :iptables -L\
  :lsqeth\
  :netstat -pantu\
  :netstat -s\
  :nm-tool\
  :nstat -az\
  :openssl engine # deprecated in OpenSSL 3.n\
  :openssl list --providers 2>/dev/null # redirect help on older systems\
  :route -n\
  "

########################################
DOCKER_CMDS="docker version\
  :docker info\
  :docker images\
  :docker network ls\
  :docker ps -a\
  :docker stats --no-stream\
  :systemctl status docker.service\
  "

########################################
KUBERNETES_CMDS="kubectl version\
  :oc version   # get also OCP version if installed\
  :kubectl top pod\
  :kubectl top node\
  :kubectl describe pod -A\
  :kubectl describe node -A\
  :kubectl describe endpoints\
  :ls -l /var/log/containers # list of logs is sufficent\
  :kubectl cluster-info dump >>${OUTPUT_FILE_KUBERNETES}.dmp\
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
  :q syscontrol\
  :ind load\
  :ind sp\
  :ind user\
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

	pr_collect_output "command"

	IFS=:
	for cmd in ${CMDS}; do
		IFS=${IFS_ORI} call_run_command "${cmd}" "${OUTPUT_FILE_CMD}"
	done
	IFS="${IFS_ORI}"
}

########################################
collect_network() {
	local cmd

	pr_collect_output "network"

	IFS=:
	for cmd in ${NETWORK_CMDS}; do
		IFS=${IFS_ORI} call_run_command "${cmd}" "${OUTPUT_FILE_NETWORK}"
	done
	IFS="${IFS_ORI}"
}

########################################
collect_vmcmdsout() {
	local vm_command
	local cp_command
	local vm_cmds
	local vm_userid
	local module_loaded=1
	local cp_buffer_size
	local rc_buffer_check

	if echo "${RUNTIME_ENVIRONMENT}" | grep -qi "z/VM" >/dev/null 2>&1; then
		pr_collect_output "z/VM"

		if type vmcp >/dev/null; then
			cp_command="vmcp"
			if ! lsmod 2>/dev/null | grep -q vmcp && modinfo vmcp >/dev/null 2>&1; then
				modprobe vmcp && module_loaded=0 && sleep 2
			fi
		elif type hcp >/dev/null; then
			cp_command="hcp"
			if ! lsmod 2>/dev/null | grep -q cpint; then
				modprobe cpint && module_loaded=0 && sleep 2
			fi
		else
			pr_log_stdout "${SCRIPTNAME}: Warning: No program to communicate to z/VM CP"
			pr_skip "z/VM: vmcp not available"
			return 1
		fi
		vm_userid=$(${cp_command} q userid 2>/dev/null | sed -ne 's/^\([^[:space:]]*\).*$/\1/p')
		vm_cmds=$(echo "${VM_CMDS}" | sed "s/VMUSERID/${vm_userid}/g")

		IFS=:
		for vm_command in ${vm_cmds}; do
			IFS="${IFS_ORI}"
			# initialize buffer values for automatic resizing
			cp_buffer_size=2
			rc_buffer_check=2
			while test ${rc_buffer_check} -eq 2 && test ${cp_buffer_size} -lt 1024; do
				cp_buffer_size=$(( cp_buffer_size * 2 ))
				eval ${cp_command} -b ${cp_buffer_size}k "${vm_command}" \
					>/dev/null 2>&1
				rc_buffer_check=$?
			done
			call_run_command "${cp_command} -b ${cp_buffer_size}k ${vm_command}" \
				"${OUTPUT_FILE_VMCMD}"
			IFS=:
		done
		IFS="${IFS_ORI}"

		if test ${module_loaded} -eq 0 && test "x${cp_command}" = "xhcp"; then
			rmmod cpint
		elif test ${module_loaded} -eq 0 && test "x${cp_command}" = "xvmcp"; then
			rmmod vmcp
		fi
	else
		pr_skip "z/VM: no z/VM environment"
	fi
}

########################################
collect_hyptop() {
	local param
	local delay=1  # seconds
	local iter=5
	local sec=`expr ${delay} \\* ${iter}`

	case ${RUNTIME_ENVIRONMENT} in
		"z/VM")
			param="\#,c,m,C:s,M:s,o"	# z/VM guest fields
			;;
		"LPAR")
			param="\#,T,c,e,m,C:s,E:s,M:s,o"  # all LPAR fields
			;;
		*)  # KVM guest
			pr_skip "hyptop: not available for ${RUNTIME_ENVIRONMENT}"
			return 1
			;;
	esac
	pr_collect_output "hyptop for ${RUNTIME_ENVIRONMENT} - ${sec}s"
	call_run_command "hyptop -b -d ${delay} -n ${iter} -f ${param} -S c" "${OUTPUT_FILE_HYPTOP}"
}

########################################
collect_procfs() {
	local file_name

	pr_collect "procfs"

	for file_name in ${PROCFILES}; do
		call_collect_file "${file_name}"
	done
}

########################################
collect_sysfs() {
	local debugfs_mounted=0
	local dir_name
	local file_name
	local rc=0

	pr_collect "sysfs"
	if ! grep -qE "${MOUNT_POINT_DEBUGFS}.*debugfs" /proc/mounts 2>/dev/null; then
		if mount -t debugfs debugfs "${MOUNT_POINT_DEBUGFS}" >/dev/null 2>&1; then
			sleep 2
			debugfs_mounted=1
		else
			pr_log_stdout "${SCRIPTNAME}: Warning: Unable to mount debugfs \
				at \"${MOUNT_POINT_DEBUGFS}\""
		fi
	fi

	# Collect sysfs files using multiple threads (-J 1) while excluding
	# files known to block on read (-x). Stop reading a file that takes
	# more than 5 seconds (-T 5) such as an active ftrace buffer.
	# error messages are not written to the log
	if test "x${DUMP2TAR_OK}" = "xYES"; then
		dump2tar /sys -z -o "${OUTPUT_FILE_SYSFS}.tgz" \
		    -x '*/tracing/trace_pipe*' \
		    -x '*/page_idle/bitmap*' \
		    -x '*/tracing/per_cpu/*' \
		    -x '*/tracing/free_buffer' \
		    -x '*/devices/css[0-9]*/[0-9]*.*.*/[0-9]*.*.*/host[0-9]*/rport-[0-9]*:*-*/target[0-9]*:*:*/[0-9]*:*:*:*/block/sd*/mq/0/cpu[0-9]*' \
		    --ignore-failed-read -J 1 -T 5 2>>${OUTPUT_FILE_SYSFS}.err
		rc=$?
	else
		echo "${SCRIPTNAME}: Warning: dump2tar is unavailable"
		rc=255
	fi


	if [ ${rc} -eq 0 ] ; then
		echo " all failed entries are logged to ${OUTPUT_FILE_SYSFS}.err"
	else
		if [ $rc -ne 255 ]; then
			echo "${SCRIPTNAME}: Warning: dump2tar failed with $rc"
		fi
		pr_log_stdout " Warning: falling back to slow path"
		call_run_command "find /sys -print0 | sort -z \
		    | xargs -0 -n 10 ls -ld" "${OUTPUT_FILE_SYSFS}.out"

		find /sys -noleaf -type d 2>/dev/null | while IFS= read -r dir_name; do
			mkdir -p "${WORKPATH}${dir_name}"
		done

		find /sys -noleaf -type f -perm /444 \
		    -a -not \( -path '*tracing*' -a -name "trace_pipe*" \) \
		    -a -not \( -path '*page_idle*' -a -name 'bitmap*' \) \
		    -a -not -path '*tracing/per_cpu*' \
		    -a -not -path '*/tracing/free_buffer' \
		    -a -not -path '*/devices/css[0-9]*/[0-9]*.*.*/[0-9]*.*.*/host[0-9]*/rport-[0-9]*:*-*/target[0-9]*:*:*/[0-9]*:*:*:*/block/sd*/mq/0/cpu[0-9]*' \
		    2>/dev/null | while IFS= read -r file_name; do
			echo " ${file_name}"
			if ! dd if="${file_name}" status=noxfer iflag=nonblock \
			    of="${WORKPATH}${file_name}" >/dev/null 2>&1; then
				echo "${SCRIPTNAME}: Warning: failed to copy \"${file_name}\""
			fi
		done
	fi

	if test ${debugfs_mounted} -eq 1; then
		umount "${MOUNT_POINT_DEBUGFS}"
	fi
}

########################################
collect_logfiles() {
	local file_name

	pr_collect "log files"

	for file_name in ${LOGFILES}; do
		call_collect_file "${file_name}"
	done

	pr_log_stdout "$(logfile_checker "/var/log*")"
}

########################################
collect_configfiles() {
	local file_name

	pr_collect "config files"

	for file_name in ${CONFIGFILES}; do
		call_collect_file "${file_name}"
	done
}

########################################
collect_initrd_configfiles() {
	local file_name
	local rd rdbase rdreldir rdextract mypopd noglob mycat patterns=""

	pr_collect "initrd config files"
	cd "${WORKPATH}" || return
	mypopd="$OLDPWD" # (pushd alternative)
	# prevent expansion of glob special characters such as '*'
	noglob=$(set +o | grep -F noglob)
	set -o noglob
	# prepare relative configfiles paths
	for file_name in ${CONFIGFILES}; do
	    # strip leading slash to make path relative as in initrd
	    file_name=${file_name#/}
	    # in contrast to call_collect_file(), cpio extract with patterns
	    # does not recurse, but cpio wildcards match slash, so add suffix;
	    # otherwise e.g. /lib/udev/rules.d or /etc/multipath only extracts
	    # just that directory without any of its content
	    file_name="${file_name}*"
	    patterns="$patterns ${file_name}"
	done
	patterns="$patterns squash-root.img"
	$noglob
	# iterate over initrds
	for rd in /boot/initr* /boot/zipl/initr* /var/lib/kdump/initr*; do
	    [ -f "$rd" ] || continue # (nullglob alternative)
	    rdbase=${rd##*/} # basename
	    rdreldir=${rd%/*} # dirname
	    rdreldir=${rdreldir#/} # strip leading slash to make path relative
	    mkdir -p "${rdreldir}"
	    cd "${rdreldir}" || break # (pushd alternative)
	    if type lsinitrd >/dev/null 2>&1; then
		lsinitrd "${rd}" > "${rdbase}.lsinitrd"
	    fi
	    if type lsinitramfs >/dev/null 2>&1; then
		lsinitramfs -l "${rd}" > "${rdbase}.lsinitramfs"
	    fi
	    cd - || break # change to $OLDPWD (popd alternative)
	    rdextract=${rd#/}
	    mkdir -p "${rdextract}"
	    cd "${rdextract}" || break # (pushd alternative)
	    case $(file "${rd}") in
		*cpio*) mycat="cat" ;;
		*gzip*) mycat="zcat" ;;
		*XZ*) mycat="xzcat" ;;
		*Zstandard*) mycat="zstdcat" ;;
		*bzip2*) mycat="bzcat" ;;
		*LZMA*) mycat="lzcat" ;;
		*)
		    # change to $OLDPWD (popd alternative)
		    cd - || { cd "$mypopd" || return; return; }
		    continue
		    ;;
	    esac
	    # prevent expansion of glob special characters such as '*'
	    noglob=$(set +o | grep -F noglob)
	    set -o noglob
	    # we expect no early-initrd stuff on s390 so extract directly.
	    # globbing is turned off and we want word split on $patterns:
	    # shellcheck disable=SC2086
	    "$mycat" "${rd}" | cpio --extract --no-absolute-filenames \
				    --make-directories \
				    --preserve-modification-time $patterns
	    $noglob
	    if [ ! -f "squash-root.img" ]; then
		cd - || break # change to $OLDPWD (popd alternative)
		continue
	    fi
	    # prevent expansion of glob special characters such as '*'
	    noglob=$(set +o | grep -F noglob)
	    set -o noglob
	    # globbing is turned off and we want word split on $patterns:
	    # shellcheck disable=SC2086
	    unsquashfs -no-progress -dest "squashfs-root" "squash-root.img" \
		       $patterns
	    $noglob
	    rm -f "squash-root.img"
	    cd - || break # change to $OLDPWD (popd alternative)
	done
	cd "$mypopd" || return
}

########################################
collect_osaoat() {
	local osa_devices
	local osa_device

	if type qethqoat >/dev/null; then
		osa_devices=$(lsqeth 2>/dev/null | grep "Device name" \
			     | sed 's/D.*:[[:space:]]*\([^[:space:]]*\)[[:space:]]\+/\1/g' \
			     | sed 's/[()]//g' )
		if test -n "${osa_devices}"; then
			pr_collect_output "osa oat"
			for osa_device in ${osa_devices}; do
				call_run_command "qethqoat ${osa_device}" \
					"${OUTPUT_FILE_OSAOAT}.out" &&
				call_run_command "qethqoat -r ${osa_device}" \
					"${OUTPUT_FILE_OSAOAT}_${osa_device}.raw"
			done
		else
			pr_skip "osa oat: no devices"
		fi
	else
		pr_skip "osa oat: qethqoat not available"
	fi
}

########################################
collect_ethtool() {
	local network_device

	if type ethtool >/dev/null; then
		if test -n "${NETWORK_DEVS}"; then
			pr_collect_output "ethtool"
			for network_device in ${NETWORK_DEVS}; do
				call_run_command "ethtool ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool -k ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool -a ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool -c ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool --per-queue ${network_device} \
					--show-coalesce" "${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool -g ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool -i ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool -l ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool -P ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool -S ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool -T ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
				call_run_command "ethtool --module-info ${network_device}" \
					"${OUTPUT_FILE_ETHTOOL}"
			done
		else
			pr_skip "ethtool: no devices"
		fi
	else
		pr_skip "ethtool: not available"
	fi
}

########################################
collect_tc() {
	local network_device

	if type tc >/dev/null; then
		if test -n "${NETWORK_DEVS}"; then
			pr_collect_output "Trafic Control"
			for network_device in ${NETWORK_DEVS}; do
				call_run_command "tc -s qdisc show dev ${network_device}" \
					"${OUTPUT_FILE_TC}"
			done
		else
			pr_skip "Trafic Control: no devices"
		fi
	else
		pr_skip "Trafic Control: tc not available"
	fi
}

########################################
collect_bridge() {
	local network_device

	if type bridge >/dev/null; then
		if test -n "${NETWORK_DEVS}"; then
			pr_collect_output "bridge"
			for network_device in ${NETWORK_DEVS}; do
				call_run_command "bridge -d link show dev ${network_device}" \
					"${OUTPUT_FILE_BRIDGE}"
				call_run_command "bridge -s fdb show dev ${network_device}" \
					"${OUTPUT_FILE_BRIDGE}"
				call_run_command "bridge -d mdb show dev ${network_device}" \
					"${OUTPUT_FILE_BRIDGE}"
			done
		else
			pr_skip "bridge: no devices"
		fi
	else
		pr_skip "bridge: not available"
	fi
}

########################################
# OpenVSwitch
collect_ovs() {
	local ovscmd
	local bridge
	local ovscmds
	local ovsbrcmd
	local ovsbrcmds

	ovscmds="ovs-dpctl -s show\
		:ovs-vsctl -t 5 show\
		:ovsdb-client dump\
		"
	if type ovs-vsctl >/dev/null; then
		pr_collect_output "OpenVSwitch"
		IFS=:
		for ovscmd in ${ovscmds}; do
			IFS=${IFS_ORI} call_run_command "${ovscmd}" "${OUTPUT_FILE_OVS}"
		done
		IFS="${IFS_ORI}"

		for bridge in ${ovs-vsctl list-br}; do
			ovsbrcmds="ovs-ofctl show ${bridge}\
				  :ovs-ofctl dump-flows ${bridge}\
				  :ovs-appctl fdb/show ${bridge}\
				  "
			IFS=:
			for ovsbrcmd in ${ovsbrcmds}; do
				IFS=${IFS_ORI} call_run_command "${ovsbrcmd}" "${OUTPUT_FILE_OVS}"
			done
			IFS="${IFS_ORI}"
		done
	else
		pr_skip "OpenVSwitch: ovs-vsctl not available"
	fi
}

########################################
collect_container() {
	local container_list
	local network_list
	local item

	# check if container environment exists
	if test "x${DOCKER}" = "xYES" || test "x${KUBERNETES}" = "xYES"; then
		pr_collect_output "container host"
	else
		pr_skip "container host: not found"
	fi

	# for docker command exists
	if [ "x${DOCKER}" = "xYES" ]; then
		pr_syslog_stdout " docker ..."
		container_list=$(docker ps -qa)
		network_list=$(docker network ls -q)
		IFS=:
		for item in ${DOCKER_CMDS}; do
			IFS=${IFS_ORI} call_run_command "${item}" "${OUTPUT_FILE_DOCKER}"
		done
		IFS="${IFS_ORI}"

		if test -n "${container_list}"; then
			for item in ${container_list}; do
				call_run_command "docker inspect ${item}" "${OUTPUT_FILE_DOCKER}"
			done
		fi

		if test -n "${network_list}"; then
			for item in ${network_list}; do
				call_run_command "docker network inspect ${item}" \
					"${OUTPUT_FILE_DOCKER}"
			done
		fi
	fi

	# for kubectl command exists
	if [ "x${KUBERNETES}" = "xYES" ]; then
		pr_syslog_stdout " Kubernetes ..."
		container_list=$(kubectl top pod | grep -v "MEMORY(bytes)" | cut -d' ' -f1)

		IFS=:
		for item in ${KUBERNETES_CMDS}; do
			IFS=${IFS_ORI} call_run_command "${item}" "${OUTPUT_FILE_KUBERNETES}.out"
		done
		IFS="${IFS_ORI}"
		if test -n "${container_list}"; then
			for item in ${container_list}; do
				call_run_command "kubectl logs --tail=${KUBERNETES_LOG_LINES} ${item}"\
				"${OUTPUT_FILE_KUBERNETES}.log"
			done
		fi
	fi
}

########################################
collect_nvme() {
	local device

	if type nvme >/dev/null; then
		pr_collect_output "NVME storage"
		call_run_command "nvme list" "${OUTPUT_FILE_NVME}"
		for device in /dev/nvme[0-9]*; do
			if [ -c $device ]; then
				call_run_command "smartctl -x $device" "${OUTPUT_FILE_NVME}"
				call_run_command "nvme fw-log $device" "${OUTPUT_FILE_NVME}"
				call_run_command "nvme smart-log $device" "${OUTPUT_FILE_NVME}"
				call_run_command "nvme error-log $device" "${OUTPUT_FILE_NVME}"
			fi
		done
	else
		pr_skip "nvme: not available"
	fi
}

########################################
collect_dasd() {
	local device

	if type dasdview >/dev/null; then
		pr_collect_output "DASD storage"
		call_run_command "lsdasd" "${OUTPUT_FILE_DASD}" # duplicate as file header
		for device in /dev/dasd*; do
			if [ -b $device ]; then
				call_run_command "dasdview -i $device" "${OUTPUT_FILE_DASD}"
				call_run_command "dasdview -t info $device" "${OUTPUT_FILE_DASD}"
			else
				echo "$device is no block device" >> ${OUTPUT_FILE_DASD}
			fi
		done
	else
		pr_skip "dasdview: not available"
	fi
}

########################################
collect_kvm() {
	local cmd
	local domain_list
	local domain

	# check if KVM virsh command exists
	if [ "x${KVM}" = "xYES" ]; then
		pr_collect_output "KVM"
		IFS=:
		for cmd in ${KVM_CMDS}; do
			IFS=${IFS_ORI} call_run_command "${cmd}" "${OUTPUT_FILE_KVM}"
		done
		IFS="${IFS_ORI}"

		# domain/guest specific commands
		domain_list=$(virsh list --all --name)
		if test -n "${domain_list}"; then
			for domain in ${domain_list}; do
				call_run_command "virsh dominfo ${domain}" "${OUTPUT_FILE_KVM}"
				call_run_command "virsh domblklist ${domain}" "${OUTPUT_FILE_KVM}"
				call_run_command "virsh domstats ${domain}" "${OUTPUT_FILE_KVM}"
			done
		else
			echo "no KVM domains found" | tee -a ${OUTPUT_FILE_KVM}
		fi
	else
		pr_skip "KVM: no virsh command"
	fi
}

########################################
post_processing() {
	local file_mtime
	local file_mtime_epoche
	local tmp_file
	local file_name
	local base_dir
	local dir_list

	pr_syslog_stdout ${step_num} "Postprocessing"

	# wipe possible passwords
	dir_list="${WORKPATH} \
	${WORKPATH}etc/ssl/ \
	${WORKPATH}etc/libvirt/"
	for base_dir in ${dir_list}; do
		find "${base_dir}" -maxdepth 2 -name "*xml" -o -name "*conf" -o -name "*cnf" \
		    2>/dev/null |  while read -r file_name; do
			file_mtime_epoche=$(stat --format=%Y "${file_name}")
			file_mtime=$(date +%Y%m%d%H%M.%S --date="@${file_mtime_epoche}")
			tmp_file=${file_name}.$$
			echo " clean pw: ${file_name}"
			if ! sed "s/\(.*[Pp]assw.*=\).*/\1********/g" "${file_name}" > "${tmp_file}"; then
				echo "${SCRIPTNAME}: Warning: Postprocessing failed on ${file_name}"
			fi
			mv "${tmp_file}" "${file_name}"
			touch --time=mtime -t "${file_mtime}" "${file_name}"
		done
	done

	# compressing data folder to avoid full unpack for any DBGINFO
	base_dir="${WORKPATH}proc/"
	search4="kallsyms"
	find "${base_dir}" -name ${search4} 2>/dev/null | while read -r file_name; do
		tmp_file=${file_name}-${KERNEL_BASE}.tgz
		echo " compress: ${file_name}"
		if ! tar -czf "${tmp_file}" -C "${base_dir}" "${search4}"; then
			echo "${SCRIPTNAME}: Warning: Postprocessing failed on ${file_name}"
			echo
		else
			rm -f "${file_name}"
		fi
	done

	echo "log work directory state after post processing:"
	echo "du summary: $(du -ks ${WORKPATH})"
	df -k ${WORKPATH}
}

########################################
# Be aware that this output must be
# redirected into a separate logfile
call_run_command() {
	local rc=0
	local cmd="${1}"
	local logfile="${2}"
	# extract the raw_command and set cmd_type, as some shell might split into
	# several lines restrict the cmd echo to the first line only
	local raw_cmd=$(echo "${cmd}" | head -1 | sed -ne 's/^\([^[:space:]]*\).*$/\1/p')
	local cmd_type=$(type ${raw_cmd} | cut -d' ' -sf4,5)

	echo "#######################################################" >> "${logfile}"
	echo "${USER}@${SYSTEMHOSTNAME:-localhost}> ${cmd}" >> "${logfile}"

	# check calling command type
	if [ "X${cmd_type}" = "Xshell builtin" ]; then
		# command is a builtin (no use of timeout possible)
		eval "${cmd}" >> ${logfile} 2>&1
		rc=$?
	elif [ "X${cmd_type}" != "Xnot found" ]; then
		if [ "x${TIMEOUT_OK}" = "xYES" ]; then
			eval timeout -k ${TOKS} ${TOS} "${cmd}" >> ${logfile} 2>&1

			rc=$?
		else
			# fall back - call all existing commands without timeout
			eval "${cmd}" >> ${logfile} 2>&1
			rc=$?
		fi
	else
		echo "${SCRIPTNAME}: Warning: Command \"${raw_cmd}\" not available" >> "${logfile}"
		echo >> "${logfile}"
		return 1
	fi

	# log a warning on rc not 0 and define return
	if [ ${rc} ]; then
		echo >> "${logfile}"
		return 0
	else
		echo "${SCRIPTNAME}: Warning: Command \"${cmd}\" failed" >> "${logfile}"
		echo >> "${logfile}"
		return 1
	fi
}

########################################
call_collect_file() {
	local file_name="${1}"
	local directory_name=$(dirname "${file_name}" 2>/dev/null)
	echo " ${file_name}"

	if test ! -e "${WORKPATH}${directory_name}"; then
		mkdir -p "${WORKPATH}${directory_name}" 2>&1
	fi
	if ! cp -r --preserve=mode,timestamps -dL --parents "${file_name}" "${WORKPATH}" 2>&1; then
		return 1
	else
		return 0
	fi
}

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
environment_setup() {
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
create_package() {
	local rc_tar
	pr_syslog_stdout ${step_num} "Finalizing: Creating archive with collected data"
	# get a copy of the script used
	cp -p "${FULLPATHSCRIPT}" "${WORKPATH}"
	# create the archive
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
		pr_stdout "Please review all collected data before sending to your" \
			  "service organization."
		pr_stdout " "
	elif [ $rc_tar -eq 127 ]; then
		pr_stdout " "
		pr_stdout "${SCRIPTNAME}: Error: tar command is not available!"
		pr_stdout "       Please install the corresponding package!"
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
environment_cleanup() {
	if ! rm -rf "${WORKPATH}" 2>/dev/null; then
		pr_stdout " "
		pr_stdout "${SCRIPTNAME}: Warning: Deletion of \"${WORKPATH}\" failed"
		pr_stdout "       Please remove the directory manually"
		pr_stdout " "
	fi
	if ! rm -f "${LOCKFILE}" 2>/dev/null; then
		pr_stdout " "
		pr_stdout "${SCRIPTNAME}: Warning: Deletion of \"${LOCKFILE}\" failed"
		pr_stdout "       Please remove the file manually"
		pr_stdout " "
	fi
}

########################################
# Function to perform a cleanup in case of a received signal
emergency_exit() {
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
pr_stdout() {
	echo "${@}" >&8
}

########################################
# Function to print to stdout and into log file when rediretion is active
pr_log_stdout() {
	echo "$@"
	echo "$@" >&8
}

########################################
# Function to print to stdout and into log file when rediretion is active
pr_syslog_stdout() {
	echo "$@" >&8
	echo
	echo "$(date +%H:%M:%S.%N) - " "$@"
	logger -t "${SCRIPTNAME}" "$@"
}

########################################
# print "Collecting ... output"
pr_collect_output() {
	pr_syslog_stdout ${step_num} "Collecting" $1 "output"
}

########################################
# print "Collecting ..." like fs
pr_collect() {
	pr_syslog_stdout ${step_num} "Collecting" "$@"
}

########################################
# print "Skipping ..." info with reason
pr_skip() {
	pr_syslog_stdout ${step_num} "Skip" "$@"
}

###############################################################################
# Running the script (main)

environment_setup
print_version

# saving stdout/stderr and redirecting stdout/stderr into log file
exec 8>&1 9>&2 >"${LOGFILE}" 2>&1

# run print_version again to be logged in dbginfo.log
print_version

# trap on SIGHUP=1 SIGINT=2 SIGTERM=15
trap emergency_exit SIGHUP SIGINT SIGTERM

pr_log_stdout ""
pr_log_stdout "Hardware platform     = ${HW}"
pr_log_stdout "Runtime environment   = ${RUNTIME_ENVIRONMENT} - DPM: ${DPM_MODE}"
pr_log_stdout "Kernel version        = ${KERNEL_INFO} (${KERNEL_BASE})"
pr_log_stdout "OS version / distro   = ${OS_NAME}"
pr_log_stdout "Date and time of info = ${DATETIME}"
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
