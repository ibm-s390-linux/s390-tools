Release history for s390-tools (MIT version)
--------------------------------------------

* __v2.23.x (2022-xx-xx)__

  For Linux kernel version: 6.x

  Add new tools / libraries:

  Changes of existing tools:

  Bug Fixes:
  - dbginfo.sh: save dbginfo.sh version to dbginfo.log
  - dbginfo.sh: ensure compatibility with /bin/dash shell
  - dbginfo.sh: add Kubernetes data collection

* __v2.23.0 (2022-08-18)__

  For Linux kernel version: 5.19

  Changes of existing tools:
  - Makefile: use common Make definition for DRACUTDIR
  - Makefile: use common Make definition for UDEVDIR and UDEVRULESDIR
  - cpacfstats: Add PAI and hotplug support
  - cpumf/pai: Omit file write progress information
  - dbginfo.sh: Get more details on lspci command
  - dumpconf: Prevent running the service in containers
  - libcpumf: Detect PMU named pai_ext
  - pvattest: Improve error reporting and logging
  - zdev: Add some --type ap examples to manpages
  - zkey: Use default benchmarked Argon2i with LUKS2

  Bug Fixes:
  - dbginfo.sh: Fix accidental ftrace buffer shrinkage/free
  - genprotimg: Fix BIO_reset() returncode handling
  - libpv: Fix dependency checking
  - pvattest: Fix dependency checking
  - zipl: Fix segmentation fault when no parmline is provided

* __v2.22.0 (2022-06-20)__

  For Linux kernel version: 5.18

  Add new tools / libraries:
  - ap_tools: Introduce ap_tools and the ap-check tool
  - cpumf/pai: Add Processor Activity Instrumentation tool
  - libpv: New library for PV tools
  - pvattest: Add new tool to create, perform, and verify attestation measurements
  - zipl/zdump: Add Next Gen Dump (NGDump) support

  Changes of existing tools:
  - Move man pages to System commands section (lscpumf, lshwc, pai, dbginfo.sh, zfcpdbf, zipl-switch-to-blscfg)
  - README.md: Add 70-chreipl-fcp-mpath.rules to the list of udev rule descriptions
  - Remove SysV related daemon scripts (cpacfstatsd, cpuplugd, mon_statd)
  - genprotimg: Move man page to section 1 for user commands
  - hyptop: increase initial update interval
  - libseckey: Adapt keymgmt_match() implementation to OpenSSL
  - libutil: Add util_exit_code
  - libutil: Introduce util_udev
  - zdev: Introduce the ap device type
  - zipl-editenv: Add zIPL multienvironment support
  - zipl: Implement sorting BLS entries by versions
  - zkey: Add initramfs hook

  Bug Fixes:
  - cmsfs-fuse: Fix enabling of hard_remove option
  - s390-tools: Fix typos that were detected by lintian as 'typo-in-manual-page'
  - zkey-kmip: Fix possible use after free
  - zkey: Fix EP11 host library version checking
  - zkey_kmip: Setup ext-lib once the APQNs have been configured

* __v2.21.0 (2022-04-20)__

  For Linux kernel version: 5.17

  Add new tools / libraries:
  - libcpumf: Create library libcpumf for CPU Measurement functions

  Changes of existing tools:
  - chreipl-fcp-mpath: bundle a pre-cooked version of the manpage for build
                       environments without access to `pandoc`
  - dbginfo.sh: Add multipath info to map paths to FC addressing and prio group
  - dbginfo.sh: Collect config files of systemd-modules-load.service
  - dbginfo.sh: Sort list of environment variables for readability
  - dbginfo.sh: Replace "which" by builtin command "type"
  - dbginfo.sh: Rework script formatting (indents, order)
  - dbginfo.sh: Update sysfs collection (excludes, messages)
  - genprotimg: Add Protected Virtualization (PV) dump support
  - genprotimg: Remove DigiCert root CA pinning
  - lszcrypt: Add CEX8S support
  - zcryptctl: Add control domain handling
  - zcryptstats: Add CEX8 support
  - zipl: Allow optional entries that are left out when files are missing
  - zipl: make IPL sections defined with BLS to inherit a target field
  - zpcictl: Add option to trigger firmware reset

  Bug Fixes:
  - cpictl: Handle excessive kernel version numbers
  - dbginfo.sh: Collect all places where modprobe.d config files could exist
  - fdasd: Fix endless menu loop on EOF
  - zdump/dfi: Fix segfault due to double free
  - zdump: Fix /dev/mem reading
  - zpcictl: Fix race of SCLP reset and Linux recovery

* __v2.20.0 (2022-02-04)__

  For Linux kernel version: 5.16

  Add new tools / libraries:
  - Add EditorConfig configuration

  Changes of existing tools:
  - s390-tools switches to Fuse 3 as Fuse 2 is deprecated.
        Affected tools: cmsfs, hmcdrvfs, hsavmcore, zdsfs, zdump
  - chreipl-fcp-mpath: don't compress the manpage before installing it
  - cpictl: Report extended version information
  - genprotimg: Add extended kernel command line support
  - zdev: modify the lsblk output parser in lszdev
  - zipl: Add support for longer kernel command lines (now supports up to 64k length)

  Bug Fixes:
  - cpictl: Suppress messages for unwritable sysfs files
  - dbginfo.sh: Fix missing syslog for step create_package
  - lshwc: Fix CPU list parameter setup for device driver
  - zdev: Check for errors when removing a devtype setting
  - zdev: Fix path resolution for multi-mount point file systems

* __v2.19.0 (2021-11-10)__

  For Linux kernel version: 5.15

  Add new tools / libraries:
  - chreipl-fcp-mpath: New toolset that uses multipath information to change
      the configured FCP re-IPL path on detecting issues with the current path

  Changes of existing tools:
  - dbginfo.sh: Add retry timeout and remove possible blocking "blockdev --report"
  - dbginfo.sh: Collect config- and debug-data for chreipl-fcp-mpath
  - hsci: Add support for multiple MAC addresses

  Bug Fixes:
  - lshwc: Fix compile error for gcc <8.1
  - zdump: Various clean-ups and fixes
  - ziomon: Correct throughput calculation in ziorep_printers
  - zipl: Fix segmentation fault when setting stage3_parms

* __v2.18.0 (2021-10-01)__

  For Linux kernel version: 5.14

  Add new tools:
  - scripts: Add tool for parsing sclp s390dbf logs
  - zdev: Add udev rule helper tool
  - zipl-editenv: Add tool to operate with zIPL environment installed in the boot record

  Changes of existing tools:
  - Makefile: Fix order of build of libraries for parallel builds
  - dbginfo.sh: Add collection in area of timedate, coredump and --check option
  - dbginfo.sh: Add exception on dump2tar for /sys/kernel/mm/page_idle/bitmap
  - dbginfo.sh: Cleanup of outdated sections and general code rework
  - dbginfo.sh: Collect zipl boot menu entries from boot loader specification
  - lszcrypt: Add support for vfio-ap status field
  - lszcrypt: Improved output for deconfig cards and queues
  - lszfcp: Add linkdown case to host marker of extended output
  - zdev: Add auto-config for PCI and crypto devices
  - zdump: Introduce multi-level message logging
  - zipl: Add support for environment block interpretation
  - zkey-cryptsetup: Support LUKS2 volumes with integrity support enabled

  Bug Fixes:
  - hsavmcore: Avoid recompilation of overlay during install step
  - libkmipclient: Fix parsing of hex values for XML and JSON encoding
  - vmur/vmur.cpp: Fix error handling on transfer failure
  - zdump: Lots of smaller fixes across the board

* __v2.17.0 (2021-07-07)__

  For Linux kernel version: 5.12 / 5.13

  Add new tools / libraries:
  - hsavmcore: New utility to make the dump process with kdump more efficient
  - libkmipclient: Add KMIP client shared library
  - libseckey: Add a secure key library
  - lshwc: New tool to extract and list complete counter sets

  Changes of existing tools:
  - genprotimg: Add '--(enable|disable)-pckmo' options
  - genprotimg: Add OpenSSL 3.0 support
  - genprotimg: Change plaintext control flags defaults so PCKMO functions are allowed
  - libutil: Introduce multi-level message logging (util_log)
  - libutil: Introduce util_arch module
  - udev/dasd: Change DASD udev-rule to set none scheduler
  - zdsfs: Add transparent codepage conversion
  - zkey: Add support for KMIP-based key management systems

  Bug Fixes:
  - ttyrun-getty: Avoid conflicts with serial-getty@
  - dbginfo: add /proc/kallsyms - refresh zVM, lscpu - fix WORKARCHIVE handling
  - dbginfo: add KVM data collection for server and guest - fix lszdev
  - genprotimg: Add missing return values in error paths
  - zkey: Fix conversion of CCA DATA keys to CCA CIPHER keys
  - znetconf: avoid conflict with "chzdev -e"

* __v2.16.0 (2021-02-19)__

  For Linux kernel version: 5.10 / 5.11

  Add new tool:
  - hsci: New tool to manage HSCI (HiperSockets Converged Interfaces)

  Changes of existing tools:
  - genprotimg: Add host-key document verification support
  - genprotimg: boot: Make boot loader -march=z900 compatible
  - libekmfweb: Make install directory for shared libraries configurable
  - lsdasd: Add FC Endpoint Security information
  - make: Add address sanitizer support
  - netboot: Add version information to scripts
  - netboot: Bump busybox version in pxelinux.0 build
  - zdev: Add FC Endpoint Security information for DASD devices
  - zdev: Add build option to update initial RAM-disk by default
  - zkey-ekmfweb: Avoid sequence number clash when generating keys
  - zkey/zkey-ekmfweb: Install KMS plugins into configurable location
  - zkey: Add support to store LUKS2 dummy passphrase in key repository

  Bug Fixes:
  - dasdfmt: Fix segfault when an incorrect option is specified
  - genprotimg: Fix several build issues
  - genprotimg: Require argument for 'ramdisk' and 'parmfile' options
  - zcryptstats: Fix handling of partial results with many domains
  - zfcpdbf: Deal with crash 7.2.9 change in caller name formatting
  - zipl/boot: Fix memory use after free in stage2
  - zipl/boot: Fix potential heap overflow in stage2
  - zipl: Fix reading 4k disk's geometry

* __v2.15.1 (2020-10-28)__

  For Linux kernel version: 5.9

  Changes of existing tools:
  - lsstp: Improve wording and fix typos in man page
  - zkey: Ensure zkey and friends are skipped with HAVE_OPENSSL=0
  - zkey: Add library versioning for libekmfweb and zkey-ekmfweb
  - libutil: Add function to determine base device of a partition block device

  Bug Fixes:
  - dasdfmt: Fix bad file descriptor error when running on symlinks
  - libdasd: Fix dasd_get_host_access_count()
  - zipl: Fix multivolume dump
  - zgetdump: Fix device node determination via sysfs to work with multivolume again
  - genprotimg/boot: Fix build by disabling SSP
  - zipl/boot: Fix build by disabling SSP

* __v2.15.0 (2020-10-15)__

  For Linux kernel version: 5.9

  Add new tool:
  - lsstp: A small utility to display the Server Time Protocol (STP) information present in sysfs

  Changes of existing tools:
  - dumpconf: support NVMe dump/reipl device
  - ipl_tools: support clear attribute for nvme re-IPL
  - zcrypt: Support new config state with lszcrypt and chzcrypt
  - zkey: Add support for key management system plugins
        including the KMS commands:
            bind, unbind, info, configure, rencipher, list, import, refresh
  - zkey: Add EKMFWeb support to remotely generate secure keys
  - libekmfweb: Add new EKMFWeb client library
  - libutil: Add util_file_read_va()
  - libutil: Add util_file_read_i()/util_file_read_ui()

  Bug Fixes:
  - cpumf: Fix version and help printout when CPUMF is not installed
  - ziomon/ziorep_printers: fix virtual adapter CSV output
  - zipl: Fix Error when title is not the first field in BLS file


* __v2.14.0 (2020-08-21)__

  For Linux kernel version: 5.7 / 5.8

  Changes of existing tools:
  - cpacfstats: Add ECC counters
  - dbginfo: Added collection of /proc/softirqs
  - ipl-tools: Add nvme device support to lsreipl/chreipl
  - zdsfs: Add coordinated read access
  - libzds: Add curl interface to access zosmf rest api
  - util_opt: Change util_opt_init() to honor current command, if set
  Bug Fixes:
  - lsluns: Try harder to find udevadm
  - mon_tools: Update udevadm location
  - zipl: Fix NVMe partition and base device detection
  - zipl/stage3: Correctly handle diag308 response code
  - znetconf: Introduce better ways to locate udevadm

* __v2.13.0 (2020-05-06)__

  For Linux kernel version: 5.5 / 5.6

  Add new tool:
  - genprotimg: Add genprotimg to create protected virtualization images
  - genprotimg: Add sample script to verify host keys

  Changes of existing tools:
  - dbginfo: Gather bridge related data (using 'bridge')
  - dbginfo: Removed collection of /var/log/opencryptoki/
  - dbginfo: collect softnet_stat
  - dbginfo: gather ethtool output for per-queue coalescing
  - ipl_tools: Support clear attribute for FCP and CCW re-IPL
  - zdev: Report FC Endpoint Security of zfcp devices
  - zdev/dracut/95zdev/module-setup.sh: Add ctcm kernel module
  - cpumf/data: Add new deflate counters for IBM z15
  - zkey: Add support for EP11 secure keys
  - zpcictl: Initiate recover after reset
  - zipl: Add support for NVMe devices
  - zipl: A multitude of code and stability improvements

  Bug Fixes:
  - zipl: Prevent endless loop during IPL
  - zipl/libc: Fix potential buffer overflow in printf
  - zkey: Fix listing of keys on file systems reporting DT_UNKNOWN
  - zkey: Fix display of clear key size for XTS, CCA-AESCIPHER, and EP11-AES XTS keys


* __v2.12.0 (2019-12-17)__

  For Linux kernel version: 5.4

  Changes of existing tools:
  - dbginfo: Gather qdisc related data (using 'tc')
  - dbginfo: Gather extended network statistics (using 'ip link')
  - dbginfo: Collect all files under /usr/lib/systemd/system/
  - cpumf/cpumf_helper: Add IBM z15 machine name
  - zkey: Display MKVP when validating a secure key
  - zkey: Cross check APQNs when generating, validating, or importing secure keys,
      and when changing APQN associations
  - zkey: Check crypto card level during APQN cross checking
  - zkey: Add support for generating, validating, and re-enciphering AES CIPHER keys
  - zkey-cryptsetup: Add --to-new and --from-old options
  - zkey-cryptsetup: Allow setkey to set different key types
  - lszcrypt/chzcrypt: CEX7S exploitation support
  - zcryptstats: Add support for CEX7 crypto card
  - zipl: Ship a minimal zipl.conf
  - zipl: Add value of target= as search path for BLS case

  Bug Fixes:
  - dasdview: Fix exit status in error cases
  - zipl: Fix various compile warnings
  - zipl: Fix dependency generation in zipl/boot
  - zipl: Fix entry point for stand-alone kdump
  - zipl: Add missing options to help output

* __v2.11.0 (2019-09-06)__

  For Linux kernel version: 5.3

  Changes of existing tools:
  - dasdfmt: Add support for thin-provisioned volumes
  - lsdasd: Add support for thin-provisioned volumes
  - libdasd: Provide function to utilise release space ioctl
  - libdasd: Provide function to read ese sysfs attribute
  - dbginfo: Add lspci (PCI devices) and smc_dbg (SMC sockets)
  - dbginfo: Gather ethtool related data

  Bug Fixes:
  - zipl: Fix freeing of uninitialized pointer
  - zipl: Set correct secure IPL default value

* __v2.10.0 (2019-07-31)__

  For Linux kernel version: 5.2

  Changes of existing tools:
  - zdev: Add zfcp dix parameter handling
  - cpumf: Add support for CPU-Measurement Facility counters SVN 6

  Bug Fixes:
  - libutil: Add functions to test path is read/write-only
  - zdev: Fix reporting of read-only sysfs attributes
  - zdev: Improve handling of invalid udev rules
  - zipl: Fix stfle zero padding
  - zipl: Fix build issues
  - zipl: Remove trailing spaces from the fields defined in BLS files
  - zipl: Do not overwrite BOOT_IMAGE entry
  - zkey: Fix auto-detection of clear key bitsize for XTS keys

* __v2.9.0 (2019-05-21)__

  For Linux kernel version: 5.0 / 5.1

  Add new tool:
  - zcryptstats: Add zcryptstats to display usage statistics of
      IBM Crypto Express adapters

  Changes of existing tools:
  - lszfcp: New command line option to show module parameters
  - lszfcp: Sdev attributes for scsi_disk, block, integrity, queue, iosched
  - lszfcp: Add new output marker for non-good SCSI devices (luns)
  - lszfcp: Add new output marker for non-good fc_rports
  - lszfcp: Clean up whitespace (mixed indentation, trailing)
  - lschp: Add support for specifying a CHPID
  - zipl: Add secure boot capabilities
  - zkey: Add common passphrase options for cryptsetup and crypttab
  - zkey: Add batch-mode option to cryptsetup and zkey-cryptsetup
  - libu2s: Remove the entire library and provide more robust functionality
      in libdasd and libutil instead

  Bug Fixes:
  - lszfcp: Allow to show zfcp_units without associated SCSI device
  - lszfcp: Attribute details for: css, zfcp_port, zfcp_unit
  - lszfcp: Allow to also enumerate FCP device that have never been online
  - lszfcp: Fix error message if no zfcp-attached SCSI device found
  - lszfcp: Fix to show defunct FCP devices again
  - lszfcp: Fix to show non-good target ports again
  - lszfcp: Fix missing block & sg device output without CONFIG_SYSFS_DEPRECATED
  - lszfcp: New command line option for extended output format
  - zfcpdbf: Warn about ambiguous payload records with dup reqid & payarea
  - zpcictl: Check for regular directory to prevent possible buffer overflow

* __v2.8.0 (2019-02-15)__

  For Linux kernel version: 4.20

  Changes of existing tools:
  - Switch to using /run directory instead of the legacy /var/run
  - zkey: Add --pbkdf pbkdf2 to generated cryptsetup luksFormat command
  - zdsfs: Add online VTOC refresh
  - pkey: Support autoloading kernel pkey module

  Bug Fixes:
  - zkey: Avoid EPERM on key change if user is not owner of key file
  - cpumf/cpumf_helper: Always return list reference for --sfb-size

* __v2.7.1 (2018-12-13)__

  For Linux kernel version: 4.19

  Changes of existing tools:
  - zkey: Enhance file read/write error handling
  - cmsfs-fuse: Write more than a single line in linefeed mode
  - zpcictl: Add warning for unsupported operations
  - zipl: Use the BLS "title" field as the IPL section name

  Bug Fixes:
  - cmsfs-fuse: Fix iconv buffer aliasing
  - cmsfs-fuse: Fix memory leak in cmsfs_rename()
  - fdasd: Fix possible integer overflow
  - fdasd: Fix resource leak in fdasd_parse_conffile()
  - zdev: Fix memory leak in misc_readlink()
  - dasdinfo: Display error messages on stderr
  - zkey: Include /sbin into PATH when executing commands
  - Makefile: Fix parallel build
  - GCC8 warning fixes across the board for:
      cmsfs-fuse, dasdinfo, dasdview, dump2tar, fdasd, hmcdrvfs, hyptop,
      ip_watcher, libvmdump, libvtoc, lsqeth, lszcrypt, qethqoat, zdev, zdsfs,
      zgetdump, zipl, zpcictl

* __v2.7.0 (2018-10-31)__

  For Linux kernel version: 4.19

  Add new tool:
  - zcryptctl: Add zcryptctl for multiple zcrypt node management
  - zpcictl: Add zpcictl for reporting defective PCI devices

  Changes of existing tools:
  - qethqoat: Add OSA-Express7S support
  - lszcrypt: Add support for alternative zcrypt device drivers
  - zfcpdump: Add install script for zfcpdump
  - zipl: Make zipl work with XFS by using the FIEMAP mapping ioctl

  Bug Fixes:
  - lstape: Fix output with SCSI lin_tape and multiple paths to same unit
  - lstape: Fix output without SCSI generic (sg)
  - lsluns: Fix to prevent error messages if there are non-zfcp SCSI devices
  - lstape: Fix to prevent error messages if there are non-zfcp SCSI devices
  - lstape: Fix description of --type and <devbusid> filter for channel tapes
  - lstape: Fix SCSI output description in man page
  - lstape: Fix SCSI HBA CCW device bus-ID e.g. for virtio-scsi-ccw
  - Direct --help and --version output to stdout for several tools
  - osasnmpd: Start without real OSA devices

* __v2.6.0 (2018-08-10)__

  For Linux kernel version: 4.18

  Add new tool:
  - zkey: Add zkey-cryptsetup tool
  Changes of existing tools:
  - netboot: add BOOTIF support

  Bug Fixes:
  - mon_procd: fix parsing of /proc/<pid>/stat
  - netboot: Include compressed kernel modules in initramfs
  - netboot: Send client architecture and handle path prefix

* __v2.5.0 (2018-06-08)__

  For Linux kernel version: 4.17

  Changes of existing tools:
  - zdev: Add support for reading firmware configuration files
  - zipl: Add BootLoaderSpec support
  - scripts: Add script to switch zipl config to a BootLoaderSpec setup

  Bug Fixes:
  - lsluns: Print a message if no adapter or port exists

* __v2.4.0 (2018-05-07)__

  For Linux kernel version: 4.16

  Changes of existing tools:
  - dbginfo: Gather nvme related data
  - zipl: Rewrite helper script in C
  - libutil: Add function util_strstrip
  - libvmcp: Introduce libvmcp
  - zipl: Extend DASD stand-alone dumpers to drop zero pages
  - zgetdump: Add verbose option
  - zgetdump: Add 'Dump file size' field for zgetdump -i output
  - cpumf: Add IBM z14 ZR1 to the CPU Measurement Facility model list
  - zkey: Add build dependency to OpenSSL (libcrypto)
  - zkey: Add keystore implementation


  Bug Fixes:
  - hmcdrvfs: fix parsing of link count >= 1000
  - zgetdump: Avoid Segfault on processing dumps with memory limit
  - chreipl: correct fcp reipl sysfs write sequence
  - udev: Replace WAIT_FOR with TEST keyword

* __v2.3.0 (2018-01-30)__

  For Linux kernel version: 4.15

  Changes of existing tools:
  - lscpumf: Add support for IBM z14 hardware counters
  - libdasd: Introduce libdasd and use for dasd tools
  - zipl: Always build and link without PIE

  Bug Fixes:
  - zgetdump: Fix handling of DASD multi-volume dump for partitions above 4 GB
  - zdev: Fix zdev dracut module aborting on unknown root device

* __v2.2.0 (2017-12-07)__

  For Linux kernel version: 4.14

  Removed tools:
  - lsmem/chmem: Moved to util-linux >= 2.30

  Changes of existing tools:
  - lszcrypt: Add CEX6S support
  - cpuplugd/mon_tools: Improve systemctl start error handling
  - systemd: Install also the unit configuration files

  Bug Fixes:
  - build process: Fix parallel build for libutil
  - cpi: Add missing Install section to service unit
  - lsluns: Do not scan (all) if filters match nothing
  - lsluns: Enhance usage statement and man page
  - zdev: Use correct path to vmcp binary
  - ziomon: Re-add missing line in ziomon_fcpconf
  - ziomon: Fix non-zero return code in ziomon_util
  - zipl: Remove invalid dasdview command line option

* __v2.1.0 (2017-09-25)__

  For Linux kernel version: 4.13

  Added new tools:
  - netboot: Scripts for building a PXE-style netboot image for KVM
  - 90-cpi.rules/cpictl: New udev rule to update CPI when KVM is used

  Changes of existing tools:
  - lsqeth/zdev: Add VNIC Characteristics support

  Bug Fixes:
  - chzcrypt: Corrected handling of insufficient permissions
  - cpacfstats: Add size setting to perf event
  - fdasd: Skip partition check with the force option
  - ttyrun: Fix deprecated BindTo usage in ttyrun-getty@.service.in
  - lszcrypt: Fix core dump caused by stack overwrite
  - lszcrypt: Fix random domain printout when no config available
  - zdev: Fix segfault with unknown qeth attribute
  - zdev: Fix IPv6 NDP proxy description
  - zdev: Fix zdev dracut module temp file location
  - zkey: Correctly detect abbreviated commands
  - zkey: Validate XTS key: ignore domain and card
  - zkey: Use octal values instead of S_IRWX* constants
  - zkey: Properly set umask to prohibit permissions to group and others
  - zkey: Add -ldl to LDLIBS (not LDFLAGS)
  - znetconf: Re-add missing line in lsznet.raw
  - Fix several gcc 7 warnings

* __v2.0.0 (2017-08-21)__

  - Publish package under the MIT license with the same contents as
    the already available s390-tools-1.39.0

Previous releases of s390-tools can be found on the IBM Developer Works
web pages:

  - https://www.ibm.com/developerworks/linux/linux390/s390-tools.html
