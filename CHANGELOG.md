Release history for s390-tools (MIT version)
--------------------------------------------
 * __v2.11.x (2019-xx-xx)__

  For Linux kernel version: 5.x

  Changes of existing tools:
  - dbginfo: Gather extended network statistics (using 'ip link')

  Bug Fixes:


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
