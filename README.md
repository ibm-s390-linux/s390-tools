s390-tools
==========

The s390-tools package contains the source tree of a set of user space
utilities for use with the s390 Linux kernel and device drivers.

The package also contains the following files:

 * [CONTRIBUTING](CONTRIBUTING.md): Contribution guidelines
 * [LICENSE](LICENSE): The MIT license that applies to this package
 * [CHANGELOG](CHANGELOG.md): The history of s390-tools versions
 * [AUTHORS](AUTHORS.md): A list of all authors of the s390-tools package
 * [CODINGSTYLE](CODINGSTYLE.md): Recommendations for writing s390-tools code

Package contents
----------------

 * rust:
   all s390-tools that are written in rust and require external crates.
   Disable the compilation of all tools in `rust/` using HAVE_CARGO=0
   See the `rust/README.md` for Details
   - cpacfinfo:
     Command line interface to get information about CP Assist for
     Cryptographic Functions (CPACF)
   - pvattest:
     Create, perform, and verify IBM Secure Execution attestation measurements.
   - pvapconfig:
     Automatic configure APQNs within an SE KVM guest
   - pvsecret:
     Manage secrets for IBM Secure Execution guests
   - pvimg:
     Create and inspect IBM Secure Execution images

 * dasdfmt:
   Low-level format ECKD DASDs with the classical Linux disk layout or the new
   z/OS compatible disk layout.

 * fdasd:
   Create or modify partitions on ECKD DASDs formatted with the z/OS
   compatible disk layout.

 * dasdview:
   Display DASD and VTOC information or dump the contents of a DASD to the
   console.

 * dasdinfo:
   Display unique DASD ID, either UID or volser.

 * genprotimg:
   Create an IBM Secure Execution (protected virtualization) image. The
   genprotimg command is a symbolic link to the `pvimg create` command.

 * udev rules:
   - 59-dasd.rules: rules for unique DASD device nodes created in /dev/disk/.
   - 57-osasnmpd.rules: udev rules for osasnmpd.
   - 60-readahead.rules: udev rules to set increased "default max readahead".
   - 40-z90crypt.rules: udev rules for z90crypt driver
   - 90-cpi.rules: udev rule to update Control-Program-Information when KVM is
                   used.
   - 70-chreipl-fcp-mpath.rules: udev rules to monitor multipath events for
                                 re-IPL path failover and to adjust the re-IPL
                                 device in case needed.

 * systemd units:
   - cpi.service: Unit to apply CPI settings
   - dumpconf.service: Unit to configure dump on panic for s390
   - mon_fsstatd.service: Unit for mon_fsstatd
   - mon_procd.service: Unit for mon_procd
   - iucvtty-login@.service: Instance unit to manage iucvtty instances
   - ttyrun-getty@.service: Instance unit to manage ttyrun

 * zipl:
   Make DASDs, SCSIs, NVMes or tapes bootable for system IPL or system dump.

 * zgetdump:
   Retrieve system dumps from either tapes, DASDs, SCSIs or NVMes.
   Decrypt Protected Virtualization (PV) dumps from IBM Secure Execution guests.

 * qetharp:
   Read and flush the ARP cache on OSA Express network cards.

 * tape390_display:
   Display information on the message display facility of a s390 tape
   device.

 * tape390_crypt:
   Control and query crypto settings for 3592 tape devices.

 * osasnmpd:
   NET-SNMP subagent implementing MIBs provided by OSA-Express
   features Fast Ethernet, Gigabit Ethernet, 10 Gigabit Ethernet.

 * qethconf:
   bash shell script simplifying the usage of qeth IPA (IP address
   takeover), VIPA (Virtual IP address) and Proxy ARP.

 * dbginfo.sh:
   Shell script collecting useful information about the current system for
   debugging purposes.

 * zfcpdump:
   Dump tool to create system dumps on fibre channel attached SCSI disk
   partitions. It is installed using the "zipl -d" command.

 * ip_watcher:
   Provides HiperSockets Network Concentrator functionality.
   It looks for addresses in the HiperSockets and sets them as Proxy ARP
   on the OSA cards. It also adds routing entries for all IP addresses
   configured on active HiperSockets devices.
   Use start_hsnc.sh to start HiperSockets Network Concentrator.

 * tunedasd:
   Adjust tunable parameters on DASD devices.

 * vmcp:
   Send commands from Linux as a z/VM guest to the z/VM control program (CP).
   Call vmcp with the CP command as an argument. The response of z/VM is
   written to the standard output.

 * vmur:
   Work with z/VM spool file queues (reader, punch, printer).

 * zfcpdbf:
   Display debug data of zfcp. zfcp provides traces via the s390 debug
   feature. Those traces are filtered with the zfcpdbf script, i.e. merge
   several traces, make it more readable etc.

 * sclpdbf:
   Display debug data for the sclp kernel component.

 * zconf:
   Set of scripts to configure and list status information of Linux on s390
   devices.
   - chccwdev: Modify generic attributes of channel attached devices.
   - lscss:      List channel subsystem devices.
   - lsdasd:     List channel attached direct access storage devices (DASD).
   - lsqeth:     List all qeth-based network devices with their corresponding
                 settings.
   - lstape:     List tape devices, both channel and FCP attached.
   - lszfcp:     Show sysfs information about zfcp adapters, ports and units
                 that are online.
   - lschp:      List information about available channel-paths.
   - lsscm:      List information about available Storage Class Memory
                 Increments.
   - chchp:      Modify channel-path state.
   - lsluns:     List LUNs discovered in the FC SAN,
                 or show encryption state of attached LUNs.
   - lszcrypt:   Show Information about zcrypt devices and configuration.
   - chzcrypt:   Modify the zcrypt configuration.
   - zcryptstats: Display usage statistics of IBM Crypto Express adapters.
   - znetconf:   List and configure network devices for s390 network adapters.
   - cio_ignore: Query and modify the contents of the CIO device driver
                 blacklist.
   - dasdstat:   Configure and format the debugfs based DASD statistics data.

 * zkey:
   Use the zkey tool to generate secure AES keys that are enciphered
   with a master key of an IBM cryptographic adapter in CCA coprocessor mode.
   You can also use the zkey tool to validate and re-encipher secure
   AES keys.

 * dumpconf:
   Configure the dump device used for system dump in case a kernel
   panic occurs. This tool can also be used by the "dumpconf" systemd unit
   or as System V init script in /etc/init.d.
   Prerequisite for dumpconf is a Linux kernel with the "dump on panic"
   feature.

 * mon_statd:
   Linux - z/VM monitoring daemons.

   - mon_fsstatd: Daemon that writes file system utilization data to the
                  z/VM monitor stream.

   - mon_procd:   Daemon that writes process information data to the z/VM
                  monitor stream.

 * cpuplugd:
   Manages CPU and memory resources based on a set of rules. Depending on
   the workload, CPUs can be enabled or disabled. The amount of memory can
   be increased or decreased exploiting the CMM1 feature.

 * ipl_tools:
   Tool set to configure and list re-IPL and shutdown actions.
   - lsreipl: List information of re-IPL device.
   - chreipl: Change re-IPL device settings.
   - lsshut:  List the actions that are configured as responses to of halt,
              poff, reboot or panic.
   - chshut:  Change the actions that are to result from of halt, poff,
              reboot or panic.

 * ziomon tools:
   Tool set to collect data for zfcp performance analysis and report.

 * iucvterm:
   z/VM IUCV terminal applications.

   A set of applications to provide terminal access via the z/VM Inter-User
   Communication Vehicle (IUCV). The terminal access does not require an
   active TCP/IP connection between two Linux guest operating systems.

   - iucvconn:  Application to establish a terminal connection via z/VM IUCV.
   - iucvtty:   Application to provide terminal access via z/VM IUCV.
   - ts-shell:  Terminal server shell to authorize and control IUCV terminal
                connections for individual Linux users.
 * ttyrun:
   Depending on your setup, Linux on s390 might or might not provide a
   particular terminal or console. The ttyrun tool safely starts getty
   programs and prevents respawns through the init program, if a terminal
   is not available.

 * cmsfs-fuse:
   Read and write files stored on a z/VM CMS disk. The cmsfs-fuse file system
   translates the record-based EDF file system on the CMS disk to UNIX
   semantics. It is possible to mount a CMS disk and use common Linux tools
   to access the files on the disk.

 * hmcdrvfs:
   Provide (read-only) access to files stored on a (assigned) DVD inserted
   in a HMC drive. The command creates a FUSE.HMCDRVFS filesystem at the
   specified mount point. The feature works with either the LPAR or the
   z/VM hypervisor. But note especially for z/VM that the DVD must be
   assigned to the associated system image (LPAR).

 * hyptop:
   Provide a dynamic real-time view of a s390 hypervisor environment.
   The tool works with the z/VM and LPAR hypervisor. Depending on the available
   data it shows e.g. CPU and memory consumption of active LPARs or z/VM
   virtual guests. The tool provides a curses based user interface similar
   to the popular Linux 'top' command.

 * qethqoat:
   Query the OSA address table and display physical and logical device
   information.

 * zdsfs:
   Mount a z/OS DASD as Linux file system.

 * CPU-measurement facilities (CPU-MF) tools:
   Use the lscpumf tool to display information about the CPU-measurement
   counter and sampling facilities.  Use the chcpumf tool to control the
   sampling facility support. Use lshwc to extract complete counter sets from
   the CPU Measurement Facilities.

 * cpacfstats:
   The cpacfstats tools provide a client/server application set to monitor
   and maintain CPACF activity counters.

 * zdev:
   Provides two tools to modify (chzdev) and display (lszdev) the persistent
   configuration of devices and device drivers that are specific to the s390
   platform.

 * dump2tar:
   dump2tar is a tool for creating a tar archive from the contents of
   arbitrary files. It works even when the size of the actual file content
   is not known beforehand (e.g. FIFOs, sysfs files).

 * netboot:
   Provides simple tools to create a binary that can be used to implement
   simple network boot setups following the PXELINUX conventions.

 * libekmfweb:
   A shared library that provides functions to communicate with an EKMF Web
   server via REST calls over HTTPS. EKMF Web stands for IBM Enterprise Key
   Management Foundation - Web Edition, and is used to manage keys in an
   enterprise.

 * libkmipclient:
   A shared library that provides an KMIP client to communicate with an KMIP
   server. KMIP stands for Key Management Interoperability Protocol, and is an
   extensible communication protocol that defines message formats for the
   manipulation of cryptographic keys on a key management server.

 * hsci:
   Manage HiperSockets Converged Interfaces (HSCI).

 * hsavmcore:
   hsavmcore is designed to make the dump process with kdump more efficient.
   With hsavmcore, the HSA memory that contains a part of the production
   kernel's memory can be released early in the process. Depending on the size
   of the production kernel's memory, writing the dump to persistent storage
   can be time consuming and prevent the HSA memory from being reused
   by other LPARs.

 * chreipl-fcp-mpath:
   Use multipath information to change the configured FCP re-IPL path on
   detecting issues with the current path.

 * ap-check:
   A utility called by mdevctl to assist in managing vfio_ap-passthrough
   devices.

For more information refer to the following publications:

  * "Device Drivers, Features, and Commands" chapter "Useful Linux commands"
  * "Using the dump tools"

Dependencies
------------

The s390-tools package has several build and runtime requirements. If your
build system does not have the required support, you can disable parts of
the s390-tools build with "`make HAVE_<LIBRARY>=0`", for example "`make
HAVE_FUSE=0`".

The following table provides an overview of the used libraries and
build options:

| __LIBRARY__  | __BUILD OPTION__   | __TOOLS__                              |
|--------------|:------------------:|:--------------------------------------:|
| fuse3        | `HAVE_FUSE`        | cmsfs-fuse, zdsfs, hmcdrvfs, zgetdump, |
|              |                    | hsavmcore                              |
| zlib         | `HAVE_ZLIB`        | zgetdump, dump2tar                     |
| ncurses      | `HAVE_NCURSES`     | hyptop                                 |
| net-snmp     | `HAVE_SNMP`        | osasnmpd                               |
| glibc-static | `HAVE_LIBC_STATIC` | zfcpdump                               |
| openssl      | `HAVE_OPENSSL`     | zkey, libekmfweb, libkmipclient,       |
|              |                    | zgetdump, rust/pvattest, rust/pvimg,   |
|              |                    | zgetdump/pvsecret, opticsmon           |
| cryptsetup   | `HAVE_CRYPTSETUP2` | zkey-cryptsetup                        |
| json-c       | `HAVE_JSONC`       | zkey-cryptsetup, libekmfweb,           |
|              |                    | libkmipclient                          |
| glib2        | `HAVE_GLIB2`       | zgetdump                               |
| libcurl      | `HAVE_LIBCURL`     | libekmfweb, libkmipclient, rust/pvimg, |
|              |                    | rust/pvattest, rust/pvsecret,          |
| libxml2      | `HAVE_LIBXML2`     | libkmipclient                          |
| systemd      | `HAVE_SYSTEMD`     | hsavmcore                              |
| libudev      | `HAVE_LIBUDEV`     | cpacfstatsd                            |
| libnl3       | `HAVE_LIBNL3`      | opticsmon                              |

This table lists additional build or install options:

| __COMPONENT__    | __OPTION__                   | __TOOLS__                |
|------------------|:----------------------------:|:------------------------:|
| dracut           | `HAVE_DRACUT`                | zdev, chreipl-fcp-mpath, |
|                  |                              | zipl                     |
| initramfs-tools  | `HAVE_INITRAMFS`             | zdev, zipl               |
|                  | `ZDEV_ALWAYS_UPDATE_INITRD`  | zdev                     |
| rust             | `HAVE_CARGO`                 | rust/*                   |

The s390-tools build process uses "pkg-config" and therefore it must be
available.

Build and runtime requirements for specific tools
-------------------------------------------------

In the following more details on the build an runtime requirements of
the different tools are provided:

* rust/pvsecret:
  For building pvsecret you need OpenSSL version 1.1.1 or newer
  installed (openssl-devel.rpm). Also required is cargo and libcurl.
  Tip: you may skip the pvsecret build by adding
  `HAVE_OPENSSL=0`, `HAVE_LIBCURL=0`, or `HAVE_CARGO=0`.

  The runtime requirements are: openssl-libs (>= 1.1.1).

* dbginfo.sh:
  The tar package is required to archive collected data.

* rust/pvimg:
  For building pvimg you need OpenSSL version 1.1.1 or newer
  installed (openssl-devel.rpm). Also required is cargo and libcurl.
  Tip: you may skip the pvimg build by adding
  `HAVE_OPENSSL=0`, `HAVE_LIBCURL=0`, or `HAVE_CARGO=0`.

  The runtime requirements are: openssl-libs (>= 1.1.1) and libcurl.

* rust/pvattest:
  For building pvattest you need OpenSSL version 1.1.1 or newer
  installed (openssl-devel.rpm). Also required is cargo and libcurl.
  Tip: you may skip the pvattest build by adding
  `HAVE_OPENSSL=0`, `HAVE_LIBCURL=0`, or `HAVE_CARGO=0`.

  The runtime requirements are: openssl-libs (>= 1.1.1) and libcurl.

* opticsmon:
  For building opticsmon OpenSSL and the Netlink Library Suite (libnl3) are
  required.
  Tip: you may skip the opticsmon build by adding
  `HAVE_OPENSSL=0` or `HAVE_LIBNL3=0`

* osasnmpd:
  You need at least the NET-SNMP 5.1.x package (net-snmp-devel.rpm)
  installed, before building the osasnmpd subagent.
  For more information on NET-SNMP refer to:
  http://net-snmp.sourceforge.net

* lsluns:
  For executing the lsluns script the sg_luns and sg_inq commands must
  be available. The sg_luns and sg_inq executables are part of the
  SCSI generic device driver package (sg3 utils/sg utils).

* ziomon tools:
  For running the ziomon tools the following tools/packages are required:
  - Packages: blktrace, multipath-tools, sg3-utils
  - Tools: rsync, tar, lsscsi

* zipl
  For CCW-type DASD dump, zlib compression can be used to compress the dump
  data before writing it to the DASD partition. It can benefit from
  s390 on-chip compression accelerator (DFLTCC) and provide a faster dumping
  process, hence lower system downtime.
  The zlib version integrated with zipl (zipl/boot/zlib) is based on the Linux
  kernel zlib (kernel version 6.3) which represents zlib version 1.1.3 with a
  limited number of functions and a number of updates on top including s390
  hardware compression (DFLTCC) support. Also, all memory allocations are
  performed in advance, which aligns with zipl requirements.
  The CCW-type standalone dumper is built as a single binary and must be
  loaded to stage2 during boot. Hence, all required zlib functions must be
  integrated into it, and its size is restricted. To limit the size, only
  deflate-related parts are integrated (no decompression is required during
  dumping).
  Removing the inflate modules and function prototypes are the only major
  modifications made to the kernel version of zlib.

* zgetdump
  For building zgetdump you need OpenSSL version 1.1.0 or newer
  installed (openssl-devel.rpm). Also required is glib2
  (glib2-devel.rpm) and zlib (zlib-devel.rpm).
  Tip: you may skip the zgetdump build by adding
  `HAVE_OPENSSL=0`, `HAVE_GLIB2=0`, or `HAVE_ZLIB=0`.

* cmsfs-fuse/zdsfs/hmcdrvfs/zgetdump:
  The tools cmsfs-fuse, zdsfs, hmcdrvfs, and zgetdump depend on FUSE.
  FUSE is provided by installing the fuse3 and libfuse3 packages and by a
  kernel compiled with `CONFIG_FUSE_FS`. For compiling the s390-tools package
  the fuse3-devel package is required.
  The cmsfs-fuse tool requires FUSE version 3.0 or newer for full
  functionality.
  For further information about FUSE see: https://github.com/libfuse/libfuse

* hyptop:
  The ncurses-devel package is required to build hyptop.
  The libncurses package is required to run hyptop.
  IMPORTANT: When running hyptop on a System z10 LPAR, the required minimum
             microcode code level is the following:
             Driver 79 MCL N24404.008 in the SE-LPAR stream

* ip_watcher/xcec-bridge:
  As of s390-tools-1.10.0, the minimum required kernel level is 2.6.26.
  For running ip_watcher these programs are required:
  - qetharp (s390-tools)
  - qethconf (s390-tools)
  - route (net-tools)

* zfcpdbf:
  As of s390-tools-1.13.0, the minimum required kernel level is 2.6.38.

* cpacfstats:
  For building the cpacfstats tools you need libudev installed
  (systemd-devel.rpm). Tip: you may skip the cpacfstats build by
  adding `HAVE_LIBUDEV=0` to the make invocation. To run the
  cpacfstats daemon the kernel needs to have performance events
  enabled (check for `CONFIG_PERF_EVENTS=y`). A new group 'cpacfstats'
  needs to be created and all users intending to use the tool should
  be added to this group.

* zdev:
  Depending on the boot loader and initial RAM-disk mechanism used by a
  Linux distribution, specific steps may be required to make changes to
  the root device configuration persistent. zdev encapsulates this root
  device logic in a helper script called 'zdev-root-update': This script
  is invoked whenever the root device configuration is changed and it must
  ensure that the persistent root device configuration is put into effect
  during boot. zdev provides a sample implementation for zdev-root-update
  which can be selected during the 'make install' step using the `HAVE_DRACUT`
  variable:

  - `HAVE_DRACUT=1` installs a zdev-root-update helper that works with zipl
    as boot loader and dracut as initial RAM-disk provider.

  Distributors with different boot or RAM-disk mechanisms should provide
  a custom zdev-root-update helper script.

  - `ZDEV_ALWAYS_UPDATE_INITRD=1` upon modification of any persistent device
    configuration, chzdev updates the initial RAM-disk by default, without any
    additional user interaction.

  For some distributions, all the configuration attributes must be copied to
  the initial RAM-disk. Because the device configuration directives applied
  in the initial RAM-disk takes precedence over those stored in the root file-
  system. This copying is done usually by explicitly invoking a command. This
  build option makes it user-friendly and does this copying without any manual
  intervention.

  Some functions of zdev require that the following programs are available:

  - modprobe (kmod)
  - udevadm (systemd)

  The following programs are not required but when available will improve
  the functionality of the zdev tools:

  - lsblk (util-linux)
  - findmnt (util-linux)
  - vmcp (s390-tools)
  - ip (iproute2)

* znetconf:
  For running znetconf these programs are required:
  - modprobe (kmod)
  - vmcp (s390-tools)

* zkey:
  For building the zkey tools you need openssl version 0.9.7 or newer installed
  (openssl-devel.rpm). Also required are cryptsetup version 2.0.3 or newer
  (cryptsetup-devel.rpm), and json-c version 0.12 or newer (json-c-devel.rpm).
  Tip: you may skip the zkey build by adding `HAVE_OPENSSL=0`, and you may
  may skip the zkey-cryptsetup build by adding `HAVE_CRYPTSETUP2=0`, or
  `HAVE_JSONC=0` to the make invocation.
  A new group 'zkeyadm' needs to be created and all users intending to use the
  tool must be added to this group. The owner of the default key repository
  '/etc/zkey/repository' must be set to group 'zkeyadm' with write permission
  for this group.

* libekmfweb:
  For building the libekmfweb shared library you need openssl version 1.1.1 or
  newer installed (openssl-devel.rpm). Also required are json-c version 0.13 or
  newer (json-c-devel.rpm), and libcurl version 7.59 or newer
  (libcurl-devel.rpm).
  Tip: you may skip the libekmfweb build by adding `HAVE_OPENSSL=0`,
  `HAVE_JSONC=0`, or `HAVE_LIBCURL=0` to the make invocation.

* hsavmcore:
  For building the hsavmcore tool you need fuse version 3.0 and optionally
  systemd which is enabled by default, to disable systemd support,
  add `HAVE_SYSTEMD=0` to the make invocation.
  Tip: you may skip the hsavmcore build by adding `HAVE_FUSE=0`
  to the make invocation.

* libkmipclient:
  For building the libkmipclient shared library you need openssl version 1.1.1
  or newer installed (openssl-devel.rpm). Also required are json-c version 0.13
  or newer (json-c-devel.rpm), libxml2 version 2.9.10 or newer
  (libxml2-devel.rpm), and libcurl version 7.59 or newer (libcurl-devel.rpm).
  Tip: you may skip the libkmipclient build by adding `HAVE_OPENSSL=0`,
  `HAVE_JSONC=0`, `HAVE_LIBXML2=0`, or `HAVE_LIBCURL=0` to the make invocation.

* chreipl-fcp-mpath:
  For a complete list and documentation of the requirements, installation and
  uninstallation, please see
  [chreipl-fcp-mpath/README.md](chreipl-fcp-mpath/README.md).

  Summarized: chreipl-fcp-mpath requires GNU Bash, GNU Core Utilities,
  util-linux, udev, and multipath-tools. When using `HAVE_DRACUT=1` with the
  make invocation, it also requires dracut. When using `ENABLE_DOC=1` with the
  make invocation to build a fresh man page (instead of using the pre-cooked
  version) and render the README.md as HTML, make further requires pandoc and
  GNU awk for the build process.

* ap-check:
  For building the ap-check mdevctl callout utility you need json-c version
  0.13 or newer (json-c-devel.rpm).
  Tip: you may skip ap-check build by adding `HAVE_JSONC=0` to the make
  invocation.
