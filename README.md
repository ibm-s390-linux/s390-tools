
s390-tools
==========

The s390-tools package contains the source tree of a set of user space
utilities for use with the s390 Linux kernel and device drivers.

The package also contains the following files:

 * [CONTRIBUTING](CONTRIBUTING.md): Contribution guidelines
 * [LICENSE](LICENSE): The MIT license that applies to this package
 * [CHANGELOG](CHANGELOG.md): The history of s390-tools versions
 * [AUTHORS](AUTHORS.md): A list of all authors of the s390-tools package

Package contents
----------------

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

 * udev rules:
   - 59-dasd.rules: rules for unique DASD device nodes created in /dev/disk/.
   - 57-osasnmpd.rules: udev rules for osasnmpd.
   - 60-readahead.rules: udev rules to set increased "default max readahead".
   - 40-z90crypt.rules: udev rules for z90crypt driver
   - 90-cpi.rules: udev rule to update Control-Program-Information when KVM is
                   used.

 * systemd units:
   - cpi.service: Unit to apply CPI settings
   - dumpconf.service: Unit to configure dump on panic for s390
   - mon_fsstatd.service: Unit for mon_fsstatd
   - mon_procd.service: Unit for mon_procd
   - iucvtty-login@.service: Instance unit to manage iucvtty instances
   - ttyrun-getty@.service: Instance unit to manage ttyrun

 * zipl:
   Make DASDs or tapes bootable for system IPL or system dump.

 * zgetdump:
   Retrieve system dumps from either tapes or DASDs.

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

 * vmconvert:
   Convert system dumps created by the z/VM VMDUMP command into dumps with
   LKCD format. These LKCD dumps can then be analyzed with the dump analysis
   tool lcrash.

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

 * scsi_logging_level:
   Create, get or set the logging level for the SCSI logging facility.

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
   - znetconf:   List and configure network devices for s390 network adapters.
   - cio_ignore: Query and modify the contents of the CIO device driver
                 blacklist.
   - lsmem:      Display the online status of the available memory.
   - chmem:      Set hotplug memory online or offline.
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
   sampling facility support.

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

| __LIBRARY__    |__BUILD OPTION__| __TOOLS__                             |
|----------------|:--------------:|:-------------------------------------:|
| fuse           | `HAVE_FUSE`    | cmsfs-fuse, zdsfs, hmcdrvfs, zgetdump |
| zlib           | `HAVE_ZLIB`    | zgetdump, dump2tar                    |
| ncurses        | `HAVE_NCURSES` | hyptop                                |
| pfm            | `HAVE_PFM`     | cpacfstats                            |
| net-snmp       | `HAVE_SNMP`    | osasnmpd                              |
| glibc-static   | `n/a`          | zfcpdump                              |

This table lists additional build or install options:

| __COMPONENT__  | __OPTION__       | __TOOLS__                       |
|----------------|:----------------:|:-------------------------------:|
| dracut         | `HAVE_DRACUT`    | zdev                            |

The s390-tools build process uses "pkg-config" if available and hard-coded
compiler and linker options otherwise.

Build and runtime requirements for specific tools
-------------------------------------------------

In the following more details on the build an runtime requirements of
the different tools are provided:

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

* cmsfs-fuse/zdsfs/hmcdrvfs/zgetdump:
  The tools cmsfs-fuse, zdsfs, hmcdrvfs, and zgetdump depend on FUSE.
  FUSE is provided by installing the fuse and libfuse packages and by a
  kernel compiled with `CONFIG_FUSE_FS`. For compiling the s390-tools package
  the fuse-devel package is required.
  The cmsfs-fuse tool requires FUSE version 2.8.1 or newer for full
  functionality.
  For further information about FUSE see: http://fuse.sourceforge.net

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
  For building the cpacfstats tools you need libpfm version 4 or
  newer installed (libpfm-devel.rpm). Tip: you may skip the cpacfstats
  build by adding `HAVE_PFN=0` to the make invocation. To run the
  cpacfstats daemon the kernel needs to have performance
  events enabled (check for `CONFIG_PERF_EVENTS=y`) and you need libpfm
  version 4 or newer installed. A new group 'cpacfstats' needs to be
  created and all users intending to use the tool should be added to
  this group.

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
