<!-- markdown documentation: https://github.github.com/gfm/ -->

NAME
====

chreipl-fcp-mpath - use multipath information for re-IPL path failover on a
running Linux instance

DESCRIPTION
===========

The IPL process of Linux on Z or LinuxONE from an FCP-attached SCSI volume uses
exactly one path to the volume. If this path is unavailable, the IPL fails.

The **chreipl-fcp-mpath** toolset monitors **udev** events about paths to the
re-IPL volume. If the currently configured re-IPL path becomes unavailable, the
toolset checks for operational paths to the same volume. If available, it
reconfigures the re-IPL settings to use an operational path.

Thus, re-IPL from an FCP-attached SCSI volume can be successful despite path
failures on a running Linux instance if at least one path to the re-IPL volume
remains operational.

**Chreipl-fcp-mpath** requires **udev**, **multipathd** and **dm-multipath**.
Once installed, the toolset runs automatically and autonomously. No user
intervention is possible or required.

Other than installing the toolset, there is no user interface for
**chreipl-fcp-mpath**.

Requirements
------------

The **chreipl-fcp-mpath** tool has the following requirements on the
Linux instance that is being monitored:

  - The Linux instance must have started successfully, during IPL.

  - The running Linux instance must use **dm-multipath** and **multipathd** for
    the configured re-IPL volume - a volume that contains a zipl boot record
    and has one of its paths used in the re-IPL configuration.

  - **udev** must run.

  - The toolset must observe at least one event about the configured re-IPL
    path. Examples for such events are: the SCSI disk comes online, or a path
    of the corresponding multipath device goes down or comes back online.

    - The WWID of the re-IPL volume must not change while the Linux instance is
      running.

  - When the configured re-IPL path becomes unavailable while the Linux
    instance is running, at least one operational path to the re-IPL volume
    must be available, or must become available. If no such path is available
    when the Linux instance is rebooted, the re-IPL path is not changed.

  - The tool assumes that any manually reconfigured re-IPL device is valid and
    operational.

    The tool treats a newly configured re-IPL device like the initially
    configured re-IPL device. In particular, if the newly configured re-IPL
    device fulfills the requirements of the tool, re-IPL path failover takes
    place if the configured re-IPL path becomes unavailable.

Caution with Manual Changes to the Configured re-IPL Target
-----------------------------------------------------------

**chreipl-fcp-mpath** is designed to accept operator-inititated changes of the
re-IPL device. However, concurrent changes by the operator and tool driven
changes can result in the operator change being overwritten.

To avoid this problem, change the re-IPL device only during steady-state
operations, when no path events happen. Alternatively, make sure that no events
are processed while you change the device. See [EXAMPLES](#examples) for one
way to suspend event processing.

MESSAGES
========

During monitoring and event processing, **chreipl-fcp-mpath** writes messages
to the syslog.

When the configured re-IPL path is changed to a different path to the same
volume (priority *daemon.notice*):

  > Changed re-IPL path to: \<device-bus-id\>:\<wwpn\>:\<lun\>.

When a path event indicates that the last available path has become
non-operational (priority *daemon.alert*):

  > The re-IPL device cannot be changed because no operational path to the
  > re-IPL volume remains. The next re-IPL might fail unless you re-attach or
  > enable at least one valid path to the re-IPL volume.

When changing the configured re-IPL device failed because of an error with the
used Linux kernel interface (priority *daemon.crit*):

  > Changing the re-IPL device failed. The current re-IPL settings might be
  > inconsistent. Check and correct the settings (see the README.md of
  > chreipl-fcp-mpath) to make sure that the current re-IPL device is valid.

A failure to change the re-IPL device can indicate an inconsistent setting that
cannot be corrected automatically by **chreipl-fcp-mpath**. As a result, the
next re-IPL might fail or might not use the intended re-IPL device.

You can use the following tools to check and correct the current settings:

  - **lsreipl** to confirm that the intended re-IPL device is configured;
  - **chreipl** to change the re-IPL device;
  - **lszfcp** to inspect the state of available paths to the re-IPL device.

<!-- NOT-IN-MAN { -->

SOFTWARE REQUIREMENTS
=====================

**chreipl-fcp-mpath** integrates into s390-tools's build and install
infrastructure. Use **make** to build it. No explicit dependency management is
in place, but the toolset has some software dependencies besides the
requirements in section [Requirements](#requirements):

  - GNU Bash;
  - GNU Core Utilities (mktemp, readlink, sync, truncate);
  - util-linux (flock, hexdump, logger);
  - udev / systemd-udev;
  - multipath-tools.

To make use of the optional dracut configuration you need: dracut.

To build and install the documentation (man page) you need:

  - pandoc;
  - GNU Core Utilities (date);
  - GNU awk;
  - GNU Gzip.

INSTALLATION
============

If your distribution includes a packaged version of **chreipl-fcp-mpath**,
either as a separate package or as part of a **s390-tools** package, install
that package. Otherwise, you can either install it from source as part of
**s390-tools** or separately.

To install **chreipl-fcp-mpath** as part of **s390-tools**, use **make** on the
top-level directory of your **s390-tools** distribution. Installing the entire
distribution might overwrite other already installed tools.

To install the tool separately, change into the **chreipl-fcp-mpath**
directory, and use **make** there.

You need *root* privileges to install the tool into the root file system.

Calling **make** runs the build steps. Calling **make install** runs the build
steps and copies the resulting components to their final destination.
**s390-tools** offers more options and targets to customize the build (see
**make help**).

**chreipl-fcp-mpath** has the following optional build options:

| Option      | Values | Default | Effect
| :-----      | :----: | :-----: | :-----
| HAVE_DRACUT | 0, 1   | 0       | Install a dracut configuration file that includes **chreipl-fcp-mpath** in the initial ramdisks built with **dracut**.
| ENABLE_DOC  | 0, 1   | 0       | Build and install a man page for **chreipl-fcp-mpath**.

Specify any options as arguments for both the **make** and **make install**
command as shown in the following example:

    ~ # cd chreipl-fcp-mpath/
    ~ # make HAVE_DRACUT=1 ENABLE_DOC=1
    ~ # make HAVE_DRACUT=1 ENABLE_DOC=1 install

After the installation, reload the udev rules database:

    ~ # udevadm control --reload

*The toolset is now active on your running Linux instance.*

If you use the *HAVE_DRACUT=1* option, also rebuild your
initial ramdisk, to immediately include the toolset instead of
waiting for the next kernel update.

How to rebuild the initial ramdisk and the naming scheme for the
resulting file or files depends on your distribution.
The following example applies to Fedora and to Red Hat Enterprise Linux:

    ~ # dracut --force /boot/initramfs-"$(uname -r)".img "$(uname -r)"

For SUSE Linux Enterprise Server run for example:

    ~ # dracut --hostonly --force /boot/initrd-"$(uname -r)" "$(uname -r)"

These commands replace the initial ramdisk for the currently running kernel.
If your distribution uses **zipl** as its boot loader, run **zipl** to refresh
the boot record to find the new initial ramdisk.

    ~ # zipl

With dracut and documentation enabled, **make install** deploys the following
files to these default locations:

    /usr/lib/chreipl-fcp-mpath/chreipl-fcp-mpath-common.sh
    /usr/lib/dracut/dracut.conf.d/70-chreipl-fcp-mpath.conf
    /usr/lib/udev/chreipl-fcp-mpath-is-ipl-tgt
    /usr/lib/udev/chreipl-fcp-mpath-is-ipl-vol
    /usr/lib/udev/chreipl-fcp-mpath-is-reipl-zfcp
    /usr/lib/udev/chreipl-fcp-mpath-record-volume-identifier
    /usr/lib/udev/chreipl-fcp-mpath-try-change-ipl-path
    /usr/lib/udev/rules.d/70-chreipl-fcp-mpath.rules
    /usr/share/man/man7/chreipl-fcp-mpath.7.gz

UNINSTALL
=========

If your distribution includes a separately from **s390-tools** packaged version
of **chreipl-fcp-mpath**, uninstall that package.

For installations without distribution packaging, you cannot uninstall
**chreipl-fcp-mpath** with **make**.

Instead, remove the toolset by deleting the installed files as listed in
[INSTALLATION](#installation)), reload the udev rules database, and rebuild all
modified initial ramdisks as described in [INSTALLATION](#installation)).

<!-- NOT-IN-MAN } -->

EXAMPLES
========

Manual Changes to the Configured re-IPL Device
----------------------------------------------

As outlined in [DESCRIPTION](#description), be cautious when manually changing
the configured re-IPL device. Assure that your reconfiguration actions do not
collide with concurrent automatic event processing by **chreipl-fcp-mpath**.
You can avoid such collisions, by stopping event processing, making your
changes, and then re-enabling event processing.  You need *root* privileges for
running the commands in the following example:

    ~ # udevadm settle
    ~ # udevadm control --stop-exec-queue
    ~ # chreipl ...
    ~ # udevadm control --start-exec-queue

Listing messages with journalctl
--------------------------------

If your Linux instance includes **journalctl**, use the following command to
list all messages that are issued by **chreipl-fcp-mpath**:

    ~ # journalctl -t chreipl-fcp-mpath

To list only messages that were issued since the last IPL, use this command:

    ~ # journalctl -t chreipl-fcp-mpath -b

REPORTING BUGS
==============

Use the **Issues** functionality on GitHub to report any bugs in
**chreipl-fcp-mpath**:
[s390-tools Issues](<https://github.com/ibm-s390-linux/s390-tools/issues> "Link to the s390-tools Issues page").

SEE ALSO
========

**chreipl**(8), **dracut**(8), **journalctl**(1), **lsreipl(8)**,
**lszfcp**(8), **multipath**(8), **multipathd**(8), **udev**(7),
**udevadm**(8), **zipl**(8)
