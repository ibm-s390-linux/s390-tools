# How to build a PXELINUX-style network boot image for KVM

## Synopsis

To build a PXELINUX-style netboot image usable for KVM a s390 Linux system
with access to the internet is required.

Running the following command will generate the netboot image pxlinux.0:

` $ make -f Makefile.pxelinux.0`

Alternatively you can use docker to build the image:

```
 $ docker build -t pxelinux0 .
 $ docker run --rm -v $(pwd):/out pxelinux0 cp /netboot/pxelinux.0 /out
 $ docker rmi pxelinux0
```

The resulting file pxelinux.0 must be copied to the system acting as
DHCP/BOOTP server for the KVM installation.

## Full Description

Starting with  QEMU 2.10 it is possible to boot s390 virtual machines over a
network interface using DHCP. As usual for DHCP/BOOTP a single bootable image
is copied from the boot server, loaded into memory and booted. In order to
boot a Linux Operating System, it is typically necessary to load a kernel
together with an initial ramdisk (initramfs) and optionally specify some kernel
command line parameters.

Alternatively, on s390 it is possible to load a single file consisting of
the kernel image followed by an initial ramdisk. Such single boot images can
be provided by a Linux distributor, e.g. on the installation media.

Single boot images can also easily be built from pre-existing kernel/initramfs
pairs by concatenating these files. In order to allow the kernel to find the
ramdisk, it is necessary to update the 8 bytes at location 0x10408 with the
offset value of the ramdisk in the new binary, and the 8 bytes at location
0x10410 with the size of the ramdisk. Both values need to be updated in binary,
big endian format.

Since PXELINUX, the PXE boot implementation provided by the Syslinux project,
has introduced a popular way to set up network boot servers for Linux, it
is desirable that s390 network boot setups can be done in a similar way.
A boot image simulating a PXELINUX-like boot for s390 can be easily
constructed by combining a Linux kernel with a small fit-to-purpose initial
ramdisk as described above. For practical purposes, using the host kernel is
a reasonable way for this kind of approach. If possible, the initial ramdisk
should be independent of the host, which is not always possible, as the kernel
might require modules for e.g. virtio network and block devices.

### Example: Building a PXELINUX-style boot image

The approach described below consists of bundling some shell scripts, busybox
and the kexec binary bundled into the initial ramdisk.

The init process can be a simple shell script that will mount a few essential
file systems, like /dev, /proc, and /sys, start a DHCP client (e.g. busybox's
udchpc) and then invoke another script to perform the network boot.
udchpc will invoke the script /usr/share/udhcpc/default.script in response
to DHCP server messages to perform configuration actions.
The sample default.script delivered with busybox can be used for that purpose,
but needs to be extended to evaluate the bootp specific DHCP options (most
important the tftp server address) and store them for use by the boot script.

The boot script itself has to retrieve the PXELINUX configuration from the
tftp server according to the rules described [here][1] then retrieve the
remote kernel and initial ramdisk and finally use kexec to boot the network
kernel.

In essence, the following steps are performed to produce the initial
ramdisk:

1. Create a skeleton initramfs directory structure
2. Create the init script, the boot script and the DHCP default script
3. Copy kexec and it's dependencies from the host into the initramfs
4. Copy virtio network and block modules of the host's active kernel into
   the initramfs
5. Copy the busybox binaries into the initramfs.
6. Copy the DHCP configuration and PXE boot scripts to the initramfs
7. Build the ramdisk (in compressed CPIO format)
8. Concatenate the kernel image and the initial ramdisk, and adjust the
   ramdisk offset as described above.

Steps 1 to 7 are performed by the sample script mk-pxelinux-ramfs, while step
8 is done with the help of mk-s390image.

The binary resulting from the procedure described above can now be deployed
to a DHCP/BOOTP server. This server should also act as a TFTP server for the
PXELINUX configuration and binary files needed to complete the network boot.

Alternatively, it is possible to use programs like [petitboot][2] or
[pxe-kexec][3] in the initial ramdisk, as these provide more sophisticated
and robust processing of PXELINUX-style configurations.

[1]: http://www.syslinux.org/wiki/index.php?title=PXELINUX
[2]: https://github.com/open-power/petitboot
[3]: https://sourceforge.net/projects/pxe-kexec.berlios/
