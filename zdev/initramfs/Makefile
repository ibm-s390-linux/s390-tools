# Common definitions
include ../../common.mak

INITRAMFSDIR := /usr/share/initramfs-tools
HOOKDIR := $(INITRAMFSDIR)/hooks
INITTOP := $(INITRAMFSDIR)/scripts/init-top

# HAVE_INITRAMFS
#
# This install time parameter determines whether the zdev initramfs support is
# installed (HAVE_INITRAMFS=1) or not (default). When installed, the module
# performs the following functions when mkinitramfs is run:
#
#  - install a boot-time hook to apply firmware-provided configuration data
#    to the system
#
ifeq ($(HAVE_INITRAMFS),1)
install:
	$(INSTALL) -m 755 -d $(DESTDIR)/$(HOOKDIR) $(DESTDIR)/$(INITTOP)
	$(INSTALL) -m 755 hooks/s390-tools-zdev $(DESTDIR)/$(HOOKDIR)
	$(INSTALL) -m 755 scripts/init-top/s390-tools-zdev $(DESTDIR)/$(INITTOP)
endif
