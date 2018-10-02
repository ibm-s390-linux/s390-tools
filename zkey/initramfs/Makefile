# Common definitions
include ../../common.mak

INITRAMFSDIR := /usr/share/initramfs-tools
HOOKDIR := $(INITRAMFSDIR)/hooks
INITTOP := $(INITRAMFSDIR)/scripts/init-top

# HAVE_INITRAMFS
#
# This install time parameter determines whether the zkey initramfs support is
# installed (HAVE_INITRAMFS=1) or not (default). When installed, the module
# performs the following functions when mkinitramfs is run:
#
#  - install a hook to include zkey related utilities and zkey repository in
#    the initramfs
#
ifeq ($(HAVE_INITRAMFS),1)
install:
	$(INSTALL) -m 755 -d $(DESTDIR)/$(HOOKDIR) $(DESTDIR)/$(INITTOP)
	$(INSTALL) -m 755 hooks/s390-tools-zkey $(DESTDIR)/$(HOOKDIR)
endif
