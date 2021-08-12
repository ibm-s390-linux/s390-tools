
include ../../common.mak

INITRAMFSTOOLSDIR := /usr/share/initramfs-tools
HOOKSDIR := $(INITRAMFSTOOLSDIR)/hooks
INITPREMOUNTDIR := $(INITRAMFSTOOLSDIR)/scripts/init-premount

# HAVE_INITRAMFS
#
# This install time parameter determines whether the ngdump initramfs-tools
# support is installed (HAVE_INITRAMFS=1) or not (default). When installed,
# the module performs the following functions when mkinitramfs is run:
#
#  - install the configuration file containing the name of a dump partition
#  - install the dump script that is run at boot
#
ifeq ($(HAVE_INITRAMFS),1)
install:
	$(INSTALL) -m 755 -d $(DESTDIR)$(HOOKSDIR)
	$(INSTALL) -m 755 -d $(DESTDIR)$(INITPREMOUNTDIR)
	$(INSTALL) -m 755 hooks/ngdump $(DESTDIR)$(HOOKSDIR)/
	$(INSTALL) -m 755 scripts/init-premount/ngdump \
		$(DESTDIR)$(INITPREMOUNTDIR)
endif
