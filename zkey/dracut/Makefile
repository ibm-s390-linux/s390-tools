
include ../../common.mak

# HAVE_DRACUT
#
# This install time parameter determines whether the pkey dracut module is
# installed (HAVE_DRACUT=1) or not (default). When installed, the module
# performs the following functions when dracut is run:
#
#  - install a dracut config file to include zkey related utilities and
#    zkey repository in the initramfs
#
ifeq ($(HAVE_DRACUT),1)
install:
	$(INSTALL) -m 755 -d $(DESTDIR)$(DRACUTCONFDIR)/
	$(INSTALL) -m 644 99-pkey.conf $(DESTDIR)$(DRACUTCONFDIR)/
endif
