# Common definitions
include ../../common.mak

MODDIR := /usr/lib/dracut/modules.d/
ZDEVDIR := 95zdev

# HAVE_DRACUT
#
# This install time parameter determines whether the zdev dracut module is
# installed (HAVE_DRACUT=1) or not (default). When installed, the module
# performs the following functions when dracut is run:
#
#  - copy the persistent root device configuration to the initial ram disk
#
ifeq ($(HAVE_DRACUT),1)
install:
	$(INSTALL) -m 755 -d $(DESTDIR)$(MODDIR)
	$(INSTALL) -m 755 -d $(DESTDIR)$(MODDIR)/$(ZDEVDIR)
	$(INSTALL) -m 755 $(ZDEVDIR)/module-setup.sh \
		$(DESTDIR)$(MODDIR)/$(ZDEVDIR)/
endif
