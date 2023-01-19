# Common definitions
include ../../common.mak

ZDEVDIR := 95zdev
ZDEVKDUMPDIR := 95zdev-kdump

# HAVE_DRACUT
#
# This install time parameter determines whether the zdev dracut module is
# installed (HAVE_DRACUT=1) or not (default). When installed, the module
# performs the following functions when dracut is run:
#
#  - copy the persistent root device configuration to the initial ram disk
#  - install a boot-time hook to apply firmware-provided configuration data
#    to the system
#
ifeq ($(HAVE_DRACUT),1)
install:
	$(INSTALL) -m 755 -d $(DESTDIR)$(DRACUTMODDIR)/
	$(INSTALL) -m 755 -d $(DESTDIR)$(DRACUTMODDIR)/$(ZDEVDIR)
	$(INSTALL) -m 755 $(ZDEVDIR)/module-setup.sh \
		$(ZDEVDIR)/parse-zdev.sh \
		$(ZDEVDIR)/zdev-lib.sh \
		$(DESTDIR)$(DRACUTMODDIR)/$(ZDEVDIR)/
	$(INSTALL) -m 755 -d $(DESTDIR)$(DRACUTMODDIR)/$(ZDEVKDUMPDIR)
	$(INSTALL) -m 755 $(ZDEVKDUMPDIR)/module-setup.sh \
		$(DESTDIR)$(DRACUTMODDIR)/$(ZDEVKDUMPDIR)/
endif
