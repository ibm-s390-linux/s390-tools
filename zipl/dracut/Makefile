
include ../../common.mak

NGDUMPDIR := 99ngdump

# HAVE_DRACUT
#
# This install time parameter determines whether the ngdump dracut module is
# installed (HAVE_DRACUT=1) or not (default). When installed, the module
# performs the following functions when dracut is run:
#
#  - install the systemd service that initiates the dump at boot
#  - install the dump script that is run by the new systemd service at boot
#
ifeq ($(HAVE_DRACUT),1)
install:
	$(INSTALL) -m 755 zipl_helper.prepare-ngdump \
		$(DESTDIR)$(TOOLS_LIBDIR)
	$(INSTALL) -m 755 -d $(DESTDIR)$(DRACUTMODDIR)/
	$(INSTALL) -m 755 -d $(DESTDIR)$(DRACUTMODDIR)/$(NGDUMPDIR)
	$(INSTALL) -m 755 $(NGDUMPDIR)/module-setup.sh \
		$(DESTDIR)$(DRACUTMODDIR)/$(NGDUMPDIR)/
	$(INSTALL) -m 644 $(NGDUMPDIR)/ngdump.service \
		$(DESTDIR)$(DRACUTMODDIR)/$(NGDUMPDIR)/
	$(INSTALL) -m 755 $(NGDUMPDIR)/ngdump.sh \
		$(DESTDIR)$(DRACUTMODDIR)/$(NGDUMPDIR)/
	$(INSTALL) -m 755 $(NGDUMPDIR)/ngdump-reipl.sh \
		$(DESTDIR)$(DRACUTMODDIR)/$(NGDUMPDIR)/
endif
