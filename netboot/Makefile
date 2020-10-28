# Install the netboot image build scripts as samples

include ../common.mak

NETBOOT_SAMPLEDIR=$(TOOLS_DATADIR)/netboot

all:

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(NETBOOT_SAMPLEDIR)
	$(INSTALL) -m 755 mk-s390image mk-pxelinux-ramfs \
		$(DESTDIR)$(NETBOOT_SAMPLEDIR)
	$(INSTALL) -m 644 Dockerfile Makefile.pxelinux.0 README.md \
		mk-s390image.1 \
		$(DESTDIR)$(NETBOOT_SAMPLEDIR)

.PHONY: all install clean
