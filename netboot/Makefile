# Install the netboot image build scripts as samples

include ../common.mak

SCRIPTS = mk-s390image mk-pxelinux-ramfs
NETBOOT_SAMPLEDIR=$(TOOLS_DATADIR)/netboot

all:

install: install-scripts
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 \
		Dockerfile Makefile.pxelinux.0 README.md mk-s390image.1 \
		$(DESTDIR)$(NETBOOT_SAMPLEDIR)

install-scripts: $(SCRIPTS)
	@if [ ! -d $(DESTDIR)$(NETBOOT_SAMPLEDIR) ]; then \
		mkdir -p $(DESTDIR)$(NETBOOT_SAMPLEDIR); \
		chown $(OWNER).$(GROUP) $(DESTDIR)$(NETBOOT_SAMPLEDIR); \
		chmod 755 $(DESTDIR)$(NETBOOT_SAMPLEDIR); \
	fi; \
	for i in $^; do \
		$(SED) -e 's/%S390_TOOLS_VERSION%/$(S390_TOOLS_RELEASE)/' \
		< $$i >$(DESTDIR)$(NETBOOT_SAMPLEDIR)/$$i; \
		chown $(OWNER).$(GROUP) $(DESTDIR)$(NETBOOT_SAMPLEDIR)/$$i; \
		chmod 755 $(DESTDIR)$(NETBOOT_SAMPLEDIR)/$$i; \
	done

.PHONY: all install clean install-scripts
