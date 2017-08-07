include ../common.mak

all:

install: qethconf
	$(SED) -e 's+%S390_TOOLS_VERSION%+$(S390_TOOLS_RELEASE)+' \
	< qethconf >$(DESTDIR)$(BINDIR)/qethconf; \
	chown $(OWNER).$(GROUP) $(DESTDIR)$(BINDIR)/qethconf; \
	chmod 755 $(DESTDIR)$(BINDIR)/qethconf; \
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 qethconf.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:

.PHONY: all install clean
