include ../common.mak

all:

install: hsci
	$(SED) -e 's/%S390_TOOLS_VERSION%/$(S390_TOOLS_RELEASE)/' \
	< hsci >$(DESTDIR)$(BINDIR)/hsci; \
	chown $(OWNER).$(GROUP) $(DESTDIR)$(BINDIR)/hsci; \
	chmod 755 $(DESTDIR)$(BINDIR)/hsci; \
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 hsci.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:

.PHONY: all install clean
