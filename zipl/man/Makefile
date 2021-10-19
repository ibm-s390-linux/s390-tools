# Common definitions
include ../../common.mak

all:

install:
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man5
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	sed -e 's@%SYSCONFDIR%@$(SYSCONFDIR)@' \
		-e 's@%TOOLS_LIBDIR%@$(TOOLS_LIBDIR)@' zipl.8.in \
		> $(DESTDIR)$(MANDIR)/man8/zipl.8
	sed -e 's@%SYSCONFDIR%@$(SYSCONFDIR)@' \
		-e 's@%TOOLS_LIBDIR%@$(TOOLS_LIBDIR)@' zipl-editenv.8.in \
		> $(DESTDIR)$(MANDIR)/man8/zipl-editenv.8
	sed -e 's@%SYSCONFDIR%@$(SYSCONFDIR)@' \
		-e 's@%TOOLS_LIBDIR%@$(TOOLS_LIBDIR)@' zipl.conf.5.in \
		> $(DESTDIR)$(MANDIR)/man5/zipl.conf.5
	chmod 644 $(DESTDIR)$(MANDIR)/man8/zipl.8 \
		$(DESTDIR)$(MANDIR)/man8/zipl-editenv.8 \
		$(DESTDIR)$(MANDIR)/man5/zipl.conf.5

clean:
