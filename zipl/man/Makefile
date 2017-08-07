# Common definitions
include ../../common.mak

all:

install:
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man5
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c zipl.8 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c zipl.conf.5 $(DESTDIR)$(MANDIR)/man5

clean:
