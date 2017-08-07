# Common definitions
include ../../common.mak

all:

install:
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 tunedasd.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:

.PHONY: all install clean
