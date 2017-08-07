include ../common.mak

all: qetharp

qetharp: qetharp.o

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8 $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 qetharp $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 644 qetharp.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f qetharp *.o *~ core

.PHONY: all install clean
