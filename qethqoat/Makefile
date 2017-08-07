include ../common.mak

all: qethqoat

qethqoat: qethqoat.o

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 qethqoat $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 qethqoat.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ qethqoat core

.PHONY: all install clean
