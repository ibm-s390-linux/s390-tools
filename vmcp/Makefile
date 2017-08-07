include ../common.mak

all: vmcp

vmcp: vmcp.o

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 vmcp $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 vmcp.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ vmcp core

.PHONY: all install clean
