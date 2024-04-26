include ../common.mak

all: zpcictl

libs =	$(rootdir)/libzpci/libzpci.a $(rootdir)/libutil/libutil.a

zpcictl: zpcictl.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zpcictl $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 zpcictl.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ zpcictl core

.PHONY: all install clean
