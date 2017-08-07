include ../common.mak

libs =	$(rootdir)/libvtoc/libvtoc.a \
	$(rootdir)/libzds/libzds.a \
	$(rootdir)/libdasd/libdasd.a \
	$(rootdir)/libu2s/libu2s.a \
	$(rootdir)/libutil/libutil.a

all: fdasd

fdasd: fdasd.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 fdasd $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 fdasd.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ fdasd core

.PHONY: all install clean
