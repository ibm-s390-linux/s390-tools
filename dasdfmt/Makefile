include ../common.mak

all: dasdfmt

libs =	$(rootdir)/libdasd/libdasd.a \
	$(rootdir)/libvtoc/libvtoc.a \
	$(rootdir)/libu2s/libu2s.a \
	$(rootdir)/libutil/libutil.a

dasdfmt: dasdfmt.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 dasdfmt $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 dasdfmt.8 \
		$(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ dasdfmt core

.PHONY: all install clean
