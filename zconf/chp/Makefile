include ../../common.mak

all: chchp lschp chpstat
	$(MAKE) -C chpstat all

libs =	$(rootdir)/libutil/libutil.a

chchp: chchp.o $(libs)
lschp: lschp.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 chchp $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 lschp $(DESTDIR)$(BINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c chchp.8 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c lschp.8 $(DESTDIR)$(MANDIR)/man8
	$(MAKE) -C chpstat install

clean:
	rm -f *.o chchp lschp
	$(MAKE) -C chpstat clean

.PHONY: all install clean
