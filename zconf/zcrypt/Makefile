include ../../common.mak

all: chzcrypt lszcrypt zcryptctl zcryptstats

libs = $(rootdir)/libutil/libutil.a

chzcrypt: chzcrypt.o misc.o $(libs)
lszcrypt: lszcrypt.o misc.o $(libs)
zcryptctl:  zcryptctl.o misc.o $(libs)
zcryptstats:  zcryptstats.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 chzcrypt $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 lszcrypt $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zcryptctl $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zcryptstats $(DESTDIR)$(BINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c chzcrypt.8 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c lszcrypt.8 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c zcryptctl.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o chzcrypt lszcrypt zcryptctl zcryptstats

.PHONY: all install clean
