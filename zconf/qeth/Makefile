include ../../common.mak

all: lsqeth

libs = $(rootdir)/libutil/libutil.a

lsqeth: lsqeth.o misc.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 lsqeth $(DESTDIR)$(BINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c lsqeth.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o lsqeth

.PHONY: all install clean

