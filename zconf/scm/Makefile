include ../../common.mak

all: lsscm

libs = $(rootdir)/libutil/libutil.a

lsscm: lsscm.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 lsscm $(DESTDIR)$(BINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c lsscm.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o lsscm

.PHONY: all install clean
