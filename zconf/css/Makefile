# Common definitions
include ../../common.mak

libs =	$(rootdir)/libccw/libccw.a \
	$(rootdir)/libutil/libutil.a

objects = lscss.o misc.o

lscss.o: lscss.c

all: lscss

lscss: $(objects) $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(BINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 lscss $(DESTDIR)$(BINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 -c lscss.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f $(objects) lscss

.PHONY: all install clean

