include ../common.mak

CPPFLAGS += -I../include
LDLIBS += -ldl -lcrypto

all: zkey

libs = $(rootdir)/libutil/libutil.a

zkey.o: zkey.c pkey.h misc.h
properties.o: properties.c properties.h

zkey: zkey.o properties.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zkey $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -m 644 -c zkey.1 $(DESTDIR)$(MANDIR)/man1

clean:
	rm -f *.o zkey

.PHONY: all install clean
