include ../common.mak

CPPFLAGS += -I../include
LDLIBS += -ldl

all: zkey

libs = $(rootdir)/libutil/libutil.a

zkey.o: zkey.c pkey.h misc.h

zkey: zkey.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zkey $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -m 644 -c zkey.1 $(DESTDIR)$(MANDIR)/man1

clean:
	rm -f *.o zkey

.PHONY: all install clean
