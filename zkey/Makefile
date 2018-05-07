include ../common.mak

ifeq (${HAVE_OPENSSL},0)

all:
	$(SKIP) HAVE_OPENSSL=0

install:
	$(SKIP) HAVE_OPENSSL=0

else

check_dep:
	$(call check_dep, \
		"zkey", \
		"openssl/evp.h", \
		"openssl-devel", \
		"HAVE_OPENSSL=0")

CPPFLAGS += -I../include
LDLIBS += -ldl -lcrypto

all: check_dep zkey

libs = $(rootdir)/libutil/libutil.a

zkey.o: zkey.c pkey.h misc.h
pkey.o: pkey.c pkey.h
properties.o: properties.c properties.h
keystore.o: keystore.c keystore.h properties.h

zkey: zkey.o pkey.o properties.o keystore.o $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zkey $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -m 644 -c zkey.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -d -m 770 $(DESTDIR)$(SYSCONFDIR)/zkey
	$(INSTALL) -d -m 770 $(DESTDIR)$(SYSCONFDIR)/zkey/repository

endif

clean:
	rm -f *.o zkey

.PHONY: all install clean
