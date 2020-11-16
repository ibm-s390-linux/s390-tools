include ../../common.mak

VERSION = 1.0
VERM = $(shell echo $(VERSION) | cut -d '.' -f 1)

all: zkey-ekmfweb.so

libs = $(rootdir)/libutil/libutil.a

zkey-ekmfweb.o: zkey-ekmfweb.c zkey-ekmfweb.h ../kms-plugin.h \
	../cca.h ../utils.h ../pkey.h ../properties.h \
	$(rootdir)include/ekmfweb/ekmfweb.h libekmfweb.dep

properties.o: ../properties.c ../properties.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

pkey.o: ../pkey.c ../pkey.h ../cca.h ../ep11.h ../utils.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

cca.o: ../cca.c ../cca.h ../pkey.h ../ep11.h ../utils.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

ep11.o: ../ep11.c ../ep11.h ../pkey.h ../cca.h ../utils.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

utils.o: ../utils.c ../utils.h ../pkey.h ../cca.h ../ep11.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

zkey-ekmfweb.so: ALL_CFLAGS += -fPIC
zkey-ekmfweb.so: LDLIBS = -L$(rootdir)/libekmfweb -lekmfweb -ldl -lcrypto
zkey-ekmfweb.so: ALL_LDFLAGS += -shared -Wl,--version-script=zkey-ekmfweb.map \
	-Wl,-z,defs,-Bsymbolic -Wl,-soname,zkey-ekmfweb.so.$(VERM)
zkey-ekmfweb.so: zkey-ekmfweb.o properties.o pkey.o cca.o ep11.o utils.o $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

install-libekmfweb.dep:
	$(MAKE) -C $(rootdir)/libekmfweb/ TOPDIR=$(TOPDIR) ARCH=$(ARCH) install
	touch install-libekmfweb.dep

libekmfweb.dep:
	$(MAKE) -C $(rootdir)/libekmfweb/ TOPDIR=$(TOPDIR) ARCH=$(ARCH) all
	touch libekmfweb.dep

install: all install-libekmfweb.dep zkey-ekmfweb.so
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -m 644 -c zkey-ekmfweb.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -d -m 755 $(DESTDIR)$(ZKEYKMSPLUGINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 -T zkey-ekmfweb.so $(DESTDIR)$(ZKEYKMSPLUGINDIR)/zkey-ekmfweb.so

clean:
	rm -f *.o zkey-ekmfweb.so install-libekmfweb.dep libekmfweb.dep

.PHONY: all install clean