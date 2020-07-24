include ../../common.mak

all: zkey-ekmfweb.so

libs = $(rootdir)/libutil/libutil.a

export LIBRARY_PATH = $(rootdir)/libekmfweb:$LIBRARY_PATH

zkey-ekmfweb.o: zkey-ekmfweb.c zkey-ekmfweb.h ../kms-plugin.h \
	../cca.h ../utils.h ../pkey.h ../properties.h \
	$(rootdir)include/ekmfweb/ekmfweb.h $(rootdir)/libekmfweb/libekmfweb.so

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
zkey-ekmfweb.so: LDLIBS = -lekmfweb -ldl -lcrypto -shared
zkey-ekmfweb.so: LDFLAGS = -shared -Wl,--version-script=zkey-ekmfweb.map \
	-Wl,-z,defs,-Bsymbolic
zkey-ekmfweb.so: zkey-ekmfweb.o properties.o pkey.o cca.o ep11.o utils.o $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

install-libekmfweb.dep:
	$(MAKE) -C $(rootdir)/libekmfweb/ TOPDIR=$(TOPDIR) ARCH=$(ARCH) install
	touch install-libekmfweb.dep

install: all install-libekmfweb.dep zkey-ekmfweb.so
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -m 644 -c zkey-ekmfweb.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -d -m 755 $(DESTDIR)$(LIB64DIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 -T zkey-ekmfweb.so $(DESTDIR)$(LIB64DIR)/zkey-ekmfweb.so

clean:
	rm -f *.o zkey-ekmfweb.so install-libekmfweb.dep

.PHONY: all install clean