include ../../common.mak

all: zkey-ekmfweb.so

libs = $(rootdir)/libutil/libutil.a

export LIBRARY_PATH = $(rootdir)/libekmfweb:$LIBRARY_PATH

zkey-ekmfweb.o: zkey-ekmfweb.c zkey-ekmfweb.h ../kms-plugin.h ../pkey.h \
	$(rootdir)include/ekmfweb/ekmfweb.h $(rootdir)/libekmfweb/libekmfweb.so

zkey-ekmfweb.so: ALL_CFLAGS += -fPIC
zkey-ekmfweb.so: LDLIBS = -lekmfweb -ldl -shared
zkey-ekmfweb.so: LDFLAGS = -shared -Wl,--version-script=zkey-ekmfweb.map \
	-Wl,-z,defs,-Bsymbolic
zkey-ekmfweb.so: zkey-ekmfweb.o $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

install-libekmfweb.dep:
	$(MAKE) -C $(rootdir)/libekmfweb/ TOPDIR=$(TOPDIR) ARCH=$(ARCH) install
	touch install-libekmfweb.dep

install: all install-libekmfweb.dep zkey-ekmfweb.so
	$(INSTALL) -d -m 755 $(DESTDIR)$(LIB64DIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 -T zkey-ekmfweb.so $(DESTDIR)$(LIB64DIR)/zkey-ekmfweb.so

clean:
	rm -f *.o zkey-ekmfweb.so install-libekmfweb.dep

.PHONY: all install clean