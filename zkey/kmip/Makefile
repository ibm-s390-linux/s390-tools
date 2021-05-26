include ../../common.mak

VERSION = 1.0
VERM = $(shell echo $(VERSION) | cut -d '.' -f 1)

all: zkey-kmip.so

libs = $(rootdir)/libutil/libutil.a $(rootdir)/libseckey/libseckey.a

zkey-kmip.o: zkey-kmip.c zkey-kmip.h ../kms-plugin.h ../plugin-utils.h \
	../cca.h ../utils.h ../pkey.h ../properties.h \
	$(rootdir)include/kmipclient/kmipclient.h libkmipclient.dep
profiles.o: profiles.c zkey-kmip.h ../properties.h

plugin-utils.o: ../plugin-utils.c ../plugin-utils.h ../kms-plugin.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

properties.o: ../properties.c ../properties.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

pkey.o: ../pkey.c ../pkey.h ../cca.h ../ep11.h ../utils.h ../kms-plugin.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

cca.o: ../cca.c ../cca.h ../pkey.h ../ep11.h ../utils.h ../properties.h ../kms-plugin.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

ep11.o: ../ep11.c ../ep11.h ../pkey.h ../cca.h ../utils.h ../kms-plugin.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

utils.o: ../utils.c ../utils.h ../pkey.h ../cca.h ../ep11.h ../kms-plugin.h
	$(CC) $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -c $< -o $@

zkey-kmip.so: ALL_CFLAGS += -fPIC
zkey-kmip.so: LDLIBS = -L$(rootdir)/libkmipclient -lkmipclient -ldl -lcrypto
zkey-kmip.so: ALL_LDFLAGS += -shared -Wl,--version-script=zkey-kmip.map \
	-Wl,-z,defs,-Bsymbolic -Wl,-soname,zkey-kmip.so.$(VERM)
zkey-kmip.so: zkey-kmip.o plugin-utils.o properties.o pkey.o cca.o ep11.o \
	utils.o profiles.o $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

install-libkmipclient.dep:
	$(MAKE) -C $(rootdir)/libkmipclient/ TOPDIR=$(TOPDIR) ARCH=$(ARCH) install
	touch install-libkmipclient.dep

libkmipclient.dep:
	$(MAKE) -C $(rootdir)/libkmipclient/ TOPDIR=$(TOPDIR) ARCH=$(ARCH) all
	touch libkmipclient.dep

install: all install-libkmipclient.dep zkey-kmip.so
	$(INSTALL) -d -m 755 $(DESTDIR)$(ZKEYKMSPLUGINDIR)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 -T zkey-kmip.so $(DESTDIR)$(ZKEYKMSPLUGINDIR)/zkey-kmip.so
	$(INSTALL) -d -m 770 $(DESTDIR)$(SYSCONFDIR)/zkey/kmip
	$(INSTALL) -d -m 770 $(DESTDIR)$(SYSCONFDIR)/zkey/kmip/profiles
	$(INSTALL) -m 644 -c profiles/*.profile $(DESTDIR)$(SYSCONFDIR)/zkey/kmip/profiles

clean:
	rm -f *.o zkey-kmip.so install-libkmipclient.dep libkmipclient.dep

.PHONY: all install clean