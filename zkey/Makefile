include ../common.mak

ifneq (${HAVE_OPENSSL},0)
	BUILD_TARGETS += zkey
	INSTALL_TARGETS += install-zkey
else
	BUILD_TARGETS += zkey-skip
	INSTALL_TARGETS += zkey-skip
endif

ifneq (${HAVE_CRYPTSETUP2},0)
	ifneq (${HAVE_JSONC},0)
		BUILD_TARGETS += zkey-cryptsetup
		INSTALL_TARGETS += install-zkey-cryptsetup
		CPPFLAGS += -DHAVE_LUKS2_SUPPORT
	else
		BUILD_TARGETS += zkey-cryptsetup-skip-jsonc
		INSTALL_TARGETS += zkey-cryptsetup-skip-jsonc
	endif
else
	BUILD_TARGETS += zkey-cryptsetup-skip-cryptsetup2
	INSTALL_TARGETS += zkey-cryptsetup-skip-cryptsetup2
endif

libs = $(rootdir)/libutil/libutil.a

detect-libcryptsetup.dep:
	echo "#include <libcryptsetup.h>" > detect-libcryptsetup.dep
	echo "#ifndef CRYPT_LUKS2" >> detect-libcryptsetup.dep
	echo "  #error libcryptsetup version 2.0.3 is required" >> detect-libcryptsetup.dep
	echo "#endif" >> detect-libcryptsetup.dep
	echo "int i = CRYPT_SLOT_UNBOUND;" >> detect-libcryptsetup.dep

check-dep-zkey:
	$(call check_dep, \
		"zkey", \
		"openssl/evp.h", \
		"openssl-devel", \
		"HAVE_OPENSSL=0")
	touch check-dep-zkey

check-dep-zkey-cryptsetup: detect-libcryptsetup.dep
	$(call check_dep, \
		"zkey-cryptsetup", \
		"detect-libcryptsetup.dep", \
		"cryptsetup-devel version 2.0.3", \
		"HAVE_CRYPTSETUP2=0", \
		"-I.")
	$(call check_dep, \
		"zkey-cryptsetup", \
		"json-c/json.h", \
		"json-c-devel", \
		"HAVE_JSONC=0")
	touch check-dep-zkey-cryptsetup

zkey-skip:
	echo "  SKIP    zkey due to HAVE_OPENSSL=0"

zkey-cryptsetup-skip-cryptsetup2:
	echo "  SKIP    zkey-cryptsetup due to HAVE_CRYPTSETUP2=0"

zkey-cryptsetup-skip-jsonc:
	echo "  SKIP    zkey-cryptsetup due to HAVE_JSONC=0"

all: $(BUILD_TARGETS)

zkey.o: zkey.c pkey.h cca.h misc.h
pkey.o: pkey.c pkey.h
cca.o: cca.c cca.h pkey.h
utils.o: utils.h
properties.o: check-dep-zkey properties.c properties.h
keystore.o: keystore.c keystore.h properties.h pkey.h cca.h utils.h
zkey-cryptsetup.o: check-dep-zkey-cryptsetup zkey-cryptsetup.c pkey.h cca.h misc.h

zkey: LDLIBS = -ldl -lcrypto
zkey: zkey.o pkey.o cca.o properties.o keystore.o utils.o $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

zkey-cryptsetup: LDLIBS = -ldl -lcryptsetup -ljson-c
zkey-cryptsetup: zkey-cryptsetup.o pkey.o cca.o $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

install-common:
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man1

install-zkey:
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zkey $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -m 644 -c zkey.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -d -m 770 $(DESTDIR)$(SYSCONFDIR)/zkey
	$(INSTALL) -d -m 770 $(DESTDIR)$(SYSCONFDIR)/zkey/repository

install-zkey-cryptsetup:
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zkey-cryptsetup $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -m 644 -c zkey-cryptsetup.1 $(DESTDIR)$(MANDIR)/man1

install: all install-common $(INSTALL_TARGETS)

clean:
	rm -f *.o zkey zkey-cryptsetup detect-libcryptsetup.dep \
		check-dep-zkey check-dep-zkey-cryptsetup

.PHONY: all install clean zkey-skip zkey-cryptsetup-skip-cryptsetup2 \
	zkey-cryptsetup-skip-jsonc install-common install-zkey \
	install-zkey-cryptsetup
