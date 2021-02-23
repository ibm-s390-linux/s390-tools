include ../common.mak

ifneq (${HAVE_OPENSSL},0)
	BUILD_TARGETS += zkey
	INSTALL_TARGETS += install-zkey
	ifneq (${HAVE_JSONC},0)
		ifneq (${HAVE_LIBCURL},0)
			SUB_DIRS += ekmfweb
		endif
	endif
else
	BUILD_TARGETS += zkey-skip
	INSTALL_TARGETS += zkey-skip
endif

ifneq (${HAVE_CRYPTSETUP2},0)
	ifneq (${HAVE_JSONC},0)
		ifneq (${HAVE_OPENSSL},0)
			BUILD_TARGETS += zkey-cryptsetup
			INSTALL_TARGETS += install-zkey-cryptsetup
			ALL_CPPFLAGS += -DHAVE_LUKS2_SUPPORT
		else
			BUILD_TARGETS += zkey-cryptsetup-skip-openssl
			INSTALL_TARGETS += zkey-cryptsetup-skip-openssl
		endif
	else
		BUILD_TARGETS += zkey-cryptsetup-skip-jsonc
		INSTALL_TARGETS += zkey-cryptsetup-skip-jsonc
	endif
else
	BUILD_TARGETS += zkey-cryptsetup-skip-cryptsetup2
	INSTALL_TARGETS += zkey-cryptsetup-skip-cryptsetup2
endif

libs = $(rootdir)/libutil/libutil.a

ALL_CFLAGS += -DKMS_PLUGIN_LOCATION=\"$(ZKEYKMSPLUGINDIR)\"

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

zkey-cryptsetup-skip-openssl:
	echo "  SKIP    zkey-cryptsetup due to HAVE_OPENSSL=0"

all: $(BUILD_TARGETS) $(SUB_DIRS)

zkey.o: zkey.c pkey.h cca.h ep11.h misc.h
pkey.o: pkey.c pkey.h cca.h ep11.h utils.h
cca.o: cca.c cca.h pkey.h ep11.h utils.h
ep11.o: ep11.c ep11.h pkey.h cca.h utils.h
utils.o: utils.h pkey.h cca.h ep11.h
properties.o: check-dep-zkey properties.c properties.h
keystore.o: keystore.c keystore.h properties.h pkey.h cca.h ep11.h utils.h
zkey-cryptsetup.o: check-dep-zkey-cryptsetup zkey-cryptsetup.c pkey.h cca.h \
			ep11.h misc.h utils.h
kms.o: kms.c kms.h kms-plugin.h utils.h pkey.h

zkey: LDLIBS = -ldl -lcrypto
zkey: zkey.o pkey.o cca.o ep11.o properties.o keystore.o utils.o kms.o $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

zkey-cryptsetup: LDLIBS = -ldl -lcryptsetup -ljson-c -lcrypto
zkey-cryptsetup: zkey-cryptsetup.o pkey.o cca.o ep11.o utils.o $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@

install-common:
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man1

install-zkey: zkey
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zkey $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -m 644 -c zkey.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -d -m 770 $(DESTDIR)$(SYSCONFDIR)/zkey
	$(INSTALL) -d -m 770 $(DESTDIR)$(SYSCONFDIR)/zkey/repository
	$(INSTALL) -m 644 -c kms-plugins.conf $(DESTDIR)$(SYSCONFDIR)/zkey

install-zkey-cryptsetup: zkey-cryptsetup
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 zkey-cryptsetup $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -m 644 -c zkey-cryptsetup.1 $(DESTDIR)$(MANDIR)/man1

install: all install-common $(INSTALL_TARGETS) $(SUB_DIRS)

clean: $(SUB_DIRS)
	rm -f *.o zkey zkey-cryptsetup detect-libcryptsetup.dep \
		check-dep-zkey check-dep-zkey-cryptsetup

#
# For simple "make" we explicitly set the MAKECMDGOALS to "all".
#
ifeq ($(MAKECMDGOALS),)
MAKECMDGOALS = all
endif

$(SUB_DIRS):
	$(foreach goal,$(MAKECMDGOALS), \
		$(MAKE) -C $@ TOPDIR=$(TOPDIR) ARCH=$(ARCH) $(goal) ;)
.PHONY: $(SUB_DIRS)

.PHONY: all install clean zkey-skip zkey-cryptsetup-skip-cryptsetup2 \
	zkey-cryptsetup-skip-jsonc install-common install-zkey \
	install-zkey-cryptsetup
