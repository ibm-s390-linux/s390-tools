include ../common.mak

VERSION = 1.0
VERM = $(shell echo $(VERSION) | cut -d '.' -f 1)

ifneq (${HAVE_OPENSSL},0)
	ifneq (${HAVE_JSONC},0)
		ifneq (${HAVE_LIBCURL},0)
			BUILD_TARGETS += libekmfweb.so.$(VERSION)
			INSTALL_TARGETS += install-libekmfweb.so.$(VERSION)
		else
			BUILD_TARGETS += skip-libekmfweb-curl
			INSTALL_TARGETS += skip-libekmfweb-curl
		endif
	else
		BUILD_TARGETS += skip-libekmfweb-jsonc
		INSTALL_TARGETS += skip-libekmfweb-jsonc
	endif
else
	BUILD_TARGETS += skip-libekmfweb-openssl
	INSTALL_TARGETS += skip-libekmfweb-openssl
endif

libs = $(rootdir)/libseckey/libseckey.a

TMPFILE := $(shell mktemp)

detect-openssl-version.dep:
	echo "#include <openssl/opensslv.h>" > $(TMPFILE)
	echo "#include <openssl/evp.h>" >> $(TMPFILE)
	echo "#ifndef OPENSSL_VERSION_PREREQ" >> $(TMPFILE)
	echo "  #if defined(OPENSSL_VERSION_MAJOR) && defined(OPENSSL_VERSION_MINOR)" >> $(TMPFILE)
	echo "    #define OPENSSL_VERSION_PREREQ(maj, min) \\" >> $(TMPFILE)
	echo "                 ((OPENSSL_VERSION_MAJOR << 16) + \\" >> $(TMPFILE)
	echo "                  OPENSSL_VERSION_MINOR >= ((maj) << 16) + (min))" >> $(TMPFILE)
	echo "  #else" >> $(TMPFILE)
	echo "    #define OPENSSL_VERSION_PREREQ(maj, min) \\" >> $(TMPFILE)
	echo "                 (OPENSSL_VERSION_NUMBER >= (((maj) << 28) | \\" >> $(TMPFILE)
	echo "		        ((min) << 20)))" >> $(TMPFILE)
	echo "  #endif" >> $(TMPFILE)
	echo "#endif" >> $(TMPFILE)
	echo "#if !OPENSSL_VERSION_PREREQ(1, 1)" >> $(TMPFILE)
	echo "  #error openssl version 1.1 is required" >> $(TMPFILE)
	echo "#endif" >> $(TMPFILE)
	echo "static void __attribute__((unused)) test(void) {" >> $(TMPFILE)
	echo "    EVP_PKEY_meth_remove(NULL);" >> $(TMPFILE)
	echo "}" >> $(TMPFILE)
	mv $(TMPFILE) $@

CURL_CONFIG ?= curl-config

check-dep-libekmfweb: detect-openssl-version.dep
	$(call check_dep, \
		"libekmfweb", \
		"detect-openssl-version.dep", \
		"openssl-devel version >= 1.1.1", \
		"HAVE_OPENSSL=0", \
		-I. `$(PKG_CONFIG) --cflags --libs libcrypto` -DOPENSSL_SUPPRESS_DEPRECATED)
	$(call check_dep, \
		"libekmfweb", \
		"json-c/json.h", \
		"json-c-devel", \
		"HAVE_JSONC=0")
	$(call check_dep, \
		"libekmfweb", \
		"curl/curl.h", \
		"libcurl-devel", \
		"HAVE_LIBCURL=0" \
		`$(PKG_CONFIG) --cflags --libs libcurl`)
	$(CURL_CONFIG) --ssl-backends | grep OpenSSL >/dev/null 2>&1 || { echo "Error: libcurl is not built with the OpenSSL backend"; exit 1; }
	touch check-dep-libekmfweb

skip-libekmfweb-openssl:
	echo "  SKIP    libekmfweb due to HAVE_OPENSSL=0"

skip-libekmfweb-jsonc:
	echo "  SKIP    libekmfweb due to HAVE_JSONC=0"

skip-libekmfweb-curl:
	echo "  SKIP    libekmfweb due to HAVE_LIBCURL=0"

all: $(BUILD_TARGETS)

ekmfweb.o: check-dep-libekmfweb ekmfweb.c utilities.h cca.h $(rootdir)include/ekmfweb/ekmfweb.h
utilities.o: check-dep-libekmfweb utilities.c utilities.h $(rootdir)include/ekmfweb/ekmfweb.h
cca.o: check-dep-libekmfweb cca.c cca.h utilities.h $(rootdir)include/ekmfweb/ekmfweb.h

libekmfweb.so.$(VERSION): ALL_CFLAGS += -fPIC `$(PKG_CONFIG) --cflags json-c libcurl libcrypto libssl`
libekmfweb.so.$(VERSION): LDLIBS = `$(PKG_CONFIG) --libs json-c libcurl libcrypto libssl` -ldl
libekmfweb.so.$(VERSION): ALL_LDFLAGS += -shared -Wl,--version-script=libekmfweb.map \
	-Wl,-z,defs,-Bsymbolic -Wl,-soname,libekmfweb.so.$(VERM)
libekmfweb.so.$(VERSION): ekmfweb.o utilities.o cca.o $(libs)
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@
	ln -sf libekmfweb.so.$(VERSION) libekmfweb.so.$(VERM)
	ln -sf libekmfweb.so.$(VERSION) libekmfweb.so

install-libekmfweb.so.$(VERSION): libekmfweb.so.$(VERSION)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 -T libekmfweb.so.$(VERSION) $(DESTDIR)$(SOINSTALLDIR)/libekmfweb.so.$(VERSION)
	ln -sf libekmfweb.so.$(VERSION) $(DESTDIR)$(SOINSTALLDIR)/libekmfweb.so.$(VERM)
	ln -sf libekmfweb.so.$(VERSION) $(DESTDIR)$(SOINSTALLDIR)/libekmfweb.so
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRINCLUDEDIR)/ekmfweb
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 $(rootdir)include/ekmfweb/ekmfweb.h $(DESTDIR)$(USRINCLUDEDIR)/ekmfweb

install: all $(INSTALL_TARGETS)

clean:
	rm -f *.o libekmfweb.so* check-dep-libekmfweb detect-openssl-version.dep

.PHONY: all install clean skip-libekmfweb-openssl skip-libekmfweb-jsonc \
	skip-libekmfweb-curl install-libekmfweb.so.$(VERSION)
