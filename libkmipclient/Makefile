include ../common.mak

VERSION = 1.0
VERM = $(shell echo $(VERSION) | cut -d '.' -f 1)

ifneq (${HAVE_OPENSSL},0)
	ifneq (${HAVE_JSONC},0)
		ifneq (${HAVE_LIBXML2},0)
			ifneq (${HAVE_LIBCURL},0)
				BUILD_TARGETS += libkmipclient.so.$(VERSION)
				INSTALL_TARGETS += install-libkmipclient.so.$(VERSION)
			else
				BUILD_TARGETS += skip-libkmipclient-curl
				INSTALL_TARGETS += skip-libkmipclient-curl
			endif
		else
			BUILD_TARGETS += skip-libkmipclient-xml
			INSTALL_TARGETS += skip-libkmipclient-xml
		endif
	else
		BUILD_TARGETS += skip-libkmipclient-jsonc
		INSTALL_TARGETS += skip-libkmipclient-jsonc
	endif
else
	BUILD_TARGETS += skip-libkmipclient-openssl
	INSTALL_TARGETS += skip-libkmipclient-openssl
endif

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
XML2_CONFIG ?= xml2-config

check-dep-libkmipclient: detect-openssl-version.dep
	$(call check_dep, \
		"libkmipclient", \
		"detect-openssl-version.dep", \
		"openssl-devel version >= 1.1.1", \
		"HAVE_OPENSSL=0", \
		-I. -lcrypto -DOPENSSL_SUPPRESS_DEPRECATED)
	$(call check_dep, \
		"libkmipclient", \
		"json-c/json.h", \
		"json-c-devel", \
		"HAVE_JSONC=0")
	$(call check_dep, \
		"libkmipclient", \
		"libxml/tree.h", \
		"libxml2-devel", \
		"HAVE_LIBXML2=0", \
		`$(XML2_CONFIG) --cflags` `$(XML2_CONFIG) --libs`)
	$(call check_dep, \
		"libkmipclient", \
		"curl/curl.h", \
		"libcurl-devel", \
		"HAVE_LIBCURL=0" \
		`$(CURL_CONFIG) --cflags` `$(CURL_CONFIG) --libs`)
	$(CURL_CONFIG) --ssl-backends | grep OpenSSL >/dev/null 2>&1 || { echo "Error: libcurl is not built with the OpenSSL backend"; exit 1; }
	touch check-dep-libkmipclient

skip-libkmipclient-openssl:
	echo "  SKIP    libkmipclient due to HAVE_OPENSSL=0"

skip-libkmipclient-jsonc:
	echo "  SKIP    libkmipclient due to HAVE_JSONC=0"

skip-libkmipclient-xml:
	echo "  SKIP    libkmipclient due to HAVE_LIBXML2=0"

skip-libkmipclient-curl:
	echo "  SKIP    libkmipclient due to HAVE_LIBCURL=0"

all: $(BUILD_TARGETS)

kmip.o: check-dep-libkmipclient kmip.c kmip.h utils.h $(rootdir)include/kmipclient/kmipclient.h
request.o: check-dep-libkmipclient request.c kmip.h names.h $(rootdir)include/kmipclient/kmipclient.h
response.o: check-dep-libkmipclient response.c kmip.h names.h $(rootdir)include/kmipclient/kmipclient.h
attribute.o: check-dep-libkmipclient attribute.c kmip.h names.h $(rootdir)include/kmipclient/kmipclient.h
key.o: check-dep-libkmipclient key.c kmip.h names.h $(rootdir)include/kmipclient/kmipclient.h
ttlv.o: check-dep-libkmipclient ttlv.c kmip.h utils.h $(rootdir)include/kmipclient/kmipclient.h
json.o: check-dep-libkmipclient json.c kmip.h names.h utils.h $(rootdir)include/kmipclient/kmipclient.h
xml.o: check-dep-libkmipclient xml.c kmip.h names.h utils.h $(rootdir)include/kmipclient/kmipclient.h
https.o: check-dep-libkmipclient https.c kmip.h utils.h $(rootdir)include/kmipclient/kmipclient.h
tls.o: check-dep-libkmipclient tls.c kmip.h utils.h $(rootdir)include/kmipclient/kmipclient.h
names.o: check-dep-libkmipclient names.c names.h utils.h $(rootdir)include/kmipclient/kmipclient.h
utils.o: check-dep-libkmipclient utils.c names.h utils.h $(rootdir)include/kmipclient/kmipclient.h

libkmipclient.so.$(VERSION): ALL_CFLAGS += -fPIC `$(XML2_CONFIG) --cflags` `$(CURL_CONFIG) --cflags`
libkmipclient.so.$(VERSION): LDLIBS = -ljson-c -lcrypto -lssl `$(XML2_CONFIG) --libs` `$(CURL_CONFIG) --libs`
libkmipclient.so.$(VERSION): ALL_LDFLAGS += -shared -Wl,--version-script=libkmipclient.map \
	-Wl,-z,defs,-Bsymbolic -Wl,-soname,libkmipclient.so.$(VERM)
libkmipclient.so.$(VERSION): kmip.o request.o response.o attribute.o key.o ttlv.o json.o \
	xml.o https.o tls.o names.o utils.o
	$(LINK) $(ALL_LDFLAGS) $^ $(LDLIBS) -o $@
	ln -srf libkmipclient.so.$(VERSION) libkmipclient.so.$(VERM)
	ln -srf libkmipclient.so.$(VERSION) libkmipclient.so

install-libkmipclient.so.$(VERSION): libkmipclient.so.$(VERSION)
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 755 -T libkmipclient.so.$(VERSION) $(DESTDIR)$(SOINSTALLDIR)/libkmipclient.so.$(VERSION)
	ln -srf $(DESTDIR)$(SOINSTALLDIR)/libkmipclient.so.$(VERSION) $(DESTDIR)$(SOINSTALLDIR)/libkmipclient.so.$(VERM)
	ln -srf $(DESTDIR)$(SOINSTALLDIR)/libkmipclient.so.$(VERSION) $(DESTDIR)$(SOINSTALLDIR)/libkmipclient.so
	$(INSTALL) -d -m 770 $(DESTDIR)$(USRINCLUDEDIR)/kmipclient
	$(INSTALL) -g $(GROUP) -o $(OWNER) -m 644 $(rootdir)include/kmipclient/kmipclient.h $(DESTDIR)$(USRINCLUDEDIR)/kmipclient

install: all $(INSTALL_TARGETS)

clean:
	rm -f *.o libkmipclient.so* check-dep-libkmipclient detect-openssl-version.dep

.PHONY: all install clean skip-libkmipclient-openssl skip-libkmipclient-jsonc \
	skip-libkmipclient-xml skip-libkmipclient-curl install-libkmipclient.so.$(VERSION)
