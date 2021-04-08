include ../common.mak

lib = libseckey.a

ifneq (${HAVE_OPENSSL},0)
	BUILD_TARGETS = $(lib)
else
	BUILD_TARGETS = skip-libseckey
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

check-dep-libseckey: detect-openssl-version.dep
	$(call check_dep, \
		"libseckey", \
		"detect-openssl-version.dep", \
		"openssl-devel version >= 1.1.1", \
		"HAVE_OPENSSL=0", \
		-I. -lcrypto -DOPENSSL_SUPPRESS_DEPRECATED)
	touch check-dep-libseckey

objects = sk_openssl.o sk_pkeymeth.o sk_provider.o sk_utilities.o sk_cca.o sk_ep11.o
headers = $(rootdir)include/libseckey/sk_openssl.h $(rootdir)include/libseckey/sk_utilities.h \
	  $(rootdir)include/libseckey/sk_cca.h $(rootdir)include/libseckey/sk_ep11.h

ALL_CFLAGS += -fPIC

$(lib): $(objects)

sk_openssl.o: check-dep-libseckey sk_openssl.c $(headers)
sk_pkeymeth.o: check-dep-libseckey sk_pkeymeth.c $(headers)
sk_provider.o: check-dep-libseckey sk_provider.c $(headers)
sk_cca.o: check-dep-libseckey sk_cca.c $(headers)
sk_ep11.o: check-dep-libseckey sk_ep11.c $(headers)

all: $(BUILD_TARGETS)

skip-libseckey:
	echo "  SKIP    libseckey due to HAVE_OPENSSL=0"

install: all

clean:
	rm -f *.o $(lib) detect-openssl-version.dep check-dep-libseckey

.PHONY: all install clean skip-libseckey
