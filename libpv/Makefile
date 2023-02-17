# Common definitions
include ../common.mak

.DEFAULT_GOAL := all

LIB := libpv.a

ifneq ($(shell sh -c 'command -v pkg-config'),)
GLIB2_CFLAGS := $(shell pkg-config --silence-errors --cflags glib-2.0)
GLIB2_LIBS := $(shell pkg-config --silence-errors --libs glib-2.0)
LIBCRYPTO_CFLAGS := $(shell pkg-config --silence-errors --cflags libcrypto openssl)
LIBCRYPTO_LIBS := $(shell pkg-config --silence-errors --libs libcrypto openssl)
LIBCURL_CFLAGS := $(shell pkg-config --silence-errors --cflags libcurl)
LIBCURL_LIBS := $(shell pkg-config --silence-errors --libs libcurl)
else
GLIB2_CFLAGS := -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include
GLIB2_LIBS := -lglib-2.0
LIBCRYPTO_CFLAGS :=
LIBCRYPTO_LIBS := -lcrypto -lssl
LIBCURL_CFLAGS := -I/usr/include/s390x-linux-gnu
LIBCURL_LIBS := -lcurl
endif
LDLIBS += $(GLIB2_LIBS) $(LIBCRYPTO_LIBS) $(LIBCURL_LIBS)

WARNINGS := -Wall -Wextra -Wshadow \
	    -Wcast-align -Wwrite-strings -Wmissing-prototypes \
	    -Wmissing-declarations -Wredundant-decls -Wnested-externs \
	    -Wno-long-long -Wuninitialized -Wconversion -Wstrict-prototypes \
	    -Wpointer-arith -Wno-error=inline \
	    -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable \
	    $(NULL)

ALL_CFLAGS += -std=gnu11 \
	      -DOPENSSL_API_COMPAT=0x10101000L \
	      $(GLIB2_CFLAGS) \
	      $(LIBCRYPTO_CFLAGS) \
	      $(LIBCURL_CFLAGS) \
	      $(WARNINGS) \
	      $(NULL)

BUILD_TARGETS := skip-$(LIB)
ifneq (${HAVE_OPENSSL},0)
ifneq (${HAVE_GLIB2},0)
ifneq (${HAVE_LIBCURL},0)
BUILD_TARGETS := $(LIB)
endif
endif
endif

sources := $(wildcard *.c)
objects := $(patsubst %.c,%.o,$(sources))

all: $(BUILD_TARGETS)

$(LIB): $(objects)
$(LIB): ALL_CFLAGS += -fPIC

$(objects): .check-dep-$(LIB)

install: all

clean:
	rm -f -- $(objects)
	rm -f -- $(LIB)
	rm -f -- .check-dep-$(LIB) .detect-openssl.dep.c

skip-$(LIB):
		echo "  SKIP    $(LIB) due to unresolved dependencies"

.PHONY: all install clean skip-$(LIB) install-$(LIB)


.detect-openssl.dep.c:
	echo "#include <openssl/evp.h>" > $@
	echo "#if OPENSSL_VERSION_NUMBER < 0x10101000L" >> $@
	echo "  #error openssl version 1.1.1 is required" >> $@
	echo "#endif" >> $@
	echo "static void __attribute__((unused)) test(void) {" >> $@
	echo "    EVP_MD_CTX *ctx = EVP_MD_CTX_new();" >> $@
	echo "    EVP_MD_CTX_free(ctx);" >> $@
	echo "}" >> $@

.check-dep-$(LIB): .detect-openssl.dep.c
	$(call check_dep, \
		"$(LIB)", \
		"glib.h", \
		"glib2-devel / libglib2.0-dev", \
		"HAVE_GLIB2=0")
	$(call check_dep, \
		"$(LIB)", \
		$^, \
		"openssl-devel / libssl-dev version >= 1.1.1", \
		"HAVE_OPENSSL=0", \
		"-I.")
	$(call check_dep, \
		"$(LIB)", \
		"curl/curl.h", \
		"libcurl-devel", \
		"HAVE_LIBCURL=0")
	touch $@
