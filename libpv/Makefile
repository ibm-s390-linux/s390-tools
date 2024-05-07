# Common definitions
include ../common.mak

.DEFAULT_GOAL := all

LIB := libpv.a

GLIB2_CFLAGS := $(shell $(PKG_CONFIG) --silence-errors --cflags glib-2.0)
GLIB2_LIBS := $(shell $(PKG_CONFIG) --silence-errors --libs glib-2.0)
LIBCRYPTO_CFLAGS := $(shell $(PKG_CONFIG) --silence-errors --cflags libcrypto)
LIBCRYPTO_LIBS := $(shell $(PKG_CONFIG) --silence-errors --libs libcrypto)
LDLIBS += $(GLIB2_LIBS) $(LIBCRYPTO_LIBS)
WARNINGS := -Wall -Wextra -Wshadow \
	    -Wcast-align -Wwrite-strings -Wmissing-prototypes \
	    -Wmissing-declarations -Wredundant-decls -Wnested-externs \
	    -Wno-long-long -Wuninitialized -Wconversion -Wstrict-prototypes \
	    -Wpointer-arith -Wno-error=inline \
	    -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable \
	    $(NULL)

ALL_CFLAGS += -DOPENSSL_API_COMPAT=0x10101000L \
	      $(GLIB2_CFLAGS) \
	      $(LIBCRYPTO_CFLAGS) \
	      $(WARNINGS) \
	      $(NULL)

BUILD_TARGETS := skip-$(LIB)
ifneq (${HAVE_OPENSSL},0)
ifneq (${HAVE_GLIB2},0)
BUILD_TARGETS := $(LIB)
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
	touch $@
