include ../../common.mak

BIN_PROGRAM = pvattest
PKGDATADIR ?= "$(DESTDIR)$(TOOLS_DATADIR)/$(BIN_PROGRAM)"

SRC_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
ROOT_DIR = $(rootdir)
PVATTESTDIR := $(ROOT_DIR)/pvattest
INCLUDE_PATHS = "$(SRC_DIR)" "$(ROOT_DIR)/include"
INCLUDE_PARMS = $(addprefix -I,$(INCLUDE_PATHS))

LIBPV_DIR = $(ROOT_DIR)/libpv
LIBPV = $(LIBPV_DIR)/libpv.a

WARNINGS := -Wall -Wextra -Wshadow \
	    -Wcast-align -Wwrite-strings -Wmissing-prototypes \
	    -Wmissing-declarations -Wredundant-decls -Wnested-externs \
	    -Wno-long-long -Wuninitialized -Wconversion -Wstrict-prototypes \
	    -Wpointer-arith -Wno-error=inline \
	    -Wno-unused-function -Wno-unused-parameter -Wno-unused-variable \
	    -Werror \
	    $(NULL)

PVATTEST_SRCS := $(wildcard *.c) \
		$(NULL)

$(BIN_PROGRAM)_SRCS := \
		$(PVATTEST_SRCS) \
		$(NULL)

$(BIN_PROGRAM)_OBJS := $($(BIN_PROGRAM)_SRCS:.c=.o)

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

ALL_CFLAGS += -std=gnu11 \
	      -DPKGDATADIR=$(PKGDATADIR) \
	      -DOPENSSL_API_COMPAT=0x10101000L \
	      $(GLIB2_CFLAGS) \
	      $(LIBCRYPTO_CFLAGS) \
	      $(LIBCURL_CFLAGS) \
	      $(WARNINGS) \
	      $(NULL)

ifneq ($(call check_header_prereq,"asm/uvdevice.h"),yes)
	ALL_CFLAGS += -DPVATTEST_NO_PERFORM
endif

ALL_CPPFLAGS += $(INCLUDE_PARMS)
LDLIBS += $(GLIB2_LIBS) $(LIBCRYPTO_LIBS) $(LIBCURL_LIBS)

BUILD_TARGETS := skip-$(BIN_PROGRAM)
INSTALL_TARGETS := skip-$(BIN_PROGRAM)
ifneq (${HAVE_OPENSSL},0)
ifneq (${HAVE_GLIB2},0)
ifneq (${HAVE_LIBCURL}, 0)
	BUILD_TARGETS := $(BIN_PROGRAM)
	INSTALL_TARGETS := install-$(BIN_PROGRAM)
endif
endif
endif

all: $(BUILD_TARGETS)

install: $(INSTALL_TARGETS)

$(BIN_PROGRAM): $($(BIN_PROGRAM)_OBJS) $(LIBPV)

skip-$(BIN_PROGRAM):
	echo "  SKIP    $(BIN_PROGRAM) due to unresolved dependencies"

clean:
	$(RM) -f -- $($(BIN_PROGRAM)_OBJS) $(BIN_PROGRAM) .check-dep-$(BIN_PROGRAM) .detect-openssl.dep.c

install-$(BIN_PROGRAM): $(BIN_PROGRAM)
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -c $^ $(DESTDIR)$(USRBINDIR)


.PHONY: all install clean skip-$(BIN_PROGRAM) install-$(BIN_PROGRAM)

$($(BIN_PROGRAM)_OBJS): .check-dep-$(BIN_PROGRAM)

.detect-openssl.dep.c:
	echo "#include <openssl/evp.h>" > $@
	echo "#if OPENSSL_VERSION_NUMBER < 0x10101000L" >> $@
	echo "  #error openssl version 1.1.1 is required" >> $@
	echo "#endif" >> $@
	echo "static void __attribute__((unused)) test(void) {" >> $@
	echo "    EVP_MD_CTX *ctx = EVP_MD_CTX_new();" >> $@
	echo "    EVP_MD_CTX_free(ctx);" >> $@
	echo "}" >> $@

.check-dep-$(BIN_PROGRAM): .detect-openssl.dep.c
	$(call check_dep, \
		"$(BIN_PROGRAM)", \
		"glib.h", \
		"glib2-devel / libglib2.0-dev", \
		"HAVE_GLIB2=0")
	$(call check_dep, \
		"$(BIN_PROGRAM)", \
		$^, \
		"openssl-devel / libssl-dev version >= 1.1.1", \
		"HAVE_OPENSSL=0", \
		"-I.")
	$(call check_dep, \
		"$(BIN_PROGRAM)", \
		"curl/curl.h", \
		"libcurl-devel", \
		"HAVE_LIBCURL=0")
	touch $@
