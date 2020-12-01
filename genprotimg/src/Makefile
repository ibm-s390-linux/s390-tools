# Common definitions
include ../../common.mak

bin_PROGRAM = genprotimg

PKGDATADIR ?= "$(DESTDIR)$(TOOLS_DATADIR)/genprotimg"
SRC_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
TOP_SRCDIR := $(SRC_DIR)/../
ROOT_DIR = $(TOP_SRC_DIR)/../../
ZIPL_DIR = $(ROOT_DIR)/zipl
LOADER_DIR = $(TOP_SRCDIR)/boot

INCLUDE_PATHS = "$(SRC_DIR)" "$(TOP_SRCDIR)" "$(ROOTDIR)/include"
INCLUDE_PARMS = $(addprefix -I,$(INCLUDE_PATHS))

WARNINGS := -Wall -Wextra -Wshadow \
	-Wcast-align -Wwrite-strings -Wmissing-prototypes \
	-Wmissing-declarations -Wredundant-decls -Wnested-externs \
	-Wno-long-long -Wuninitialized -Wconversion -Wstrict-prototypes \
	-Wpointer-arith -Werror -Wno-error=inline \
	$(NULL)

$(bin_PROGRAM)_SRCS := $(bin_PROGRAM).c pv/pv_stage3.c pv/pv_image.c \
	pv/pv_comp.c pv/pv_hdr.c pv/pv_ipib.c utils/crypto.c utils/file_utils.c \
	pv/pv_args.c utils/buffer.c pv/pv_comps.c pv/pv_error.c \
	pv/pv_opt_item.c utils/curl.c \
	$(NULL)
$(bin_PROGRAM)_OBJS := $($(bin_PROGRAM)_SRCS:.c=.o)

ALL_CFLAGS += -std=gnu11 -DPKGDATADIR=$(PKGDATADIR) \
	$(GLIB2_CFLAGS) $(LIBCRYPTO_CFLAGS) $(LIBCURL_CFLAGS) \
	$(WARNINGS) \
	$(NULL)
ALL_CPPFLAGS += $(INCLUDE_PARMS)
LDLIBS += $(GLIB2_LIBS) $(LIBCRYPTO_LIBS) $(LIBCURL_LIBS)


ifneq ($(shell sh -c 'command -v pkg-config'),)
GLIB2_CFLAGS := $(shell pkg-config --silence-errors --cflags glib-2.0)
GLIB2_LIBS := $(shell pkg-config --silence-errors --libs glib-2.0)
LIBCRYPTO_CFLAGS := $(shell pkg-config --silence-errors --cflags libcrypto)
LIBCRYPTO_LIBS := $(shell pkg-config --silence-errors --libs libcrypto)
LIBCURL_CFLAGS := $(shell pkg-config --silence-errors --cflags libcurl)
LIBCURL_LIBS := $(shell pkg-config --silence-errors --libs libcurl)
else
GLIB2_CFLAGS := -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include
GLIB2_LIBS := -lglib-2.0
LIBCRYPTO_CFLAGS :=
LIBCRYPTO_LIBS := -lcrypto
LIBCURL_CFLAGS :=
LIBCURL_LIBS := -lcurl
endif

BUILD_TARGETS := skip-$(bin_PROGRAM)
INSTALL_TARGETS := skip-$(bin_PROGRAM)
ifneq (${HAVE_OPENSSL},0)
ifneq (${HAVE_GLIB2},0)
ifneq (${HAVE_LIBCURL},0)
BUILD_TARGETS := $(bin_PROGRAM)
INSTALL_TARGETS := install-$(bin_PROGRAM)
endif
endif
endif

all: $(BUILD_TARGETS)

install: $(INSTALL_TARGETS)

$(bin_PROGRAM): $($(bin_PROGRAM)_OBJS)

skip-$(bin_PROGRAM):
	echo "  SKIP    $(bin_PROGRAM) due to unresolved dependencies"

install-$(bin_PROGRAM): $(bin_PROGRAM)
	$(INSTALL) -d -m 755 $(DESTDIR)$(USRBINDIR)
	$(INSTALL) -c $^ $(DESTDIR)$(USRBINDIR)

clean:
	$(RM) -f $($(bin_PROGRAM)_OBJS) $(bin_PROGRAM) .check-dep-$(bin_PROGRAM) .detect-openssl.dep.c

.PHONY: all install clean skip-$(bin_PROGRAM) install-$(bin_PROGRAM)

$($(bin_PROGRAM)_OBJS): .check-dep-$(bin_PROGRAM)

.detect-openssl.dep.c:
	echo "#include <openssl/evp.h>" > $@
	echo "#if OPENSSL_VERSION_NUMBER < 0x10100000L" >> $@
	echo "  #error openssl version 1.1.0 is required" >> $@
	echo "#endif" >> $@
	echo "static void __attribute__((unused)) test(void) {" >> $@
	echo "    EVP_MD_CTX *ctx = EVP_MD_CTX_new();" >> $@
	echo "    EVP_MD_CTX_free(ctx);" >> $@
	echo "}" >> $@

.check-dep-$(bin_PROGRAM): .detect-openssl.dep.c
	$(call check_dep, \
		"$(bin_PROGRAM)", \
		"glib.h", \
		"glib2-devel / libglib2.0-dev", \
		"HAVE_GLIB2=0")
	$(call check_dep, \
		"$(bin_PROGRAM)", \
		$^, \
		"openssl-devel / libssl-dev version >= 1.1.0", \
		"HAVE_OPENSSL=0", \
		"-I.")
	$(call check_dep, \
		"$(bin_PROGRAM)", \
		"curl/curl.h", \
		"libcurl-devel", \
		"HAVE_LIBCURL=0")
	touch $@
