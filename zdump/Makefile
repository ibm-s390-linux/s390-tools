include ../common.mak

ALL_CFLAGS += -Wno-address-of-packed-member

#
# HAVE_FUSE: Allow to build zgetdump without mount support
#
ifeq (${HAVE_FUSE},0)

check_dep_fuse:

else

check_dep_fuse:
	$(call check_dep, \
		"zgetdump mount support", \
		"fuse.h", \
		"fuse3-devel or libfuse3-dev", \
		"HAVE_FUSE=0", \
		"-DFUSE_USE_VERSION=30")
endif

.detect_openssl.dep.c:
	echo "#include <openssl/evp.h>" > $@
	echo "#if OPENSSL_VERSION_NUMBER < 0x10100000L" >> $@
	echo "  #error At least OpenSSL version 1.1.0 is required" >> $@
	echo "#endif" >> $@
	echo "static void __attribute__((unused)) test(void) {" >> $@
	echo "    EVP_MD_CTX *ctx = EVP_MD_CTX_new();" >> $@
	echo "    EVP_MD_CTX_free(ctx);" >> $@
	echo "}" >> $@

.check_dep_zgetdump: .detect_openssl.dep.c check_dep_fuse
	$(call check_dep, \
		"zgetdump", \
		"zlib.h", \
		"zlib-devel or libz-dev", \
		"HAVE_ZLIB=0")
	$(call check_dep, \
		"zgetdump", \
		"glib.h", \
		"glib2-devel / libglib2.0-dev", \
		"HAVE_GLIB2=0")
	$(call check_dep, \
		"zgetdump", \
		$<, \
		"openssl-devel / libssl-dev version >= 1.1.0", \
		"HAVE_OPENSSL=0", \
		"-I.")
	touch $@

#
# Allow skip of zgetdump build, when no zlib-devel, openssl-devel, glib2-devel is available
#
BUILD_TARGETS :=skip-zgetdump
INSTALL_TARGETS := skip-zgetdump
ifneq (${HAVE_ZLIB},0)
ifneq (${HAVE_OPENSSL},0)
ifneq (${HAVE_GLIB2},0)
BUILD_TARGETS := zgetdump
INSTALL_TARGETS := install-zgetdump
endif
endif
endif

OBJECTS = zgetdump.o opts.o zg.o zg_error.o zg_print.o \
	  dfi.o dfi_mem_chunk.o dfi_vmcoreinfo.o \
	  dfi_lkcd.o dfi_elf.o dfi_elf_common.o dfi_pv_elf.o \
	  dfi_s390.o dfi_s390_ext.o\
	  dfi_s390mv.o dfi_s390mv_ext.o \
	  dfi_s390tape.o dfi_kdump.o \
	  dfi_devmem.o dfo.o dfo_mem_chunk.o \
	  dfo_elf.o dfo_s390.o \
	  df_elf.o df_s390.o \
	  dt.o dt_s390sv.o dt_s390sv_ext.o \
	  dt_s390mv.o dt_s390mv_ext.o \
	  dt_scsi.o output.o \
	  ngdump.o dt_ngdump.o dfi_ngdump.o \
	  pv_utils.o

ifneq ($(shell sh -c 'command -v pkg-config'),)
GLIB2_CFLAGS := $(shell pkg-config --silence-errors --cflags glib-2.0)
GLIB2_LIBS := $(shell pkg-config --silence-errors --libs glib-2.0)
LIBCRYPTO_CFLAGS := $(shell pkg-config --silence-errors --cflags libcrypto)
LIBCRYPTO_LIBS := $(shell pkg-config --silence-errors --libs libcrypto)
else
GLIB2_CFLAGS := -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include
GLIB2_LIBS := -lglib-2.0
LIBCRYPTO_CFLAGS :=
LIBCRYPTO_LIBS := -lcrypto
endif

LIBPV = $(rootdir)/libpv/libpv.a
LIBPV_CFLAGS := -DOPENSSL_API_COMPAT=0x10100000L \
	$(GLIB2_CFLAGS) \
	$(LIBCRYPTO_CFLAGS) \
	$(NULL)
LIBPV_LIBS := $(GLIB2_LIBS) $(LIBCRYPTO_LIBS)

ifeq ("$(HAVE_FUSE)","0")
FUSE_CFLAGS = -DHAVE_FUSE=0 -D_FILE_OFFSET_BITS=64
FUSE_LDLIBS =
else ifneq ($(shell sh -c 'command -v pkg-config'),)
FUSE_CFLAGS = -DHAVE_FUSE=1 $(shell pkg-config --silence-errors --cflags fuse3)
FUSE_LDLIBS = $(shell pkg-config --silence-errors --libs fuse3)
else
FUSE_CFLAGS = -DHAVE_FUSE=1 -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse3
FUSE_LDLIBS = -lfuse3
endif
LDLIBS += -lz $(FUSE_LDLIBS) $(LIBPV_LIBS)
ALL_CFLAGS += $(FUSE_CFLAGS) $(LIBPV_CFLAGS)

ifneq ("$(HAVE_FUSE)","0")
OBJECTS += zfuse.o
endif

libs = $(rootdir)/libutil/libutil.a $(LIBPV)

all: $(BUILD_TARGETS)

zgetdump: .check_dep_zgetdump $(OBJECTS) $(libs)

skip-zgetdump:
	echo "  SKIP    zgetdump due to unresolved dependencies"

install-zgetdump: zgetdump
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8 $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 zgetdump $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 644 zgetdump.8 $(DESTDIR)$(MANDIR)/man8

install: $(INSTALL_TARGETS)

clean:
	rm -f -- *.o *~ zgetdump core.* .detect_openssl.dep.c .check_dep_zgetdump

.PHONY: all install clean check_dep_fuse check_dep_zlib skip-zgetdump install-zgetdump
