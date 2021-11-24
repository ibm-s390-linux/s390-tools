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
		"fuse-devel or libfuse-dev", \
		"HAVE_FUSE=0")
endif

#
# HAVE_ZLIB: Allow skip zgetdump build, when no zlib-devel is available
#
ifeq (${HAVE_ZLIB},0)

all:
	$(SKIP) HAVE_ZLIB=0

install:
	$(SKIP) HAVE_ZLIB=0

else

check_dep_zlib:
	$(call check_dep, \
			"zgetdump", \
			"zlib.h", \
			"zlib-devel or libz-dev", \
			"HAVE_ZLIB=0")

all: check_dep_fuse check_dep_zlib zgetdump

OBJECTS = zgetdump.o opts.o zg.o zg_error.o zg_print.o \
	  dfi.o dfi_mem_chunk.o dfi_vmcoreinfo.o \
	  dfi_lkcd.o dfi_elf.o \
	  dfi_s390.o dfi_s390_ext.o\
	  dfi_s390mv.o dfi_s390mv_ext.o \
	  dfi_s390tape.o dfi_kdump.o \
	  dfi_devmem.o dfo.o dfo_mem_chunk.o \
	  dfo_elf.o dfo_s390.o \
	  df_elf.o df_s390.o \
	  dt.o dt_s390sv.o dt_s390sv_ext.o \
	  dt_s390mv.o dt_s390mv_ext.o \
	  dt_scsi.o output.o

ifeq ("$(HAVE_FUSE)","0")
FUSE_CFLAGS = -DHAVE_FUSE=0 -D_FILE_OFFSET_BITS=64
FUSE_LDLIBS =
else ifneq ($(shell sh -c 'command -v pkg-config'),)
FUSE_CFLAGS = -DHAVE_FUSE=1 $(shell pkg-config --silence-errors --cflags fuse)
FUSE_LDLIBS = $(shell pkg-config --silence-errors --libs fuse)
else
FUSE_CFLAGS = -DHAVE_FUSE=1 -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse
FUSE_LDLIBS = -lfuse
endif
LDLIBS += -lz $(FUSE_LDLIBS)
ALL_CFLAGS += $(FUSE_CFLAGS)

ifneq ("$(HAVE_FUSE)","0")
OBJECTS += zfuse.o
endif

libs = $(rootdir)/libutil/libutil.a
zgetdump: $(OBJECTS) $(libs)

install: all
	$(INSTALL) -d -m 755 $(DESTDIR)$(MANDIR)/man8 $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 zgetdump $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 644 zgetdump.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f *.o *~ zgetdump core.*
endif

.PHONY: all install clean check_dep_fuse check_dep_zlib
